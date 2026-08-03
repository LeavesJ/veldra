//! Shared harness for the pool-verifier ingress integration tests.
//!
//! `ingress_conn_cap.rs` (PB-26), `ingress_reaping.rs` (PB-27, PB-28)
//! and `https_surface.rs` (PB-30) all boot the real release binary,
//! drive it over a real socket, and assert on wire behaviour or on a
//! shipped `/metrics` sample rather than on an internal counter. PB-27
//! is the third caller of the scratch-dir, subprocess, connect, and
//! propose helpers, and `ingress_conn_cap.rs` said in prose that the
//! shared module was waiting for exactly that, so the helpers live here
//! now and that file imports them instead of keeping its own copies.
//!
//! `phase2_tcp.rs` keeps its own copies on purpose: its policy file
//! carries a `[policy.mempool]` section, it spawns a mock bitcoind RPC
//! the verifier must poll, and its round trip opens a fresh connection
//! per template. Folding it in would mean parameterising three unrelated
//! things through one helper.

// Cargo compiles this module separately into every integration test
// binary that declares `mod common;`, so anything only one of them uses
// is dead code in the other. Without this the `-D warnings` clippy gate
// fails on the binary that does not use it.
#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rg_protocol::gateway::{InternalMessage, msg_types};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// RAII scratch directory. Composes the path with pid plus nanos for
/// collision safety and tears down on `Drop`, so a panicking test never
/// leaks the tree.
pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    pub fn new(label: &str) -> std::io::Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("rg-{label}-{pid}-{nanos}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `Drop` guard that kills the spawned pool-verifier subprocess so a
/// panicking test never leaks a process holding the listener port.
pub struct VerifierProcess {
    child: Child,
    _scratch: ScratchDir,
}

impl Drop for VerifierProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Booted verifier under test. `proc` is held for its `Drop` side
/// effect and for `exit_status`.
pub struct Booted {
    pub proc: VerifierProcess,
    pub tcp_port: u16,
    pub http_port: u16,
}

impl Booted {
    /// Dial string for the IPv4 loopback view of the ingress.
    pub fn v4_addr(&self) -> String {
        format!("127.0.0.1:{}", self.tcp_port)
    }

    /// Dial string for the IPv6 loopback view of the ingress. Only
    /// reachable when the verifier was booted with `bind_host = "[::]"`.
    pub fn v6_addr(&self) -> String {
        format!("[::1]:{}", self.tcp_port)
    }

    /// `Some(status)` once the child has exited. Used to tell "the
    /// ingress is still starting" from "the ingress died on boot".
    pub fn exit_status(&mut self) -> Option<std::process::ExitStatus> {
        self.proc.child.try_wait().ok().flatten()
    }
}

/// Serializes the port-discovery / spawn window across the tests in one
/// binary. cargo runs tests inside one binary on multiple threads, and
/// the kernel can hand the same `127.0.0.1:0` port to two parallel
/// discovery calls between their drop-and-spawn windows.
pub static BOOT_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn discover_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

/// Phase 1 policy: every threshold permissive, no `[policy.mempool]`
/// section, so the tests exercise the ingress and not the evaluator.
pub fn write_policy_toml(scratch: &Path) -> PathBuf {
    let policy_path = scratch.join("policy.toml");
    let toml = r"[policy]
protocol_version = 2
required_prevhash_len = 64
min_total_fees = 0
max_tx_count = 4294967295
low_mempool_tx = 0
high_mempool_tx = 0
min_avg_fee_lo = 0
min_avg_fee_mid = 0
min_avg_fee_hi = 0
reject_empty_templates = false
reject_coinbase_zero = false
unknown_mempool_as_high = true

[policy.safety]
max_weight_ratio = 0.999
enforce_weight_ratio = false
enforce_template_age = false
warn_sigops_ratio = 0.95
warn_coinbase_sigops_max = 400
";
    let mut f = std::fs::File::create(&policy_path).expect("create policy.toml");
    f.write_all(toml.as_bytes()).expect("write policy.toml");
    policy_path
}

/// Knobs the ingress tests need to vary when booting the real binary.
pub struct BootOptions {
    /// Scratch-directory label, so a leaked tree names its test.
    pub label: &'static str,
    /// `VELDRA_VERIFIER_MAX_CONNECTIONS`. Two is enough to prove the
    /// global cap binds while leaving one connection provably good.
    pub max_connections: u32,
    /// `VELDRA_VERIFIER_MAX_CONNECTIONS_PER_IP`. `None` leaves the
    /// shipped default in place.
    pub max_connections_per_ip: Option<u32>,
    /// `VELDRA_VERIFIER_IDLE_TIMEOUT_SECS`. `None` leaves the shipped
    /// default in place, which is far too long for a test to wait on.
    pub idle_timeout_secs: Option<u64>,
    /// Host part of `VELDRA_VERIFIER_ADDR`. `"[::]"` gives a dual-stack
    /// listener, which is the only way to reach one listener from two
    /// distinct peer IPs without a loopback alias (macOS has no
    /// 127.0.0.2 without root). Verified: the IPv4 client is reported
    /// as `::ffff:127.0.0.1` and the IPv6 client as `::1`.
    pub bind_host: &'static str,
    /// Generate a self-signed cert and boot the ingress with TLS, so
    /// the TLS handshake path is under test.
    pub tls: bool,
    /// `VELDRA_TLS_SELF_SIGNED=1`: serve the HTTP surface (`/metrics`,
    /// `/health`, the dashboard) over HTTPS. Independent of `tls`, which
    /// is the NDJSON ingress. PB-30: HTTPS on with ingress TLS off is
    /// the shipped default and the combination that had no test.
    pub https_self_signed: bool,
}

impl Default for BootOptions {
    fn default() -> Self {
        Self {
            label: "ingress",
            max_connections: 2,
            max_connections_per_ip: None,
            idle_timeout_secs: None,
            bind_host: "127.0.0.1",
            tls: false,
            https_self_signed: false,
        }
    }
}

/// Boot the real binary under `opts`.
pub async fn boot_verifier(opts: BootOptions) -> Booted {
    let _boot_guard = BOOT_MUTEX.lock().await;

    let tcp_port = discover_free_port().await;
    let http_port = discover_free_port().await;
    let scratch = ScratchDir::new(opts.label).expect("create scratch dir");
    let policy_path = write_policy_toml(scratch.path());

    let bin = env!("CARGO_BIN_EXE_pool-verifier");
    let mut cmd = Command::new(bin);
    cmd.env("VELDRA_POLICY_FILE", &policy_path)
        .env(
            "VELDRA_VERIFIER_ADDR",
            format!("{}:{tcp_port}", opts.bind_host),
        )
        .env("VELDRA_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
        .env(
            "VELDRA_VERIFIER_MAX_CONNECTIONS",
            opts.max_connections.to_string(),
        )
        .env("VELDRA_API_SECRET_OPTIONAL", "1")
        .env(
            "VELDRA_VERIFIER_CONFIG",
            scratch.path().join("verifier.toml"),
        )
        .env("VELDRA_LOG_FILTER", "warn")
        .current_dir(scratch.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(per_ip) = opts.max_connections_per_ip {
        cmd.env("VELDRA_VERIFIER_MAX_CONNECTIONS_PER_IP", per_ip.to_string());
    }
    if let Some(idle) = opts.idle_timeout_secs {
        cmd.env("VELDRA_VERIFIER_IDLE_TIMEOUT_SECS", idle.to_string());
    }
    if opts.tls {
        let (cert_pem, key_pem) = self_signed_pem();
        let cert_path = scratch.path().join("ingress-cert.pem");
        let key_path = scratch.path().join("ingress-key.pem");
        std::fs::write(&cert_path, cert_pem).expect("write cert pem");
        std::fs::write(&key_path, key_pem).expect("write key pem");
        cmd.env("VELDRA_VERIFIER_TLS_CERT", &cert_path)
            .env("VELDRA_VERIFIER_TLS_KEY", &key_path);
    }
    if opts.https_self_signed {
        cmd.env("VELDRA_TLS_SELF_SIGNED", "1");
    }

    let child = cmd.spawn().expect("spawn pool-verifier");

    Booted {
        proc: VerifierProcess {
            child,
            _scratch: scratch,
        },
        tcp_port,
        http_port,
    }
}

/// Self-signed cert and key PEMs for the TLS ingress tests. Same rcgen
/// shape as `ingress::generate_self_signed_cert`, which an integration
/// test cannot reach because it is crate-private.
fn self_signed_pem() -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("rcgen params");
    let cert = params.self_signed(&key_pair).expect("rcgen self-sign");
    (
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    )
}

/// A live ingress connection held open for the duration of a test.
///
/// Generic over the transport so the same `propose` / `closed_within`
/// observables work on a plaintext socket and on a completed TLS
/// session.
pub struct Conn<S = tokio::net::tcp::OwnedReadHalf, W = tokio::net::tcp::OwnedWriteHalf> {
    pub reader: BufReader<S>,
    pub writer: W,
}

/// Connect to the ingress, retrying until the listener is bound.
///
/// Deliberately keeps the first connection that succeeds instead of
/// probing with a throwaway socket: a probe would burn a permit, and
/// the server only releases it once the connection ends, which races
/// the very cap these tests exercise.
pub async fn connect(addr: &str, deadline: Duration) -> Conn {
    let start = Instant::now();
    loop {
        if let Ok(stream) = TcpStream::connect(addr).await {
            let (read_half, writer) = stream.into_split();
            return Conn {
                reader: BufReader::new(read_half),
                writer,
            };
        }
        assert!(
            start.elapsed() < deadline,
            "verifier ingress on {addr} never accepted within {deadline:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn clean_template(id: u64) -> TemplatePropose {
    TemplatePropose {
        version: PROTOCOL_VERSION,
        id,
        block_height: 800_000,
        prev_hash: "a".repeat(64),
        coinbase_value: 312_500_000,
        tx_count: 1,
        total_fees: 0,
        observed_weight: None,
        created_at_unix_ms: None,
        total_sigops: None,
        coinbase_sigops: None,
        template_weight: None,
        gateway_instance_id: None,
        raw_block_hex: None,
    }
}

pub fn envelope_line(template: &TemplatePropose) -> String {
    let env = InternalMessage {
        msg_type: msg_types::TEMPLATE_PROPOSE.to_string(),
        version: PROTOCOL_VERSION,
        payload: serde_json::to_value(template).expect("serialize template"),
    };
    let mut line = serde_json::to_string(&env).expect("serialize envelope");
    line.push('\n');
    line
}

/// Outcome of pushing one template down a connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The verifier answered with a `TemplateVerdict` for `id`.
    Verdict { id: u64, accepted: bool },
    /// The verifier closed the connection without answering. This is
    /// how a refused connection looks on the wire: the accept loop
    /// drops the socket, so the peer sees EOF or a reset rather than a
    /// verdict.
    Closed,
}

/// Write one template and read at most one line back, bounded by `wait`
/// so a hung ingress fails the test instead of hanging it.
pub async fn propose<S, W>(
    conn: &mut Conn<S, W>,
    template: &TemplatePropose,
    wait: Duration,
) -> Outcome
where
    S: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let line = envelope_line(template);
    if conn.writer.write_all(line.as_bytes()).await.is_err() || conn.writer.flush().await.is_err() {
        // A reset arriving before the write lands is the same refusal.
        return Outcome::Closed;
    }
    read_outcome(conn, wait).await
}

/// Read at most one verdict line from an already-written connection.
pub async fn read_outcome<S, W>(conn: &mut Conn<S, W>, wait: Duration) -> Outcome
where
    S: AsyncRead + Unpin,
{
    let mut buf = String::new();
    // A bounded wait, so a hung ingress fails this test instead of
    // hanging the suite. `Elapsed` carries nothing to match on.
    let read = tokio::time::timeout(wait, conn.reader.read_line(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("ingress neither answered nor closed within {wait:?}"));
    match read {
        Err(_reset) => Outcome::Closed,
        Ok(0) => Outcome::Closed,
        Ok(_n) => {
            let env: InternalMessage =
                serde_json::from_str(buf.trim()).expect("parse verdict envelope");
            assert_eq!(
                env.msg_type,
                msg_types::TEMPLATE_VERDICT,
                "unexpected msg_type: {}",
                env.msg_type
            );
            let verdict: TemplateVerdict =
                serde_json::from_value(env.payload).expect("parse verdict payload");
            Outcome::Verdict {
                id: verdict.id,
                accepted: verdict.accepted,
            }
        }
    }
}

/// Did the server close this connection within `wait`?
///
/// The distinguishing observable for peers that never speak: a refused
/// or reaped connection sees EOF or a reset, an admitted one sees
/// neither. Returns `false` on timeout rather than panicking, because
/// "still open" is a legitimate answer here.
pub async fn closed_within<S, W>(conn: &mut Conn<S, W>, wait: Duration) -> bool
where
    S: AsyncRead + Unpin,
{
    let mut buf = String::new();
    match tokio::time::timeout(wait, conn.reader.read_line(&mut buf)).await {
        Err(_elapsed) => false,
        Ok(Err(_reset)) => true,
        Ok(Ok(0)) => true,
        Ok(Ok(_n)) => panic!("expected silence or a close, got a line: {buf}"),
    }
}

/// Scrape the public `/metrics` endpoint.
pub async fn scrape_metrics(http_port: u16) -> String {
    let url = format!("http://127.0.0.1:{http_port}/metrics");
    let client = reqwest::Client::new();
    let start = Instant::now();
    loop {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return resp.text().await.expect("read /metrics body");
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "/metrics on 127.0.0.1:{http_port} never served within 30s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Read one unlabelled sample from the exposition text. Counters and
/// gauges print the same `name value` shape, so one reader covers both;
/// gauges are signed, which is why this returns `i64`.
pub fn sample_value(body: &str, name: &str) -> i64 {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix(name)
            && let Some(v) = rest.strip_prefix(' ')
        {
            return v
                .trim()
                .parse::<i64>()
                .unwrap_or_else(|e| panic!("sample `{name}` value `{v}` is not an integer: {e}"));
        }
    }
    panic!("metric `{name}` absent from /metrics:\n{body}");
}

/// Poll `/metrics` until `name` reads `want`, or fail with the last
/// value seen. Used where the observable is a metric that settles
/// asynchronously, such as a slot returning after a reap.
pub async fn wait_for_sample(http_port: u16, name: &str, want: i64, deadline: Duration) {
    let start = Instant::now();
    let mut last = i64::MIN;
    while start.elapsed() < deadline {
        let body = scrape_metrics(http_port).await;
        last = sample_value(&body, name);
        if last == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("`{name}` never reached {want} within {deadline:?}; last value {last}");
}

// ── TLS client ───────────────────────────────────────────────────────

/// Complete a real TLS handshake against the ingress and return the
/// established session as a `Conn`.
///
/// The cert is generated per boot and self-signed, so the client skips
/// certificate validation: this exercises the server's handshake path,
/// which is what PB-28 broke, not PKI. The provider is passed to the
/// client builder explicitly rather than installed process-wide, so
/// this helper cannot mask a missing `install_default` on the server
/// side, which is the exact defect under test.
pub async fn tls_connect(
    addr: &str,
    deadline: Duration,
) -> Conn<
    tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>,
    tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
> {
    use tokio_rustls::rustls::{ClientConfig, crypto, pki_types::ServerName};

    let provider = Arc::new(crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"rg-ndjson".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let start = Instant::now();
    loop {
        if let Ok(tcp) = TcpStream::connect(addr).await {
            let name = ServerName::try_from("localhost").expect("server name");
            match connector.connect(name, tcp).await {
                Ok(tls) => {
                    let (read_half, writer) = tokio::io::split(tls);
                    return Conn {
                        reader: BufReader::new(read_half),
                        writer,
                    };
                }
                Err(e) => {
                    assert!(
                        start.elapsed() < deadline,
                        "TLS handshake against {addr} never completed within {deadline:?}: {e}"
                    );
                }
            }
        }
        assert!(
            start.elapsed() < deadline,
            "verifier TLS ingress on {addr} never accepted within {deadline:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `GET path` over HTTPS against the verifier's HTTP surface, returning
/// the status code and the response body.
///
/// PB-30 needs the status, not "did anything come back", so this speaks
/// HTTP/1.1 down a `tokio-rustls` session rather than using `reqwest`.
/// Two reasons: the provider is passed to the client builder explicitly,
/// so a missing process-level install on the server side cannot be
/// masked by one this test process happens to have made, and the raw
/// status line is the observable the report has to quote.
pub async fn https_get(http_port: u16, path: &str, deadline: Duration) -> (u16, String) {
    use tokio_rustls::rustls::{ClientConfig, crypto};

    let provider = Arc::new(crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    // `axum-server` offers h2 and http/1.1. Pin http/1.1 so the request
    // written below is the protocol actually negotiated.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let addr = format!("127.0.0.1:{http_port}");

    let start = Instant::now();
    let mut last = "no attempt completed".to_string();
    while start.elapsed() < deadline {
        match https_get_once(&connector, &addr, path).await {
            Ok(response) => return response,
            Err(e) => last = e,
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("HTTPS GET {path} on {addr} never answered within {deadline:?}; last error: {last}");
}

async fn https_get_once(
    connector: &tokio_rustls::TlsConnector,
    addr: &str,
    path: &str,
) -> Result<(u16, String), String> {
    use tokio::io::AsyncReadExt as _;
    use tokio_rustls::rustls::pki_types::ServerName;

    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("tcp connect: {e}"))?;
    let name = ServerName::try_from("localhost").map_err(|e| format!("server name: {e}"))?;
    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| format!("tls handshake: {e}"))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write request: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut raw = Vec::new();
    tls.read_to_end(&mut raw)
        .await
        .map_err(|e| format!("read response: {e}"))?;
    let text = String::from_utf8_lossy(&raw).into_owned();

    let status_line = text.lines().next().ok_or("empty response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("no status code in `{status_line}`"))?
        .parse()
        .map_err(|e| format!("status code in `{status_line}`: {e}"))?;
    let body = text
        .split_once("\r\n\r\n")
        .map_or_else(String::new, |(_headers, body)| body.to_string());
    Ok((status, body))
}

/// Accepts any server certificate. Test-only, and only reachable from
/// `tls_connect` above.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<tokio_rustls::rustls::crypto::CryptoProvider>);

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
