//! PB-26 regression: the NDJSON ingress must cap concurrent TCP
//! connections.
//!
//! The ingress accepts unauthenticated peers (`ingress.rs` builds its
//! TLS acceptor `.with_no_client_auth()`, and shadow/observe compose
//! bind it on `0.0.0.0:9090`), and every live connection holds a line
//! buffer up to `MAX_INTERNAL_LINE_BYTES`, which PB-19 raised to
//! 20 MiB so mainnet `raw_block_hex` fits. Without a cap on how many
//! connections are live at once, any reachable peer can drive the
//! verifier out of memory. That does not fail closed: the gateway's
//! `auto_degrade` (default true) observes the dead verifier, suspends
//! enforcement, and keeps shipping templates, which is exactly what
//! the Invariant Shield exists to prevent.
//!
//! These tests drive the real release binary over a real socket and
//! assert on wire behaviour (a verdict came back, or the peer was
//! closed without one), not on an internal counter. They are NOT
//! `#[ignore]`d: a Critical remote-DoS regression test that only runs
//! when someone remembers to pass `--ignored` is a test nobody runs.
//!
//! The scratch-dir and subprocess guards below are a second copy of
//! the ones in `phase2_tcp.rs`. Integration tests are separate crates
//! and cannot share private helpers without a `tests/common` module;
//! two copies is a copy, so under the repo's rule of three the shared
//! module waits for a third test binary that needs them.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rg_protocol::gateway::{InternalMessage, msg_types};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

/// Cap the verifier under test runs with. Two is enough to prove the
/// cap binds, that a connection under it still works, and that a
/// permit comes back on disconnect.
const TEST_CAP: u32 = 2;

/// RAII scratch directory. Composes the path with pid plus nanos for
/// collision safety and tears down on `Drop`, so a panicking test
/// never leaks the tree.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(label: &str) -> std::io::Result<Self> {
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

    fn path(&self) -> &Path {
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
struct VerifierProcess {
    child: Child,
    _scratch: ScratchDir,
}

impl Drop for VerifierProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Booted verifier under test. `_proc` is held only for its `Drop`
/// side effect.
struct Booted {
    _proc: VerifierProcess,
    tcp_port: u16,
    http_port: u16,
}

/// Serializes the port-discovery / spawn window across the tests in
/// this binary. cargo runs tests inside one binary on multiple
/// threads, and the kernel can hand the same `127.0.0.1:0` port to
/// two parallel discovery calls between their drop-and-spawn windows.
static BOOT_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn discover_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

/// Phase 1 policy: every threshold permissive, no `[policy.mempool]`
/// section, so the tests exercise the ingress and not the evaluator.
fn write_policy_toml(scratch: &Path) -> PathBuf {
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

/// Boot the real binary with the connection cap set to `TEST_CAP`.
async fn boot_verifier() -> Booted {
    let _boot_guard = BOOT_MUTEX.lock().await;

    let tcp_port = discover_free_port().await;
    let http_port = discover_free_port().await;
    let scratch = ScratchDir::new("pb26-conn-cap").expect("create scratch dir");
    let policy_path = write_policy_toml(scratch.path());

    let bin = env!("CARGO_BIN_EXE_pool-verifier");
    let child = Command::new(bin)
        .env("VELDRA_POLICY_FILE", &policy_path)
        .env("VELDRA_VERIFIER_ADDR", format!("127.0.0.1:{tcp_port}"))
        .env("VELDRA_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
        .env("VELDRA_VERIFIER_MAX_CONNECTIONS", TEST_CAP.to_string())
        .env("VELDRA_API_SECRET_OPTIONAL", "1")
        .env(
            "VELDRA_VERIFIER_CONFIG",
            scratch.path().join("verifier.toml"),
        )
        .env("VELDRA_LOG_FILTER", "warn")
        .current_dir(scratch.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pool-verifier");

    Booted {
        _proc: VerifierProcess {
            child,
            _scratch: scratch,
        },
        tcp_port,
        http_port,
    }
}

/// A live ingress connection held open for the duration of a test.
struct Conn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

/// Connect to the ingress, retrying until the listener is bound.
///
/// Deliberately keeps the first connection that succeeds instead of
/// probing with a throwaway socket: a probe would burn a permit, and
/// the server only releases it once it observes EOF, which races the
/// very cap this file is testing.
async fn connect(port: u16, deadline: Duration) -> Conn {
    let start = Instant::now();
    loop {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            let (read_half, writer) = stream.into_split();
            return Conn {
                reader: BufReader::new(read_half),
                writer,
            };
        }
        assert!(
            start.elapsed() < deadline,
            "verifier ingress on 127.0.0.1:{port} never accepted within {deadline:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn clean_template(id: u64) -> TemplatePropose {
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

fn envelope_line(template: &TemplatePropose) -> String {
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
enum Outcome {
    /// The verifier answered with a `TemplateVerdict` for `id`.
    Verdict { id: u64, accepted: bool },
    /// The verifier closed the connection without answering. This is
    /// how a refused connection looks on the wire: the accept loop
    /// drops the socket, so the peer sees EOF or a reset rather than
    /// a verdict.
    Closed,
}

/// Write one template and read at most one line back, bounded by
/// `wait` so a hung ingress fails the test instead of hanging it.
async fn propose(conn: &mut Conn, template: &TemplatePropose, wait: Duration) -> Outcome {
    let line = envelope_line(template);
    if conn.writer.write_all(line.as_bytes()).await.is_err() || conn.writer.flush().await.is_err() {
        // A reset arriving before the write lands is the same refusal.
        return Outcome::Closed;
    }

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

/// Scrape the public `/metrics` endpoint.
async fn scrape_metrics(http_port: u16) -> String {
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

/// Read the value of a single unlabelled counter sample.
fn counter_value(body: &str, name: &str) -> u64 {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix(name)
            && let Some(v) = rest.strip_prefix(' ')
        {
            return v.trim().parse::<u64>().unwrap_or_else(|e| {
                panic!("counter `{name}` sample `{v}` is not an integer: {e}")
            });
        }
    }
    panic!("counter `{name}` absent from /metrics:\n{body}");
}

/// PB-26 core regression. With the cap at 2, the third concurrent
/// peer must not be admitted, and the slot must come back when a
/// held connection goes away.
#[tokio::test]
async fn ingress_refuses_connections_beyond_the_cap() {
    let booted = boot_verifier().await;
    let port = booted.tcp_port;
    let answer = Duration::from_secs(10);

    // Two connections inside the cap: both must work normally. This
    // is the legitimate gateway path (one persistent NDJSON stream
    // per gateway), so it doubles as the "did not break the good
    // case" assertion.
    let mut first = connect(port, Duration::from_secs(30)).await;
    assert_eq!(
        propose(&mut first, &clean_template(1), answer).await,
        Outcome::Verdict {
            id: 1,
            accepted: true
        },
        "connection 1 of {TEST_CAP} must be served normally"
    );

    let mut second = connect(port, Duration::from_secs(5)).await;
    assert_eq!(
        propose(&mut second, &clean_template(2), answer).await,
        Outcome::Verdict {
            id: 2,
            accepted: true
        },
        "connection 2 of {TEST_CAP} must be served normally"
    );

    // Third concurrent peer, one past the cap. It must be closed
    // without a verdict rather than admitted and given a 20 MiB line
    // buffer of its own.
    let mut third = connect(port, Duration::from_secs(5)).await;
    assert_eq!(
        propose(&mut third, &clean_template(3), answer).await,
        Outcome::Closed,
        "connection {} exceeds the cap of {TEST_CAP} and must not be admitted",
        TEST_CAP + 1
    );

    // The refusal must be observable, not silent.
    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        counter_value(&body, "verifier_connections_refused_total"),
        1,
        "exactly one refusal expected in /metrics:\n{body}"
    );

    // The cap is on concurrency, not on lifetime totals: dropping a
    // held connection must return its slot.
    drop(first);
    let mut replacement = None;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        let mut candidate = connect(port, Duration::from_secs(5)).await;
        if let Outcome::Verdict { id, accepted } =
            propose(&mut candidate, &clean_template(4), answer).await
        {
            replacement = Some((id, accepted));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        replacement,
        Some((4, true)),
        "the permit held by connection 1 must be released when it disconnects"
    );

    // `second` stays live to the end so the cap is genuinely
    // saturated for the whole test rather than by accident of GC.
    drop(second);
    drop(third);
}

/// The cap must not undo PB-19. A multi-megabyte `raw_block_hex`
/// line, the reason `MAX_INTERNAL_LINE_BYTES` is 20 MiB and the
/// shape the Class M mainnet soak sends, must still round-trip on an
/// admitted connection.
#[tokio::test]
async fn large_raw_block_hex_line_still_round_trips_under_the_cap() {
    let booted = boot_verifier().await;
    let mut conn = connect(booted.tcp_port, Duration::from_secs(30)).await;

    // 2 MiB of block bytes, so 4 MiB of hex: four times the 1 MiB
    // budget that predated PB-19, and comfortably inside 20 MiB. The
    // bytes are not a real block, so the Invariant Shield rejects the
    // template; what is under test is that the line was read, parsed,
    // evaluated, and answered rather than truncated or dropped.
    let mut template = clean_template(7);
    template.raw_block_hex = Some("00".repeat(2 * 1024 * 1024));

    let line_len = envelope_line(&template).len();
    assert!(
        line_len > 4 * 1024 * 1024,
        "test is only meaningful past the pre-PB-19 1 MiB budget, line was {line_len} bytes"
    );

    let outcome = propose(&mut conn, &template, Duration::from_secs(30)).await;
    assert_eq!(
        outcome,
        Outcome::Verdict {
            id: 7,
            accepted: false
        },
        "a {line_len}-byte line must still reach the evaluator and get a verdict"
    );

    // The same connection stays usable afterwards: the oversize line
    // consumed its budget, not the stream.
    assert_eq!(
        propose(&mut conn, &clean_template(8), Duration::from_secs(10)).await,
        Outcome::Verdict {
            id: 8,
            accepted: true
        },
        "the connection must survive a multi-megabyte line"
    );
}
