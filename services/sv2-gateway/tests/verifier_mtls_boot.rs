//! PB-30 regression: the gateway must be able to open its mTLS channel
//! to the verifier.
//!
//! PB-28 made the verifier's TLS ingress bootable by installing a
//! process-level rustls `CryptoProvider` inside the verifier. Nothing
//! installed one in `sv2-gateway`: `grep -rn install_default
//! services/sv2-gateway/src/` returned nothing, and the workspace
//! enables two providers (`aws-lc-rs` via `axum-server`/`tokio-rustls`,
//! `ring` via `reqwest`), so `ClientConfig::builder()` in
//! `build_verifier_tls` (`main.rs:2440`) panicked with "Could not
//! automatically determine the process-level CryptoProvider from Rustls
//! crate features" the moment `verifier.tls_ca_cert` was set. The server
//! end was fixed while its only production client still died on the
//! first line of the same handshake.
//!
//! The observable is the handshake itself, not the absence of a panic:
//! this test stands up a real mTLS listener holding the verifier's role
//! and asserts the gateway completes a session against it, presenting a
//! client certificate the listener's `WebPkiClientVerifier` accepts.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;

/// The gateway is given this long to boot and complete the handshake. A
/// panicking gateway never connects at all, so the failure this guards
/// is "never", not "late".
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// RAII scratch directory, torn down on `Drop` so a panicking test does
/// not leak the tree.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("rg-{label}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `Drop` guard so a panicking test never leaks a gateway process.
struct GatewayProcess {
    child: Child,
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A CA plus the two leaf identities the mTLS channel needs.
struct Pki {
    ca_pem: String,
    server_chain: Vec<rcgen::CertifiedKey>,
}

/// Mint a CA, a server certificate for `localhost`, and a client
/// certificate, all under the one CA. Written out as the three PEM files
/// the gateway config names plus the pair the test listener serves.
fn write_pki(dir: &Path) -> (Pki, PathBuf, PathBuf, PathBuf) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let ca_key = KeyPair::generate().expect("ca keypair");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign ca");

    let server_key = KeyPair::generate().expect("server keypair");
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server cert");

    let client_key = KeyPair::generate().expect("client keypair");
    let mut client_params =
        CertificateParams::new(vec!["gateway".to_string()]).expect("client params");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("sign client cert");

    let ca_path = dir.join("ca.pem");
    let client_cert_path = dir.join("client-cert.pem");
    let client_key_path = dir.join("client-key.pem");
    write(&ca_path, &ca_cert.pem());
    write(&client_cert_path, &client_cert.pem());
    write(&client_key_path, &client_key.serialize_pem());

    (
        Pki {
            ca_pem: ca_cert.pem(),
            server_chain: vec![rcgen::CertifiedKey {
                cert: server_cert,
                key_pair: server_key,
            }],
        },
        ca_path,
        client_cert_path,
        client_key_path,
    )
}

fn write(path: &Path, contents: &str) {
    let mut f = std::fs::File::create(path).expect("create pem");
    f.write_all(contents.as_bytes()).expect("write pem");
}

/// Stand in for the verifier's TLS ingress: a listener that demands a
/// client certificate signed by the same CA. Returns the bound address
/// and a channel that carries the first completed handshake.
async fn spawn_verifier_tls_listener(
    pki: &Pki,
) -> (String, tokio::sync::oneshot::Receiver<String>) {
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::server::WebPkiClientVerifier;
    use tokio_rustls::rustls::{RootCertStore, ServerConfig, crypto};

    // The provider is handed to the builder explicitly. A listener that
    // relied on the process-level default would install one as a side
    // effect and mask the very defect under test.
    let provider = Arc::new(crypto::aws_lc_rs::default_provider());

    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut pki.ca_pem.as_bytes()) {
        roots.add(cert.expect("parse ca pem")).expect("add ca");
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .expect("client verifier");

    let certified = &pki.server_chain[0];
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut certified.cert.pem().as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse server cert");
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut certified.key_pair.serialize_pem().as_bytes())
            .expect("parse server key")
            .expect("server key present");

    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let addr = listener.local_addr().expect("local addr").to_string();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                return;
            };
            match acceptor.accept(stream).await {
                Ok(_session) => {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(format!("mTLS session established from {peer}"));
                    }
                }
                Err(e) => {
                    // Keep serving: the gateway reconnects, and one
                    // failed handshake is not the verdict.
                    eprintln!("test listener handshake failed from {peer}: {e}");
                }
            }
        }
    });

    (addr, rx)
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let port = l.local_addr().expect("local addr").port();
    drop(l);
    port
}

/// The gateway boots with `verifier.tls_ca_cert` set and opens the mTLS
/// channel. Before PB-30 it panicked on the rustls `CryptoProvider`
/// before the first packet, so no session ever reached the verifier.
#[tokio::test]
async fn gateway_opens_the_verifier_mtls_channel() {
    let scratch = ScratchDir::new("pb30-gw-mtls");
    let (pki, ca_path, client_cert_path, client_key_path) = write_pki(&scratch.path);
    let (verifier_addr, handshake_rx) = spawn_verifier_tls_listener(&pki).await;
    let health_port = free_port().await;

    // Shadow mode: no miner listener, so no Noise authority keypair is
    // required, and the verifier channel is still opened
    // unconditionally (`main.rs:902`).
    let config = format!(
        r#"mode = "shadow"

[gateway]
listen_addr = "127.0.0.1:0"
health_addr = "127.0.0.1:{health_port}"
noise_keypair_path = "unused-in-shadow-mode.key"
authority_pubkey = "9095236f0477b38d1dabc5a098de5f19da2b1400c67cb7b3fd15904b4b9ab7b8"
template_url = "http://127.0.0.1:1"

[verifier]
addr = "{verifier_addr}"
tls_ca_cert = "{ca}"
tls_client_cert = "{client_cert}"
tls_client_key = "{client_key}"
tls_server_name = "localhost"
"#,
        ca = ca_path.display(),
        client_cert = client_cert_path.display(),
        client_key = client_key_path.display(),
    );
    let config_path = scratch.path.join("gateway.toml");
    write(&config_path, &config);

    let mut gateway = GatewayProcess {
        child: Command::new(env!("CARGO_BIN_EXE_sv2-gateway"))
            .arg("--config")
            .arg(&config_path)
            .env("VELDRA_API_SECRET_OPTIONAL", "1")
            .env("VELDRA_LOG_FILTER", "warn")
            .current_dir(&scratch.path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sv2-gateway"),
    };

    let established = tokio::time::timeout(HANDSHAKE_DEADLINE, handshake_rx)
        .await
        .unwrap_or_else(|_| {
            let exit = gateway.child.try_wait().ok().flatten();
            panic!(
                "the gateway never completed an mTLS handshake against the verifier within \
                 {HANDSHAKE_DEADLINE:?} (process exit status: {exit:?})"
            )
        })
        .expect("listener task dropped the handshake channel");
    assert!(
        established.contains("mTLS session established"),
        "unexpected handshake report: {established}"
    );

    assert_eq!(
        gateway.child.try_wait().ok().flatten(),
        None,
        "the gateway exited after establishing the verifier channel"
    );
}
