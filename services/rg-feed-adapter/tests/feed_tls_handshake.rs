//! PB-32 regression: the adapter must be able to open its `wss://` feed.
//!
//! `Cargo.toml` asks `tokio-tungstenite` for `rustls-tls-webpki-roots`,
//! which pulls `rustls` with neither the `aws-lc-rs` nor the `ring`
//! provider feature: `cargo tree -e features -p rg-feed-adapter` showed
//! `rustls feature "std"` and nothing else. `connect_async`
//! (`src/feed.rs:61`) reaches `ClientConfig::builder()` inside
//! `tokio_tungstenite::tls`, which panics with "Could not automatically
//! determine the process-level `CryptoProvider` from Rustls crate
//! features" the moment the scheme is `wss`. Both shipped configs are
//! `wss` (`config/observe.toml:7`, `config/shadow.toml:6`), so the feed
//! reader never sent a byte in either mode.
//!
//! The failure is quiet, which is why nothing caught it earlier: the
//! feed loop runs under `tokio::spawn` (`src/main.rs:127`), so the panic
//! aborts that one task and leaves the process up, still answering
//! `/health` with `feed_connected: false` and never retrying.
//!
//! The observable is the handshake, not the absence of a panic. This
//! test points the adapter's `feed_url` at a plain TCP listener over
//! `wss://` and asserts the bytes that arrive are a TLS `ClientHello`.
//! `rustls` cannot assemble a `ClientHello` without a provider to name
//! cipher suites and key shares from, so one on the wire is positive
//! proof the provider was installed and selected. Before the
//! fix the listener sees the TCP connection open and close again with
//! zero bytes written, because `connect` (`tokio-tungstenite`
//! `connect.rs`) establishes the socket before it ever builds the TLS
//! config.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;

/// The adapter is given this long to boot and reach the handshake. It
/// connects immediately on startup with no initial backoff
/// (`src/feed.rs:22`), so the failure this guards is "never", not
/// "late". A panicking adapter closes the socket right away, so the
/// red path does not wait this out.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// Enough of the first TLS record to identify it: a 5 byte record
/// header plus the handshake message type.
const CLIENT_HELLO_PREFIX: usize = 6;

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

/// `Drop` guard so a panicking test never leaks an adapter process.
struct AdapterProcess {
    child: Child,
}

impl AdapterProcess {
    /// Stop the adapter and return whatever it wrote to stderr, so a
    /// failing assertion can quote the panic instead of describing it.
    fn kill_and_drain_stderr(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut buf = String::new();
        if let Some(mut err) = self.child.stderr.take() {
            let _ = err.read_to_string(&mut buf);
        }
        buf
    }
}

impl Drop for AdapterProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Stand in for the `wss://` feed endpoint: a bare TCP listener that
/// reports the first bytes the adapter writes. It deliberately speaks no
/// TLS, because the assertion is about what the client emits, and a
/// rustls server would install a process-level provider in this test
/// process and mask nothing but would add a moving part for no gain.
///
/// Returns the bound port and a channel carrying the first bytes of the
/// first connection. An empty vector means the peer opened the socket
/// and closed it without writing.
async fn spawn_feed_listener() -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let port = listener.local_addr().expect("local addr").port();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 1024];
        while buf.len() < CLIENT_HELLO_PREFIX {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = tx.send(buf);
    });

    (port, rx)
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write file");
}

/// The adapter reaches the TLS handshake on a `wss://` feed URL.
///
/// Before PB-32 it panicked inside `connect_async` on the rustls
/// `CryptoProvider` lookup, after the TCP connection was already open,
/// so the endpoint saw a socket that opened and closed without a byte.
#[tokio::test]
async fn adapter_reaches_the_tls_handshake_on_a_wss_feed() {
    let scratch = ScratchDir::new("pb32-feed-tls");
    let (feed_port, first_bytes_rx) = spawn_feed_listener().await;

    // Loopback listen address keeps SEC-006 satisfied; port 0 lets the
    // OS pick so concurrent test binaries do not collide.
    let config = format!(
        r#"[adapter]
listen = "127.0.0.1:0"
feed_url = "wss://127.0.0.1:{feed_port}/ws"
license_key = ""
"#
    );
    let config_path = scratch.path.join("adapter.toml");
    write(&config_path, &config);

    let mut adapter = AdapterProcess {
        child: Command::new(env!("CARGO_BIN_EXE_rg-feed-adapter"))
            .arg("--config")
            .arg(&config_path)
            .env("VELDRA_LOG_FILTER", "warn")
            .current_dir(&scratch.path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rg-feed-adapter"),
    };

    let first_bytes = match tokio::time::timeout(HANDSHAKE_DEADLINE, first_bytes_rx).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => panic!("listener task dropped the channel"),
        Err(_) => {
            let stderr = adapter.kill_and_drain_stderr();
            panic!(
                "the adapter never opened a connection to its wss:// feed within \
                 {HANDSHAKE_DEADLINE:?}; adapter stderr:\n{stderr}"
            );
        }
    };

    assert!(
        first_bytes.len() >= CLIENT_HELLO_PREFIX,
        "the adapter connected to its wss:// feed and wrote {} byte(s) before closing, \
         so it never reached the TLS handshake; adapter stderr:\n{}",
        first_bytes.len(),
        adapter.kill_and_drain_stderr()
    );

    // TLS record header: type 0x16 (handshake), legacy record version
    // 0x0301, then the handshake message type 0x01 (ClientHello) at
    // offset 5. RFC 8446 5.1 and 4.1.2.
    assert_eq!(
        (first_bytes[0], first_bytes[1], first_bytes[5]),
        (0x16, 0x03, 0x01),
        "the adapter's first bytes on the wss:// feed were not a TLS ClientHello: {:02x?}",
        &first_bytes[..CLIENT_HELLO_PREFIX]
    );

    assert_eq!(
        adapter.child.try_wait().ok().flatten(),
        None,
        "the adapter exited after reaching the feed handshake"
    );
}
