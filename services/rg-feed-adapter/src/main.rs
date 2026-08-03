// rg-feed-adapter: translates a WebSocket template feed into bitcoind JSON-RPC
// responses so template-manager can consume feed data without code changes.
//
// Supports two feed sources:
//   - rg-demo-feed (shadow mode, unauthenticated)
//   - rg-feed-server (observe mode, license key auth)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::{get, post};
use clap::Parser;
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

mod config;
mod feed;
mod rpc;

use config::AdapterConfig;

// ---------------------------------------------------------------------------
// Shared state: latest feed data buffered for RPC consumers
// ---------------------------------------------------------------------------

/// Holds the most recent feed frames. Updated by the WebSocket reader task,
/// read by the JSON-RPC handler on each template-manager poll.
#[derive(Default)]
pub struct FeedBuffer {
    /// Raw JSON value from the latest `blocktemplate` feed frame.
    pub block_template: Option<serde_json::Value>,
    /// Raw JSON value from the latest `mempoolinfo` feed frame.
    pub mempool_info: Option<serde_json::Value>,
    /// When the last `blocktemplate` frame arrived.
    pub last_template_ts: Option<Instant>,
    /// Whether the WebSocket is currently connected.
    pub feed_connected: bool,
}

pub type SharedBuffer = Arc<RwLock<FeedBuffer>>;

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    feed_connected: bool,
    last_template_age_ms: Option<u64>,
}

async fn health(State(buf): State<SharedBuffer>) -> axum::Json<HealthResponse> {
    let guard = buf.read().await;
    let age = guard
        .last_template_ts
        .map(|ts| u64::try_from(ts.elapsed().as_millis()).unwrap_or(u64::MAX));
    axum::Json(HealthResponse {
        status: if guard.feed_connected {
            "ok"
        } else {
            "degraded"
        },
        feed_connected: guard.feed_connected,
        last_template_age_ms: age,
    })
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "rg-feed-adapter",
    about = "WebSocket feed to bitcoind JSON-RPC adapter"
)]
struct Cli {
    /// Path to TOML config file.
    #[arg(
        long,
        env = "VELDRA_ADAPTER_CONFIG",
        default_value = "config/adapter.toml"
    )]
    config: String,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Tracing setup ---------------------------------------------------------
    let filter = std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into());
    let fmt = std::env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "pretty".into());

    let subscriber = tracing_subscriber::fmt().with_env_filter(&filter);

    if fmt == "json" {
        subscriber.json().init();
    } else {
        subscriber.init();
    }

    // Ahead of the feed reader task, because `connect_async` builds a
    // rustls `ClientConfig` the moment the feed URL is `wss://`, which
    // both shipped configs are (PB-32). `tokio-tungstenite`'s
    // `rustls-tls-webpki-roots` resolved rustls with no provider feature
    // at all, so that builder panicked and took the feed task with it.
    //
    // What repaired that is the `reservegrid-common/rustls-provider`
    // edge in Cargo.toml: with `aws-lc-rs` resolving and `ring` not,
    // rustls' own lazy auto-selection would now find exactly one
    // candidate. Removing this call alone leaves the test in
    // `tests/feed_tls_handshake.rs` green, and that was measured, not
    // assumed. The call stays because "exactly one provider feature
    // resolves transitively" is the assumption that broke three times
    // (PB-28, PB-30, PB-32): one `reqwest` anywhere in this crate's
    // graph adds `ring` and the count goes to two. Pinning the choice
    // here makes that a no-op instead of a fresh panic, and makes a
    // provider that cannot install a startup error rather than a panic
    // in a spawned task that leaves the process up serving `/health`
    // with `feed_connected: false` and never retrying.
    //
    // Shared with `pool-verifier` and `sv2-gateway`; see
    // `reservegrid_common::crypto_provider`.
    if let Err(e) = reservegrid_common::crypto_provider::install_default() {
        error!(error = %e, "failed to install the rustls CryptoProvider");
        std::process::exit(1);
    }

    let cli = Cli::parse();
    let cfg = match AdapterConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!(path = %cli.config, error = %e, "failed to load config");
            std::process::exit(1);
        }
    };

    info!(
        listen = %cfg.listen,
        feed_url = %cfg.feed_url,
        has_license_key = !cfg.license_key.is_empty(),
        "rg-feed-adapter starting"
    );

    let buffer: SharedBuffer = Arc::new(RwLock::new(FeedBuffer::default()));

    // Spawn WebSocket feed reader -------------------------------------------
    let feed_buf = buffer.clone();
    let feed_url = cfg.feed_url.clone();
    let license_key = cfg.license_key.clone();
    tokio::spawn(async move {
        feed::run_feed_loop(feed_url, license_key, feed_buf).await;
    });

    // HTTP server (JSON-RPC + health) ---------------------------------------
    let app = Router::new()
        .route("/", post(rpc::handle_jsonrpc))
        .route("/health", get(health))
        .with_state(buffer)
        .layer(DefaultBodyLimit::max(64 * 1024)); // 64 KiB; JSON-RPC calls are small

    let addr: SocketAddr = cfg.listen.parse().unwrap_or_else(|e| {
        error!(listen = %cfg.listen, error = %e, "invalid listen address");
        std::process::exit(1);
    });

    // SEC-006: block non-loopback bind unless explicitly opted in.
    if !addr.ip().is_loopback() {
        let allow_non_loopback =
            std::env::var("VELDRA_ALLOW_NON_LOOPBACK").ok().as_deref() == Some("1");
        if !allow_non_loopback {
            error!(
                %addr,
                "refusing to bind to non-loopback address; set VELDRA_ALLOW_NON_LOOPBACK=1 to override"
            );
            std::process::exit(1);
        }
        warn!(
            %addr,
            "feed adapter binding to non-loopback address (VELDRA_ALLOW_NON_LOOPBACK=1)"
        );
    }

    info!(%addr, "JSON-RPC server listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            error!(%addr, error = %e, "failed to bind");
            std::process::exit(1);
        });

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| {
            error!(error = %e, "server error");
        });
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            error!("failed to install SIGTERM handler, falling back to ctrl-c only");
            ctrl_c.await.ok();
            return;
        };
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
    info!("shutdown signal received");
}
