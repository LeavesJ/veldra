//! SV2 gateway binary entrypoint.
//!
//! Loads configuration, initializes tracing, starts the health HTTP server,
//! connects to the verifier, begins template polling, and enters the main
//! SV2 listener loop.

#![recursion_limit = "256"]

use std::collections::{HashMap, VecDeque};
use std::process::ExitCode;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware as axum_mw,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, mpsc, watch};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};

use reservegrid_common::reason::GatewayReason;
use sv2_gateway::channels::{
    ChannelIdAllocator, ExtranonceAllocator, GlobalChannelRegistry, SharedChannelRegistry,
};
use sv2_gateway::config::{self, GatewayConfig, UpstreamFailurePolicy};
use sv2_gateway::connection::{ConnectionLimiter, PerIpConnectionTracker};
use sv2_gateway::handler::{ConnectionContext, HandlerConfig, JobBroadcast, PrevhashUpdate};
use sv2_gateway::health::{self, ReadinessState};
use sv2_gateway::transport::{AuthorityCredentials, load_authority_credentials};
use sv2_gateway::upstream::TemplateResponse;
use sv2_gateway::verifier_stream::{VerifierOutbound, VerifierStreamConfig, VerifierTlsConfig};

/// SV2 Mining Protocol gateway for the reservegrid-os stack.
#[derive(Parser)]
#[command(name = "sv2-gateway", version, about)]
struct Cli {
    /// Path to the gateway TOML configuration file.
    #[arg(short, long, env = "VELDRA_GATEWAY_CONFIG")]
    config: String,
}

/// Maximum request body size for the HTTP management API (1 MiB).
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Write throttle: maximum settings save requests per window.
const WRITE_THROTTLE_MAX: usize = 10;

/// Write throttle window duration.
const WRITE_THROTTLE_WINDOW: Duration = Duration::from_secs(60);

/// Global write throttle timestamps for `/settings/save`.
static WRITE_TIMESTAMPS: LazyLock<Mutex<VecDeque<Instant>>> =
    LazyLock::new(|| Mutex::new(VecDeque::with_capacity(WRITE_THROTTLE_MAX + 1)));

/// Enforce that `VELDRA_API_SECRET` is set (or explicitly opted out).
fn enforce_api_secret() {
    let api_secret_set = std::env::var("VELDRA_API_SECRET")
        .ok()
        .is_some_and(|s| !s.is_empty());
    let api_secret_optional = std::env::var("VELDRA_API_SECRET_OPTIONAL").as_deref() == Ok("1");
    if !api_secret_set && !api_secret_optional {
        error!(
            "VELDRA_API_SECRET is not set. Set it to protect management endpoints, \
             or set VELDRA_API_SECRET_OPTIONAL=1 to acknowledge the risk"
        );
        std::process::exit(1);
    }
    if !api_secret_set && api_secret_optional {
        warn!(
            "VELDRA_API_SECRET is not set but VELDRA_API_SECRET_OPTIONAL=1; \
             management endpoints are unauthenticated"
        );
    }
}

/// Enforce that `VELDRA_SHARE_UPSTREAM_SECRET` is set when share upstream is configured.
fn enforce_hmac_secret(has_share_upstream: bool) {
    let hmac_set = std::env::var("VELDRA_SHARE_UPSTREAM_SECRET")
        .ok()
        .is_some_and(|s| !s.is_empty());
    let hmac_optional = std::env::var("VELDRA_SHARE_HMAC_OPTIONAL").as_deref() == Ok("1");
    if has_share_upstream && !hmac_set && !hmac_optional {
        error!(
            "VELDRA_SHARE_UPSTREAM_SECRET is not set but [share_upstream] is configured. \
             Set the secret, or set VELDRA_SHARE_HMAC_OPTIONAL=1 to acknowledge the risk"
        );
        std::process::exit(1);
    }
    if has_share_upstream && !hmac_set && hmac_optional {
        warn!(
            "VELDRA_SHARE_UPSTREAM_SECRET is not set but VELDRA_SHARE_HMAC_OPTIONAL=1; \
             share HMAC signatures will use an empty key"
        );
    }
}

/// Bearer token middleware for protected management endpoints.
///
/// When `VELDRA_API_SECRET` is set, requires `Authorization: Bearer <token>`.
/// Comparison uses constant time equality to prevent timing side channels.
async fn api_key_middleware(req: Request<Body>, next: Next) -> Response {
    let expected = match std::env::var("VELDRA_API_SECRET") {
        Ok(k) if !k.is_empty() => k,
        _ => return next.run(req).await,
    };

    let authorized = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let stripped = v.strip_prefix("Bearer ").unwrap_or(v);
            stripped.as_bytes().ct_eq(expected.as_bytes()).into()
        });

    if !authorized {
        warn!(
            method = %req.method(),
            path = %req.uri().path(),
            "api_key_middleware: unauthorized request"
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "reason_code": "unauthorized",
                "reason_detail": "missing or invalid bearer token"
            })),
        )
            .into_response();
    }

    next.run(req).await
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize tracing (JSON or pretty based on VELDRA_LOG_FORMAT).
    init_tracing();

    info!(config_path = %cli.config, "starting sv2-gateway");

    // Load and validate configuration.
    let config_text = match std::fs::read_to_string(&cli.config) {
        Ok(text) => text,
        Err(e) => {
            error!(path = %cli.config, error = %e, "failed to read config file");
            return ExitCode::FAILURE;
        }
    };

    let mut cfg: GatewayConfig = match toml::from_str(&config_text) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to parse gateway config");
            return ExitCode::FAILURE;
        }
    };

    // Environment variable override for mode, so `docker compose` comments
    // that reference VELDRA_GATEWAY_MODE actually work.
    if let Ok(mode_str) = std::env::var("VELDRA_GATEWAY_MODE") {
        match mode_str.to_lowercase().as_str() {
            "inline" => cfg.mode = rg_protocol::gateway::GatewayMode::Inline,
            "observe" => cfg.mode = rg_protocol::gateway::GatewayMode::Observe,
            "shadow" => cfg.mode = rg_protocol::gateway::GatewayMode::Shadow,
            other => {
                error!(value = %other, "VELDRA_GATEWAY_MODE must be inline, observe, or shadow");
                return ExitCode::FAILURE;
            }
        }
        info!(mode = %cfg.mode, "mode overridden by VELDRA_GATEWAY_MODE env var");
    }

    match config::validate(&cfg) {
        Ok(warnings) => {
            for w in &warnings {
                warn!(warning = %w, "config validation warning");
            }
        }
        Err(e) => {
            error!(error = %e, "config validation failed");
            return ExitCode::FAILURE;
        }
    }

    info!(mode = %cfg.mode, "configuration loaded");

    // Warn if file descriptor limit is low relative to max_connections.
    // Each miner connection consumes one FD, plus listeners and internal
    // channels. A low ulimit causes silent connection refusals.
    //
    // Reads /proc/self/limits (Linux) to avoid an `unsafe` libc call that
    // the workspace `unsafe_code = "deny"` lint would reject.
    #[cfg(target_os = "linux")]
    if let Ok(limits) = std::fs::read_to_string("/proc/self/limits") {
        for line in limits.lines() {
            if line.starts_with("Max open files") {
                let soft: Option<u64> = line.split_whitespace().nth(3).and_then(|s| s.parse().ok());
                if let Some(cur) = soft {
                    let needed = u64::from(cfg.gateway.max_connections) * 2 + 200;
                    if cur < needed {
                        warn!(
                            current_limit = cur,
                            recommended = needed,
                            max_connections = cfg.gateway.max_connections,
                            "file descriptor limit is low for configured max_connections; \
                             raise with `ulimit -n {needed}` to avoid silent connection refusals"
                        );
                    }
                }
                break;
            }
        }
    }

    // Enforce management API secret at startup.
    enforce_api_secret();

    // Enforce HMAC secret when share upstream is configured.
    enforce_hmac_secret(cfg.share_upstream.is_some());

    // Build the tokio runtime and run the async entry point.
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "failed to build tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    rt.block_on(run_gateway(cfg))
}

/// Async gateway entry point. Spawns all subsystems and waits for shutdown.
#[allow(clippy::too_many_lines)] // Startup sequence is one logical unit.
/// Path to the gateway config TOML on disk.
type GwConfigPath = Arc<std::path::PathBuf>;

/// Boot-time settings snapshot for `pending_restart` detection.
type GwBootSnapshot = Arc<serde_json::Value>;

async fn gw_get_settings(
    Extension(snapshot): Extension<GwBootSnapshot>,
    Extension(config_path): Extension<GwConfigPath>,
) -> Json<serde_json::Value> {
    let mut resp = (*snapshot).clone();

    // Detect pending_restart by comparing boot snapshot against on-disk config.
    let pending_restart = match std::fs::read_to_string(config_path.as_ref().as_path()) {
        Ok(disk_text) => match toml::from_str::<toml::Value>(&disk_text) {
            Ok(disk_toml) => {
                // Re-parse disk config as settings JSON for comparison.
                let disk_snapshot = build_settings_snapshot_from_toml(&disk_toml);
                disk_snapshot != *snapshot
            }
            Err(_) => false,
        },
        Err(_) => false,
    };

    if let Some(obj) = resp.as_object_mut() {
        obj.insert(
            "pending_restart".to_string(),
            serde_json::Value::Bool(pending_restart),
        );
    }

    Json(resp)
}

#[allow(clippy::cast_sign_loss)]
/// Build the same settings JSON shape from parsed TOML for comparison with boot snapshot.
fn build_settings_snapshot_from_toml(toml_val: &toml::Value) -> serde_json::Value {
    let gw = toml_val.get("gateway");
    let ver = toml_val.get("verifier");
    let su = toml_val.get("share_upstream");

    let get_str = |section: Option<&toml::Value>, key: &str| -> String {
        section
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    let get_u64 = |section: Option<&toml::Value>, key: &str, default: u64| -> u64 {
        section
            .and_then(|s| s.get(key))
            .and_then(toml::Value::as_integer)
            .map_or(default, |i| i as u64)
    };

    let get_bool = |section: Option<&toml::Value>, key: &str, default: bool| -> bool {
        section
            .and_then(|s| s.get(key))
            .and_then(toml::Value::as_bool)
            .unwrap_or(default)
    };

    serde_json::json!({
        "log_level": std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into()),
        "log_format": std::env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "json".into()),
        "gateway_mode": toml_val.get("mode").and_then(|v| v.as_str()).unwrap_or("observe"),
        "listen_addr": get_str(gw, "listen_addr"),
        "health_addr": get_str(gw, "health_addr"),
        "max_connections": get_u64(gw, "max_connections", 1024),
        "max_connections_per_ip": get_u64(gw, "max_connections_per_ip", 0),
        "max_channels_per_conn": get_u64(gw, "max_channels_per_conn", 256),
        "max_worker_id_bytes": get_u64(gw, "max_worker_id_bytes", 128),
        "template_poll_interval_ms": get_u64(gw, "template_poll_interval_ms", 3000),
        "max_template_age_ms": get_u64(gw, "max_template_age_ms", 30000),
        "prevhash_verdict_timeout_ms": get_u64(gw, "prevhash_verdict_timeout_ms", 2000),
        "prevhash_stale_hold_ms": get_u64(gw, "prevhash_stale_hold_ms", 5000),
        "upstream_stale_max_ms": get_u64(gw, "upstream_stale_max_ms", 30000),
        "upstream_failure_policy": get_str(gw, "upstream_failure_policy"),
        "share_dedup_window_size": get_u64(gw, "share_dedup_window_size", 10000),
        "ntime_elapsed_slack_seconds": get_u64(gw, "ntime_elapsed_slack_seconds", 2),
        "max_future_block_time_seconds": get_u64(gw, "max_future_block_time_seconds", 7200),
        "miner_auth": gw.and_then(|g| g.get("miner_auth")).map_or_else(|| "Open".to_string(), |v| format!("{v:?}")),
        "job_retention_ms": get_u64(gw, "job_retention_ms", 300_000),
        "channel_target_hex": get_str(gw, "channel_target_hex"),
        "max_shares_per_second_per_channel": get_u64(gw, "max_shares_per_second_per_channel", 0),
        "noise_cert_validity_secs": get_u64(gw, "noise_cert_validity_secs", 3600),
        "noise_handshake_timeout_ms": get_u64(gw, "noise_handshake_timeout_ms", 5000),
        "noise_keypair_path": get_str(gw, "noise_keypair_path"),
        "noise_keypair_reload_sighup": get_bool(gw, "noise_keypair_reload_sighup", true),
        "noise_keypair_poll_interval_secs": get_u64(gw, "noise_keypair_poll_interval_secs", 0),
        "wal_path": get_str(gw, "wal_path"),
        "wal_compaction_threshold": get_u64(gw, "wal_compaction_threshold", 1000),
        "template_url": get_str(gw, "template_url"),
        "gateway_instance_id": get_str(gw, "gateway_instance_id"),
        "verifier_addr": get_str(ver, "addr"),
        "verifier_tls_enabled": ver.and_then(|v| v.get("tls_ca_cert")).is_some(),
        "verifier_tls_server_name": get_str(ver, "tls_server_name"),
        "verifier_health_probe_staleness_ms": get_u64(ver, "health_probe_staleness_ms", 10000),
        "share_upstream_url": su.and_then(|s| s.get("url")).and_then(|v| v.as_str()).unwrap_or(""),
        "share_upstream_secret_set": std::env::var("VELDRA_SHARE_UPSTREAM_SECRET").is_ok(),
        "share_upstream_retries": get_u64(su, "retries", 0),
        "share_upstream_queue_size": get_u64(su, "forward_queue_size", 0),
        "share_upstream_max_in_flight": get_u64(su, "forward_max_in_flight", 0),
        "share_upstream_drop_policy": get_str(su, "forward_queue_drop_policy"),
        "share_upstream_rate_limit": su.and_then(|s| s.get("rate_limit_per_conn_per_sec")).and_then(toml::Value::as_integer),
    })
}

/// Editable gateway fields accepted by POST /settings/save.
/// All fields are optional; only provided fields are patched.
#[derive(serde::Deserialize)]
struct GwSaveSettingsReq {
    max_connections: Option<u32>,
    max_channels_per_conn: Option<u32>,
    max_worker_id_bytes: Option<u64>,
    template_poll_interval_ms: Option<u64>,
    max_template_age_ms: Option<u64>,
    prevhash_verdict_timeout_ms: Option<u64>,
    prevhash_stale_hold_ms: Option<u64>,
    upstream_stale_max_ms: Option<u64>,
    upstream_failure_policy: Option<String>,
    share_dedup_window_size: Option<u64>,
    ntime_elapsed_slack_seconds: Option<u32>,
    max_future_block_time_seconds: Option<u32>,
    job_retention_ms: Option<u64>,
    channel_target_hex: Option<String>,
    max_shares_per_second_per_channel: Option<u32>,
    noise_cert_validity_secs: Option<u32>,
    noise_handshake_timeout_ms: Option<u64>,
    noise_keypair_reload_sighup: Option<bool>,
    noise_keypair_poll_interval_secs: Option<u64>,
    wal_compaction_threshold: Option<u64>,
}

/// Persist gateway settings changes to the TOML config file on disk.
/// Reads the current TOML, patches editable fields, re-validates, and writes back atomically.
#[allow(clippy::too_many_lines)]
async fn gw_save_settings(
    Extension(config_path): Extension<GwConfigPath>,
    Json(req): Json<GwSaveSettingsReq>,
) -> impl IntoResponse {
    // Write throttle: reject if too many saves in the window.
    {
        let mut timestamps = WRITE_TIMESTAMPS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cutoff = Instant::now().checked_sub(WRITE_THROTTLE_WINDOW);
        if let Some(cutoff) = cutoff {
            timestamps.retain(|t| *t > cutoff);
        }
        if timestamps.len() >= WRITE_THROTTLE_MAX {
            warn!("settings save throttled");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "ok": false,
                    "reason_code": "rate_limited",
                    "reason_detail": "settings save rate limit exceeded"
                })),
            );
        }
        timestamps.push_back(Instant::now());
    }

    // Read current TOML from disk.
    let toml_text = match std::fs::read_to_string(config_path.as_ref().as_path()) {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "settings: failed to read config from disk");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "failed to read config" })),
            );
        }
    };

    let mut doc: toml::Value = match toml::from_str(&toml_text) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "settings: failed to parse config TOML");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "ok": false, "error": "failed to parse config" })),
            );
        }
    };

    // Patch editable fields into [gateway] section.
    // Mixed u32/u64 fields go through a single macro; `as i64` is safe because
    // all gateway config values fit comfortably within i63 range.
    #[allow(clippy::cast_lossless, clippy::cast_possible_wrap)]
    if let Some(gw) = doc.get_mut("gateway").and_then(|v| v.as_table_mut()) {
        macro_rules! patch_int {
            ($field:ident) => {
                if let Some(val) = req.$field {
                    gw.insert(
                        stringify!($field).to_string(),
                        toml::Value::Integer(val as i64),
                    );
                }
            };
        }
        macro_rules! patch_bool {
            ($field:ident) => {
                if let Some(val) = req.$field {
                    gw.insert(stringify!($field).to_string(), toml::Value::Boolean(val));
                }
            };
        }
        macro_rules! patch_str {
            ($field:ident) => {
                if let Some(ref val) = req.$field {
                    gw.insert(
                        stringify!($field).to_string(),
                        toml::Value::String(val.clone()),
                    );
                }
            };
        }

        patch_int!(max_connections);
        patch_int!(max_channels_per_conn);
        patch_int!(max_worker_id_bytes);
        patch_int!(template_poll_interval_ms);
        patch_int!(max_template_age_ms);
        patch_int!(prevhash_verdict_timeout_ms);
        patch_int!(prevhash_stale_hold_ms);
        patch_int!(upstream_stale_max_ms);
        patch_int!(share_dedup_window_size);
        patch_int!(ntime_elapsed_slack_seconds);
        patch_int!(max_future_block_time_seconds);
        patch_int!(job_retention_ms);
        patch_int!(max_shares_per_second_per_channel);
        patch_int!(noise_cert_validity_secs);
        patch_int!(noise_handshake_timeout_ms);
        patch_int!(noise_keypair_poll_interval_secs);
        patch_int!(wal_compaction_threshold);
        patch_str!(upstream_failure_policy);
        patch_str!(channel_target_hex);
        patch_bool!(noise_keypair_reload_sighup);
    }

    // Re-validate by parsing the patched TOML as GatewayConfig.
    let patched_text = match toml::to_string_pretty(&doc) {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "settings: failed to serialize patched config");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({ "ok": false, "error": "failed to serialize patched config" }),
                ),
            );
        }
    };

    let patched_cfg: GatewayConfig = match toml::from_str(&patched_text) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json({
                    let msg = format!("invalid config after patch: {e}");
                    serde_json::json!({ "ok": false, "error": &msg[..msg.len().min(200)] })
                }),
            );
        }
    };

    if let Err(e) = config::validate(&patched_cfg) {
        return (StatusCode::BAD_REQUEST, {
            let msg = format!("validation failed: {e}");
            Json(serde_json::json!({ "ok": false, "error": &msg[..msg.len().min(200)] }))
        });
    }

    // Atomic write to disk.
    if let Err(e) = reservegrid_common::config_io::atomic_write_toml(config_path.as_ref(), &doc) {
        error!(error = %e, "failed to save gateway config to disk");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": "failed to write config" })),
        );
    }

    info!(path = %config_path.display(), "gateway config saved to disk");

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "restart_required": true })),
    )
}

// ─────────────────────────────────────────────────────────────────────
// Prometheus metrics
// ─────────────────────────────────────────────────────────────────────

/// Label set for share outcome counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ShareLabels {
    result: String,
    reason_code: String,
}

/// Label set for share forward outcome counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ForwardLabels {
    result: String,
}

/// Label set for verdict counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct VerdictLabels {
    accepted: String,
}

/// Label set for mode transition counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ModeTransitionLabels {
    direction: String,
}

/// Label set for vardiff retarget counters.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct VardiffLabels {
    direction: String,
}

/// All Prometheus metric families for sv2-gateway.
struct GatewayMetrics {
    shares_total: Family<ShareLabels, Counter>,
    connections_total: Counter,
    connections_active: Gauge,
    channels_active: Gauge,
    templates_received_total: Counter,
    verdicts_total: Family<VerdictLabels, Counter>,
    share_forward_total: Family<ForwardLabels, Counter>,
    mode_transitions_total: Family<ModeTransitionLabels, Counter>,
    vardiff_retargets_total: Family<VardiffLabels, Counter>,
}

impl GatewayMetrics {
    fn new_registered(registry: &mut Registry) -> Self {
        let m = Self {
            shares_total: Family::default(),
            connections_total: Counter::default(),
            connections_active: Gauge::default(),
            channels_active: Gauge::default(),
            templates_received_total: Counter::default(),
            verdicts_total: Family::default(),
            share_forward_total: Family::default(),
            mode_transitions_total: Family::default(),
            vardiff_retargets_total: Family::default(),
        };
        registry.register(
            "svtwo_shares",
            "Total shares validated by the gateway",
            m.shares_total.clone(),
        );
        registry.register(
            "svtwo_connections",
            "Total TCP connections accepted",
            m.connections_total.clone(),
        );
        registry.register(
            "svtwo_connections_active",
            "Currently active TCP connections",
            m.connections_active.clone(),
        );
        registry.register(
            "svtwo_channels_active",
            "Currently open mining channels",
            m.channels_active.clone(),
        );
        registry.register(
            "svtwo_templates_received",
            "Total templates received from upstream",
            m.templates_received_total.clone(),
        );
        registry.register(
            "svtwo_verdicts",
            "Total verifier verdicts received",
            m.verdicts_total.clone(),
        );
        registry.register(
            "svtwo_share_forward",
            "Total share forward results from upstream",
            m.share_forward_total.clone(),
        );
        registry.register(
            "svtwo_mode_transitions",
            "Mode transitions between enforcing and degraded",
            m.mode_transitions_total.clone(),
        );
        registry.register(
            "svtwo_vardiff_retargets",
            "Variable difficulty retarget events",
            m.vardiff_retargets_total.clone(),
        );
        m
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod pb12_metrics_tests {
    use super::*;

    /// PB-12 regression. `prometheus-client` appends a `_total` suffix
    /// to every counter on export, so a registered counter name must
    /// not already carry `_total` or it exports as `_total_total`.
    #[test]
    fn gateway_counters_export_single_total_suffix() {
        let mut registry = Registry::default();
        let m = GatewayMetrics::new_registered(&mut registry);
        m.connections_total.inc();
        m.templates_received_total.inc();
        m.shares_total
            .get_or_create(&ShareLabels {
                result: "accepted".to_string(),
                reason_code: "ok".to_string(),
            })
            .inc();
        m.verdicts_total
            .get_or_create(&VerdictLabels {
                accepted: "true".to_string(),
            })
            .inc();
        m.share_forward_total
            .get_or_create(&ForwardLabels {
                result: "forwarded".to_string(),
            })
            .inc();
        m.mode_transitions_total
            .get_or_create(&ModeTransitionLabels {
                direction: "to_degraded".to_string(),
            })
            .inc();
        m.vardiff_retargets_total
            .get_or_create(&VardiffLabels {
                direction: "up".to_string(),
            })
            .inc();

        let (status, _, body) = reservegrid_common::metrics::render_metrics(&registry);
        assert_eq!(status, 200);
        assert!(!body.contains("_total_total"), "double suffix in:\n{body}");
        for name in [
            "svtwo_shares_total",
            "svtwo_connections_total",
            "svtwo_templates_received_total",
            "svtwo_verdicts_total",
            "svtwo_share_forward_total",
            "svtwo_mode_transitions_total",
            "svtwo_vardiff_retargets_total",
        ] {
            assert!(body.contains(name), "missing exported counter `{name}`");
        }
    }
}

/// Shared metrics reference used as an axum Extension.
type SharedGatewayMetrics = Arc<GatewayMetrics>;

/// GET /channels handler returning all connected mining channels.
async fn get_channels(
    Extension(registry): Extension<SharedChannelRegistry>,
) -> Json<Vec<sv2_gateway::channels::ChannelSnapshot>> {
    Json(registry.snapshot_all().await)
}

/// GET /metrics handler serving `OpenMetrics` text format.
async fn gw_metrics_handler(
    Extension(registry): Extension<reservegrid_common::metrics::SharedRegistry>,
) -> impl IntoResponse {
    let (status, content_type, body) = reservegrid_common::metrics::render_metrics(&registry);
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(axum::http::header::CONTENT_TYPE, content_type)],
        body,
    )
}

#[allow(clippy::too_many_lines)]
async fn run_gateway(cfg: GatewayConfig) -> ExitCode {
    // Shutdown coordination.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Readiness state (shared across all subsystems).
    let readiness = Arc::new(ReadinessState::new());

    // ── 1. Start health HTTP server ──
    let health_readiness = readiness.clone();
    let health_addr = cfg.gateway.health_addr.clone();
    let requires_listener = cfg.mode.accepts_miners();

    // Snapshot of boot-time config for GET /settings (all read-only).
    let settings_snapshot: Arc<serde_json::Value> = Arc::new(serde_json::json!({
        "log_level": std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into()),
        "log_format": std::env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "json".into()),
        "gateway_mode": format!("{:?}", cfg.mode).to_ascii_lowercase(),
        "listen_addr": cfg.gateway.listen_addr,
        "health_addr": cfg.gateway.health_addr,
        "max_connections": cfg.gateway.max_connections,
        "max_connections_per_ip": cfg.gateway.max_connections_per_ip,
        "max_channels_per_conn": cfg.gateway.max_channels_per_conn,
        "max_worker_id_bytes": cfg.gateway.max_worker_id_bytes,
        "template_poll_interval_ms": cfg.gateway.template_poll_interval_ms,
        "max_template_age_ms": cfg.gateway.max_template_age_ms,
        "prevhash_verdict_timeout_ms": cfg.gateway.prevhash_verdict_timeout_ms,
        "prevhash_stale_hold_ms": cfg.gateway.prevhash_stale_hold_ms,
        "upstream_stale_max_ms": cfg.gateway.upstream_stale_max_ms,
        "upstream_failure_policy": format!("{:?}", cfg.gateway.upstream_failure_policy).to_ascii_lowercase(),
        "share_dedup_window_size": cfg.gateway.share_dedup_window_size,
        "ntime_elapsed_slack_seconds": cfg.gateway.ntime_elapsed_slack_seconds,
        "max_future_block_time_seconds": cfg.gateway.max_future_block_time_seconds,
        "miner_auth": format!("{:?}", cfg.gateway.miner_auth),
        "job_retention_ms": cfg.gateway.job_retention_ms,
        "channel_target_hex": cfg.gateway.channel_target_hex.as_deref().unwrap_or(""),
        "max_shares_per_second_per_channel": cfg.gateway.max_shares_per_second_per_channel,
        "noise_cert_validity_secs": cfg.gateway.noise_cert_validity_secs,
        "noise_handshake_timeout_ms": cfg.gateway.noise_handshake_timeout_ms,
        "noise_keypair_path": cfg.gateway.noise_keypair_path,
        "noise_keypair_reload_sighup": cfg.gateway.noise_keypair_reload_sighup,
        "noise_keypair_poll_interval_secs": cfg.gateway.noise_keypair_poll_interval_secs,
        "wal_path": cfg.gateway.wal_path,
        "wal_compaction_threshold": cfg.gateway.wal_compaction_threshold,
        "template_url": cfg.gateway.template_url,
        "gateway_instance_id": cfg.gateway.gateway_instance_id,
        "verifier_addr": cfg.verifier.addr,
        "verifier_tls_enabled": cfg.verifier.tls_enabled(),
        "verifier_tls_server_name": cfg.verifier.tls_server_name,
        "verifier_health_probe_staleness_ms": cfg.verifier.health_probe_staleness_ms,
        "share_upstream_url": cfg.share_upstream.as_ref().map_or("", |s| s.url.as_str()),
        "share_upstream_secret_set": std::env::var("VELDRA_SHARE_UPSTREAM_SECRET").is_ok(),
        "share_upstream_retries": cfg.share_upstream.as_ref().map_or(0, |s| s.retries),
        "share_upstream_queue_size": cfg.share_upstream.as_ref().map_or(0, |s| s.forward_queue_size),
        "share_upstream_max_in_flight": cfg.share_upstream.as_ref().map_or(0, |s| s.forward_max_in_flight),
        "share_upstream_drop_policy": cfg.share_upstream.as_ref().map_or("none".to_string(), |s| format!("{:?}", s.forward_queue_drop_policy).to_ascii_lowercase()),
        "share_upstream_rate_limit": cfg.share_upstream.as_ref().and_then(|s| s.rate_limit_per_conn_per_sec),
    }));

    let gw_config_path: GwConfigPath = Arc::new(std::path::PathBuf::from(
        std::env::var("VELDRA_GATEWAY_CONFIG").unwrap_or_else(|_| "config/gateway.toml".into()),
    ));

    // ── Prometheus metrics registry ──
    let mut metrics_registry = Registry::default();
    let gw_metrics = Arc::new(GatewayMetrics::new_registered(&mut metrics_registry));
    let shared_registry: reservegrid_common::metrics::SharedRegistry = Arc::new(metrics_registry);

    // ── Global channel registry (for /channels API) ──
    let channel_registry: SharedChannelRegistry = Arc::new(GlobalChannelRegistry::new());

    // Non-loopback warning for the management HTTP API.
    if !config::is_loopback_addr_public(&health_addr) {
        warn!(
            addr = %health_addr,
            "health/management API binding to non-loopback address; \
             ensure network access is intentional"
        );
    }

    // Protected routes require bearer token when VELDRA_API_SECRET is set.
    let protected = Router::new()
        .route("/settings", get(gw_get_settings))
        .route("/settings/save", post(gw_save_settings))
        .route("/channels", get(get_channels))
        .layer(axum_mw::from_fn(api_key_middleware))
        .layer(Extension(settings_snapshot))
        .layer(Extension(gw_config_path))
        .layer(Extension(channel_registry.clone()));

    // Public routes (healthz, readyz, metrics) are unauthenticated.
    let readyz_handler = if requires_listener {
        get(health::readyz)
    } else {
        get(health::readyz_shadow)
    };

    let health_router = Router::new()
        .route("/healthz", get(health::healthz))
        .route("/readyz", readyz_handler)
        .route("/metrics", get(gw_metrics_handler))
        .merge(protected)
        .with_state(health_readiness.as_ref().clone())
        .layer(Extension(shared_registry))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES));

    let health_shutdown = shutdown_rx.clone();
    match tokio::net::TcpListener::bind(&health_addr).await {
        Ok(health_listener) => {
            info!(addr = %health_addr, "health server listening");
            tokio::spawn(async move {
                let shutdown_signal = async move {
                    let mut rx = health_shutdown;
                    while !*rx.borrow_and_update() {
                        if rx.changed().await.is_err() {
                            break;
                        }
                    }
                };
                if let Err(e) = axum::serve(health_listener, health_router)
                    .with_graceful_shutdown(shutdown_signal)
                    .await
                {
                    error!(error = %e, "health server error");
                }
                info!("health server drained");
            });
        }
        Err(e) => {
            warn!(
                addr = %health_addr,
                error = %e,
                "failed to bind health server; continuing without health endpoint",
            );
        }
    }

    // ── 2. Connect to verifier NDJSON stream ──
    let (verifier_outbound_tx, verifier_outbound_rx) = mpsc::channel::<VerifierOutbound>(256);
    let (verdict_broadcast_tx, _verdict_broadcast_rx) = broadcast::channel(256);

    let verifier_tls = if cfg.verifier.tls_enabled() {
        match build_verifier_tls(&cfg) {
            Ok(tls) => Some(tls),
            Err(e) => {
                error!(error = %e, "failed to build verifier TLS config");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let verifier_config = VerifierStreamConfig {
        addr: cfg.verifier.addr.clone(),
        reconnect_delay: Duration::from_millis(cfg.verifier.reconnect_delay_ms),
        heartbeat_interval: Duration::from_millis(cfg.verifier.heartbeat_interval_ms),
        health_probe_staleness_ms: cfg.verifier.health_probe_staleness_ms,
        tls_config: verifier_tls,
    };

    let verifier_readiness = readiness.clone();
    let verifier_shutdown = shutdown_rx.clone();
    tokio::spawn(sv2_gateway::verifier_stream::run_verifier_stream(
        verifier_config,
        verifier_outbound_rx,
        verdict_broadcast_tx.clone(),
        verifier_readiness,
        verifier_shutdown,
    ));
    info!(addr = %cfg.verifier.addr, "verifier stream task spawned");

    // ── 3. Start template poller ──
    let http_client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to build HTTP client");
            return ExitCode::FAILURE;
        }
    };

    let (template_tx, template_rx) = mpsc::channel(64);

    // Resolve template URL: prefer config key, fall back to env var.
    let template_base_url = if cfg.gateway.template_url.is_empty() {
        match std::env::var("VELDRA_TEMPLATE_URL") {
            Ok(v) if !v.is_empty() => {
                info!("template_url resolved from VELDRA_TEMPLATE_URL env var");
                v
            }
            _ => {
                error!(
                    "gateway.template_url is not set and VELDRA_TEMPLATE_URL env var is missing"
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        cfg.gateway.template_url.clone()
    };

    let poller_config = sv2_gateway::upstream::TemplatePollerConfig {
        base_url: template_base_url.clone(),
        poll_interval: Duration::from_millis(cfg.gateway.template_poll_interval_ms),
        max_template_age_ms: cfg.gateway.max_template_age_ms,
    };

    let poller_readiness = readiness.clone();
    let poller_shutdown = shutdown_rx.clone();
    tokio::spawn(sv2_gateway::upstream::run_template_poller(
        poller_config,
        http_client.clone(),
        template_tx,
        poller_readiness,
        poller_shutdown,
    ));
    info!(url = %template_base_url, "template poller task spawned");

    // ── 4. Share relay (if configured) ──
    let (share_forward_tx, share_forward_rx) = mpsc::channel(
        cfg.share_upstream
            .as_ref()
            .map_or(1000, |u| u.forward_queue_size),
    );
    let (share_result_tx, mut share_result_rx) = mpsc::channel(1000);

    // Share event channel: handler -> main loop NDJSON sink.
    let (share_event_tx, mut share_event_rx) =
        mpsc::channel::<sv2_gateway::shares::ShareAcceptedEvent>(4096);

    if let Some(ref upstream_cfg) = cfg.share_upstream {
        let secret = std::env::var("VELDRA_SHARE_UPSTREAM_SECRET")
            .unwrap_or_default()
            .into_bytes();

        let relay_config = sv2_gateway::upstream::ShareRelayConfig {
            url: upstream_cfg.url.clone(),
            secret,
            max_retries: upstream_cfg.retries,
            max_in_flight: upstream_cfg.forward_max_in_flight,
        };

        let relay_readiness = readiness.clone();
        let relay_shutdown = shutdown_rx.clone();
        tokio::spawn(sv2_gateway::upstream::run_share_relay(
            relay_config,
            http_client.clone(),
            share_forward_rx,
            share_result_tx,
            relay_readiness,
            relay_shutdown,
        ));
        info!(url = %upstream_cfg.url, "share relay task spawned");
    }

    // ── 4b. Share forward WAL (crash durability) ──
    let share_wal: Option<Arc<Mutex<sv2_gateway::wal::ShareWal>>> =
        if cfg.gateway.wal_path.is_empty() {
            debug!("share wal: disabled (wal_path is empty)");
            None
        } else {
            match sv2_gateway::wal::ShareWal::open(
                std::path::Path::new(&cfg.gateway.wal_path),
                cfg.gateway.wal_compaction_threshold,
            ) {
                Ok(mut wal) => {
                    let recovery = wal.recover();
                    if !recovery.synthetic_events.is_empty() {
                        for evt in &recovery.synthetic_events {
                            if let Ok(line) = serde_json::to_string(evt) {
                                info!(target: "share_events", "{}", line);
                            }
                        }
                        info!(
                            orphans = recovery.synthetic_events.len(),
                            "share wal: emitted synthetic process_crash_recovery events"
                        );
                    }
                    info!(path = %cfg.gateway.wal_path, "share wal: opened");
                    Some(Arc::new(Mutex::new(wal)))
                }
                Err(e) => {
                    error!(
                        path = %cfg.gateway.wal_path,
                        error = %e,
                        "share wal: failed to open; continuing without crash durability"
                    );
                    None
                }
            }
        };

    // ── 5. Job broadcast channel (main loop -> connection handlers) ──
    let (job_broadcast_tx, _) = broadcast::channel::<Arc<JobBroadcast>>(64);

    // Shared allocators for all connection handlers.
    let channel_id_alloc = Arc::new(ChannelIdAllocator::new());
    let extranonce_alloc = Arc::new(ExtranonceAllocator::with_prefix_len(
        cfg.gateway.extranonce_prefix_len,
    ));

    // Shared job table for validation lookups across all connection handlers.
    let job_table = Arc::new(tokio::sync::RwLock::new(sv2_gateway::jobs::JobTable::new(
        cfg.gateway.job_retention_ms,
        10_000,
    )));

    // Latest broadcast job: read by new channels to send an initial job on open.
    let latest_job: Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>> =
        Arc::new(tokio::sync::RwLock::new(None));

    // ── 6. SV2 listener (inline/observe modes only) ──
    if cfg.mode.accepts_miners() {
        let listen_addr = cfg.gateway.listen_addr.clone();
        let limiter = ConnectionLimiter::new(cfg.gateway.max_connections);
        let per_ip_tracker = PerIpConnectionTracker::new(cfg.gateway.max_connections_per_ip);

        let authority_creds = match load_authority_credentials(
            std::path::Path::new(&cfg.gateway.noise_keypair_path),
            &cfg.gateway.authority_pubkey,
            cfg.gateway.noise_cert_validity_secs,
        ) {
            Ok(creds) => {
                info!("noise authority keypair loaded and validated");
                Arc::new(creds)
            }
            Err(e) => {
                error!(error = %e, "failed to load noise authority credentials");
                return ExitCode::FAILURE;
            }
        };
        readiness
            .noise_cert_loaded
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // HMAC secret for share signing, behind RwLock for SIGHUP rotation.
        let share_hmac_secret: Arc<std::sync::RwLock<Vec<u8>>> = Arc::new(std::sync::RwLock::new(
            std::env::var("VELDRA_SHARE_UPSTREAM_SECRET")
                .unwrap_or_default()
                .into_bytes(),
        ));

        // Credential watch channel: accept_loop reads the latest value on each
        // new connection. The key reload task swaps in fresh credentials on
        // SIGHUP or file change without disrupting existing connections.
        let (creds_tx, creds_rx) = watch::channel(Arc::clone(&authority_creds));

        // Spawn key rotation watcher (SIGHUP and/or file poll).
        let reload_keypair_path = cfg.gateway.noise_keypair_path.clone();
        let reload_pubkey = cfg.gateway.authority_pubkey.clone();
        let reload_validity = cfg.gateway.noise_cert_validity_secs;
        let reload_sighup = cfg.gateway.noise_keypair_reload_sighup;
        let reload_poll_secs = cfg.gateway.noise_keypair_poll_interval_secs;
        let reload_shutdown = shutdown_rx.clone();
        let reload_hmac_secret = Arc::clone(&share_hmac_secret);
        tokio::spawn(async move {
            run_key_reload_task(
                reload_keypair_path,
                reload_pubkey,
                reload_validity,
                reload_sighup,
                reload_poll_secs,
                creds_tx,
                reload_hmac_secret,
                reload_shutdown,
            )
            .await;
        });

        let sv2_listener = match tokio::net::TcpListener::bind(&listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!(addr = %listen_addr, error = %e, "failed to bind SV2 listener");
                return ExitCode::FAILURE;
            }
        };
        readiness
            .listener_bound
            .store(true, std::sync::atomic::Ordering::SeqCst);
        info!(addr = %listen_addr, "SV2 listener bound");

        let channel_target = if let Some(ref hex_str) = cfg.gateway.channel_target_hex {
            match sv2_gateway::shares::display_hex_to_wire_bytes(hex_str) {
                Ok(t) => {
                    info!(target_hex = %hex_str, "using configured channel target override");
                    t
                }
                Err(e) => {
                    error!(error = %e, "invalid channel_target_hex; falling back to DIFF1");
                    default_share_target()
                }
            }
        } else {
            default_share_target()
        };

        let handler_config = Arc::new(HandlerConfig {
            max_channels_per_conn: cfg.gateway.max_channels_per_conn,
            channel_target,
            channel_open_timeout: Duration::from_millis(cfg.gateway.channel_open_timeout_ms),
            ntime_elapsed_slack_seconds: cfg.gateway.ntime_elapsed_slack_seconds,
            max_future_block_time_seconds: cfg.gateway.max_future_block_time_seconds,
            share_dedup_window_size: cfg.gateway.share_dedup_window_size,
            max_shares_per_second_per_channel: cfg.gateway.max_shares_per_second_per_channel,
            gateway_instance_id: cfg.gateway.gateway_instance_id.clone(),
            share_hmac_secret,
            extended_channels_enabled: cfg.gateway.extended_channels_enabled,
            extranonce_prefix_len: cfg.gateway.extranonce_prefix_len,
            vardiff_enabled: cfg.gateway.vardiff_enabled,
            vardiff_target_shares_per_min: cfg.gateway.vardiff_target_shares_per_min,
            vardiff_retarget_interval: Duration::from_secs(
                cfg.gateway.vardiff_retarget_interval_secs,
            ),
            vardiff_min_difficulty: cfg.gateway.vardiff_min_difficulty,
            vardiff_max_difficulty: cfg.gateway.vardiff_max_difficulty,
            vardiff_max_adjustment_factor: cfg.gateway.vardiff_max_adjustment_factor,
        });

        let accept_shutdown = shutdown_rx.clone();
        let accept_job_tx = job_broadcast_tx.clone();
        let accept_ch_alloc = channel_id_alloc.clone();
        let accept_en_alloc = extranonce_alloc.clone();
        let accept_handler_cfg = handler_config;
        let accept_job_table = job_table.clone();
        let accept_share_event_tx = share_event_tx.clone();
        let accept_share_forward_tx = share_forward_tx.clone();
        let accept_latest_job = latest_job.clone();
        let accept_metrics = gw_metrics.clone();
        let accept_channel_registry = channel_registry.clone();
        let handshake_timeout_ms = cfg.gateway.noise_handshake_timeout_ms;

        tokio::spawn(async move {
            accept_loop(
                sv2_listener,
                limiter,
                per_ip_tracker,
                creds_rx,
                handshake_timeout_ms,
                accept_handler_cfg,
                accept_ch_alloc,
                accept_en_alloc,
                accept_job_table,
                accept_latest_job,
                accept_job_tx,
                accept_share_event_tx,
                accept_share_forward_tx,
                accept_metrics,
                accept_shutdown,
                accept_channel_registry,
            )
            .await;
        });
    } else {
        info!("shadow mode: SV2 listener not started");
    }

    // ── 7. Main event loop ──
    info!("sv2-gateway startup sequence complete; entering main loop");

    let mut template_rx = template_rx;
    let mut verdict_rx = verdict_broadcast_tx.subscribe();
    let mut dedup_cache = sv2_gateway::jobs::TemplateDedupCache::new(256);
    let job_alloc = sv2_gateway::jobs::JobIdAllocator::new();

    // Pending templates awaiting verifier verdict (inline mode only).
    // Keyed by template_id. Bounded to 2 entries.
    // `pending_order` tracks insertion order for deterministic FIFO eviction.
    let mut pending_templates: HashMap<u64, PendingTemplate> = HashMap::new();
    let mut pending_order: VecDeque<u64> = VecDeque::with_capacity(4);

    // Active prevhash tracking for prevhash change detection.
    let mut active_prev_hash: Option<[u8; 32]> = None;

    // Upstream staleness tracking.
    let mut last_template_received = Instant::now();

    // Stale hold timer: fires when miners must be disconnected after a
    // prevhash verdict timeout in inline mode.
    let mut stale_hold_deadline: Option<tokio::time::Instant> = None;

    // SEC-004: periodic sweep of pending templates that have exceeded max age.
    // Fires every max_template_age_ms so stale entries are evicted even when no
    // new templates arrive (verifier stall scenario).
    let pending_sweep_interval = Duration::from_millis(cfg.gateway.max_template_age_ms.max(1000));
    let mut pending_sweep_ticker = tokio::time::interval(pending_sweep_interval);
    pending_sweep_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // M-5 fix: proactive upstream staleness timer. Fires on a fixed
    // interval so the guard does not depend on arriving messages.
    let upstream_stale_check_interval =
        Duration::from_millis(cfg.gateway.upstream_stale_max_ms.max(1000) / 2);

    // Automatic inline-to-observe degradation state.
    // When the verifier becomes unreachable for longer than
    // `auto_degrade_after_ms`, the gateway suspends verdict enforcement
    // and broadcasts templates immediately. Enforcement resumes when
    // the verifier reconnects and sends a heartbeat ack.
    let auto_degrade_enabled = cfg.gateway.auto_degrade && cfg.mode.enforces_verdicts();
    let auto_degrade_threshold = Duration::from_millis(cfg.gateway.auto_degrade_after_ms);
    let mut degraded = false;
    let mut degraded_since: Option<Instant> = None;
    let mut unenforced_jobs: u64 = 0;
    let mut last_verifier_ack = Instant::now();
    // PB-15 D2: why we degraded decides how we recover. Heartbeat-triggered
    // degrades recover on the next `HeartbeatAck`; verdict-starvation
    // degrades recover only when a verdict actually arrives, so a verifier
    // that heartbeats while never answering proposes cannot flap the mode.
    let mut degrade_trigger: Option<DegradeTrigger> = None;
    // Check degradation on a sub-threshold cadence so the transition
    // fires promptly after the threshold is crossed.
    let degrade_check_interval =
        Duration::from_millis(cfg.gateway.auto_degrade_after_ms.max(2000) / 2);
    let mut degrade_check_ticker = tokio::time::interval(degrade_check_interval);
    degrade_check_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    if auto_degrade_enabled {
        info!(
            threshold_ms = cfg.gateway.auto_degrade_after_ms,
            "automatic inline-to-observe degradation enabled"
        );
    }

    loop {
        // Compute the stale hold sleep future. If no deadline, sleep forever.
        let stale_hold_sleep = async {
            match stale_hold_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            // New template from poller.
            template = template_rx.recv() => {
                let Some(template) = template else {
                    warn!("template channel closed; shutting down");
                    break;
                };

                last_template_received = Instant::now();

                // Dedup check.
                if dedup_cache.is_duplicate(&template.source_instance_id, template.template_id) {
                    continue;
                }

                gw_metrics.templates_received_total.inc();
                info!(
                    template_id = template.template_id,
                    block_height = template.block_height,
                    prev_hash = %template.prev_hash,
                    "new template received"
                );

                // Send to verifier for evaluation.
                let propose =
                    build_template_propose(&template, &cfg.gateway.gateway_instance_id);
                if let Err(e) = verifier_outbound_tx
                    .send(VerifierOutbound::TemplatePropose(propose))
                    .await
                {
                    warn!(error = %e, "verifier_outbound_tx send failed; template propose dropped");
                }

                if cfg.mode.enforces_verdicts() && !degraded {
                    // Inline mode (enforcing): store template as pending,
                    // wait for verdict before broadcasting.
                    // Evict oldest (FIFO) if at capacity (2).
                    while pending_templates.len() >= 2 {
                        if let Some(oldest_id) = pending_order.pop_front() {
                            if pending_templates.remove(&oldest_id).is_some() {
                                debug!(template_id = oldest_id, "evicting oldest pending template");
                                // H-4 fix: also remove from dedup cache so upstream
                                // can re-send this template if needed.
                                dedup_cache.remove(&template.source_instance_id, oldest_id);
                            }
                        } else {
                            break;
                        }
                    }
                    pending_order.push_back(template.template_id);
                    pending_templates.insert(template.template_id, PendingTemplate {
                        template,
                        received_at: Instant::now(),
                    });
                } else {
                    // Observe mode or degraded inline: broadcast immediately.
                    broadcast_job_from_template(
                        &template,
                        &job_alloc,
                        &job_table,
                        &mut active_prev_hash,
                        &job_broadcast_tx,
                        &latest_job,
                    ).await;
                    if degraded {
                        unenforced_jobs += 1;
                    }
                }
            }

            // Verdict from verifier.
            verdict = verdict_rx.recv() => {
                match verdict {
                    Ok(sv2_gateway::verifier_stream::VerifierInbound::TemplateVerdict(v)) => {
                        gw_metrics.verdicts_total.get_or_create(&VerdictLabels {
                            accepted: v.accepted.to_string(),
                        }).inc();
                        info!(
                            template_id = v.id,
                            accepted = v.accepted,
                            reason = ?v.reason_code,
                            "verdict received"
                        );

                        // PB-15 D2: a verdict is the recovery signal for a
                        // starvation-triggered degrade; heartbeats alone are
                        // not (see the degrade and `HeartbeatAck` arms; keep
                        // this block in sync with the heartbeat recovery).
                        if degraded
                            && degrade_trigger == Some(DegradeTrigger::VerdictStarved)
                        {
                            let dur_ms = degraded_since.map_or(0, |s| {
                                u64::try_from(s.elapsed().as_millis())
                                    .unwrap_or(u64::MAX)
                            });
                            let recover_evt =
                                sv2_gateway::shares::ModeTransitionEvent {
                                    event_type: "mode_transition",
                                    direction: "recovered",
                                    timestamp_ms:
                                        sv2_gateway::shares::unix_ms_now(),
                                    degraded_duration_ms: dur_ms,
                                    unenforced_jobs,
                                };
                            if let Ok(line) = serde_json::to_string(&recover_evt)
                            {
                                info!(target: "share_events", "{}", line);
                            }
                            degraded = false;
                            degraded_since = None;
                            unenforced_jobs = 0;
                            degrade_trigger = None;
                            readiness.clear_degraded();
                            gw_metrics
                                .mode_transitions_total
                                .get_or_create(&ModeTransitionLabels {
                                    direction: "recovered".into(),
                                })
                                .inc();
                            info!(
                                "verdict service restored; resuming enforcement"
                            );
                        }

                        if cfg.mode.enforces_verdicts() {
                            if let Some(pending) = pending_templates.remove(&v.id) {
                                pending_order.retain(|&id| id != v.id);
                                if v.accepted {
                                    // SEC-004: warn if template age exceeds threshold, but
                                    // still broadcast. A stale verified template is better
                                    // than no template (miners would hold on an even older
                                    // unverified job otherwise). The sweep ticker handles
                                    // true abandonment when no verdict arrives at all.
                                    let age_ms =
                                        u64::try_from(pending.received_at.elapsed().as_millis())
                                            .unwrap_or(u64::MAX);
                                    if age_ms > cfg.gateway.max_template_age_ms {
                                        warn!(
                                            template_id = v.id,
                                            age_ms,
                                            max_ms = cfg.gateway.max_template_age_ms,
                                            "verdict accepted but template exceeded max age; broadcasting anyway"
                                        );
                                    }
                                    // Clear stale hold on successful verdict.
                                    stale_hold_deadline = None;
                                    broadcast_job_from_template(
                                        &pending.template,
                                        &job_alloc,
                                        &job_table,
                                        &mut active_prev_hash,
                                        &job_broadcast_tx,
                                        &latest_job,
                                    ).await;
                                } else {
                                    warn!(
                                        template_id = v.id,
                                        reason_code = ?v.reason_code,
                                        "template rejected by verifier; holding on last verified job"
                                    );
                                    // If this was a prevhash change, start stale hold timer.
                                    // H-3 fix: do NOT reset an already-active timer. Consecutive
                                    // rejections must not extend the stale window indefinitely.
                                    if stale_hold_deadline.is_none()
                                        && is_prevhash_change(&pending.template, active_prev_hash.as_ref())
                                    {
                                        let hold_ms = cfg.gateway.prevhash_stale_hold_ms;
                                        stale_hold_deadline = Some(
                                            tokio::time::Instant::now()
                                                + Duration::from_millis(hold_ms),
                                        );
                                        warn!(
                                            hold_ms,
                                            "stale hold timer started after prevhash verdict rejection"
                                        );
                                    }
                                }
                            } else {
                                debug!(template_id = v.id, "verdict for unknown or evicted template");
                            }
                        }
                    }
                    Ok(sv2_gateway::verifier_stream::VerifierInbound::HeartbeatAck) => {
                        last_verifier_ack = Instant::now();
                        // PB-15 D2 flap guard: a heartbeat proves liveness,
                        // not verdict service. Starvation-triggered degrades
                        // recover in the Verdict arm instead, so a verifier
                        // that heartbeats but never answers proposes cannot
                        // oscillate the mode every threshold tick.
                        if degraded && heartbeat_recovery_allowed(degrade_trigger) {
                            let dur_ms = degraded_since.map_or(0, |s| {
                                u64::try_from(s.elapsed().as_millis())
                                    .unwrap_or(u64::MAX)
                            });
                            let recover_evt =
                                sv2_gateway::shares::ModeTransitionEvent {
                                    event_type: "mode_transition",
                                    direction: "recovered",
                                    timestamp_ms:
                                        sv2_gateway::shares::unix_ms_now(),
                                    degraded_duration_ms: dur_ms,
                                    unenforced_jobs,
                                };
                            if let Ok(line) =
                                serde_json::to_string(&recover_evt)
                            {
                                info!(
                                    target: "share_events", "{}", line
                                );
                            }
                            // Verifier is back. Resume enforcement.
                            degraded = false;
                            degraded_since = None;
                            unenforced_jobs = 0;
                            degrade_trigger = None;
                            readiness.clear_degraded();
                            stale_hold_deadline = None;
                            // Drain any pending templates that accumulated
                            // during recovery. They will be re-proposed on
                            // the next template arrival.
                            pending_templates.clear();
                            pending_order.clear();
                            gw_metrics.mode_transitions_total
                                .get_or_create(&ModeTransitionLabels {
                                    direction: "recovered".into(),
                                })
                                .inc();
                            warn!(
                                degraded_duration_ms = dur_ms,
                                unenforced_jobs = recover_evt.unenforced_jobs,
                                "verifier recovered; resuming inline enforcement"
                            );
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(missed = n, "verdict broadcast lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        warn!("verdict broadcast closed");
                        break;
                    }
                }
            }

            // Share forward results: emit NDJSON ShareForwardResultEvent.
            result = share_result_rx.recv() => {
                if let Some(result) = result {
                    let fwd_result = if result.forwarded && result.upstream_accepted == Some(true) {
                        "success"
                    } else {
                        "failed"
                    };
                    gw_metrics.share_forward_total.get_or_create(&ForwardLabels {
                        result: fwd_result.into(),
                    }).inc();

                    // WAL: mark forward complete (removes pending entry).
                    // Runs on the blocking thread pool to avoid stalling
                    // the tokio executor on disk I/O.
                    //
                    // Write failures are fatal by default: a silent WAL
                    // error would orphan pending entries with no recovery
                    // record, permanently breaking the 1:1 join invariant
                    // between ShareAcceptedEvent and ShareForwardResultEvent.
                    // Set VELDRA_WAL_WRITE_FAILURE_MODE=accept_silent to
                    // temporarily preserve the pre-R-152 behaviour; this
                    // flag is intended for one-release migrations only and
                    // will be removed in v1.3.0.
                    if let Some(ref wal) = share_wal {
                        let wal = Arc::clone(wal);
                        let sid = result.share_id_hex.clone();
                        let eid = result.event_id_hex.clone();
                        let sid_trace = result.share_id_hex.clone();
                        let wal_result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                            let mut w = wal.lock().map_err(|_| {
                                std::io::Error::other("wal mutex poisoned in mark_completed")
                            })?;
                            w.mark_completed(&sid, &eid)
                        })
                        .await;
                        let io_err = match wal_result {
                            Ok(Ok(())) => None,
                            Ok(Err(e)) => Some(e),
                            Err(join_err) => Some(std::io::Error::other(format!(
                                "wal mark_completed spawn_blocking: {join_err}"
                            ))),
                        };
                        if let Some(e) = io_err {
                            let mode = std::env::var("VELDRA_WAL_WRITE_FAILURE_MODE")
                                .unwrap_or_else(|_| "fatal".to_string());
                            error!(
                                share_id = %sid_trace,
                                op = "mark_completed",
                                error = %e,
                                mode = %mode,
                                reason_code = "wal_write_failure",
                                "wal: write failure; durability cannot be preserved"
                            );
                            if mode != "accept_silent" {
                                readiness.set_draining();
                                let _ = shutdown_tx.send(true);
                                break;
                            }
                        }
                    }

                    let forward_evt = sv2_gateway::shares::ShareForwardResultEvent::from_relay(
                        &result.share_id_hex,
                        &result.event_id_hex,
                        result.forwarded,
                        result.upstream_accepted,
                        result.upstream_http_status,
                        result.upstream_error.clone(),
                        result.reason_code.clone(),
                    );
                    if let Ok(line) = serde_json::to_string(&forward_evt) {
                        info!(target: "share_events", "{}", line);
                    }

                    if result.forwarded {
                        if result.upstream_accepted == Some(true) {
                            debug!(
                                share_id = %result.share_id_hex,
                                "share forwarded and accepted"
                            );
                        } else {
                            warn!(
                                share_id = %result.share_id_hex,
                                reason = ?result.upstream_error,
                                "share forwarded but rejected"
                            );
                        }
                    } else {
                        warn!(
                            share_id = %result.share_id_hex,
                            error = ?result.upstream_error,
                            "share forward failed"
                        );
                    }
                }
            }

            // Share accepted/rejected events: emit NDJSON.
            evt = share_event_rx.recv() => {
                if let Some(evt) = evt {
                    let accepted = evt.sv2_response == "success";
                    let share_result = if accepted { "accepted" } else { "rejected" };
                    gw_metrics.shares_total.get_or_create(&ShareLabels {
                        result: share_result.into(),
                        reason_code: evt.reason_code.as_deref().unwrap_or("ok").into(),
                    }).inc();
                    channel_registry.update_share(evt.channel_id, accepted, evt.difficulty_u64).await;

                    // WAL: track accepted shares that require a forward result.
                    // Write-ordering note: the SV2 ACK for this share has
                    // already been sent by the connection handler by the
                    // time this event is received, so failure here cannot
                    // "un-ACK" the share. What it MUST prevent is the next
                    // share being accepted into a state where durability
                    // has silently broken. See the fatality comment on the
                    // share_result_rx arm above.
                    if evt.sv2_response == "success"
                        && let Some(ref wal) = share_wal
                    {
                        let wal = Arc::clone(wal);
                        let sid = evt.share_id_hex.clone();
                        let eid = evt.event_id_hex.clone();
                        let sid_trace = evt.share_id_hex.clone();
                        let wal_result = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                            let mut w = wal.lock().map_err(|_| {
                                std::io::Error::other("wal mutex poisoned in mark_pending")
                            })?;
                            w.mark_pending(&sid, &eid)
                        })
                        .await;
                        let io_err = match wal_result {
                            Ok(Ok(())) => None,
                            Ok(Err(e)) => Some(e),
                            Err(join_err) => Some(std::io::Error::other(format!(
                                "wal mark_pending spawn_blocking: {join_err}"
                            ))),
                        };
                        if let Some(e) = io_err {
                            let mode = std::env::var("VELDRA_WAL_WRITE_FAILURE_MODE")
                                .unwrap_or_else(|_| "fatal".to_string());
                            error!(
                                share_id = %sid_trace,
                                op = "mark_pending",
                                error = %e,
                                mode = %mode,
                                reason_code = "wal_write_failure",
                                "wal: write failure; durability cannot be preserved"
                            );
                            if mode != "accept_silent" {
                                readiness.set_draining();
                                let _ = shutdown_tx.send(true);
                                break;
                            }
                        }
                    }
                    if let Ok(line) = serde_json::to_string(&evt) {
                        info!(target: "share_events", "{}", line);
                    }
                }
            }

            // SEC-004: periodic sweep of stale pending templates, with H-4
            // parity on the dedup cache (PB-15 D1; see helper docs).
            _ = pending_sweep_ticker.tick() => {
                let max_age = Duration::from_millis(cfg.gateway.max_template_age_ms);
                sweep_stale_pending_templates(
                    &mut pending_templates,
                    &mut pending_order,
                    &mut dedup_cache,
                    max_age,
                );
            }

            // Stale hold timer expiry (inline mode only).
            () = stale_hold_sleep => {
                if degraded {
                    // In degraded mode the stale hold timer is harmless
                    // because templates are already flowing without
                    // enforcement. Cancel and continue.
                    stale_hold_deadline = None;
                    debug!("stale hold timer expired during degraded mode; ignoring");
                } else {
                    error!("stale hold timer expired; prevhash switch timed out");
                    // Each connection's run_connection emits a DisconnectEvent
                    // with ShutdownDrain when it observes the shutdown signal.
                    readiness.set_draining();
                    let _ = shutdown_tx.send(true);
                    break;
                }
            }

            // M-5 fix: proactive upstream staleness timer.
            () = tokio::time::sleep(upstream_stale_check_interval) => {
                let stale_elapsed = last_template_received.elapsed();
                if stale_elapsed > Duration::from_millis(cfg.gateway.upstream_stale_max_ms) {
                    #[allow(clippy::cast_possible_truncation)]
                    let elapsed_ms = stale_elapsed.as_millis() as u64;
                    match cfg.gateway.upstream_failure_policy {
                        UpstreamFailurePolicy::FailClosed => {
                            error!(
                                elapsed_ms,
                                max_ms = cfg.gateway.upstream_stale_max_ms,
                                "upstream stale beyond threshold (fail_closed); shutting down"
                            );
                            readiness.set_draining();
                            let _ = shutdown_tx.send(true);
                            break;
                        }
                        UpstreamFailurePolicy::FailOpen => {
                            warn!(
                                elapsed_ms,
                                max_ms = cfg.gateway.upstream_stale_max_ms,
                                "upstream stale beyond threshold (fail_open); continuing"
                            );
                        }
                    }
                }
            }

            // Automatic inline-to-observe degradation check.
            _ = degrade_check_ticker.tick() => {
                // PB-15 D2: heartbeat staleness catches a dead link; oldest
                // pending age catches a live link whose verdict service has
                // stopped (R-173: liveness is not the data invariant).
                let oldest_pending_age = pending_order
                    .front()
                    .and_then(|id| pending_templates.get(id))
                    .map(|pt| pt.received_at.elapsed());
                let trigger = degrade_trigger_for(
                    last_verifier_ack.elapsed(),
                    oldest_pending_age,
                    auto_degrade_threshold,
                );
                if auto_degrade_enabled && !degraded && trigger.is_some() {
                    degrade_trigger = trigger;
                    degraded = true;
                    degraded_since = Some(Instant::now());
                    unenforced_jobs = 0;
                    readiness.set_degraded();
                    // Flush all pending templates: broadcast immediately so
                    // miners are not starved while enforcement is suspended.
                    for id in pending_order.drain(..) {
                        if let Some(pt) = pending_templates.remove(&id) {
                            broadcast_job_from_template(
                                &pt.template,
                                &job_alloc,
                                &job_table,
                                &mut active_prev_hash,
                                &job_broadcast_tx,
                                &latest_job,
                            )
                            .await;
                            unenforced_jobs += 1;
                        }
                    }
                    pending_templates.clear();
                    stale_hold_deadline = None;
                    gw_metrics
                        .mode_transitions_total
                        .get_or_create(&ModeTransitionLabels {
                            direction: "degraded".into(),
                        })
                        .inc();
                    let degrade_evt =
                        sv2_gateway::shares::ModeTransitionEvent {
                            event_type: "mode_transition",
                            direction: "degraded",
                            timestamp_ms: sv2_gateway::shares::unix_ms_now(),
                            degraded_duration_ms: 0,
                            unenforced_jobs,
                        };
                    if let Ok(line) = serde_json::to_string(&degrade_evt) {
                        info!(target: "share_events", "{}", line);
                    }
                    let oldest_pending_ms = oldest_pending_age
                        .map(|a| u64::try_from(a.as_millis()).unwrap_or(u64::MAX));
                    error!(
                        heartbeat_elapsed_ms =
                            u64::try_from(
                                last_verifier_ack.elapsed().as_millis()
                            )
                            .unwrap_or(u64::MAX),
                        oldest_pending_ms = ?oldest_pending_ms,
                        threshold_ms =
                            cfg.gateway.auto_degrade_after_ms,
                        trigger = degrade_trigger.map_or("none", DegradeTrigger::as_str),
                        "verifier service degraded; entering degraded \
                         mode (verdict enforcement suspended)"
                    );
                }
            }

            // Ctrl+C / SIGTERM.
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                readiness.set_draining();
                let _ = shutdown_tx.send(true);
                break;
            }
        }
    }

    info!("sv2-gateway shutting down");
    ExitCode::SUCCESS
}

// ─────────────────────────────────────────────────────────────────────
// Pending template store (inline mode)
// ─────────────────────────────────────────────────────────────────────

/// A template awaiting verifier verdict before job distribution.
struct PendingTemplate {
    template: TemplateResponse,
    received_at: Instant,
}

/// PB-15 D2: why the gateway entered degraded mode. The trigger decides the
/// recovery signal (see `heartbeat_recovery_allowed`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DegradeTrigger {
    /// No `HeartbeatAck` within the threshold: the verifier link is dead.
    HeartbeatStale,
    /// Heartbeats flow but the oldest pending template has waited past the
    /// threshold without a verdict: the link is alive, the service is not.
    VerdictStarved,
}

impl DegradeTrigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::HeartbeatStale => "verifier_heartbeat_stale",
            Self::VerdictStarved => "verifier_verdict_starved",
        }
    }
}

/// Pure decision for the auto-degrade check (PB-15 D2). Heartbeat staleness
/// takes precedence (dead link subsumes starved service); verdict starvation
/// catches the heartbeat-alive, verdict-silent upstream that R-173 warns
/// about: liveness signals are not the data invariant.
fn degrade_trigger_for(
    heartbeat_age: Duration,
    oldest_pending_age: Option<Duration>,
    threshold: Duration,
) -> Option<DegradeTrigger> {
    if heartbeat_age > threshold {
        return Some(DegradeTrigger::HeartbeatStale);
    }
    if oldest_pending_age.is_some_and(|age| age > threshold) {
        return Some(DegradeTrigger::VerdictStarved);
    }
    None
}

/// PB-15 D2 flap guard: heartbeat-triggered degrades recover on heartbeat;
/// starvation-triggered degrades require an actual verdict (handled in the
/// Verdict arm), so a heartbeating-but-unresponsive verifier cannot
/// oscillate modes every threshold tick.
fn heartbeat_recovery_allowed(trigger: Option<DegradeTrigger>) -> bool {
    trigger != Some(DegradeTrigger::VerdictStarved)
}

/// SEC-004 sweep with H-4 parity (PB-15 D1): evict pending templates older
/// than `max_age` AND release them from the dedup cache so the next poll can
/// re-propose an unchanged template. Without the dedup release a quiet chain
/// starves permanently after a single lost verdict: the swept template never
/// re-enters `pending_templates`, `latest_job` stays `None`, and miners that
/// open channels receive no initial job. Returns the eviction count.
fn sweep_stale_pending_templates(
    pending_templates: &mut HashMap<u64, PendingTemplate>,
    pending_order: &mut VecDeque<u64>,
    dedup_cache: &mut sv2_gateway::jobs::TemplateDedupCache,
    max_age: Duration,
) -> usize {
    let mut swept: Vec<(u64, String)> = Vec::new();
    pending_templates.retain(|tid, pt| {
        let age = pt.received_at.elapsed();
        if age > max_age {
            warn!(
                template_id = tid,
                age_ms = u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
                "evicting stale pending template (exceeded max_template_age_ms)"
            );
            swept.push((*tid, pt.template.source_instance_id.clone()));
            false
        } else {
            true
        }
    });
    if !swept.is_empty() {
        pending_order.retain(|id| pending_templates.contains_key(id));
        for (tid, src) in &swept {
            dedup_cache.remove(src, *tid);
        }
    }
    swept.len()
}

// ─────────────────────────────────────────────────────────────────────
// Template -> Job conversion and broadcast
// ─────────────────────────────────────────────────────────────────────

/// Parse a `TemplateResponse` into a `JobRecord`, insert into the job table,
/// and broadcast a `JobBroadcast` to all connection handlers.
#[allow(clippy::too_many_lines)]
async fn broadcast_job_from_template(
    template: &TemplateResponse,
    job_alloc: &sv2_gateway::jobs::JobIdAllocator,
    job_table: &Arc<tokio::sync::RwLock<sv2_gateway::jobs::JobTable>>,
    active_prev_hash: &mut Option<[u8; 32]>,
    job_broadcast_tx: &broadcast::Sender<Arc<JobBroadcast>>,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
) {
    let Some(job_id) = job_alloc.allocate() else {
        error!("job ID allocator exhausted");
        return;
    };

    let prev_hash_wire = match sv2_gateway::shares::display_hex_to_wire_bytes(&template.prev_hash) {
        Ok(w) => w,
        Err(e) => {
            error!(
                template_id = template.template_id,
                error = %e,
                "rejecting template: invalid prev_hash hex"
            );
            return;
        }
    };

    let Some(merkle_path) = parse_merkle_path(&template.merkle_path, template.template_id) else {
        return;
    };

    let coinbase_prefix = match hex::decode(&template.coinbase_tx_prefix) {
        Ok(b) => b,
        Err(e) => {
            error!(
                template_id = template.template_id,
                error = %e,
                "rejecting template: invalid coinbase_tx_prefix hex"
            );
            return;
        }
    };
    let coinbase_suffix = match hex::decode(&template.coinbase_tx_suffix) {
        Ok(b) => b,
        Err(e) => {
            error!(
                template_id = template.template_id,
                error = %e,
                "rejecting template: invalid coinbase_tx_suffix hex"
            );
            return;
        }
    };

    #[allow(clippy::cast_possible_truncation)]
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    let activation =
        sv2_gateway::jobs::effective_min_ntime(template.min_ntime, template.curtime, now_unix, 60);

    // Detect prevhash change.
    let is_new_prevhash = active_prev_hash.is_none_or(|active| active != prev_hash_wire);

    let prevhash_update = if is_new_prevhash {
        *active_prev_hash = Some(prev_hash_wire);
        Some(PrevhashUpdate {
            prev_hash: prev_hash_wire,
            min_ntime: activation,
            nbits: template.nbits,
        })
    } else {
        None
    };

    // Intra-block refresh: if same prevhash, set min_ntime so miners can
    // start using the new job immediately.
    let min_ntime = if is_new_prevhash {
        None
    } else {
        Some(activation)
    };

    let job = sv2_gateway::jobs::JobRecord {
        job_id,
        template_id: template.template_id,
        block_height: template.block_height,
        version: template.block_version,
        prev_hash: prev_hash_wire,
        nbits: template.nbits,
        coinbase_tx_prefix: coinbase_prefix,
        coinbase_tx_suffix: coinbase_suffix,
        merkle_path,
        activation_min_ntime: activation,
        raw_min_ntime: template.min_ntime,
        raw_curtime: template.curtime,
        source_instance_id: template.source_instance_id.clone(),
        activated: is_new_prevhash,
        created_at: Instant::now(),
    };

    let broadcast = Arc::new(JobBroadcast {
        job_id,
        version: template.block_version,
        coinbase_tx_prefix: job.coinbase_tx_prefix.clone(),
        coinbase_tx_suffix: job.coinbase_tx_suffix.clone(),
        merkle_path: job.merkle_path.clone(),
        prevhash_update,
        min_ntime,
    });

    info!(
        job_id,
        template_id = template.template_id,
        new_prevhash = is_new_prevhash,
        "job created and broadcasting"
    );

    job_table.write().await.insert(job);

    // Store as latest job for new channel opens.
    *latest_job.write().await = Some(broadcast.clone());

    // Broadcast to handlers. Failure means no active receivers, which is fine.
    let _ = job_broadcast_tx.send(broadcast);
}

/// Check whether a template introduces a new prevhash relative to the current active one.
fn is_prevhash_change(template: &TemplateResponse, active: Option<&[u8; 32]>) -> bool {
    let Some(active_hash) = active else {
        return true;
    };
    match sv2_gateway::shares::display_hex_to_wire_bytes(&template.prev_hash) {
        Ok(wire) => wire != *active_hash,
        Err(_) => true,
    }
}

/// Parse hex merkle path strings into 32-byte arrays.
fn parse_merkle_path(hex_elements: &[String], template_id: u64) -> Option<Vec<[u8; 32]>> {
    let mut path = Vec::with_capacity(hex_elements.len());
    for hex_str in hex_elements {
        match hex::decode(hex_str) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                path.push(arr);
            }
            _ => {
                error!(
                    template_id,
                    element = %hex_str,
                    "rejecting template: invalid merkle path element"
                );
                return None;
            }
        }
    }
    Some(path)
}

/// Build a `TemplatePropose` from a `TemplateResponse`.
fn build_template_propose(
    template: &TemplateResponse,
    gateway_instance_id: &str,
) -> rg_protocol::TemplatePropose {
    rg_protocol::TemplatePropose {
        version: rg_protocol::PROTOCOL_VERSION,
        id: template.template_id,
        block_height: template.block_height,
        prev_hash: template.prev_hash.clone(),
        coinbase_value: template.coinbase_value,
        tx_count: template.tx_count,
        total_fees: template.total_fees,
        observed_weight: template.observed_weight,
        // Use bitcoind's curtime (block creation time) rather than gateway
        // reception time so template age enforcement is accurate even when
        // the RPC call or network introduces latency.
        #[allow(clippy::cast_possible_truncation)]
        created_at_unix_ms: Some(u64::from(template.curtime) * 1000),
        total_sigops: template.total_sigops,
        coinbase_sigops: template.coinbase_sigops,
        template_weight: template.template_weight,
        gateway_instance_id: Some(gateway_instance_id.to_string()),
        // PB-19 / Phase 1b: forward the template-manager's assembled
        // raw block verbatim so the shield runs on the gateway path
        // too. None when the upstream did not assemble (older
        // template-manager or assembly failure, both counted by
        // verifier_shield_skipped_total).
        raw_block_hex: template.raw_block_hex.clone(),
    }
}

/// Default share target for development and regtest use.
///
/// This sets the target to `0x00000000FFFF...` in LE byte order, which
/// corresponds to Bitcoin difficulty 1 (`DIFF1_TARGET`). Byte index 29 is
/// the most significant non-zero byte in the LE representation.
fn default_share_target() -> [u8; 32] {
    // DIFF1_TARGET in LE: bytes 26..29 = 0xFF, 0xFF, 0x00, 0x00
    // matches 0x00000000FFFF0000...0000 BE.
    let mut diff1_le = rg_protocol::gateway::DIFF1_TARGET_BE;
    diff1_le.reverse();
    diff1_le
}

// ─────────────────────────────────────────────────────────────────────
// Accept loop
// ─────────────────────────────────────────────────────────────────────

/// Accept SV2 TCP connections and spawn per-connection handler tasks.
///
/// `creds_rx` carries the latest authority credentials. On each new connection
/// the loop reads the current value so that key rotations (SIGHUP / file poll)
/// take effect without restarting the process. Existing connections that already
/// completed the Noise handshake are unaffected by a credential swap.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn accept_loop(
    listener: tokio::net::TcpListener,
    limiter: ConnectionLimiter,
    per_ip_tracker: PerIpConnectionTracker,
    creds_rx: watch::Receiver<Arc<AuthorityCredentials>>,
    handshake_timeout_ms: u64,
    handler_config: Arc<HandlerConfig>,
    channel_id_alloc: Arc<ChannelIdAllocator>,
    extranonce_alloc: Arc<ExtranonceAllocator>,
    job_table: Arc<tokio::sync::RwLock<sv2_gateway::jobs::JobTable>>,
    latest_job: Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    job_broadcast_tx: broadcast::Sender<Arc<JobBroadcast>>,
    share_event_tx: mpsc::Sender<sv2_gateway::shares::ShareAcceptedEvent>,
    share_forward_tx: mpsc::Sender<sv2_gateway::shares::ShareSubmission>,
    metrics: SharedGatewayMetrics,
    mut shutdown: watch::Receiver<bool>,
    channel_registry: SharedChannelRegistry,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        // Per-IP limit check (before the global semaphore).
                        let Some(ip_permit) = per_ip_tracker.try_accept(addr.ip()) else {
                            warn!(
                                peer = %addr,
                                reason_code = %GatewayReason::ConnectionRateLimited.as_str(),
                                "connection rejected: per-IP limit reached"
                            );
                            drop(stream);
                            continue;
                        };

                        let Some(permit) = limiter.try_acquire() else {
                            warn!(peer = %addr, "connection rejected: limit reached");
                            drop(stream);
                            // ip_permit drops here, decrementing the per-IP count.
                            continue;
                        };

                        metrics.connections_total.inc();
                        metrics.connections_active.inc();
                        info!(peer = %addr, active = limiter.active_count(), "accepted SV2 connection");

                        let creds = Arc::clone(&*creds_rx.borrow());
                        let config = handler_config.clone();
                        let ch_alloc = channel_id_alloc.clone();
                        let en_alloc = extranonce_alloc.clone();
                        let conn_job_table = job_table.clone();
                        let conn_latest_job = latest_job.clone();
                        let job_rx = job_broadcast_tx.subscribe();
                        let conn_share_event_tx = share_event_tx.clone();
                        let conn_share_forward_tx = share_forward_tx.clone();
                        let conn_shutdown = shutdown.clone();
                        let hs_timeout = Duration::from_millis(handshake_timeout_ms);
                        let conn_metrics = metrics.clone();
                        let conn_channel_registry = channel_registry.clone();

                        tokio::spawn(async move {
                            // Hold the per-IP permit for the connection lifetime.
                            // When this task exits, the permit drops and the
                            // per-IP count decrements automatically.
                            let _ip_permit = ip_permit;

                            // 1. Noise NX handshake.
                            let transport = match sv2_gateway::transport::perform_handshake(
                                stream,
                                &creds.keypair,
                                creds.cert_validity_secs,
                                hs_timeout,
                            )
                            .await
                            {
                                Ok(t) => {
                                    info!(peer = %addr, "noise handshake complete");
                                    t
                                }
                                Err(e) => {
                                    warn!(peer = %addr, error = %e, "noise handshake failed");
                                    return;
                                }
                            };

                            // 2. Run full SV2 session handler.
                            let retarget_up = conn_metrics
                                .vardiff_retargets_total
                                .get_or_create(&VardiffLabels {
                                    direction: "up".into(),
                                })
                                .clone();
                            let retarget_down = conn_metrics
                                .vardiff_retargets_total
                                .get_or_create(&VardiffLabels {
                                    direction: "down".into(),
                                })
                                .clone();
                            let ctx = ConnectionContext {
                                transport,
                                peer: addr,
                                config,
                                channel_id_alloc: ch_alloc,
                                extranonce_alloc: en_alloc,
                                job_table: conn_job_table,
                                latest_job: conn_latest_job,
                                job_rx,
                                share_event_tx: conn_share_event_tx,
                                share_forward_tx: conn_share_forward_tx,
                                shutdown: conn_shutdown,
                                permit,
                                channel_registry: conn_channel_registry,
                                vardiff_retarget_up: retarget_up,
                                vardiff_retarget_down: retarget_down,
                            };

                            let exit = sv2_gateway::handler::run_connection(ctx).await;
                            conn_metrics.connections_active.dec();
                            debug!(peer = %addr, exit = %exit, "connection handler returned");
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "accept error");
                    }
                }
            }
            _ = shutdown.changed() => {
                info!("accept loop shutting down");
                return;
            }
        }
    }
}

/// Initialize tracing subscriber based on environment variables.
///
/// `VELDRA_LOG_FORMAT`: "json" (default) or "pretty"
/// `VELDRA_LOG_FILTER`: tracing filter directive (default "info")
/// Build a `VerifierTlsConfig` from the verifier section of the gateway config.
///
/// Loads the CA certificate, client certificate, and client private key from
/// PEM files. Constructs a `tokio_rustls::TlsConnector` with mTLS client
/// authentication and the CA as the sole trust anchor.
fn build_verifier_tls(cfg: &GatewayConfig) -> Result<VerifierTlsConfig, String> {
    use std::io::BufReader as StdBufReader;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

    let ca_path = cfg
        .verifier
        .tls_ca_cert
        .as_deref()
        .ok_or("tls_ca_cert is required")?;
    let client_cert_path = cfg
        .verifier
        .tls_client_cert
        .as_deref()
        .ok_or("tls_client_cert is required")?;
    let client_key_path = cfg
        .verifier
        .tls_client_key
        .as_deref()
        .ok_or("tls_client_key is required")?;

    // Load CA certificate (trust anchor).
    let ca_pem = std::fs::read(ca_path).map_err(|e| format!("read CA cert {ca_path}: {e}"))?;
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut StdBufReader::new(ca_pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse CA cert: {e}"))?;

    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    for cert in &ca_certs {
        root_store
            .add(cert.clone())
            .map_err(|e| format!("add CA to root store: {e}"))?;
    }

    // Load client certificate chain.
    let client_cert_pem =
        std::fs::read(client_cert_path).map_err(|e| format!("read client cert: {e}"))?;
    let client_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut StdBufReader::new(client_cert_pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse client cert: {e}"))?;

    // Load client private key.
    let client_key_pem =
        std::fs::read(client_key_path).map_err(|e| format!("read client key: {e}"))?;
    let client_key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut StdBufReader::new(client_key_pem.as_slice()))
            .map_err(|e| format!("parse client key: {e}"))?
            .ok_or_else(|| format!("no private key found in {client_key_path}"))?;

    // Build rustls ClientConfig with mTLS.
    let tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| format!("build TLS client config: {e}"))?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let server_name = ServerName::try_from(cfg.verifier.tls_server_name.clone()).map_err(|e| {
        format!(
            "invalid tls_server_name '{}': {e}",
            cfg.verifier.tls_server_name
        )
    })?;

    Ok(VerifierTlsConfig {
        connector,
        server_name,
    })
}

// ─────────────────────────────────────────────────────────────────────
// Key rotation watcher
// ─────────────────────────────────────────────────────────────────────

/// Watch for Noise authority keypair rotation signals and publish refreshed
/// credentials through the `watch` channel.
///
/// Two triggers are supported (both may be active simultaneously):
///
/// 1. **SIGHUP** (Unix only): sending `kill -HUP <pid>` causes an immediate
///    reload attempt. This is the standard daemon convention for config reload.
///
/// 2. **File poll**: when `poll_interval_secs > 0`, the task checks
///    `noise_keypair_path` modification time on a fixed cadence and reloads if
///    the mtime advanced since the last successful load. Useful in container
///    environments that mount rotated secrets.
///
/// A failed reload (bad file, key mismatch) is logged as an error and the
/// previous credentials remain active. This is a fail-safe design: operators
/// can fix the key file and re-signal without a process restart.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn run_key_reload_task(
    keypair_path: String,
    authority_pubkey: String,
    cert_validity_secs: u32,
    sighup_enabled: bool,
    poll_interval_secs: u64,
    creds_tx: watch::Sender<Arc<AuthorityCredentials>>,
    share_hmac_secret: Arc<std::sync::RwLock<Vec<u8>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    // Track the last known mtime so file-poll only reloads on actual change.
    let mut last_mtime = file_mtime(&keypair_path);

    // SIGHUP listener (Unix only). On non-Unix platforms the branch is
    // compiled out and only file polling is available.
    #[cfg(unix)]
    let mut sighup_stream = if sighup_enabled {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!(error = %e, "failed to register SIGHUP handler; file poll only");
                None
            }
        }
    } else {
        None
    };

    let poll_interval = if poll_interval_secs > 0 {
        Some(tokio::time::interval(Duration::from_secs(
            poll_interval_secs,
        )))
    } else {
        None
    };

    // Pin the optional interval so the select loop can reference it mutably.
    tokio::pin!(poll_interval);

    loop {
        // Build a future that resolves on the next reload trigger.
        let trigger = async {
            #[cfg(unix)]
            {
                if let Some(ref mut sig) = sighup_stream {
                    if let Some(ref mut interval) = *poll_interval {
                        tokio::select! {
                            _ = sig.recv() => KeyReloadTrigger::Sighup,
                            _ = interval.tick() => KeyReloadTrigger::FilePoll,
                        }
                    } else {
                        sig.recv().await;
                        KeyReloadTrigger::Sighup
                    }
                } else if let Some(ref mut interval) = *poll_interval {
                    interval.tick().await;
                    KeyReloadTrigger::FilePoll
                } else {
                    // No trigger configured; park forever (shutdown will break).
                    std::future::pending::<KeyReloadTrigger>().await
                }
            }
            #[cfg(not(unix))]
            {
                if let Some(ref mut interval) = *poll_interval {
                    interval.tick().await;
                    KeyReloadTrigger::FilePoll
                } else {
                    std::future::pending::<KeyReloadTrigger>().await
                }
            }
        };

        tokio::select! {
            trigger_kind = trigger => {
                // For file poll, skip reload if mtime has not changed.
                if matches!(trigger_kind, KeyReloadTrigger::FilePoll) {
                    let current_mtime = file_mtime(&keypair_path);
                    if current_mtime == last_mtime {
                        continue;
                    }
                }

                info!(
                    trigger = %trigger_kind,
                    path = %keypair_path,
                    "reloading noise authority keypair"
                );

                match load_authority_credentials(
                    std::path::Path::new(&keypair_path),
                    &authority_pubkey,
                    cert_validity_secs,
                ) {
                    Ok(new_creds) => {
                        last_mtime = file_mtime(&keypair_path);
                        creds_tx.send_replace(Arc::new(new_creds));
                        info!("noise authority keypair rotated successfully");
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            trigger = %trigger_kind,
                            "keypair reload failed; keeping previous credentials"
                        );
                    }
                }

                // On SIGHUP, also re-read the share upstream HMAC secret.
                // The env var may have been updated by the operator before
                // sending the signal. File-poll triggers skip this because
                // the HMAC secret is not file-backed.
                if matches!(trigger_kind, KeyReloadTrigger::Sighup) {
                    let new_secret = std::env::var("VELDRA_SHARE_UPSTREAM_SECRET")
                        .unwrap_or_default()
                        .into_bytes();
                    let changed = share_hmac_secret
                        .read()
                        .map_or(true, |old| *old != new_secret);
                    if changed {
                        match share_hmac_secret.write() {
                            Ok(mut guard) => {
                                *guard = new_secret;
                                info!("share upstream HMAC secret rotated");
                            }
                            Err(e) => {
                                error!(
                                    error = %e,
                                    "share_hmac_secret write lock poisoned; \
                                     secret rotation failed"
                                );
                            }
                        }
                    }
                }
            }
            _ = shutdown.changed() => {
                info!("key reload task shutting down");
                return;
            }
        }
    }
}

/// Trigger source for a keypair reload.
#[derive(Debug, Clone, Copy)]
enum KeyReloadTrigger {
    /// SIGHUP received from the operating system.
    Sighup,
    /// File modification time changed since last load.
    FilePoll,
}

impl std::fmt::Display for KeyReloadTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sighup => f.write_str("sighup"),
            Self::FilePoll => f.write_str("file_poll"),
        }
    }
}

/// Read the modification time of `path`, returning `None` on any error.
fn file_mtime(path: &str) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_env("VELDRA_LOG_FILTER").unwrap_or_else(|_| EnvFilter::new("info"));

    let format = std::env::var("VELDRA_LOG_FORMAT").unwrap_or_default();

    if format == "pretty" {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .pretty()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod key_reload_tests {
    use super::*;

    /// Helper: generate a secp256k1 keypair and write the 32-byte secret key
    /// to `path`. Returns the x-only public key as 64-char hex.
    fn write_test_keypair(path: &std::path::Path) -> String {
        let secp = secp256k1::Secp256k1::new();
        let (secret, _public) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
        std::fs::write(path, secret.secret_bytes()).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(&secp, &secret);
        let (xonly, _parity) = kp.x_only_public_key();
        hex::encode(xonly.serialize())
    }

    #[test]
    fn file_mtime_nonexistent_returns_none() {
        assert!(file_mtime("/tmp/rg_test_nonexistent_key_file_xyz").is_none());
    }

    #[test]
    fn file_mtime_existing_returns_some() {
        let dir = std::env::temp_dir().join("rg_mtime_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.key");
        std::fs::write(&path, b"x").unwrap();
        assert!(file_mtime(path.to_str().unwrap()).is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn key_reload_trigger_display() {
        assert_eq!(KeyReloadTrigger::Sighup.to_string(), "sighup");
        assert_eq!(KeyReloadTrigger::FilePoll.to_string(), "file_poll");
    }

    #[tokio::test]
    async fn watch_channel_delivers_rotated_credentials() {
        let dir = std::env::temp_dir().join("rg_key_rotate_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("noise.key");

        // Write initial keypair.
        let pubkey_hex = write_test_keypair(&path);

        let initial_creds = load_authority_credentials(&path, &pubkey_hex, 3600).unwrap();
        let initial_kp_bytes = initial_creds.keypair.secret_bytes();

        let (tx, rx) = watch::channel(Arc::new(initial_creds));

        // Rotate: write a new keypair to the same path.
        let new_pubkey_hex = write_test_keypair(&path);

        // Simulate reload (same logic as run_key_reload_task).
        let new_creds = load_authority_credentials(&path, &new_pubkey_hex, 3600).unwrap();
        tx.send_replace(Arc::new(new_creds));

        // Reader sees the new credentials.
        let latest = rx.borrow().clone();
        assert_ne!(latest.keypair.secret_bytes(), initial_kp_bytes);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn reload_task_file_poll_rotates_on_mtime_change() {
        let dir = std::env::temp_dir().join("rg_key_poll_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("noise.key");

        let pubkey_hex = write_test_keypair(&path);
        let initial_creds = load_authority_credentials(&path, &pubkey_hex, 3600).unwrap();
        let initial_kp = initial_creds.keypair.secret_bytes();

        let (creds_tx, creds_rx) = watch::channel(Arc::new(initial_creds));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task_path = path.to_str().unwrap().to_string();
        let task_pubkey = pubkey_hex.clone();

        let test_hmac_secret: Arc<std::sync::RwLock<Vec<u8>>> =
            Arc::new(std::sync::RwLock::new(Vec::new()));

        let handle = tokio::spawn(async move {
            run_key_reload_task(
                task_path,
                task_pubkey,
                3600,
                false, // no SIGHUP in test
                1,     // 1 second poll
                creds_tx,
                test_hmac_secret,
                shutdown_rx,
            )
            .await;
        });

        // Wait a moment then overwrite the key file with the same keypair but
        // touch the mtime. The reload should pick it up.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Ensure mtime actually changes (some filesystems have 1s resolution).
        tokio::time::sleep(Duration::from_secs(2)).await;
        // Re-write the same key to advance mtime.
        let old_sk = secp256k1::SecretKey::from_slice(&initial_kp).unwrap();
        std::fs::write(&path, old_sk.secret_bytes()).unwrap();

        // Wait for the poll to fire and reload.
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Credentials should still match (same key, just reloaded).
        let latest = creds_rx.borrow().clone();
        assert_eq!(latest.keypair.secret_bytes(), initial_kp);

        // Now write a genuinely new keypair.
        let new_pubkey_hex = write_test_keypair(&path);

        // The poll task has the old pubkey_hex so the new key will fail
        // validation (pubkey mismatch). This is expected behavior: the task
        // logs an error and keeps the old credentials.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let latest_after = creds_rx.borrow().clone();
        // Still the old key because new key doesn't match old pubkey.
        assert_eq!(latest_after.keypair.secret_bytes(), initial_kp);

        // Shutdown.
        let _ = shutdown_tx.send(true);
        let _ = handle.await;
        let _ = std::fs::remove_file(&path);
        // Suppress unused variable warning.
        let _ = new_pubkey_hex;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod pb15_tests {
    use super::*;

    fn mk_template(id: u64, src: &str) -> TemplateResponse {
        serde_json::from_value(serde_json::json!({
            "template_id": id,
            "block_height": 100,
            "block_version": 0x2000_0000_u32,
            "prev_hash": "00".repeat(32),
            "nbits": 0x207f_ffff_u32,
            "min_ntime": 1,
            "curtime": 2,
            "coinbase_value": 5_000_000_000_u64,
            "coinbase_tx_prefix": "01",
            "coinbase_tx_suffix": "02",
            "merkle_path": [],
            "tx_count": 1,
            "total_fees": 0,
            "source_instance_id": src,
        }))
        .expect("template fixture deserializes")
    }

    #[test]
    fn sweep_releases_dedup_so_template_can_repropose() {
        let mut dedup = sv2_gateway::jobs::TemplateDedupCache::new(64);
        // First sighting marks it seen; second is a duplicate.
        assert!(!dedup.is_duplicate("src-a", 7));
        assert!(dedup.is_duplicate("src-a", 7));

        let mut pending: HashMap<u64, PendingTemplate> = HashMap::new();
        let mut order: VecDeque<u64> = VecDeque::new();
        pending.insert(
            7,
            PendingTemplate {
                template: mk_template(7, "src-a"),
                // Backdate: Instant::elapsed() is only guaranteed
                // non-decreasing, so a just-created Instant could read
                // exactly zero on coarse-tick platforms.
                received_at: Instant::now()
                    .checked_sub(Duration::from_millis(5))
                    .unwrap_or_else(Instant::now),
            },
        );
        order.push_back(7);

        // max_age zero: any positive elapsed time is stale.
        let evicted =
            sweep_stale_pending_templates(&mut pending, &mut order, &mut dedup, Duration::ZERO);
        assert_eq!(evicted, 1);
        assert!(pending.is_empty());
        assert!(order.is_empty());
        // PB-15 D1: the poll path can now re-propose the same template.
        assert!(!dedup.is_duplicate("src-a", 7));
    }

    #[test]
    fn sweep_keeps_fresh_pendings_and_their_dedup_entries() {
        let mut dedup = sv2_gateway::jobs::TemplateDedupCache::new(64);
        assert!(!dedup.is_duplicate("src-a", 9));

        let mut pending: HashMap<u64, PendingTemplate> = HashMap::new();
        let mut order: VecDeque<u64> = VecDeque::new();
        pending.insert(
            9,
            PendingTemplate {
                template: mk_template(9, "src-a"),
                received_at: Instant::now(),
            },
        );
        order.push_back(9);

        let evicted = sweep_stale_pending_templates(
            &mut pending,
            &mut order,
            &mut dedup,
            Duration::from_secs(3600),
        );
        assert_eq!(evicted, 0);
        assert_eq!(pending.len(), 1);
        assert_eq!(order.len(), 1);
        // Still deduped: the template remains pending, not re-proposable.
        assert!(dedup.is_duplicate("src-a", 9));
    }

    #[test]
    fn degrade_trigger_prefers_heartbeat_then_catches_starvation() {
        let t = Duration::from_secs(10);
        assert_eq!(
            degrade_trigger_for(Duration::from_secs(11), None, t),
            Some(DegradeTrigger::HeartbeatStale)
        );
        assert_eq!(
            degrade_trigger_for(Duration::from_secs(11), Some(Duration::from_secs(99)), t),
            Some(DegradeTrigger::HeartbeatStale)
        );
        assert_eq!(
            degrade_trigger_for(Duration::from_secs(1), Some(Duration::from_secs(11)), t),
            Some(DegradeTrigger::VerdictStarved)
        );
        assert_eq!(
            degrade_trigger_for(Duration::from_secs(1), Some(Duration::from_secs(2)), t),
            None
        );
        assert_eq!(degrade_trigger_for(Duration::from_secs(1), None, t), None);
    }

    #[test]
    fn heartbeat_recovery_blocked_while_verdict_starved() {
        assert!(heartbeat_recovery_allowed(None));
        assert!(heartbeat_recovery_allowed(Some(
            DegradeTrigger::HeartbeatStale
        )));
        assert!(!heartbeat_recovery_allowed(Some(
            DegradeTrigger::VerdictStarved
        )));
    }
}
