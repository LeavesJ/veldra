use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader as StdBufReader;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::time::Duration;
use tracing::{error, info, warn};

// ── Write throttle for mutation endpoints ────────────

/// Global write throttle: max 10 mutation requests per 60 second window.
/// Prevents rapid-fire policy/settings changes even from authenticated callers.
static WRITE_THROTTLE: std::sync::LazyLock<Mutex<VecDeque<Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(VecDeque::new()));

const WRITE_THROTTLE_WINDOW_SECS: u64 = 60;
const WRITE_THROTTLE_MAX: usize = 10;

/// Check and record a write operation. Returns `Err(StatusCode)` if throttled.
fn check_write_throttle() -> Result<(), (StatusCode, String)> {
    let now = Instant::now();
    let window = std::time::Duration::from_secs(WRITE_THROTTLE_WINDOW_SECS);
    let mut guard = WRITE_THROTTLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Evict expired entries.
    while guard
        .front()
        .is_some_and(|t| now.duration_since(*t) > window)
    {
        guard.pop_front();
    }

    if guard.len() >= WRITE_THROTTLE_MAX {
        warn!(
            event = "write_throttled",
            count = guard.len(),
            "mutation endpoint rate limited"
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many write requests; try again later".to_string(),
        ));
    }

    guard.push_back(now);
    Ok(())
}

use pool_verifier::policy::PolicyConfig;
use reservegrid_common::DeployMode;
use rg_protocol::TemplatePropose;

use crate::state::AppState;
use crate::types::{LogReloadHandle, POLICY_LOADED_OK};
use crate::verdicts::{DEPLOY_MODE, LOG_WRITE_ERRORS, LoggedVerdict, StatsResponse, VerdictLog};

// ── Query structs ────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct TailQuery {
    pub(crate) tail: Option<usize>, // lines
}

#[derive(Deserialize)]
pub(crate) struct LimitQuery {
    pub(crate) limit: Option<usize>, // rows
}

// ── Request/Response wrappers ────────────────────────

#[derive(Deserialize)]
pub(crate) struct ApplyPolicyReq {
    pub(crate) low_mempool_tx: Option<u64>,
    pub(crate) high_mempool_tx: Option<u64>,
    pub(crate) min_avg_fee_lo: Option<u64>,
    pub(crate) min_avg_fee_mid: Option<u64>,
    pub(crate) min_avg_fee_hi: Option<u64>,
    pub(crate) min_total_fees: Option<u64>,
    pub(crate) max_tx_count: Option<u32>,
    // Boolean enforcement toggles
    pub(crate) reject_empty_templates: Option<bool>,
    pub(crate) reject_coinbase_zero: Option<bool>,
    pub(crate) enforce_weight_ratio: Option<bool>,
    pub(crate) enforce_template_age: Option<bool>,
    // Safety thresholds (numeric, optional)
    pub(crate) max_weight_ratio: Option<f64>,
    pub(crate) max_template_age_ms: Option<u64>,
    pub(crate) warn_sigops_ratio: Option<f64>,
    pub(crate) warn_coinbase_sigops_max: Option<u32>,
}

#[derive(Serialize)]
pub(crate) struct PolicyWrapper<'a> {
    pub(crate) policy: &'a PolicyConfig,
}

#[derive(Deserialize)]
pub(crate) struct ApplySettingsReq {
    pub(crate) log_level: Option<String>,
    pub(crate) mempool_url: Option<String>,
}

#[derive(Clone)]
pub(crate) struct RuntimeSettings {
    pub(crate) log_level: String,
    pub(crate) mempool_url: String,
}

pub(crate) type SharedRuntimeSettings = Arc<RwLock<RuntimeSettings>>;

#[derive(Deserialize)]
pub(crate) struct SaveSettingsReq {
    pub(crate) log_level: Option<String>,
    pub(crate) log_format: Option<String>,
    pub(crate) mempool_url: Option<String>,
}

/// Path to the verifier config TOML on disk.
pub(crate) type ConfigFilePath = Arc<PathBuf>;

/// Snapshot of config values at boot for detecting on-disk drift.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct VerifierDiskConfig {
    #[serde(default = "default_log_level")]
    pub(crate) log_level: String,
    #[serde(default = "default_log_format")]
    pub(crate) log_format: String,
    #[serde(default)]
    pub(crate) mempool_url: String,
}

pub(crate) fn default_log_level() -> String {
    "info".into()
}

pub(crate) fn default_log_format() -> String {
    "json".into()
}

pub(crate) type BootConfigSnapshot = Arc<VerifierDiskConfig>;

/// Resolved CLI addresses, shared via Extension so handlers never re-read env
/// vars with potentially different defaults.
#[derive(Debug, Clone)]
pub(crate) struct BootAddrs {
    pub(crate) tcp_addr: String,
    pub(crate) http_addr: String,
    pub(crate) policy_file: String,
}

pub(crate) type SharedBootAddrs = Arc<BootAddrs>;

#[derive(Deserialize)]
pub(crate) struct PolicyTomlWrapper {
    pub(crate) policy: PolicyConfig,
}

// ── Helper functions ────────────────────────────────

pub(crate) fn compute_avg_fee_sats_per_tx(t: &TemplatePropose) -> u64 {
    if t.tx_count == 0 {
        0
    } else {
        t.total_fees / u64::from(t.tx_count)
    }
}

// ── HTTP Handlers ────────────────────────────────────

pub(crate) async fn health_check() -> &'static str {
    "ok"
}

pub(crate) async fn readiness_check() -> impl IntoResponse {
    use crate::verdicts::LAST_MEMPOOL_OK_UNIX;
    use std::sync::atomic::Ordering;

    let policy_ok = POLICY_LOADED_OK.load(Ordering::Relaxed);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last_mempool = LAST_MEMPOOL_OK_UNIX.load(Ordering::Relaxed);
    let mempool_age_secs = if last_mempool > 0 {
        now.saturating_sub(last_mempool)
    } else {
        u64::MAX
    };
    let mempool_ok = mempool_age_secs < 30;

    let ready = policy_ok && mempool_ok;

    let body = json!({
        "ready": ready,
        "policy_loaded": policy_ok,
        "mempool_reachable": mempool_ok,
        "mempool_last_ok_age_secs": if last_mempool > 0 { Some(mempool_age_secs) } else { None::<u64> },
    });

    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(body))
}

pub(crate) async fn get_verdicts(
    Extension(log): Extension<VerdictLog>,
) -> Json<Vec<LoggedVerdict>> {
    let log = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Json(log.clone())
}

pub(crate) async fn get_verdict_log(Query(q): Query<TailQuery>) -> impl IntoResponse {
    use crate::verdicts::VERDICT_LOG_PATH;

    let tail = q.tail.unwrap_or(2000).min(10_000);

    // File open + full read runs on the blocking thread pool so dashboard
    // polls do not stall the tokio executor.
    let result = tokio::task::spawn_blocking(move || {
        let Ok(f) = File::open(VERDICT_LOG_PATH) else {
            return None;
        };
        let reader = StdBufReader::new(f);
        let mut buf: VecDeque<String> = VecDeque::with_capacity(tail);
        for line in reader.lines().map_while(Result::ok) {
            if buf.len() == tail {
                buf.pop_front();
            }
            buf.push_back(line);
        }
        let mut out = String::new();
        for line in buf {
            out.push_str(&line);
            out.push('\n');
        }
        Some(out)
    })
    .await;

    match result {
        Ok(Some(out)) => (
            StatusCode::OK,
            [("Content-Type", "application/x-ndjson")],
            out,
        ),
        _ => (
            StatusCode::OK,
            [("Content-Type", "text/plain")],
            "no verdicts yet\n".to_string(),
        ),
    }
}

pub(crate) async fn get_verdicts_csv(
    Query(q): Query<LimitQuery>,
    Extension(log): Extension<VerdictLog>,
) -> impl IntoResponse {
    use std::fmt::Write as _;

    let log = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let limit = q.limit.unwrap_or(1000).min(10_000);
    let start = log.len().saturating_sub(limit);

    let mut out = String::new();
    out.push_str("log_id,template_id,height,total_fees,tx_count,accepted,fee_tier,tier_source,min_avg_fee_used,avg_fee_sats_per_tx,reason_code,reason_detail,reason,timestamp,template_weight,total_sigops,coinbase_sigops,created_at_unix_ms,safety_warnings,second_chance,second_chance_still_absent\n");

    for v in log.iter().skip(start) {
        let reason_code = v
            .reason_code
            .as_deref()
            .unwrap_or(if v.accepted { "ok" } else { "" });
        let reason_detail = v.reason_detail.as_deref().unwrap_or("");
        let escaped_code = reason_code.replace('"', "\"\"");
        let escaped_detail = reason_detail.replace('"', "\"\"");

        let reason = v.reason.as_deref().unwrap_or("ok");
        let escaped_reason = reason.replace('"', "\"\"");

        let tw = v.template_weight.map(|w| w.to_string()).unwrap_or_default();
        let ts = v.total_sigops.map(|s| s.to_string()).unwrap_or_default();
        let cs = v.coinbase_sigops.map(|s| s.to_string()).unwrap_or_default();
        let ca = v
            .created_at_unix_ms
            .map(|t| t.to_string())
            .unwrap_or_default();
        let sw = v.safety_warnings.join(";");
        // PB-40: without these two columns a reviewer tallying
        // rejections from CSV would see no adjudication at all and
        // count every upheld or unadjudicated rejection as confirmed.
        // The NDJSON verdict log carries the full record including the
        // still-absent txids; these are the two fields a tally needs.
        let (sc, sc_absent) = v.mempool_adjudication.as_ref().map_or_else(
            || (String::new(), String::new()),
            |a| (a.outcome.clone(), a.still_absent.to_string()),
        );

        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},\"{}\",\"{}\",\"{}\",{},{},{},{},{},\"{}\",{},{}",
            v.log_id,
            v.template_id,
            v.height,
            v.total_fees,
            v.tx_count,
            v.accepted,
            v.fee_tier,
            v.tier_source,
            v.min_avg_fee_used,
            v.avg_fee_sats_per_tx,
            escaped_code,
            escaped_detail,
            escaped_reason,
            v.timestamp,
            tw,
            ts,
            cs,
            ca,
            sw,
            sc,
            sc_absent,
        );
    }

    (StatusCode::OK, [("Content-Type", "text/csv")], out)
}

pub(crate) async fn apply_policy(
    State(app_state): State<AppState>,
    Extension(metrics): Extension<crate::metrics::SharedVerifierMetrics>,
    Json(req): Json<ApplyPolicyReq>,
) -> impl IntoResponse {
    if let Err(e) = check_write_throttle() {
        return e;
    }
    let base_cfg = {
        let holder = app_state
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        holder.config.clone()
    };

    let mut cfg = base_cfg;
    if let Some(v) = req.low_mempool_tx {
        cfg.low_mempool_tx = v;
    }
    if let Some(v) = req.high_mempool_tx {
        cfg.high_mempool_tx = v;
    }
    if let Some(v) = req.min_avg_fee_lo {
        cfg.min_avg_fee_lo = v;
    }
    if let Some(v) = req.min_avg_fee_mid {
        cfg.min_avg_fee_mid = v;
    }
    if let Some(v) = req.min_avg_fee_hi {
        cfg.min_avg_fee_hi = v;
    }
    if let Some(v) = req.min_total_fees {
        cfg.min_total_fees = v;
    }
    if let Some(v) = req.max_tx_count {
        cfg.max_tx_count = v;
    }
    if let Some(v) = req.reject_empty_templates {
        cfg.reject_empty_templates = v;
    }
    if let Some(v) = req.reject_coinbase_zero {
        cfg.reject_coinbase_zero = v;
    }
    if let Some(v) = req.enforce_weight_ratio {
        cfg.safety.enforce_weight_ratio = v;
    }
    if let Some(v) = req.enforce_template_age {
        cfg.safety.enforce_template_age = v;
    }
    if let Some(v) = req.max_weight_ratio {
        cfg.safety.max_weight_ratio = v;
    }
    if let Some(v) = req.max_template_age_ms {
        cfg.safety.max_template_age_ms = Some(v);
    }
    if let Some(v) = req.warn_sigops_ratio {
        cfg.safety.warn_sigops_ratio = v;
    }
    if let Some(v) = req.warn_coinbase_sigops_max {
        cfg.safety.warn_coinbase_sigops_max = v;
    }

    if let Err(e) = cfg.validate() {
        metrics
            .policy_reloads_total
            .get_or_create(&crate::metrics::PolicyReloadLabels {
                result: "failed".into(),
            })
            .inc();
        return (
            StatusCode::BAD_REQUEST,
            format!("policy validation failed: {e:?}"),
        );
    }

    let toml_text = toml::to_string_pretty(&PolicyWrapper { policy: &cfg })
        .unwrap_or_else(|_| "# policy serialization failed\n".to_string());

    {
        let mut holder = app_state
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        holder.config = cfg;
        holder.toml_text = toml_text;
    }

    metrics
        .policy_reloads_total
        .get_or_create(&crate::metrics::PolicyReloadLabels {
            result: "success".into(),
        })
        .inc();
    info!(
        event = "policy_applied",
        source = "json",
        "policy updated via JSON API"
    );
    (StatusCode::OK, "ok".to_string())
}

pub(crate) async fn get_policy(State(app_state): State<AppState>) -> Json<serde_json::Value> {
    let holder = app_state
        .policy
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let policy = &holder.config;

    let body = json!({
        "protocol_version": policy.protocol_version,
        "required_prevhash_len": policy.required_prevhash_len,
        "min_total_fees": policy.min_total_fees,
        "max_tx_count": policy.max_tx_count,

        "low_mempool_tx": policy.low_mempool_tx,
        "high_mempool_tx": policy.high_mempool_tx,
        "min_avg_fee_lo": policy.min_avg_fee_lo,
        "min_avg_fee_mid": policy.min_avg_fee_mid,
        "min_avg_fee_hi": policy.min_avg_fee_hi,

        "max_weight_ratio": policy.safety.max_weight_ratio,
        "enforce_weight_ratio": policy.safety.enforce_weight_ratio,
        "max_template_age_ms": policy.safety.max_template_age_ms,
        "enforce_template_age": policy.safety.enforce_template_age,
        "warn_sigops_ratio": policy.safety.warn_sigops_ratio,
        "warn_coinbase_sigops_max": policy.safety.warn_coinbase_sigops_max,

        "reject_empty_templates": policy.reject_empty_templates,
        "reject_coinbase_zero": policy.reject_coinbase_zero,
        "unknown_mempool_as_high": policy.unknown_mempool_as_high,
    });

    Json(body)
}

pub(crate) async fn get_settings(
    Extension(ui_mode): Extension<String>,
    Extension(runtime): Extension<SharedRuntimeSettings>,
    Extension(boot_snapshot): Extension<BootConfigSnapshot>,
    Extension(config_path): Extension<ConfigFilePath>,
    Extension(boot_addrs): Extension<SharedBootAddrs>,
) -> Json<serde_json::Value> {
    let rt = runtime
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let log_level = rt.log_level.clone();
    let mempool_url = rt.mempool_url.clone();
    drop(rt);
    let log_format = env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "json".into());
    let api_key_set = env::var("VELDRA_API_SECRET").is_ok();
    let tls_cert = env::var("VELDRA_TLS_CERT")
        .ok()
        .or_else(|| env::var("VELDRA_VERIFIER_TLS_CERT").ok());
    let tls_key = env::var("VELDRA_TLS_KEY")
        .ok()
        .or_else(|| env::var("VELDRA_VERIFIER_TLS_KEY").ok());
    let tls_enabled = tls_cert.is_some() && tls_key.is_some();
    let tls_self_signed = env::var("VELDRA_TLS_SELF_SIGNED").as_deref() == Ok("1");
    let mtls_client_ca_set = env::var("VELDRA_VERIFIER_TLS_CLIENT_CA").is_ok();
    let tcp_addr = &boot_addrs.tcp_addr;
    let http_addr = &boot_addrs.http_addr;
    let policy_file = &boot_addrs.policy_file;

    // Detect pending_restart: compare boot snapshot against on-disk config.
    let pending_restart = match reservegrid_common::config_io::read_toml::<VerifierDiskConfig>(
        config_path.as_ref(),
    ) {
        Ok(disk_cfg) => *boot_snapshot != disk_cfg,
        Err(_) => false, // No file on disk yet means no drift.
    };

    let deploy_mode = DEPLOY_MODE.get().copied().unwrap_or(DeployMode::Shadow);
    Json(json!({
        "log_level": log_level,
        "log_format": log_format,
        "deploy_mode": deploy_mode.as_str(),
        "dash_mode": ui_mode,
        "mempool_url": mempool_url,
        "api_key_set": api_key_set,
        "tls_enabled": tls_enabled,
        "tls_self_signed": tls_self_signed,
        "mtls_client_ca_set": mtls_client_ca_set,
        "tcp_addr": tcp_addr,
        "http_addr": http_addr,
        "policy_file": policy_file,
        "pending_restart": pending_restart,
    }))
}

pub(crate) async fn apply_settings(
    Extension(reload_handle): Extension<Arc<LogReloadHandle>>,
    Extension(runtime): Extension<SharedRuntimeSettings>,
    Json(req): Json<ApplySettingsReq>,
) -> impl IntoResponse {
    if let Err(e) = check_write_throttle() {
        return e;
    }
    if let Some(ref level) = req.log_level {
        let allowed = ["trace", "debug", "info", "warn", "error"];
        if !allowed.contains(&level.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid log_level: {level}; expected one of {allowed:?}"),
            );
        }
        match tracing_subscriber::EnvFilter::try_new(level) {
            Ok(new_filter) => {
                if let Err(e) = reload_handle.reload(new_filter) {
                    warn!(error = %e, "failed to reload tracing filter");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to reload log filter: {e}"),
                    );
                }
                runtime
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .log_level
                    .clone_from(level);
                info!(new_level = %level, "log level changed at runtime");
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid filter expression: {e}"),
                );
            }
        }
    }

    if let Some(ref url) = req.mempool_url {
        runtime
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .mempool_url
            .clone_from(url);
        info!(new_url = %url, "mempool URL changed at runtime");
    }

    (StatusCode::OK, "ok".to_string())
}

pub(crate) async fn save_settings(
    Extension(reload_handle): Extension<Arc<LogReloadHandle>>,
    Extension(runtime): Extension<SharedRuntimeSettings>,
    Extension(config_path): Extension<ConfigFilePath>,
    Json(req): Json<SaveSettingsReq>,
) -> impl IntoResponse {
    if check_write_throttle().is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "ok": false, "error": "too many write requests; try again later" })),
        );
    }
    // Validate log_level if provided.
    if let Some(ref level) = req.log_level {
        let allowed = ["trace", "debug", "info", "warn", "error"];
        if !allowed.contains(&level.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "ok": false, "error": format!("invalid log_level: {level}; expected one of {allowed:?}") }),
                ),
            );
        }
    }

    // Validate log_format if provided.
    if let Some(ref fmt) = req.log_format {
        let allowed = ["json", "text", "pretty"];
        if !allowed.contains(&fmt.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "ok": false, "error": format!("invalid log_format: {fmt}; expected one of {allowed:?}") }),
                ),
            );
        }
    }

    // Read current on-disk config or start from defaults.
    let mut disk_cfg: VerifierDiskConfig =
        reservegrid_common::config_io::read_toml(config_path.as_ref()).unwrap_or_else(|_| {
            VerifierDiskConfig {
                log_level: default_log_level(),
                log_format: default_log_format(),
                mempool_url: String::new(),
            }
        });

    // Merge patch into disk config.
    if let Some(ref level) = req.log_level {
        disk_cfg.log_level.clone_from(level);
    }
    if let Some(ref fmt) = req.log_format {
        disk_cfg.log_format.clone_from(fmt);
    }
    if let Some(ref url) = req.mempool_url {
        disk_cfg.mempool_url.clone_from(url);
    }

    // Atomic write to disk.
    if let Err(e) =
        reservegrid_common::config_io::atomic_write_toml(config_path.as_ref(), &disk_cfg)
    {
        error!(error = %e, "failed to save verifier config to disk");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": format!("failed to write config: {e}") })),
        );
    }

    // Hot-reload log_level at runtime (same as apply_settings).
    if let Some(ref level) = req.log_level
        && let Ok(new_filter) = tracing_subscriber::EnvFilter::try_new(level)
    {
        if let Err(e) = reload_handle.reload(new_filter) {
            warn!(error = %e, "saved to disk but failed to hot-reload log filter");
        } else {
            runtime
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .log_level
                .clone_from(level);
            info!(new_level = %level, "log level saved and hot-reloaded");
        }
    }

    // Hot-reload mempool_url at runtime.
    if let Some(ref url) = req.mempool_url {
        runtime
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .mempool_url
            .clone_from(url);
        info!(new_url = %url, "mempool URL saved and hot-reloaded");
    }

    info!(path = %config_path.display(), "verifier config saved to disk");

    (
        StatusCode::OK,
        Json(json!({ "ok": true, "restart_required": true })),
    )
}

pub(crate) async fn get_meta(Extension(ui_mode): Extension<String>) -> Json<serde_json::Value> {
    let deploy_mode = DEPLOY_MODE.get().copied().unwrap_or(DeployMode::Shadow);
    let body = json!({
        "mode": ui_mode,
        "deploy_mode": deploy_mode.as_str(),
        "persist_verdicts": deploy_mode.persist_verdicts(),
        "is_enforcing": deploy_mode.is_enforcing(),
        "log_write_errors": LOG_WRITE_ERRORS.load(std::sync::atomic::Ordering::Relaxed),
    });
    Json(body)
}

pub(crate) async fn get_mempool_proxy() -> Json<serde_json::Value> {
    use crate::mempool_client::mempool_url_from_env;

    let Some(url) = mempool_url_from_env() else {
        return Json(json!({ "error": "VELDRA_MEMPOOL_URL not set" }));
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(
            crate::mempool_client::mempool_timeout_ms(),
        ))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return Json(json!({ "error": format!("mempool fetch failed: {}", e) })),
    };

    match resp.json::<serde_json::Value>().await {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "error": format!("invalid mempool json: {}", e) })),
    }
}

pub(crate) async fn get_stats(Extension(log): Extension<VerdictLog>) -> Json<StatsResponse> {
    let log = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut total = 0_u64;
    let mut accepted = 0_u64;
    let mut rejected = 0_u64;
    let mut by_reason: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_tier: BTreeMap<String, u64> = BTreeMap::new();

    #[allow(clippy::explicit_iter_loop)] // log is MutexGuard; &log has no IntoIterator
    for v in log.iter() {
        total += 1;
        if v.accepted {
            accepted += 1;
        } else {
            rejected += 1;
        }

        // reason_code is canonical from rg-protocol. No normalization.
        // Legacy lines without reason_code aggregate under "unknown".
        let reason_key = if v.accepted {
            "ok".to_string()
        } else if let Some(ref code) = v.reason_code {
            code.clone()
        } else {
            "unknown".to_string()
        };

        *by_reason.entry(reason_key).or_insert(0) += 1;
        *by_tier.entry(v.fee_tier.clone()).or_insert(0) += 1;
    }

    Json(StatsResponse {
        total,
        accepted,
        rejected,
        by_reason,
        by_tier,
        last: log.last().cloned(),
    })
}

pub(crate) async fn apply_policy_toml(
    State(app_state): State<AppState>,
    bytes: Bytes,
) -> impl IntoResponse {
    if check_write_throttle().is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "ok": false, "error": "too many write requests; try again later" })),
        );
    }
    let body = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": format!("body must be utf8 text: {e}"),
                })),
            );
        }
    };

    let parsed: PolicyTomlWrapper = match toml::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            let detail = format!("{e}");
            // Truncate verbose TOML parse details to avoid leaking structure.
            let sanitized = if detail.len() > 200 {
                format!("{}...", &detail[..200])
            } else {
                detail.clone()
            };
            tracing::warn!(error = %detail, "toml_parse_failed");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": format!("toml parse failed: {sanitized}"),
                })),
            );
        }
    };

    if let Err(e) = parsed.policy.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": format!("policy validation failed: {:?}", e),
            })),
        );
    }

    {
        let mut holder = match app_state.policy.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        holder.config = parsed.policy;
        holder.toml_text = body;
    }

    info!(
        event = "policy_applied",
        source = "toml",
        "policy updated via TOML API"
    );
    (StatusCode::OK, Json(json!({ "ok": true })))
}
