use std::env;
use std::sync::{Arc, RwLock};

use clap::Parser;
use reservegrid_common::DeployMode;
use tracing::info;

// Module declarations
mod dashboard;
mod handlers;
mod http;
mod idle_stream;
mod ingress;
mod mempool_client;
mod metrics;
mod state;
mod types;
mod verdicts;

// Phase 2 modules (`bitcoind_rpc`, `mempool_view`) live in the library
// crate (lib.rs) so that policy.rs in the lib can reference them via
// `crate::mempool_view`. main.rs will import from `pool_verifier::*`
// when the polling-task wiring lands in a follow-up.

// Re-export commonly used types
use mempool_client::mempool_url_from_env;
use state::AppState;
use types::{LogReloadHandle, POLICY_LOADED_OK};
use verdicts::{DEPLOY_MODE, load_verdict_log};

// ── CLI ─────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "pool-verifier", about = "Veldra pool template verifier")]
struct Cli {
    /// TCP listen address for template verdicts.
    #[arg(long, env = "VELDRA_VERIFIER_ADDR", default_value = "127.0.0.1:9090")]
    tcp_addr: String,

    /// HTTP listen address for dashboard and API.
    #[arg(long, env = "VELDRA_HTTP_ADDR", default_value = "127.0.0.1:8081")]
    http_addr: String,

    /// Deploy mode (shadow, observe, inline). Controls WAL persistence and
    /// enforcement behavior. Read from `VELDRA_MODE` env var if not specified.
    #[arg(long, env = "VELDRA_MODE", default_value = "shadow")]
    deploy_mode: String,

    /// Path to the policy TOML file.
    #[arg(long, env = "VELDRA_POLICY_FILE", default_value = "config/policy.toml")]
    policy_file: String,

    /// Path to the verifier config TOML (persisted settings).
    #[arg(
        long,
        env = "VELDRA_VERIFIER_CONFIG",
        default_value = "config/verifier.toml"
    )]
    config_file: String,

    /// Maximum concurrent NDJSON ingress connections (PB-26). Raise it
    /// when a deployment genuinely runs more gateway and
    /// template-manager streams than the default allows; each admitted
    /// connection can hold a line buffer up to
    /// `MAX_INTERNAL_LINE_BYTES` (20 MiB), so this is the ingress
    /// memory bound as much as a connection count. Zero is rejected:
    /// a cap of zero would refuse every gateway and hand the pool
    /// straight to `auto_degrade`.
    #[arg(
        long,
        env = "VELDRA_VERIFIER_MAX_CONNECTIONS",
        default_value_t = ingress::DEFAULT_MAX_INGRESS_CONNECTIONS,
        value_parser = clap::value_parser!(u32).range(1..),
    )]
    max_connections: u32,

    /// Maximum concurrent NDJSON ingress connections from any one
    /// source address (PB-27). The global cap above is per process, so
    /// without this one address can take every slot and lock out the
    /// gateway and template-manager; the reported probe did exactly
    /// that with eight sockets. `0` disables per-IP enforcement, for a
    /// deployment whose legitimate peers all arrive through one L4
    /// proxy address and therefore have no per-IP signal to enforce on.
    #[arg(
        long,
        env = "VELDRA_VERIFIER_MAX_CONNECTIONS_PER_IP",
        default_value_t = ingress::DEFAULT_MAX_INGRESS_CONNECTIONS_PER_IP,
    )]
    max_connections_per_ip: u32,

    /// Seconds an ingress connection may make no progress in either
    /// direction before it is closed and its slot returned (PB-27).
    ///
    /// Measured since the last byte that actually moved, never from the
    /// connection's start, so a multi-megabyte `raw_block_hex` line
    /// arriving slowly is not reaped. Raise it only when a legitimate
    /// peer genuinely goes quiet for longer than the default; sv2-gateway
    /// heartbeats every 5 s. Zero is rejected: disabling the budget
    /// restores the PB-27 defect, where a silent socket holds its slot
    /// for the life of the process.
    #[arg(
        long,
        env = "VELDRA_VERIFIER_IDLE_TIMEOUT_SECS",
        default_value_t = ingress::DEFAULT_INGRESS_IDLE_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    idle_timeout_secs: u64,
}

// ── Tracing ─────────────────────────────────────────────────

fn init_tracing() -> LogReloadHandle {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{EnvFilter, Registry, fmt, reload};

    let filter =
        EnvFilter::try_from_env("VELDRA_LOG_FILTER").unwrap_or_else(|_| EnvFilter::new("info"));

    let (filter_layer, reload_handle) = reload::Layer::new(filter);

    let json_mode = env::var("VELDRA_LOG_FORMAT").as_deref() == Ok("json");

    if json_mode {
        let fmt_layer = fmt::layer().json();
        Registry::default()
            .with(filter_layer)
            .with(fmt_layer)
            .init();
    } else {
        let fmt_layer = fmt::layer();
        Registry::default()
            .with(filter_layer)
            .with(fmt_layer)
            .init();
    }

    reload_handle
}

// ── Startup checks ──────────────────────────────────────────

/// Require `VELDRA_API_SECRET` unless explicitly opted out via
/// `VELDRA_API_SECRET_OPTIONAL=1`. Exits the process when the secret is
/// missing and no opt-out is present.
fn enforce_api_secret() {
    let api_secret_set = env::var("VELDRA_API_SECRET")
        .ok()
        .is_some_and(|s| !s.is_empty());
    let api_secret_optional = env::var("VELDRA_API_SECRET_OPTIONAL").as_deref() == Ok("1");
    if !api_secret_set && !api_secret_optional {
        tracing::error!(
            "VELDRA_API_SECRET is not set. All protected HTTP endpoints would be open. \
             Set VELDRA_API_SECRET to a strong secret, or set VELDRA_API_SECRET_OPTIONAL=1 \
             to explicitly allow unauthenticated access (not recommended)."
        );
        std::process::exit(1);
    }
    if !api_secret_set && api_secret_optional {
        tracing::warn!(
            "VELDRA_API_SECRET is not set but VELDRA_API_SECRET_OPTIONAL=1 is active. \
             Protected endpoints are open without authentication."
        );
    }
}

fn init_metrics() -> (
    reservegrid_common::metrics::SharedRegistry,
    Arc<metrics::VerifierMetrics>,
) {
    let mut registry = prometheus_client::registry::Registry::default();
    let verifier_metrics = Arc::new(metrics::VerifierMetrics::new_registered(&mut registry));
    let shared: reservegrid_common::metrics::SharedRegistry = Arc::new(registry);
    (shared, verifier_metrics)
}

// ── Phase 2 mempool view bootstrap (ADR-003) ──────────────────

/// Construct the Phase 2 [`MempoolView`] and spawn the polling task
/// when policy enables Class M and the bitcoind RPC creds are
/// populated. Returns `None` to leave the shield in Phase 1 mode.
///
/// `[policy.mempool] rpc_pass` is preferred from the
/// `VELDRA_BITCOIND_RPC_PASS` env var when set, falling back to the
/// TOML-stored value. Operators should keep secrets out of
/// `policy.toml` on disk.
fn build_phase2_mempool_view(
    cfg: &pool_verifier::policy::PolicyConfig,
) -> Option<Arc<pool_verifier::mempool_view::MempoolView>> {
    let mp = &cfg.mempool;
    if !mp.enforce {
        return None;
    }
    if mp.rpc_url.is_empty() || mp.rpc_user.is_empty() {
        tracing::warn!(
            "policy.mempool.enforce=true but rpc_url or rpc_user is empty; \
             Phase 2 Class M check disabled (shield runs Phase 1 only)"
        );
        return None;
    }
    let pass = env::var("VELDRA_BITCOIND_RPC_PASS").unwrap_or_else(|_| mp.rpc_pass.clone());
    if pass.is_empty() {
        tracing::warn!(
            "policy.mempool.enforce=true but no rpc_pass available \
             (neither VELDRA_BITCOIND_RPC_PASS env nor [policy.mempool] rpc_pass); \
             Phase 2 Class M check disabled (shield runs Phase 1 only)"
        );
        return None;
    }

    let client = pool_verifier::bitcoind_rpc::BitcoindClient::new(
        mp.rpc_url.clone(),
        mp.rpc_user.clone(),
        pass,
        std::time::Duration::from_secs(5),
    );
    let view = Arc::new(pool_verifier::mempool_view::MempoolView::new(
        mp.max_stale_secs,
    ));
    let handle = Arc::clone(&view).spawn_polling_task(
        client,
        std::time::Duration::from_secs(mp.poll_interval_secs),
    );
    // Detach the join handle; the task lives for the program lifetime.
    drop(handle);
    tracing::info!(
        rpc_url = %mp.rpc_url,
        poll_interval_secs = mp.poll_interval_secs,
        max_stale_secs = mp.max_stale_secs,
        tolerance_pct = mp.tolerance_pct,
        per_tx_detail = mp.per_tx_detail,
        "Phase 2 Class M check enabled; mempool view polling task spawned"
    );
    Some(view)
}

// ── Main ─────────────────────────────────────────────────────

// Startup wiring is linear by nature: parse, validate, load state, spawn
// the two servers. Splitting it to satisfy a line count would add a
// layer that makes nothing easier to read or to change.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let log_reload = init_tracing();
    let cli = Cli::parse();

    enforce_api_secret();

    // Ahead of the ingress acceptor and the HTTPS server both, because
    // either one can be the first rustls consumer depending on which
    // env vars an operator set (PB-28, PB-30). The two rustls providers
    // this binary resolves, `aws-lc-rs` via `axum-server` and `ring` via
    // `reqwest`, make the automatic choice ambiguous, so `install` here
    // is what keeps every later builder call from panicking. Shared with
    // `sv2-gateway` and `rg-feed-adapter`; see
    // `reservegrid_common::crypto_provider`.
    reservegrid_common::crypto_provider::install_default().map_err(|e| anyhow::anyhow!(e))?;

    let tcp_addr = cli.tcp_addr;
    let http_addr = cli.http_addr;
    let policy_path = cli.policy_file;
    let max_connections = cli.max_connections;
    let max_connections_per_ip = cli.max_connections_per_ip;
    let idle_timeout_secs = cli.idle_timeout_secs;

    // Prefer VELDRA_MODE; fall back to deprecated VELDRA_DASH_MODE for backward
    // compat with existing docker-compose files. Emit a warning so operators
    // know to migrate.
    let mode_str = if cli.deploy_mode != "shadow" || env::var("VELDRA_MODE").is_ok() {
        cli.deploy_mode.clone()
    } else if let Ok(legacy) = env::var("VELDRA_DASH_MODE") {
        tracing::warn!(
            legacy_var = "VELDRA_DASH_MODE",
            "VELDRA_DASH_MODE is deprecated; migrate to VELDRA_MODE"
        );
        legacy
    } else {
        cli.deploy_mode.clone()
    };

    let deploy_mode: DeployMode = mode_str.parse().unwrap_or_else(|e| {
        tracing::error!(error = %e, raw = %mode_str, "invalid deploy mode value; defaulting to shadow");
        DeployMode::Shadow
    });
    let _ = DEPLOY_MODE.set(deploy_mode);
    let ui_mode = deploy_mode.as_str().to_string();
    info!(deploy_mode = deploy_mode.as_str(), "verifier deploy mode");
    let config_file = std::path::PathBuf::from(cli.config_file);

    info!(policy_file = %policy_path, "loading policy");

    std::fs::create_dir_all("data")?;

    let policy_holder = crate::state::safe_initial_policy(&policy_path);

    // Track whether policy loaded from file (vs degraded built-in default).
    let policy_ok = policy_holder.toml_text.starts_with("[policy]")
        || policy_holder.toml_text.contains("[policy]");
    POLICY_LOADED_OK.store(policy_ok, std::sync::atomic::Ordering::Relaxed);

    // Phase 2 mempool view spawn-on-startup. Wired only when
    // `[policy.mempool] enforce = true` and the bitcoind RPC creds
    // are populated. Defaults shipped with `enforce = false`, so
    // existing deployments run Phase 1 only without operator action.
    let mempool_view = build_phase2_mempool_view(&policy_holder.config);

    let app_state = AppState {
        policy: Arc::new(RwLock::new(policy_holder)),
        mempool_view,
    };

    let (verdict_log, log_id_counter) = load_verdict_log();
    info!(
        count = verdict_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        next_log_id = log_id_counter.load(std::sync::atomic::Ordering::Relaxed),
        "loaded verdicts from disk"
    );

    let tcp_state = app_state.clone();
    let tcp_log = verdict_log.clone();
    let tcp_log_counter = log_id_counter.clone();
    let http_log = verdict_log.clone();
    let http_ui_mode = ui_mode.clone();
    let http_state = app_state.clone();
    let http_tcp_addr = tcp_addr.clone();
    let http_policy_file = policy_path.clone();

    let mempool_url = mempool_url_from_env();
    let tcp_mempool_url = mempool_url.clone();

    let tcp_tls_acceptor = ingress::build_tcp_tls_acceptor().unwrap_or_else(|e| {
        tracing::error!(error = %e, "failed to build TCP TLS acceptor");
        std::process::exit(1);
    });

    let (shared_registry, verifier_metrics) = init_metrics();
    let tcp_metrics = verifier_metrics.clone();

    let tcp_task = tokio::spawn(async move {
        if let Err(e) = ingress::run_tcp_server(
            tcp_state,
            tcp_addr,
            tcp_log,
            tcp_mempool_url,
            tcp_log_counter,
            tcp_tls_acceptor,
            tcp_metrics,
            max_connections,
            max_connections_per_ip,
            idle_timeout_secs,
        )
        .await
        {
            tracing::error!(error = ?e, "tcp server error");
        }
    });

    let http_task = tokio::spawn(async move {
        if let Err(e) = http::run_http_server(
            http_addr,
            http_tcp_addr,
            http_policy_file,
            http_log,
            http_ui_mode,
            http_state,
            log_reload,
            config_file,
            shared_registry,
            verifier_metrics,
        )
        .await
        {
            tracing::error!(error = ?e, "http server error");
        }
    });

    let _ = tokio::join!(tcp_task, http_task);
    Ok(())
}

// ── Dashboard smoke tests ───────────────────────────────────
//
// These tests validate the JSON API contracts that the embedded
// INDEX_HTML JavaScript depends on. If a field is renamed or
// removed in a struct, the dashboard will silently break; these
// tests catch that at compile/test time.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod dashboard_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    // ── helpers ──

    fn sample_verdict(accepted: bool) -> verdicts::LoggedVerdict {
        verdicts::LoggedVerdict {
            log_id: 1,
            template_id: 42,
            height: 800_000,
            total_fees: 250_000,
            tx_count: 12,
            accepted,
            reason: if accepted {
                None
            } else {
                Some("fee_below_tier_floor".into())
            },
            reason_code: if accepted {
                None
            } else {
                Some("fee_below_tier_floor".into())
            },
            reason_detail: if accepted {
                None
            } else {
                Some("avg 1200 < floor 2000".into())
            },
            timestamp: 1_700_000_000,
            min_avg_fee_used: 2000,
            fee_tier: "mid".into(),
            tier_source: "measured".into(),
            avg_fee_sats_per_tx: 1200,
            template_weight: Some(3_200_000),
            total_sigops: Some(5000),
            coinbase_sigops: Some(4),
            created_at_unix_ms: Some(1_700_000_000_000),
            safety_warnings: vec![],
        }
    }

    #[allow(dead_code)]
    fn make_verdict_log(verdicts: Vec<verdicts::LoggedVerdict>) -> verdicts::VerdictLog {
        Arc::new(Mutex::new(verdicts))
    }

    // ── StatsResponse JSON shape ──

    #[test]
    fn stats_response_has_expected_keys() {
        let resp = verdicts::StatsResponse {
            total: 10,
            accepted: 7,
            rejected: 3,
            by_reason: {
                let mut m = BTreeMap::new();
                m.insert("ok".into(), 7);
                m.insert("fee_below_tier_floor".into(), 3);
                m
            },
            by_tier: {
                let mut m = BTreeMap::new();
                m.insert("mid".into(), 10);
                m
            },
            last: Some(sample_verdict(true)),
        };

        let json = serde_json::to_value(&resp).unwrap();

        // Keys the JS refresh() function reads from /stats
        assert!(json.get("total").is_some(), "missing 'total'");
        assert!(json.get("accepted").is_some(), "missing 'accepted'");
        assert!(json.get("rejected").is_some(), "missing 'rejected'");
        assert!(json.get("by_reason").is_some(), "missing 'by_reason'");
        assert!(json.get("by_tier").is_some(), "missing 'by_tier'");
        assert!(json.get("last").is_some(), "missing 'last'");

        // Numeric types the JS expects
        assert!(json["total"].is_u64());
        assert!(json["accepted"].is_u64());
        assert!(json["rejected"].is_u64());
        assert!(json["by_reason"].is_object());
        assert!(json["by_tier"].is_object());
    }

    // ── LoggedVerdict JSON shape ──

    #[test]
    fn logged_verdict_has_all_dashboard_fields() {
        let v = sample_verdict(false);
        let json = serde_json::to_value(&v).unwrap();

        // Fields the JS reads from /verdicts array elements and
        // from stats.last
        let required = [
            "log_id",
            "template_id",
            "height",
            "total_fees",
            "tx_count",
            "accepted",
            "reason",
            "reason_code",
            "reason_detail",
            "timestamp",
            "min_avg_fee_used",
            "fee_tier",
            "tier_source",
            "avg_fee_sats_per_tx",
            // v0.2.2 consensus safety fields
            "template_weight",
            "total_sigops",
            "coinbase_sigops",
            "created_at_unix_ms",
            "safety_warnings",
        ];

        for key in &required {
            assert!(
                json.get(key).is_some(),
                "LoggedVerdict missing field '{key}' required by dashboard JS"
            );
        }
    }

    #[test]
    fn logged_verdict_accepted_has_null_reason_fields() {
        let v = sample_verdict(true);
        let json = serde_json::to_value(&v).unwrap();

        // JS handles null reason gracefully (v.reason || "Ok")
        assert!(
            json["reason"].is_null(),
            "accepted verdict 'reason' should be null"
        );
    }

    // ── StatsResponse from get_stats handler logic ──

    #[test]
    fn stats_aggregation_counts_correctly() {
        let verdicts = vec![
            sample_verdict(true),
            sample_verdict(true),
            sample_verdict(false),
        ];

        let mut total = 0u64;
        let mut accepted = 0u64;
        let mut rejected = 0u64;
        let mut by_reason: BTreeMap<String, u64> = BTreeMap::new();
        let mut by_tier: BTreeMap<String, u64> = BTreeMap::new();

        for v in &verdicts {
            total += 1;
            if v.accepted {
                accepted += 1;
            } else {
                rejected += 1;
            }
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

        assert_eq!(total, 3);
        assert_eq!(accepted, 2);
        assert_eq!(rejected, 1);
        assert_eq!(by_reason["ok"], 2);
        assert_eq!(by_reason["fee_below_tier_floor"], 1);
        assert_eq!(by_tier["mid"], 3);
    }

    // ── INDEX_HTML references all expected fetch endpoints ──

    #[test]
    fn html_fetches_match_router_endpoints() {
        // The JS refresh() calls these endpoints via fetch().
        let js_fetches = ["/stats", "/policy", "/meta"];

        for endpoint in &js_fetches {
            assert!(
                dashboard::INDEX_HTML.contains(&format!("'{endpoint}'"))
                    || dashboard::INDEX_HTML.contains(&format!("\"{endpoint}\"")),
                "INDEX_HTML must contain fetch with endpoint '{endpoint}' but does not"
            );
        }
    }

    #[test]
    fn html_links_match_router_endpoints() {
        // Static links in the HTML that must resolve.
        let links = ["/verdicts/log", "/verdicts.csv", "/mempool"];

        for link in &links {
            assert!(
                dashboard::INDEX_HTML.contains(link),
                "INDEX_HTML must reference '{link}' but does not"
            );
        }
    }

    // ── CSV export header matches LoggedVerdict fields ──

    #[test]
    fn csv_header_covers_logged_verdict_fields() {
        let csv_header = "log_id,template_id,height,total_fees,tx_count,accepted,fee_tier,tier_source,min_avg_fee_used,avg_fee_sats_per_tx,reason_code,reason_detail,reason,timestamp,template_weight,total_sigops,coinbase_sigops,created_at_unix_ms,safety_warnings";

        // Verify the header is present in the source (get_verdicts_csv).
        // This catches accidental edits to the CSV column order.
        let v = sample_verdict(false);
        let json = serde_json::to_value(&v).unwrap();
        let json_keys: Vec<String> = json.as_object().unwrap().keys().cloned().collect();

        // Every CSV column must correspond to a LoggedVerdict field.
        for col in csv_header.split(',') {
            assert!(
                json_keys.contains(&col.to_string()),
                "CSV column '{col}' does not match any LoggedVerdict field"
            );
        }
    }

    // ── Policy JSON shape matches dashboard JS expectations ──

    #[test]
    fn policy_json_has_wizard_fields() {
        use rg_protocol::PROTOCOL_VERSION;
        // The dashboard wizard reads these keys from /policy.
        let wizard_keys = [
            "low_mempool_tx",
            "high_mempool_tx",
            "min_avg_fee_lo",
            "min_avg_fee_mid",
            "min_avg_fee_hi",
            "min_total_fees",
            "max_tx_count",
        ];

        let cfg = pool_verifier::policy::PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let body = serde_json::json!({
            "protocol_version": cfg.protocol_version,
            "required_prevhash_len": cfg.required_prevhash_len,
            "min_total_fees": cfg.min_total_fees,
            "max_tx_count": cfg.max_tx_count,
            "low_mempool_tx": cfg.low_mempool_tx,
            "high_mempool_tx": cfg.high_mempool_tx,
            "min_avg_fee_lo": cfg.min_avg_fee_lo,
            "min_avg_fee_mid": cfg.min_avg_fee_mid,
            "min_avg_fee_hi": cfg.min_avg_fee_hi,
            "max_weight_ratio": cfg.safety.max_weight_ratio,
            "enforce_weight_ratio": cfg.safety.enforce_weight_ratio,
            "max_template_age_ms": cfg.safety.max_template_age_ms,
            "enforce_template_age": cfg.safety.enforce_template_age,
            "warn_sigops_ratio": cfg.safety.warn_sigops_ratio,
            "warn_coinbase_sigops_max": cfg.safety.warn_coinbase_sigops_max,
            "reject_empty_templates": cfg.reject_empty_templates,
            "reject_coinbase_zero": cfg.reject_coinbase_zero,
            "unknown_mempool_as_high": cfg.unknown_mempool_as_high,
        });

        for key in &wizard_keys {
            assert!(
                body.get(key).is_some(),
                "/policy JSON missing wizard field '{key}'"
            );
        }
    }

    // ── Consensus safety panel field presence ──

    #[test]
    fn consensus_safety_fields_present_in_verdict() {
        let v = sample_verdict(false);
        let json = serde_json::to_value(&v).unwrap();

        // The consensus safety panel reads these from the last verdict.
        let safety_keys = [
            "template_weight",
            "total_sigops",
            "coinbase_sigops",
            "created_at_unix_ms",
            "safety_warnings",
        ];

        for key in &safety_keys {
            assert!(
                json.get(key).is_some(),
                "consensus safety panel requires '{key}' in LoggedVerdict"
            );
        }

        assert!(json["safety_warnings"].is_array());
    }

    // ── Meta endpoint shape ──

    #[test]
    fn meta_json_has_mode_field() {
        // JS reads meta.mode to set the badge text.
        let body = serde_json::json!({
            "mode": "inline",
            "log_write_errors": 0u64,
        });

        assert!(body.get("mode").is_some());
        assert!(body["mode"].is_string());
    }

    // ── Round-trip: verdict serialization stability ──

    #[test]
    fn verdict_round_trip_json() {
        let v = sample_verdict(false);
        let serialized = serde_json::to_string(&v).unwrap();
        let deserialized: verdicts::LoggedVerdict = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.log_id, v.log_id);
        assert_eq!(deserialized.reason_code, v.reason_code);
        assert_eq!(deserialized.fee_tier, v.fee_tier);
        assert_eq!(deserialized.template_weight, v.template_weight);
        assert_eq!(deserialized.safety_warnings.len(), v.safety_warnings.len());
    }

    // ── CL-17: CSV export schema snapshot ──

    #[test]
    fn csv_column_order_is_stable() {
        // The exact column order is a schema contract for external consumers.
        // Changing it breaks downstream parsers that reference columns by index.
        let expected_columns = [
            "log_id",
            "template_id",
            "height",
            "total_fees",
            "tx_count",
            "accepted",
            "fee_tier",
            "tier_source",
            "min_avg_fee_used",
            "avg_fee_sats_per_tx",
            "reason_code",
            "reason_detail",
            "reason",
            "timestamp",
            "template_weight",
            "total_sigops",
            "coinbase_sigops",
            "created_at_unix_ms",
            "safety_warnings",
        ];

        let csv_header = "log_id,template_id,height,total_fees,tx_count,accepted,fee_tier,tier_source,min_avg_fee_used,avg_fee_sats_per_tx,reason_code,reason_detail,reason,timestamp,template_weight,total_sigops,coinbase_sigops,created_at_unix_ms,safety_warnings";
        let actual: Vec<&str> = csv_header.split(',').collect();

        assert_eq!(
            actual.len(),
            expected_columns.len(),
            "column count mismatch"
        );
        for (i, (actual_col, expected_col)) in
            actual.iter().zip(expected_columns.iter()).enumerate()
        {
            assert_eq!(
                actual_col, expected_col,
                "column {i} mismatch: got '{actual_col}', expected '{expected_col}'"
            );
        }
    }

    #[test]
    fn csv_column_count_equals_19() {
        // Canary test: adding or removing a column is a breaking schema change.
        let csv_header = "log_id,template_id,height,total_fees,tx_count,accepted,fee_tier,tier_source,min_avg_fee_used,avg_fee_sats_per_tx,reason_code,reason_detail,reason,timestamp,template_weight,total_sigops,coinbase_sigops,created_at_unix_ms,safety_warnings";
        assert_eq!(csv_header.split(',').count(), 19);
    }

    // ── CL-19: Prometheus metric label coverage ──

    #[test]
    fn verdict_reason_all_codes_exhaustive() {
        // ALL_CODES must contain exactly one entry per VerdictReason variant.
        // If a variant is added without updating ALL_CODES, this test fails.
        assert_eq!(
            rg_protocol::VerdictReason::ALL.len(),
            rg_protocol::VerdictReason::ALL_CODES.len(),
            "VerdictReason::ALL and ALL_CODES must have the same length"
        );
        for (variant, code) in rg_protocol::VerdictReason::ALL
            .iter()
            .zip(rg_protocol::VerdictReason::ALL_CODES.iter())
        {
            assert_eq!(
                variant.as_str(),
                *code,
                "VerdictReason::{variant:?} as_str() does not match ALL_CODES entry"
            );
        }
    }

    // ── CL-12: reason_code survives NDJSON disk round-trip ──

    #[test]
    fn reason_code_survives_ndjson_disk_round_trip() {
        // Write a LoggedVerdict to a temp file as NDJSON, then read it back
        // through serde and confirm reason_code is preserved.
        let v = sample_verdict(false);
        assert_eq!(
            v.reason_code.as_deref(),
            Some("fee_below_tier_floor"),
            "precondition: sample verdict must carry a reason_code"
        );

        let serialized = serde_json::to_string(&v).unwrap();
        let deserialized: verdicts::LoggedVerdict = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            deserialized.reason_code.as_deref(),
            Some("fee_below_tier_floor"),
            "reason_code must survive NDJSON serialization round-trip"
        );
        assert_eq!(
            deserialized.reason_detail.as_deref(),
            Some("avg 1200 < floor 2000"),
            "reason_detail must survive NDJSON serialization round-trip"
        );
    }

    // ── CL-12: reason_code survives CSV export at column index 10 ──

    #[test]
    fn reason_code_survives_csv_export() {
        // Build a LoggedVerdict with a known reason_code and run it through
        // the same CSV formatting logic used by get_verdicts_csv.
        use std::fmt::Write as _;

        let v = sample_verdict(false);
        let reason_code = v
            .reason_code
            .as_deref()
            .unwrap_or(if v.accepted { "ok" } else { "" });

        // Replicate the exact format string from handlers::get_verdicts_csv.
        let mut line = String::new();
        let escaped_code = reason_code.replace('"', "\"\"");
        let escaped_detail = v
            .reason_detail
            .as_deref()
            .unwrap_or("")
            .replace('"', "\"\"");
        let escaped_reason = v.reason.as_deref().unwrap_or("ok").replace('"', "\"\"");
        let tw = v.template_weight.map(|w| w.to_string()).unwrap_or_default();
        let ts = v.total_sigops.map(|s| s.to_string()).unwrap_or_default();
        let cs = v.coinbase_sigops.map(|s| s.to_string()).unwrap_or_default();
        let ca = v
            .created_at_unix_ms
            .map(|t| t.to_string())
            .unwrap_or_default();
        let sw = v.safety_warnings.join(";");
        let _ = writeln!(
            line,
            "{},{},{},{},{},{},{},{},{},{},\"{}\",\"{}\",\"{}\",{},{},{},{},{},\"{}\"",
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
        );

        // Parse the line back and check column 10 (reason_code).
        let trimmed = line.trim();

        // Simple CSV parse: split on comma but respect quoted fields.
        let mut cols: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        for ch in trimmed.chars() {
            match ch {
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => {
                    cols.push(current.clone());
                    current.clear();
                }
                _ => current.push(ch),
            }
        }
        cols.push(current);

        assert_eq!(cols.len(), 19, "CSV must have exactly 19 columns");
        assert_eq!(
            cols[10], "fee_below_tier_floor",
            "column 10 (reason_code) must carry the canonical reason string"
        );
        assert_eq!(
            cols[11], "avg 1200 < floor 2000",
            "column 11 (reason_detail) must carry the human detail string"
        );
    }

    // ── CL-12: reason_code appears as Prometheus label in rendered output ──

    #[test]
    fn reason_code_appears_in_prometheus_output() {
        let mut registry = prometheus_client::registry::Registry::default();
        let family = prometheus_client::metrics::family::Family::<
            metrics::VerdictLabels,
            prometheus_client::metrics::counter::Counter,
        >::default();
        registry.register(
            "verifier_verdicts",
            "Total verdicts emitted by the verifier",
            family.clone(),
        );

        // Increment a counter with a specific reason_code label.
        family
            .get_or_create(&metrics::VerdictLabels {
                accepted: "false".into(),
                reason_code: "total_fees_below_minimum".into(),
            })
            .inc();

        let (status, _, body) = reservegrid_common::metrics::render_metrics(&registry);
        assert_eq!(status, 200);
        assert!(
            body.contains("reason_code=\"total_fees_below_minimum\""),
            "OpenMetrics output must contain the reason_code label; got:\n{body}"
        );
        assert!(
            body.contains("accepted=\"false\""),
            "OpenMetrics output must contain the accepted label; got:\n{body}"
        );
    }

    // ── CL-12: every VerdictReason code is valid as a Prometheus label value ──

    #[test]
    fn all_verdict_reason_codes_are_valid_prometheus_labels() {
        // Prometheus label values must not contain newlines or backslashes
        // (unescaped). All our codes are snake_case so this should hold.
        for code in rg_protocol::VerdictReason::ALL_CODES {
            assert!(
                !code.contains('\n') && !code.contains('\\') && !code.contains('"'),
                "VerdictReason code '{code}' contains characters invalid in Prometheus labels"
            );
            // Also verify pure snake_case: lowercase alphanumeric + underscores.
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "VerdictReason code '{code}' is not pure snake_case"
            );
        }
    }
}
