//! Gateway configuration loading and validation.
//!
//! Config is loaded from TOML with environment variable overlay.
//! All keys use the `VELDRA_` prefix per repo conventions.

use rg_protocol::gateway::GatewayMode;
use serde::Deserialize;

/// Top-level gateway configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Operating mode: inline, observe, or shadow.
    pub mode: GatewayMode,

    /// Gateway section for SV2 transport and operational parameters.
    pub gateway: GatewaySection,

    /// Verifier connection section.
    pub verifier: VerifierSection,

    /// Upstream share relay section.
    #[serde(default)]
    pub share_upstream: Option<ShareUpstreamSection>,
}

/// SV2 gateway operational parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct GatewaySection {
    /// SV2 listener bind address (e.g., "0.0.0.0:3333").
    pub listen_addr: String,

    /// HTTP health/metrics bind address (e.g., "0.0.0.0:8080").
    #[serde(default = "default_health_addr")]
    pub health_addr: String,

    /// Path to the Noise NX static keypair file (DER or PEM).
    pub noise_keypair_path: String,

    /// Path to a static `SIGNATURE_NOISE_MESSAGE` file (74 bytes).
    /// Reserved for forward compatibility. The current implementation generates
    /// per-connection certificates from the authority keypair at runtime, so this
    /// field is not read. Certificate rotation is achieved by reloading the
    /// authority keypair via SIGHUP or file polling (see
    /// `noise_keypair_reload_sighup` and `noise_keypair_poll_interval_secs`).
    #[serde(default)]
    pub noise_cert_path: String,

    /// Authority x-only secp256k1 public key (64 hex chars).
    pub authority_pubkey: String,

    /// Maximum concurrent SV2 connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Maximum concurrent connections from a single IP address. Default 16.
    /// When nonzero, connections beyond this threshold from the same source
    /// IP are rejected before the Noise handshake. Set to 0 to disable
    /// (not recommended for production).
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,

    /// Maximum standard mining channels per connection.
    #[serde(default = "default_max_channels_per_conn")]
    pub max_channels_per_conn: u32,

    /// Timeout for the initial channel open after `SetupConnection` (ms).
    /// Miners that do not open a channel within this period are disconnected.
    /// Default 30000 (30 seconds).
    #[serde(default = "default_channel_open_timeout_ms")]
    pub channel_open_timeout_ms: u64,

    /// Maximum worker identity length in bytes.
    #[serde(default = "default_max_worker_id_bytes")]
    pub max_worker_id_bytes: usize,

    /// Noise certificate validity period in seconds. Each incoming connection
    /// receives a fresh certificate signed by the authority keypair. Defaults to
    /// 3600 (one hour).
    #[serde(default = "default_noise_cert_validity_secs")]
    pub noise_cert_validity_secs: u32,

    /// Noise handshake timeout in milliseconds.
    #[serde(default = "default_noise_handshake_timeout_ms")]
    pub noise_handshake_timeout_ms: u64,

    /// Template polling interval in milliseconds.
    #[serde(default = "default_template_poll_interval_ms")]
    pub template_poll_interval_ms: u64,

    /// Maximum template age before discarding (milliseconds).
    #[serde(default = "default_max_template_age_ms")]
    pub max_template_age_ms: u64,

    /// Prevhash verdict timeout in milliseconds (inline mode only).
    #[serde(default = "default_prevhash_verdict_timeout_ms")]
    pub prevhash_verdict_timeout_ms: u64,

    /// How long to hold miners on stale job after prevhash timeout (ms).
    #[serde(default = "default_prevhash_stale_hold_ms")]
    pub prevhash_stale_hold_ms: u64,

    /// Maximum time upstream template source can be silent (ms).
    #[serde(default = "default_upstream_stale_max_ms")]
    pub upstream_stale_max_ms: u64,

    /// Behavior when upstream goes stale beyond `upstream_stale_max_ms`.
    #[serde(default = "default_upstream_failure_policy")]
    pub upstream_failure_policy: UpstreamFailurePolicy,

    /// Share deduplication window size (inline mode).
    #[serde(default = "default_share_dedup_window_size")]
    pub share_dedup_window_size: usize,

    /// Ntime elapsed slack in seconds (absorbs network latency).
    #[serde(default = "default_ntime_elapsed_slack_seconds")]
    pub ntime_elapsed_slack_seconds: u32,

    /// Max future block time override (default 7200, do not change for mainnet).
    #[serde(default = "default_max_future_block_time_seconds")]
    pub max_future_block_time_seconds: u32,

    /// Miner authorization mode.
    #[serde(default)]
    pub miner_auth: MinerAuthMode,

    /// Job retention after `source_instance_id` change (ms).
    #[serde(default = "default_job_retention_ms")]
    pub job_retention_ms: u64,

    /// Optional channel share target as 64-char hex (32 bytes LE).
    /// Overrides the default DIFF1 target. Use all-FF for regtest
    /// where miners submit random nonces.
    #[serde(default)]
    pub channel_target_hex: Option<String>,

    /// Maximum share submissions per second per channel. 0 means unlimited.
    /// Excess shares are rejected with `share_rate_limited` `reason_code`.
    #[serde(default)]
    pub max_shares_per_second_per_channel: u32,

    /// Extranonce prefix length in bytes for standard channels. Default 4.
    /// Extended channels use the same prefix length but add a miner-controlled
    /// suffix. Valid range: 2..=8.
    #[serde(default = "default_extranonce_prefix_len")]
    pub extranonce_prefix_len: usize,

    /// Whether to accept extended mining channel requests (SV2 0x13).
    /// When false, extended channel opens are rejected with `CloseChannel`.
    /// Default true (most production ASIC firmware requires extended channels).
    #[serde(default = "default_extended_channels_enabled")]
    pub extended_channels_enabled: bool,

    /// Enable variable difficulty adjustment per channel. When enabled, the
    /// gateway adjusts each channel's target to maintain the configured
    /// shares-per-minute rate. Default false (static difficulty).
    #[serde(default)]
    pub vardiff_enabled: bool,

    /// Target share submission rate in shares per minute per channel.
    /// The vardiff algorithm adjusts difficulty to converge on this rate.
    /// Default 20.0.
    #[serde(default = "default_vardiff_target_shares_per_min")]
    pub vardiff_target_shares_per_min: f64,

    /// Retarget evaluation interval in seconds. The gateway evaluates
    /// whether to adjust difficulty after this many seconds of observation.
    /// Default 90.
    #[serde(default = "default_vardiff_retarget_interval_secs")]
    pub vardiff_retarget_interval_secs: u64,

    /// Minimum difficulty floor for vardiff. Prevents the target from
    /// becoming trivially easy. Default 1.
    #[serde(default = "default_vardiff_min_difficulty")]
    pub vardiff_min_difficulty: u64,

    /// Maximum difficulty ceiling for vardiff. Default `u64::MAX` (no cap).
    #[serde(default = "default_vardiff_max_difficulty")]
    pub vardiff_max_difficulty: u64,

    /// Maximum multiplicative adjustment factor per retarget. Limits how
    /// aggressively difficulty can change in a single step. For example,
    /// 4.0 means difficulty can at most quadruple or quarter per retarget.
    /// Default 4.0.
    #[serde(default = "default_vardiff_max_adjustment_factor")]
    pub vardiff_max_adjustment_factor: f64,

    /// Enable SIGHUP triggered reload of the Noise authority keypair.
    /// When `true` (the default), sending SIGHUP to the gateway process causes
    /// it to re-read `noise_keypair_path`, validate against `authority_pubkey`,
    /// and swap the credentials atomically. Existing connections are unaffected;
    /// only new handshakes use the refreshed keypair.
    #[serde(default = "default_noise_keypair_reload_sighup")]
    pub noise_keypair_reload_sighup: bool,

    /// Periodic file poll interval (seconds) for keypair rotation. When nonzero
    /// the gateway checks `noise_keypair_path` mtime on this cadence and reloads
    /// if the file changed since the last successful load. Use this in container
    /// environments where SIGHUP delivery is inconvenient. Default 0 (disabled).
    #[serde(default)]
    pub noise_keypair_poll_interval_secs: u64,

    /// Path to the share forward WAL (write-ahead log) for crash-durable event
    /// delivery. When set, the gateway persists pending forward state so that a
    /// crash between share acceptance (Event 1) and forward completion (Event 2)
    /// is recoverable on restart with a synthetic `process_crash_recovery` event.
    /// Empty string disables the WAL (suitable for regtest and development).
    #[serde(default)]
    pub wal_path: String,

    /// WAL compaction threshold. After this many completed records are appended,
    /// the WAL is rewritten with only the pending entries. Default 1000. Set 0
    /// to disable auto-compaction.
    #[serde(default = "default_wal_compaction_threshold")]
    pub wal_compaction_threshold: usize,

    /// Unique identifier for this gateway instance. Embedded in every
    /// `ShareSubmission` so downstream systems can trace shares back to the
    /// originating process. Defaults to hostname if not set.
    #[serde(default = "default_gateway_instance_id")]
    pub gateway_instance_id: String,

    /// HTTP base URL of the template manager (e.g., `"http://template-manager:8082"`).
    /// When empty, falls back to the `VELDRA_TEMPLATE_URL` environment variable.
    #[serde(default)]
    pub template_url: String,

    /// Enable automatic inline-to-observe degradation when the verifier
    /// stops serving verdicts. Two triggers (PB-15 D2, PB-17): heartbeat
    /// loss beyond `auto_degrade_after_ms` (dead link), or verdict
    /// starvation beyond the same threshold while proposals are
    /// outstanding (live link, mute verdict service; detected via the
    /// oldest pending template's age plus an eviction-proof starvation
    /// clock). While degraded the gateway suspends verdict enforcement
    /// and broadcasts templates immediately (observe equivalent).
    /// Recovery depends on the trigger: heartbeat-loss degrades recover
    /// on the next heartbeat ack; starvation degrades recover only when
    /// a verdict actually arrives. Default true.
    #[serde(default = "default_auto_degrade")]
    pub auto_degrade: bool,

    /// Milliseconds before the gateway transitions to degraded mode,
    /// applied to both degrade signals: time without a verifier
    /// heartbeat ack, and time without a verdict while proposals are
    /// outstanding. Only effective when `auto_degrade` is true and the
    /// configured mode is inline. Default 10000.
    #[serde(default = "default_auto_degrade_after_ms")]
    pub auto_degrade_after_ms: u64,
}

/// Verifier connection parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierSection {
    /// TCP address of the verifier NDJSON endpoint.
    pub addr: String,

    /// Health probe staleness threshold (ms).
    #[serde(default = "default_health_probe_staleness_ms")]
    pub health_probe_staleness_ms: u64,

    /// Delay between reconnect attempts to the verifier (ms). Default 2000.
    #[serde(default = "default_verifier_reconnect_delay_ms")]
    pub reconnect_delay_ms: u64,

    /// Heartbeat send interval on the verifier stream (ms). Default 5000.
    #[serde(default = "default_verifier_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u64,

    /// Path to the CA certificate PEM file for verifying the verifier's server
    /// certificate. When set, TLS is enabled on the verifier channel.
    #[serde(default)]
    pub tls_ca_cert: Option<String>,

    /// Path to the client certificate PEM file (mTLS client identity).
    /// Required when `tls_ca_cert` is set.
    #[serde(default)]
    pub tls_client_cert: Option<String>,

    /// Path to the client private key PEM file (mTLS client identity).
    /// Required when `tls_ca_cert` is set.
    #[serde(default)]
    pub tls_client_key: Option<String>,

    /// DNS name (SNI) used for TLS server certificate verification.
    /// Defaults to `"localhost"` if not specified.
    #[serde(default = "default_tls_server_name")]
    pub tls_server_name: String,
}

/// Returns `true` when the verifier section has TLS enabled.
impl VerifierSection {
    pub fn tls_enabled(&self) -> bool {
        self.tls_ca_cert.is_some()
    }
}

fn default_tls_server_name() -> String {
    "localhost".to_string()
}

/// Upstream share relay parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareUpstreamSection {
    /// HTTP endpoint for share submission.
    pub url: String,

    /// HMAC shared secret (hex encoded, loaded from env at runtime).
    /// This field is intentionally not in the TOML file.
    #[serde(skip)]
    pub secret: Option<String>,

    /// Maximum retries on forward failure.
    #[serde(default = "default_share_upstream_retries")]
    pub retries: u32,

    /// Forward queue size.
    #[serde(default = "default_share_forward_queue_size")]
    pub forward_queue_size: usize,

    /// Maximum concurrent HTTP requests to share upstream.
    #[serde(default = "default_share_forward_max_in_flight")]
    pub forward_max_in_flight: usize,

    /// Queue drop policy when full.
    #[serde(default)]
    pub forward_queue_drop_policy: QueueDropPolicy,

    /// Per-connection share rate limit (shares/sec). None means unlimited.
    #[serde(default)]
    pub rate_limit_per_conn_per_sec: Option<u32>,
}

/// Upstream failure policy when template source goes silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamFailurePolicy {
    /// Stop distributing jobs, disconnect miners.
    FailClosed,
    /// Continue with last known template, emit warnings.
    FailOpen,
}

/// Queue drop policy for share forwarding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueDropPolicy {
    /// Reject incoming shares at the boundary.
    #[default]
    DropNew,
    /// Evict oldest queued share to make room.
    DropOld,
}

/// Miner authorization mode.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum MinerAuthMode {
    /// No identity enforcement.
    #[default]
    Open,
    /// Static allowlist of worker identities.
    Allowlist { identities: Vec<String> },
    /// Identity prefix to account mapping.
    PrefixMap { mappings: Vec<PrefixMapping> },
}

/// A single prefix-to-account mapping entry.
#[derive(Debug, Clone, Deserialize)]
pub struct PrefixMapping {
    pub prefix: String,
    pub account: String,
}

// ── Default value functions ──

fn default_health_addr() -> String {
    "127.0.0.1:8080".to_string()
}
fn default_max_connections() -> u32 {
    1024
}
fn default_max_connections_per_ip() -> u32 {
    16
}
fn default_max_channels_per_conn() -> u32 {
    256
}
fn default_max_worker_id_bytes() -> usize {
    128
}
fn default_noise_cert_validity_secs() -> u32 {
    3600
}
fn default_noise_handshake_timeout_ms() -> u64 {
    5000
}
fn default_template_poll_interval_ms() -> u64 {
    3000
}
fn default_max_template_age_ms() -> u64 {
    30_000
}
fn default_prevhash_verdict_timeout_ms() -> u64 {
    // Mainnet-safe default. 50ms was regtest-only and would cause mass
    // miner disconnection under real network latency. Regtest/dev configs
    // explicitly override this to 50ms in dev/gateway.toml. The
    // sub-1000ms regtest warning in validate_timing_chain still fires
    // for any override below 1s. See lessons.md R-107.
    2000
}
fn default_prevhash_stale_hold_ms() -> u64 {
    5000
}
fn default_upstream_stale_max_ms() -> u64 {
    30_000
}
fn default_upstream_failure_policy() -> UpstreamFailurePolicy {
    UpstreamFailurePolicy::FailClosed
}
fn default_share_dedup_window_size() -> usize {
    10_000
}
fn default_ntime_elapsed_slack_seconds() -> u32 {
    2
}
fn default_max_future_block_time_seconds() -> u32 {
    rg_protocol::gateway::MAX_FUTURE_BLOCK_TIME_SECONDS
}
fn default_health_probe_staleness_ms() -> u64 {
    10_000
}
fn default_verifier_reconnect_delay_ms() -> u64 {
    2_000
}
fn default_verifier_heartbeat_interval_ms() -> u64 {
    5_000
}
fn default_channel_open_timeout_ms() -> u64 {
    30_000
}
fn default_share_upstream_retries() -> u32 {
    2
}
fn default_share_forward_queue_size() -> usize {
    50_000
}
fn default_share_forward_max_in_flight() -> usize {
    256
}
fn default_job_retention_ms() -> u64 {
    300_000
}
fn default_noise_keypair_reload_sighup() -> bool {
    true
}
fn default_wal_compaction_threshold() -> usize {
    1000
}

fn default_extranonce_prefix_len() -> usize {
    4
}
fn default_extended_channels_enabled() -> bool {
    true
}

fn default_vardiff_target_shares_per_min() -> f64 {
    20.0
}
fn default_vardiff_retarget_interval_secs() -> u64 {
    90
}
fn default_vardiff_min_difficulty() -> u64 {
    1
}
fn default_vardiff_max_difficulty() -> u64 {
    u64::MAX
}
fn default_vardiff_max_adjustment_factor() -> f64 {
    4.0
}

fn default_auto_degrade() -> bool {
    true
}
fn default_auto_degrade_after_ms() -> u64 {
    10_000
}

fn default_gateway_instance_id() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("VELDRA_GATEWAY_INSTANCE_ID"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Check whether an address string (host:port or host) resolves to a loopback
/// interface. Accepts `127.x.x.x`, `::1`, `[::1]:port`, and `localhost` variants.
///
/// Public alias used by the binary for startup warnings.
pub fn is_loopback_addr_public(addr: &str) -> bool {
    is_loopback_addr(addr)
}

fn is_loopback_addr(addr: &str) -> bool {
    // Try parsing as SocketAddr first (covers "127.0.0.1:9100" and "[::1]:9100").
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return sa.ip().is_loopback();
    }
    // Try parsing as bare IpAddr (covers "127.0.0.1" and "::1").
    if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    // Strip port suffix for IPv4/hostname:port forms only (no colons in host).
    // IPv6 with port uses bracket notation handled by SocketAddr above.
    let host = if addr.starts_with('[') {
        addr
    } else {
        addr.rsplit_once(':').map_or(addr, |(h, _)| h)
    };
    host == "localhost"
}

/// Timing invariant chain:
/// `verdict_timeout < stale_hold < upstream_stale_max <= job_retention`
fn validate_timing_chain(config: &GatewayConfig, warnings: &mut Vec<String>) -> Result<(), String> {
    if config.gateway.prevhash_verdict_timeout_ms == 0 {
        return Err("prevhash_verdict_timeout_ms must be > 0".to_string());
    }
    if config.gateway.prevhash_verdict_timeout_ms >= config.gateway.prevhash_stale_hold_ms {
        return Err(format!(
            "prevhash_verdict_timeout_ms ({}) must be < prevhash_stale_hold_ms ({}); \
             the verdict must arrive before the stale hold expires",
            config.gateway.prevhash_verdict_timeout_ms, config.gateway.prevhash_stale_hold_ms,
        ));
    }
    if config.gateway.prevhash_stale_hold_ms >= config.gateway.upstream_stale_max_ms {
        return Err(format!(
            "prevhash_stale_hold_ms ({}) must be < upstream_stale_max_ms ({}); \
             the stale hold must finish before the upstream is declared dead",
            config.gateway.prevhash_stale_hold_ms, config.gateway.upstream_stale_max_ms,
        ));
    }
    if config.gateway.job_retention_ms < config.gateway.upstream_stale_max_ms {
        return Err(format!(
            "job_retention_ms ({}) must be >= upstream_stale_max_ms ({}); \
             jobs must outlive upstream staleness detection",
            config.gateway.job_retention_ms, config.gateway.upstream_stale_max_ms,
        ));
    }
    if config.verifier.health_probe_staleness_ms == 0 {
        return Err("health_probe_staleness_ms must be > 0".to_string());
    }
    if config.gateway.prevhash_verdict_timeout_ms < 1000 {
        warnings.push(format!(
            "prevhash_verdict_timeout_ms={} is below 1000ms; \
             this is regtest-appropriate but will cause mass disconnections on mainnet",
            config.gateway.prevhash_verdict_timeout_ms,
        ));
    }
    Ok(())
}

/// Verifier TLS field consistency and remote security enforcement.
fn validate_verifier_security(
    config: &GatewayConfig,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    if config.verifier.tls_ca_cert.is_some()
        && (config.verifier.tls_client_cert.is_none() || config.verifier.tls_client_key.is_none())
    {
        return Err(
            "verifier.tls_ca_cert is set but tls_client_cert and tls_client_key are \
             both required for mTLS"
                .to_string(),
        );
    }

    if !is_loopback_addr(&config.verifier.addr) {
        if config.verifier.tls_enabled() {
            // TLS configured for remote verifier. Expected production path.
        } else {
            let allow_insecure = std::env::var("VELDRA_ALLOW_INSECURE_VERIFIER")
                .map(|v| v == "1")
                .unwrap_or(false);
            let allow_legacy = std::env::var("VELDRA_ALLOW_REMOTE_VERIFIER")
                .map(|v| v == "1")
                .unwrap_or(false);

            if !allow_insecure && !allow_legacy {
                return Err(format!(
                    "verifier.addr={} is not loopback and TLS is not configured. \
                     Configure verifier TLS (tls_ca_cert, tls_client_cert, tls_client_key) \
                     or set VELDRA_ALLOW_INSECURE_VERIFIER=1 to override",
                    config.verifier.addr,
                ));
            }
            warnings.push(format!(
                "insecure verifier override active; verifier at {} uses plaintext TCP. \
                 This is not safe for untrusted networks",
                config.verifier.addr,
            ));
        }
    }

    Ok(())
}

/// Validate configuration at startup. Returns a list of warnings
/// (non-fatal) and an error if anything is invalid.
pub fn validate(config: &GatewayConfig) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();

    // Shadow mode must not have a listen_addr expectation for miners
    if config.mode == GatewayMode::Shadow && config.share_upstream.is_some() {
        warnings.push(
            "shadow mode has share_upstream configured; shares will not be generated".to_string(),
        );
    }

    // Non-standard max_future_block_time_seconds
    if config.gateway.max_future_block_time_seconds
        != rg_protocol::gateway::MAX_FUTURE_BLOCK_TIME_SECONDS
    {
        warnings.push(format!(
            "max_future_block_time_seconds={} differs from Bitcoin consensus default 7200; \
             only use for development or non-Bitcoin test environments",
            config.gateway.max_future_block_time_seconds,
        ));
    }

    // drop_old is rejected in inline mode (without escape hatch)
    if config.mode == GatewayMode::Inline
        && let Some(ref upstream) = config.share_upstream
        && upstream.forward_queue_drop_policy == QueueDropPolicy::DropOld
    {
        let allow = std::env::var("VELDRA_ALLOW_DROP_OLD_INLINE")
            .map(|v| v == "1")
            .unwrap_or(false);
        if !allow {
            return Err(
                "drop_old is not permitted in inline mode (violates ACK integrity); \
                 set VELDRA_ALLOW_DROP_OLD_INLINE=1 to override for development"
                    .to_string(),
            );
        }
        warnings.push(
            "VELDRA_ALLOW_DROP_OLD_INLINE=1 active; drop_old enabled in inline mode".to_string(),
        );
    }

    // drop_old in observe mode gets a warning
    if config.mode == GatewayMode::Observe
        && let Some(ref upstream) = config.share_upstream
        && upstream.forward_queue_drop_policy == QueueDropPolicy::DropOld
    {
        warnings.push(
            "drop_old enabled in observe mode; evicted shares lose telemetry value".to_string(),
        );
    }

    // Inline mode requires share_upstream
    if config.mode == GatewayMode::Inline && config.share_upstream.is_none() {
        return Err("inline mode requires [share_upstream] configuration".to_string());
    }

    // M-7: Bounds validation on timing-critical fields.
    if config.gateway.noise_handshake_timeout_ms == 0 {
        return Err("noise_handshake_timeout_ms must be > 0".to_string());
    }
    if config.gateway.template_poll_interval_ms == 0 {
        return Err("template_poll_interval_ms must be > 0".to_string());
    }
    if config.gateway.prevhash_stale_hold_ms == 0 {
        return Err("prevhash_stale_hold_ms must be > 0".to_string());
    }
    if config.gateway.upstream_stale_max_ms < 1000 {
        return Err("upstream_stale_max_ms must be >= 1000".to_string());
    }
    if config.gateway.noise_handshake_timeout_ms > 120_000 {
        warnings.push("noise_handshake_timeout_ms > 120s is unusually high".to_string());
    }

    validate_timing_chain(config, &mut warnings)?;
    validate_verifier_security(config, &mut warnings)?;

    // Degradation threshold must exceed heartbeat interval, otherwise
    // the gateway will enter degraded mode between heartbeats and never
    // recover because no ack can arrive in time.
    if config.gateway.auto_degrade
        && config.mode.enforces_verdicts()
        && config.gateway.auto_degrade_after_ms < config.verifier.heartbeat_interval_ms
    {
        warnings.push(format!(
            "auto_degrade_after_ms ({}) is below \
             heartbeat_interval_ms ({}); the gateway will enter \
             permanent degradation because no heartbeat ack can \
             arrive within the threshold",
            config.gateway.auto_degrade_after_ms, config.verifier.heartbeat_interval_ms,
        ));
    }

    // PB-15: the verdict-starvation degrade trigger only fires if a pending
    // template can outlive auto_degrade_after_ms before the SEC-004 sweep
    // evicts it at max_template_age_ms and releases its dedup entry, which
    // resets the age clock on re-propose (R-107 ordering dependency).
    // PB-17: still accurate with the starvation clock, which re-anchors on
    // the empty-to-non-empty pending transition the sweep's evict/re-propose
    // cycle produces, so neither signal outlives the sweep in this config.
    if config.gateway.auto_degrade
        && config.mode.enforces_verdicts()
        && config.gateway.auto_degrade_after_ms >= config.gateway.max_template_age_ms
    {
        warnings.push(format!(
            "auto_degrade_after_ms ({}) is not below \
             max_template_age_ms ({}); the stale-pending sweep will \
             evict and re-propose a starved template before the \
             verdict-starvation degrade can fire",
            config.gateway.auto_degrade_after_ms, config.gateway.max_template_age_ms,
        ));
    }

    Ok(warnings)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn minimal_config(mode: GatewayMode) -> GatewayConfig {
        GatewayConfig {
            mode,
            gateway: GatewaySection {
                listen_addr: "0.0.0.0:3333".to_string(),
                health_addr: default_health_addr(),
                noise_keypair_path: "/etc/sv2/keypair.der".to_string(),
                noise_cert_path: "/etc/sv2/cert.bin".to_string(),
                authority_pubkey: "a".repeat(64),
                max_connections: default_max_connections(),
                max_connections_per_ip: default_max_connections_per_ip(),
                max_channels_per_conn: default_max_channels_per_conn(),
                channel_open_timeout_ms: default_channel_open_timeout_ms(),
                max_worker_id_bytes: default_max_worker_id_bytes(),
                noise_cert_validity_secs: default_noise_cert_validity_secs(),
                noise_handshake_timeout_ms: default_noise_handshake_timeout_ms(),
                template_poll_interval_ms: default_template_poll_interval_ms(),
                max_template_age_ms: default_max_template_age_ms(),
                prevhash_verdict_timeout_ms: default_prevhash_verdict_timeout_ms(),
                prevhash_stale_hold_ms: default_prevhash_stale_hold_ms(),
                upstream_stale_max_ms: default_upstream_stale_max_ms(),
                upstream_failure_policy: default_upstream_failure_policy(),
                share_dedup_window_size: default_share_dedup_window_size(),
                ntime_elapsed_slack_seconds: default_ntime_elapsed_slack_seconds(),
                max_future_block_time_seconds: default_max_future_block_time_seconds(),
                miner_auth: MinerAuthMode::Open,
                job_retention_ms: default_job_retention_ms(),
                channel_target_hex: None,
                max_shares_per_second_per_channel: 0,
                extranonce_prefix_len: default_extranonce_prefix_len(),
                extended_channels_enabled: default_extended_channels_enabled(),
                vardiff_enabled: false,
                vardiff_target_shares_per_min: default_vardiff_target_shares_per_min(),
                vardiff_retarget_interval_secs: default_vardiff_retarget_interval_secs(),
                vardiff_min_difficulty: default_vardiff_min_difficulty(),
                vardiff_max_difficulty: default_vardiff_max_difficulty(),
                vardiff_max_adjustment_factor: default_vardiff_max_adjustment_factor(),
                noise_keypair_reload_sighup: default_noise_keypair_reload_sighup(),
                noise_keypair_poll_interval_secs: 0,
                wal_path: String::new(),
                wal_compaction_threshold: default_wal_compaction_threshold(),
                gateway_instance_id: "test-gateway".to_string(),
                template_url: String::new(),
                auto_degrade: default_auto_degrade(),
                auto_degrade_after_ms: default_auto_degrade_after_ms(),
            },
            verifier: VerifierSection {
                addr: "127.0.0.1:9100".to_string(),
                health_probe_staleness_ms: default_health_probe_staleness_ms(),
                reconnect_delay_ms: default_verifier_reconnect_delay_ms(),
                heartbeat_interval_ms: default_verifier_heartbeat_interval_ms(),
                tls_ca_cert: None,
                tls_client_cert: None,
                tls_client_key: None,
                tls_server_name: default_tls_server_name(),
            },
            share_upstream: Some(ShareUpstreamSection {
                url: "http://localhost:8081/shares".to_string(),
                secret: None,
                retries: default_share_upstream_retries(),
                forward_queue_size: default_share_forward_queue_size(),
                forward_max_in_flight: default_share_forward_max_in_flight(),
                forward_queue_drop_policy: QueueDropPolicy::DropNew,
                rate_limit_per_conn_per_sec: None,
            }),
        }
    }

    #[test]
    fn validate_inline_with_upstream_succeeds() {
        let mut config = minimal_config(GatewayMode::Inline);
        // Use a production-appropriate verdict timeout to avoid the regtest warning.
        config.gateway.prevhash_verdict_timeout_ms = 2000;
        let result = validate(&config);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn validate_inline_without_upstream_fails() {
        let mut config = minimal_config(GatewayMode::Inline);
        config.share_upstream = None;
        let result = validate(&config);
        assert!(result.is_err());
    }

    #[test]
    fn validate_shadow_with_upstream_warns() {
        let config = minimal_config(GatewayMode::Shadow);
        let result = validate(&config);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("shadow mode")),
            "expected shadow mode warning, got: {warnings:?}",
        );
    }

    #[test]
    fn validate_non_standard_future_block_time_warns() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.gateway.max_future_block_time_seconds = 3600;
        let result = validate(&config);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("max_future_block_time_seconds")),
            "expected future block time warning, got: {warnings:?}",
        );
    }

    #[test]
    fn validate_drop_old_inline_rejected_without_escape() {
        let mut config = minimal_config(GatewayMode::Inline);
        if let Some(ref mut upstream) = config.share_upstream {
            upstream.forward_queue_drop_policy = QueueDropPolicy::DropOld;
        }
        let result = validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("drop_old"));
    }

    #[test]
    fn validate_drop_old_observe_warns() {
        let mut config = minimal_config(GatewayMode::Observe);
        if let Some(ref mut upstream) = config.share_upstream {
            upstream.forward_queue_drop_policy = QueueDropPolicy::DropOld;
        }
        let result = validate(&config);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("drop_old")),
            "expected drop_old warning, got: {warnings:?}",
        );
    }

    #[test]
    fn default_queue_drop_policy_is_drop_new() {
        assert_eq!(QueueDropPolicy::default(), QueueDropPolicy::DropNew);
    }

    #[test]
    fn default_miner_auth_is_open() {
        assert!(matches!(MinerAuthMode::default(), MinerAuthMode::Open));
    }

    #[test]
    fn is_loopback_accepts_127_0_0_1() {
        assert!(is_loopback_addr("127.0.0.1:9100"));
        assert!(is_loopback_addr("127.0.0.1"));
    }

    #[test]
    fn is_loopback_accepts_ipv6_loopback() {
        assert!(is_loopback_addr("[::1]:9100"));
        assert!(is_loopback_addr("::1"));
    }

    #[test]
    fn is_loopback_accepts_localhost() {
        assert!(is_loopback_addr("localhost:9100"));
        assert!(is_loopback_addr("localhost"));
    }

    #[test]
    fn is_loopback_rejects_non_loopback() {
        assert!(!is_loopback_addr("10.0.0.5:9100"));
        assert!(!is_loopback_addr("192.168.1.1:9100"));
        assert!(!is_loopback_addr("verifier.example.com:9100"));
    }

    #[test]
    fn validate_rejects_non_loopback_verifier_without_tls() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.verifier.addr = "10.0.0.5:9100".to_string();
        let result = validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not loopback"));
    }

    #[test]
    fn validate_accepts_non_loopback_verifier_with_tls() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.verifier.addr = "10.0.0.5:9100".to_string();
        config.verifier.tls_ca_cert = Some("/etc/ssl/ca.pem".to_string());
        config.verifier.tls_client_cert = Some("/etc/ssl/client.pem".to_string());
        config.verifier.tls_client_key = Some("/etc/ssl/client-key.pem".to_string());
        let result = validate(&config);
        assert!(result.is_ok(), "expected ok, got: {result:?}");
        // No warnings expected for TLS-secured remote verifier.
        let warnings = result.unwrap();
        assert!(
            !warnings.iter().any(|w| w.contains("insecure")),
            "unexpected insecure warning: {warnings:?}",
        );
    }

    #[test]
    fn validate_rejects_partial_tls_config() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.verifier.tls_ca_cert = Some("/etc/ssl/ca.pem".to_string());
        // Missing client cert and key.
        let result = validate(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tls_client_cert"));
    }

    #[test]
    fn verifier_tls_enabled_reflects_ca_cert_presence() {
        let mut section = VerifierSection {
            addr: "127.0.0.1:9100".to_string(),
            health_probe_staleness_ms: 10_000,
            reconnect_delay_ms: default_verifier_reconnect_delay_ms(),
            heartbeat_interval_ms: default_verifier_heartbeat_interval_ms(),
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
            tls_server_name: default_tls_server_name(),
        };
        assert!(!section.tls_enabled());
        section.tls_ca_cert = Some("/etc/ssl/ca.pem".to_string());
        assert!(section.tls_enabled());
    }

    #[test]
    fn validate_accepts_loopback_verifier() {
        let config = minimal_config(GatewayMode::Observe);
        assert_eq!(config.verifier.addr, "127.0.0.1:9100");
        let result = validate(&config);
        assert!(result.is_ok());
    }

    // ── Timing cross-validation tests ──

    #[test]
    fn validate_default_timing_chain_satisfies_invariants() {
        let config = minimal_config(GatewayMode::Observe);
        let result = validate(&config);
        assert!(result.is_ok(), "defaults must pass: {result:?}");
    }

    #[test]
    fn validate_rejects_zero_prevhash_verdict_timeout() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.gateway.prevhash_verdict_timeout_ms = 0;
        let result = validate(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("prevhash_verdict_timeout_ms must be > 0"),
        );
    }

    #[test]
    fn validate_rejects_verdict_timeout_gte_stale_hold() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.gateway.prevhash_verdict_timeout_ms = 5000;
        config.gateway.prevhash_stale_hold_ms = 5000;
        let result = validate(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("must be < prevhash_stale_hold_ms"),
        );
    }

    #[test]
    fn validate_rejects_stale_hold_gte_upstream_stale_max() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.gateway.prevhash_stale_hold_ms = 30_000;
        config.gateway.upstream_stale_max_ms = 30_000;
        let result = validate(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("must be < upstream_stale_max_ms"),
        );
    }

    #[test]
    fn validate_rejects_job_retention_below_upstream_stale_max() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.gateway.job_retention_ms = 10_000;
        config.gateway.upstream_stale_max_ms = 30_000;
        let result = validate(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("must be >= upstream_stale_max_ms"),
        );
    }

    #[test]
    fn validate_rejects_zero_health_probe_staleness() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.verifier.health_probe_staleness_ms = 0;
        let result = validate(&config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("health_probe_staleness_ms must be > 0"),
        );
    }

    #[test]
    fn validate_warns_on_low_prevhash_verdict_timeout() {
        let mut config = minimal_config(GatewayMode::Observe);
        // Explicitly set a regtest-grade value (<1000ms) to exercise the warning.
        // Default is mainnet-safe (2000ms) and must NOT trigger this warning.
        config.gateway.prevhash_verdict_timeout_ms = 50;
        let result = validate(&config);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("prevhash_verdict_timeout_ms=50")),
            "expected regtest warning, got: {warnings:?}",
        );
    }

    #[test]
    fn default_prevhash_verdict_timeout_is_mainnet_safe() {
        // Guard against accidental regression to the regtest-only 50ms default.
        // The sub-1000ms regtest warning must NOT fire for shipped defaults.
        let config = minimal_config(GatewayMode::Observe);
        assert!(
            config.gateway.prevhash_verdict_timeout_ms >= 1000,
            "default prevhash_verdict_timeout_ms must be >= 1000ms for mainnet \
             safety; got {}",
            config.gateway.prevhash_verdict_timeout_ms,
        );
        let warnings = validate(&config).expect("defaults must validate");
        assert!(
            !warnings.iter().any(|w| w.contains("regtest-appropriate")),
            "default config must not trigger the regtest warning: {warnings:?}",
        );
    }

    #[test]
    fn validate_no_regtest_warning_above_1000ms() {
        let mut config = minimal_config(GatewayMode::Observe);
        config.gateway.prevhash_verdict_timeout_ms = 2000;
        let result = validate(&config);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(
            !warnings.iter().any(|w| w.contains("regtest")),
            "unexpected regtest warning: {warnings:?}",
        );
    }

    #[test]
    fn auto_degrade_defaults() {
        let config = minimal_config(GatewayMode::Inline);
        assert!(config.gateway.auto_degrade);
        assert_eq!(config.gateway.auto_degrade_after_ms, 10_000);
    }

    #[test]
    fn auto_degrade_only_effective_for_inline() {
        let inline = minimal_config(GatewayMode::Inline);
        let observe = minimal_config(GatewayMode::Observe);
        let shadow = minimal_config(GatewayMode::Shadow);
        assert!(inline.gateway.auto_degrade && inline.mode.enforces_verdicts());
        assert!(!observe.mode.enforces_verdicts());
        assert!(!shadow.mode.enforces_verdicts());
    }

    #[test]
    fn validate_warns_degrade_below_heartbeat() {
        let mut config = minimal_config(GatewayMode::Inline);
        config.gateway.prevhash_verdict_timeout_ms = 2000;
        config.gateway.auto_degrade_after_ms = 2000;
        config.verifier.heartbeat_interval_ms = 5000;
        let result = validate(&config);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("auto_degrade_after_ms")),
            "expected degradation threshold warning, got: {warnings:?}",
        );
    }

    #[test]
    fn validate_no_degrade_warning_when_threshold_sufficient() {
        let mut config = minimal_config(GatewayMode::Inline);
        config.gateway.prevhash_verdict_timeout_ms = 2000;
        config.gateway.auto_degrade_after_ms = 10_000;
        config.verifier.heartbeat_interval_ms = 5000;
        let result = validate(&config);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(
            !warnings.iter().any(|w| w.contains("auto_degrade_after_ms")),
            "unexpected degradation warning: {warnings:?}",
        );
    }
}
