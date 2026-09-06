use std::{
    collections::{VecDeque, hash_map::DefaultHasher},
    env,
    hash::{Hash, Hasher},
    sync::{Arc, LazyLock, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Duration, sleep, timeout};

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bitcoincore_rpc::json::GetBlockTemplateResult;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tower_http::limit::RequestBodyLimitLayer;

use clap::Parser;
use tracing::{debug, error, info, warn};

use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict};

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use reservegrid_common::metrics::{SharedRegistry, render_metrics};
use reservegrid_common::reason::GatewayReason;

mod config;
use config::TemplateManagerConfig;

use async_trait::async_trait;

// ── CLI ─────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "template-manager", about = "Veldra template manager")]
struct Cli {
    /// Path to manager config file.
    #[arg(
        long,
        env = "VELDRA_MANAGER_CONFIG",
        default_value = "config/manager.toml"
    )]
    config: String,
}

// ── Tracing ─────────────────────────────────────────────────

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter =
        EnvFilter::try_from_env("VELDRA_LOG_FILTER").unwrap_or_else(|_| EnvFilter::new("info"));

    let json_mode = std::env::var("VELDRA_LOG_FORMAT").as_deref() == Ok("json");

    if json_mode {
        fmt().json().with_env_filter(filter).init();
    } else {
        fmt().with_env_filter(filter).init();
    }
}

// ── Security: startup enforcement ────────────────────────────

/// Exit immediately if `VELDRA_API_SECRET` is unset without explicit opt-out.
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

/// Warn loudly when HMAC share verification is disabled without explicit opt-out.
fn enforce_hmac_secret() {
    let hmac_set = env::var("VELDRA_SHARE_UPSTREAM_SECRET")
        .ok()
        .is_some_and(|s| !s.is_empty());
    let hmac_optional = env::var("VELDRA_SHARE_HMAC_OPTIONAL").as_deref() == Ok("1");
    if !hmac_set && !hmac_optional {
        tracing::error!(
            "VELDRA_SHARE_UPSTREAM_SECRET is not set. Share submissions will be accepted \
             without signature verification. Set VELDRA_SHARE_UPSTREAM_SECRET to a shared \
             secret, or set VELDRA_SHARE_HMAC_OPTIONAL=1 to explicitly allow unsigned \
             shares (not recommended in production)."
        );
        std::process::exit(1);
    }
    if !hmac_set && hmac_optional {
        tracing::warn!(
            "VELDRA_SHARE_UPSTREAM_SECRET is not set but VELDRA_SHARE_HMAC_OPTIONAL=1 \
             is active. Share submissions are accepted without signature verification."
        );
    }
}

// ── Security: API key auth middleware ────────────────────────

async fn api_key_middleware(req: Request<Body>, next: Next) -> Response {
    // If VELDRA_API_SECRET_OPTIONAL=1 was set and no secret exists, allow all.
    let expected = match env::var("VELDRA_API_SECRET") {
        Ok(k) if !k.is_empty() => k,
        _ => return next.run(req).await,
    };

    // Check Authorization header: "Bearer <key>" or raw key.
    let authorized = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let stripped = v.strip_prefix("Bearer ").unwrap_or(v);
            stripped.as_bytes().ct_eq(expected.as_bytes()).into()
        });

    if authorized {
        next.run(req).await
    } else {
        tracing::warn!(
            path = %req.uri().path(),
            "api_key_auth_failed"
        );
        (StatusCode::UNAUTHORIZED, "missing or invalid api key").into_response()
    }
}

// ── Security: write throttle ─────────────────────────────────

static WRITE_TIMESTAMPS: LazyLock<Mutex<VecDeque<Instant>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

const WRITE_THROTTLE_WINDOW: Duration = Duration::from_secs(60);
const WRITE_THROTTLE_MAX: usize = 10;

fn check_write_throttle() -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let now = Instant::now();
    let mut ts = WRITE_TIMESTAMPS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while ts
        .front()
        .is_some_and(|t| now.duration_since(*t) > WRITE_THROTTLE_WINDOW)
    {
        ts.pop_front();
    }
    if ts.len() >= WRITE_THROTTLE_MAX {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok": false,
                "error": "write rate limit exceeded, try again later"
            })),
        ));
    }
    ts.push_back(now);
    Ok(())
}

// ── Security: share log path validation ──────────────────────

fn validate_share_log_path(path: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    if !p.is_absolute() {
        return Err(format!(
            "VELDRA_SHARE_LOG_PATH must be absolute, got: {path}"
        ));
    }
    let normalized = p.to_string_lossy();
    if normalized.contains("..") {
        return Err(format!(
            "VELDRA_SHARE_LOG_PATH contains path traversal: {path}"
        ));
    }
    Ok(())
}

// ── Prometheus Metrics ──────────────────────────────────────

struct TemplateManagerMetrics {
    templates_polled_total: Counter,
    templates_cached: Gauge,
    shares_ingested_total: Counter,
    poll_errors_total: Counter,
}

type SharedTmgrMetrics = Arc<TemplateManagerMetrics>;

impl TemplateManagerMetrics {
    fn new_registered(registry: &mut Registry) -> Self {
        let m = Self {
            templates_polled_total: Counter::default(),
            templates_cached: Gauge::default(),
            shares_ingested_total: Counter::default(),
            poll_errors_total: Counter::default(),
        };
        registry.register(
            "tmgr_templates_polled",
            "Templates polled from backend",
            m.templates_polled_total.clone(),
        );
        registry.register(
            "tmgr_templates_cached",
            "Templates currently in the log",
            m.templates_cached.clone(),
        );
        registry.register(
            "tmgr_shares_ingested",
            "Shares ingested via POST /shares",
            m.shares_ingested_total.clone(),
        );
        registry.register(
            "tmgr_poll_errors",
            "Template poll errors",
            m.poll_errors_total.clone(),
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
    fn tmgr_counters_export_single_total_suffix() {
        let mut registry = Registry::default();
        let m = TemplateManagerMetrics::new_registered(&mut registry);
        m.templates_polled_total.inc();
        m.shares_ingested_total.inc();
        m.poll_errors_total.inc();

        let (status, _, body) = reservegrid_common::metrics::render_metrics(&registry);
        assert_eq!(status, 200);
        assert!(!body.contains("_total_total"), "double suffix in:\n{body}");
        for name in [
            "tmgr_templates_polled_total",
            "tmgr_shares_ingested_total",
            "tmgr_poll_errors_total",
        ] {
            assert!(body.contains(name), "missing exported counter `{name}`");
        }
    }
}

async fn tmgr_metrics_handler(Extension(registry): Extension<SharedRegistry>) -> impl IntoResponse {
    let (status, content_type, body) = render_metrics(&registry);
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        [(axum::http::header::CONTENT_TYPE, content_type)],
        body,
    )
}

/// Extra GBT fields needed by the gateway but not part of `TemplatePropose`.
#[derive(Debug, Clone)]
struct GbtExtras {
    block_version: u32,
    nbits: u32,
    min_ntime: u32,
    curtime: u32,
    coinbase_tx_prefix: String,
    coinbase_tx_suffix: String,
    merkle_path: Vec<String>,
}

/// Source of block templates.
#[async_trait]
trait TemplateSource: Send {
    async fn next_template(&mut self) -> Result<Option<(TemplatePropose, Option<GbtExtras>)>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TemplateFingerprint {
    height: u64,
    prev_hash: String,
    tx_count: u32,
    total_fees: u64,
    txids_hash: u64,
}

fn hash_txids(txids: &[String]) -> u64 {
    // Order-independent hash so reordering doesn’t create fake “new templates”.
    let mut v = txids.to_vec();
    v.sort();
    let mut h = DefaultHasher::new();
    for t in v {
        t.hash(&mut h);
    }
    h.finish()
}

fn block_subsidy_sats(height: u32) -> u64 {
    // Bitcoin mainnet schedule. Regtest uses same unless you changed params.
    // 50 BTC = 5_000_000_000 sats at height 0, halves every 210_000 blocks.
    let halvings = height / 210_000;
    if halvings >= 64 {
        return 0;
    }
    (50u64 * 100_000_000u64) >> halvings
}

fn stable_template_id(fp: &TemplateFingerprint) -> u64 {
    let mut h = DefaultHasher::new();
    fp.height.hash(&mut h);
    fp.prev_hash.hash(&mut h);
    fp.tx_count.hash(&mut h);
    fp.total_fees.hash(&mut h);
    fp.txids_hash.hash(&mut h);
    h.finish()
}

// ── Coinbase construction ───────────────────────────────────────────

/// Encode a block height as a BIP 34 `CScriptNum` data push.
///
/// The result is the push opcode byte (data length) followed by the
/// minimally encoded little-endian height bytes. This is what Bitcoin
/// Core places at the start of the coinbase scriptSig.
fn bip34_height_push(height: u32) -> Vec<u8> {
    if height == 0 {
        // CScriptNum(0) serializes as empty, but BIP 34 mandates at
        // least one byte of height data in the scriptSig.
        return vec![0x01, 0x00];
    }

    // Minimal LE encoding of height.
    let mut v = Vec::with_capacity(4);
    let mut n = height;
    while n > 0 {
        v.push((n & 0xFF) as u8);
        n >>= 8;
    }
    // If the high bit of the last byte is set, append a 0x00 sign byte
    // to keep the number positive in CScriptNum interpretation.
    if v.last().is_some_and(|b| b & 0x80 != 0) {
        v.push(0x00);
    }

    let mut result = Vec::with_capacity(1 + v.len());
    #[allow(clippy::cast_possible_truncation)]
    // Safe: scripts in Bitcoin are limited to 520 bytes
    result.push(v.len() as u8); // data push opcode
    result.extend_from_slice(&v);
    result
}

/// Decode a display-order (RPC big-endian) block hash hex string into
/// internal byte order. Returns `None` on invalid hex or wrong length.
fn display_hex_to_internal(display_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(display_hex).ok()?;
    let mut internal: [u8; 32] = bytes.try_into().ok()?;
    internal.reverse();
    Some(internal)
}

/// Assemble the full raw template block and hex-encode it for
/// `raw_block_hex` (PB-19 / ADR-002 Phase 1b).
///
/// The coinbase is the SV2 job coinbase with the extranonce slot
/// zero-filled: `prefix || 0u8 x extranonce_size || suffix`, the same
/// bytes miners will ultimately vary, so every declared field the
/// shield re-derives (value, sigops, BIP-34 height, commitment) is
/// consistent by construction. Assembly itself happens behind the
/// rg-consensus facade (R-154).
///
/// Failure policy: log loudly and return `None`. The propose still
/// ships without the field and the verifier counts the skip in
/// `verifier_shield_skipped_total`, so an assembly regression is
/// visible on the dashboard rather than silently dropping templates.
#[allow(clippy::too_many_arguments)]
fn assemble_raw_block_hex(
    block_version: u32,
    nbits: u32,
    curtime: u32,
    prev_hash_display: &str,
    cb_prefix: &[u8],
    cb_suffix: &[u8],
    extranonce_size: usize,
    txs_raw: &[Vec<u8>],
) -> Option<String> {
    let Some(prev_hash) = display_hex_to_internal(prev_hash_display) else {
        warn!(
            prev_hash = %prev_hash_display,
            "raw block assembly skipped: prev_hash is not 32 bytes of hex"
        );
        return None;
    };

    let mut coinbase_legacy =
        Vec::with_capacity(cb_prefix.len() + extranonce_size + cb_suffix.len());
    coinbase_legacy.extend_from_slice(cb_prefix);
    coinbase_legacy.extend(std::iter::repeat_n(0u8, extranonce_size));
    coinbase_legacy.extend_from_slice(cb_suffix);

    // Bit-pattern preserving u32 -> i32: GBT `version` is a consensus
    // int32 transported unsigned.
    let version = i32::from_le_bytes(block_version.to_le_bytes());

    let parts = rg_consensus::TemplateBlockParts {
        version,
        prev_hash,
        time: curtime,
        bits: nbits,
        coinbase_legacy: &coinbase_legacy,
        txs_raw,
    };
    match rg_consensus::assemble_template_block(&parts) {
        Ok(raw) => Some(hex::encode(raw)),
        Err(e) => {
            warn!(
                error = %e,
                "raw block assembly failed; propose ships without raw_block_hex \
                 and the shield will count the skip"
            );
            None
        }
    }
}

/// Build coinbase transaction prefix and suffix, split at the extranonce
/// boundary.
///
/// The assembled coinbase is: `prefix || extranonce || suffix` and forms
/// a valid Bitcoin transaction when the extranonce is filled in by the
/// gateway per channel.
///
/// `coinbase_aux` contains raw bytes decoded from the GBT `coinbaseaux`
/// map values. These are injected into the scriptSig after the BIP 34
/// height push and before the extranonce slot, following the GBT spec.
///
/// If `witness_commitment_script` is provided (the raw scriptPubKey bytes
/// from `default_witness_commitment` in GBT), a second output with value 0
/// carrying the `SegWit` witness commitment is appended before locktime.
///
/// Returns `(prefix_bytes, suffix_bytes)`.
///
/// # Errors
///
/// Returns an error if the combined `scriptSig` length exceeds 252 bytes
/// (the single-byte varint limit), which would produce an invalid coinbase.
fn build_coinbase_halves(
    block_height: u32,
    coinbase_value: u64,
    coinbase_output_script: &[u8],
    extranonce_size: usize,
    coinbase_aux: &[u8],
    witness_commitment_script: Option<&[u8]>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let height_push = bip34_height_push(block_height);
    let scriptsig_len = height_push.len() + coinbase_aux.len() + extranonce_size;

    // Consensus `bad-cb-length`: the coinbase scriptSig must be 2..=100
    // bytes. A larger one produces a block Bitcoin Core rejects and the
    // shield flags as `v2_invariant_coinbase_script_length` (PB-19; the
    // previous 252-byte single-byte-varint cap was necessary but not
    // sufficient).
    anyhow::ensure!(
        scriptsig_len <= 100,
        "coinbase scriptSig exceeds the 100-byte consensus cap: {scriptsig_len} \
         (height push {} + coinbaseaux {} + extranonce {extranonce_size})",
        height_push.len(),
        coinbase_aux.len()
    );

    // ── PREFIX ──
    let mut prefix = Vec::with_capacity(41 + height_push.len() + coinbase_aux.len());
    // tx version 2 (BIP 68/112/113)
    prefix.extend_from_slice(&2u32.to_le_bytes());
    // input count
    prefix.push(0x01);
    // prevout hash (coinbase: all zeros)
    prefix.extend_from_slice(&[0u8; 32]);
    // prevout index (coinbase: 0xFFFFFFFF)
    prefix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // scriptSig length (varint, single byte safe for values < 253)
    anyhow::ensure!(
        scriptsig_len < 253,
        "coinbase scriptSig too large for single-byte varint: {scriptsig_len}"
    );
    #[allow(clippy::cast_possible_truncation)]
    // Safe: assert above guarantees scriptsig_len < 253
    prefix.push(scriptsig_len as u8);
    // BIP 34 height push
    prefix.extend_from_slice(&height_push);
    // coinbaseaux flags (from GBT)
    prefix.extend_from_slice(coinbase_aux);
    // [extranonce inserted here by the gateway]

    // ── SUFFIX ──
    let has_witness = witness_commitment_script.is_some();
    let output_count: u8 = if has_witness { 2 } else { 1 };

    let mut suffix = Vec::with_capacity(
        4 + 1
            + 8
            + 1
            + coinbase_output_script.len()
            + if has_witness {
                8 + 1 + witness_commitment_script.map_or(0, <[u8]>::len)
            } else {
                0
            }
            + 4,
    );
    // sequence
    suffix.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // output count
    suffix.push(output_count);
    // Output 0: payout
    suffix.extend_from_slice(&coinbase_value.to_le_bytes());
    assert!(
        coinbase_output_script.len() < 253,
        "coinbase output script too large for single-byte varint"
    );
    #[allow(clippy::cast_possible_truncation)]
    // Safe: assert above guarantees length < 253
    suffix.push(coinbase_output_script.len() as u8);
    suffix.extend_from_slice(coinbase_output_script);

    // Output 1: SegWit witness commitment (BIP 141)
    if let Some(wc_script) = witness_commitment_script {
        // value = 0 satoshis
        suffix.extend_from_slice(&0u64.to_le_bytes());
        anyhow::ensure!(
            wc_script.len() < 253,
            "witness commitment script too large for single-byte varint: {}",
            wc_script.len()
        );
        #[allow(clippy::cast_possible_truncation)]
        // Safe: ensure above guarantees length < 253
        suffix.push(wc_script.len() as u8);
        suffix.extend_from_slice(wc_script);
    }

    // locktime
    suffix.extend_from_slice(&0u32.to_le_bytes());

    Ok((prefix, suffix))
}

/// Double SHA256 (`SHA256d`).
fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Compute the merkle branch for the coinbase transaction (index 0)
/// from the GBT transaction ID list.
///
/// GBT txids are in display byte order (reversed from the internal
/// `SHA256d` hash). This function reverses each txid to internal order,
/// builds the merkle tree level by level, and collects the sibling
/// hash at each level along the coinbase path.
///
/// The returned branch elements are hex-encoded in internal byte order,
/// which is what the gateway's `compute_merkle_root` expects.
fn compute_merkle_branch(txid_hex_display: &[String]) -> Result<Vec<String>> {
    if txid_hex_display.is_empty() {
        return Ok(vec![]);
    }

    // Parse txids and reverse from display to internal byte order.
    // Index 0 is a placeholder for the coinbase (value does not affect
    // sibling hashes, so zero is fine).
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(1 + txid_hex_display.len());
    level.push([0u8; 32]); // coinbase placeholder
    for hex_str in txid_hex_display {
        let bytes = hex::decode(hex_str)
            .with_context(|| format!("invalid txid hex in merkle branch: {hex_str}"))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "txid is not 32 bytes in merkle branch (got {}): {hex_str}",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr.reverse(); // display -> internal
        level.push(arr);
    }

    let mut branch = Vec::new();
    let mut index: usize = 0;

    while level.len() > 1 {
        // Bitcoin merkle tree rule: duplicate last element when count is odd.
        if !level.len().is_multiple_of(2) {
            // SAFETY: loop guard `level.len() > 1` guarantees non-empty.
            let last = level[level.len() - 1];
            level.push(last);
        }

        // Collect the sibling of the coinbase descendant at this level.
        let sibling_idx = if index.is_multiple_of(2) {
            index + 1
        } else {
            index - 1
        };
        branch.push(hex::encode(level[sibling_idx]));

        // Reduce to the next tree level by combining pairs.
        let mut next = Vec::with_capacity(level.len() / 2);
        for i in (0..level.len()).step_by(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&level[i]);
            combined[32..].copy_from_slice(&level[i + 1]);
            next.push(sha256d(&combined));
        }

        level = next;
        index /= 2;
    }

    Ok(branch)
}

fn build_bitcoind_client(cfg: &TemplateManagerConfig) -> anyhow::Result<Arc<Client>> {
    let url = cfg
        .rpc_url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:18443".to_string());
    let user = cfg
        .rpc_user
        .clone()
        .or_else(|| std::env::var("VELDRA_BITCOIND_RPC_USER").ok())
        .unwrap_or_else(|| "reservegrid".to_string());
    let pass = cfg
        .rpc_pass
        .clone()
        .or_else(|| std::env::var("VELDRA_BITCOIND_RPC_PASS").ok())
        .context("rpc_pass not set in config and VELDRA_BITCOIND_RPC_PASS not in environment")?;

    let auth = Auth::UserPass(user, pass);
    let client = Client::new(&url, auth).context("failed to create bitcoind RPC client")?;
    Ok(Arc::new(client))
}

/// Bitcoind-backed template source using getblocktemplate.
struct BitcoindTemplateSource {
    client: Arc<Client>,
    last_fp: Option<TemplateFingerprint>,
    had_rpc_error: bool,
    coinbase_output_script: Vec<u8>,
    extranonce_size: usize,
}

impl BitcoindTemplateSource {
    fn new(client: Arc<Client>, coinbase_output_script: Vec<u8>, extranonce_size: usize) -> Self {
        Self {
            client,
            last_fp: None,
            had_rpc_error: false,
            coinbase_output_script,
            extranonce_size,
        }
    }
}

#[async_trait]
impl TemplateSource for BitcoindTemplateSource {
    #[allow(clippy::too_many_lines)]
    async fn next_template(&mut self) -> Result<Option<(TemplatePropose, Option<GbtExtras>)>> {
        let mut attempts = 0;

        let tpl_opt = loop {
            let client = self.client.clone();

            // Raw JSON-RPC call so we can request the `coinbasetxn` capability
            // which the typed crate API does not expose (empty enum).
            let res = tokio::task::spawn_blocking(move || {
                let raw: serde_json::Value = client.call(
                    "getblocktemplate",
                    &[serde_json::json!({
                        "mode": "template",
                        "rules": ["segwit"],
                        "capabilities": ["coinbasetxn"]
                    })],
                )?;
                let cb_sigops = extract_coinbase_sigops(&raw);
                if cb_sigops.is_none() && raw.get("coinbasetxn").is_some() {
                    tracing::warn!(
                        "coinbasetxn present but sigops field missing; \
                         coinbase sigops anomaly detection will be inactive"
                    );
                }
                let typed: GetBlockTemplateResult =
                    serde_json::from_value(raw).map_err(bitcoincore_rpc::Error::Json)?;
                Ok::<_, bitcoincore_rpc::Error>((typed, cb_sigops))
            })
            .await;

            match res {
                Ok(Ok(t)) => break Some(t),
                Ok(Err(e)) => {
                    attempts += 1;
                    warn!(attempts, error = ?e, "get_block_template failed");

                    if attempts >= 3 {
                        warn!(
                            attempts,
                            "get_block_template giving up for this poll, will retry next tick"
                        );
                        self.had_rpc_error = true;
                        break None;
                    }

                    sleep(Duration::from_millis(200)).await;
                }
                Err(join_err) => {
                    attempts += 1;
                    error!(attempts, error = ?join_err, "get_block_template spawn_blocking join error");

                    if attempts >= 3 {
                        self.had_rpc_error = true;
                        break None;
                    }

                    sleep(Duration::from_millis(200)).await;
                }
            }
        };

        let (tpl, coinbase_sigops) = match tpl_opt {
            Some(t) => {
                if self.had_rpc_error {
                    info!("get_block_template RPC recovered");
                    self.had_rpc_error = false;
                }
                t
            }
            None => return Ok(None),
        };

        #[allow(clippy::cast_possible_truncation)]
        // Safe: block height in Bitcoin is limited to 2^31-1
        let block_height = tpl.height as u32;
        let prev_hash = tpl.previous_block_hash.to_string();

        #[allow(clippy::cast_possible_truncation)]
        // Safe: transaction count in a block is limited to ~4000
        let tx_count = tpl.transactions.len() as u32;
        let total_fees: u64 = tpl.transactions.iter().map(|tx| tx.fee.to_sat()).sum();

        let coinbase_raw: u64 = tpl.coinbase_value.to_sat();
        let coinbase_value: u64 = if coinbase_raw == 0 {
            let fallback = block_subsidy_sats(block_height) + total_fees;
            warn!(
                height = block_height,
                tx_count,
                total_fees,
                fallback,
                "coinbase_value=0 from getblocktemplate, using fallback"
            );
            fallback
        } else {
            coinbase_raw
        };

        // ── v0.2.2: extract weight and sigops from GBT transactions ──
        let template_weight: u64 = tpl.transactions.iter().map(|tx| tx.weight as u64).sum();
        let total_sigops: u32 = tpl.transactions.iter().map(|tx| tx.sigops).sum();

        // coinbase_sigops was extracted from the raw GBT JSON `coinbasetxn.sigops`
        // field above. It is None when Bitcoin Core omits the field (older versions
        // or when the coinbasetxn capability is not honoured).

        let txids: Vec<String> = tpl
            .transactions
            .iter()
            .map(|tx| tx.txid.to_string())
            .collect();

        let fp = TemplateFingerprint {
            height: u64::from(block_height),
            prev_hash: prev_hash.clone(),
            tx_count,
            total_fees,
            txids_hash: hash_txids(&txids),
        };

        if self.last_fp.as_ref() == Some(&fp) {
            return Ok(None);
        }

        // stable id BEFORE moving fp
        let id: u64 = stable_template_id(&fp);
        self.last_fp = Some(fp);

        // Extract SegWit witness commitment from GBT if present.
        // `default_witness_commitment` is the complete scriptPubKey
        // (OP_RETURN + push + aa21a9ed + commitment) ready to embed as
        // a second coinbase output.
        let wc_bytes = tpl.default_witness_commitment.as_bytes();
        let witness_commitment: Option<&[u8]> = if wc_bytes.is_empty() {
            None
        } else {
            Some(wc_bytes)
        };

        // Extract coinbaseaux flags from GBT. The map values are hex
        // encoded byte sequences that belong in the coinbase scriptSig
        // after the BIP 34 height push (GBT spec). Bitcoin Core typically
        // sets a single "flags" key; we concatenate all values in sorted
        // key order for determinism.
        let coinbase_aux = {
            let mut keys: Vec<&String> = tpl.coinbaseaux.keys().collect();
            keys.sort();
            let mut buf = Vec::new();
            for key in keys {
                if let Some(hex_val) = tpl.coinbaseaux.get(key) {
                    match hex::decode(hex_val) {
                        Ok(bytes) => buf.extend_from_slice(&bytes),
                        Err(e) => {
                            warn!(
                                key = %key,
                                value = %hex_val,
                                error = %e,
                                "skipping invalid coinbaseaux hex value"
                            );
                        }
                    }
                }
            }
            buf
        };

        // Build coinbase transaction halves for SV2 job construction.
        let (cb_prefix, cb_suffix) = build_coinbase_halves(
            block_height,
            coinbase_value,
            &self.coinbase_output_script,
            self.extranonce_size,
            &coinbase_aux,
            witness_commitment,
        )?;

        // Compute proper merkle branch for the coinbase (index 0) from
        // the GBT transaction IDs. The branch contains sibling hashes at
        // each tree level, not raw txids.
        let merkle_branch = compute_merkle_branch(&txids)?;

        // PB-19 / Phase 1b: assemble the full raw block so the shield
        // has bytes to re-derive from. GBT supplies every non-coinbase
        // tx pre-serialized; the coinbase is the job coinbase with a
        // zero-filled extranonce slot.
        let txs_raw: Vec<Vec<u8>> = tpl
            .transactions
            .iter()
            .map(|tx| tx.raw_tx.clone())
            .collect();
        let nbits = bits_to_nbits(&tpl.bits);
        #[allow(clippy::cast_possible_truncation)]
        // Safe: Unix timestamps fit in u32 until year 2106
        let curtime_u32 = tpl.current_time as u32;
        let raw_block_hex = assemble_raw_block_hex(
            tpl.version,
            nbits,
            curtime_u32,
            &prev_hash,
            &cb_prefix,
            &cb_suffix,
            self.extranonce_size,
            &txs_raw,
        );

        // Extract GBT extras for the /latest endpoint.
        let extras = GbtExtras {
            block_version: tpl.version,
            nbits: bits_to_nbits(&tpl.bits),
            #[allow(clippy::cast_possible_truncation)]
            // Safe: Unix timestamps fit in u32 until year 2106
            min_ntime: tpl.min_time as u32,
            #[allow(clippy::cast_possible_truncation)]
            // Safe: Unix timestamps fit in u32 until year 2106
            curtime: tpl.current_time as u32,
            coinbase_tx_prefix: hex::encode(cb_prefix),
            coinbase_tx_suffix: hex::encode(cb_suffix),
            merkle_path: merkle_branch,
        };

        Ok(Some((
            TemplatePropose {
                version: PROTOCOL_VERSION,
                id,
                block_height,
                prev_hash,
                coinbase_value,
                tx_count,
                total_fees,
                observed_weight: Some(template_weight),
                created_at_unix_ms: Some(now_unix_ms()),
                total_sigops: Some(total_sigops),
                coinbase_sigops,
                template_weight: Some(template_weight),
                gateway_instance_id: None,
                // PB-19 / Phase 1b: the shield runs against these
                // bytes. None only when assembly failed (logged).
                raw_block_hex,
            },
            Some(extras),
        )))
    }
}

/// Stratum-backed template source.
/// Expects a local bridge that sends `TemplatePropose` as newline-delimited JSON.
struct StratumTemplateSource {
    rx: mpsc::Receiver<TemplatePropose>,
}

impl StratumTemplateSource {
    fn from_config(cfg: &TemplateManagerConfig) -> Self {
        let addr = cfg
            .stratum_addr
            .clone()
            .unwrap_or_else(|| "127.0.0.1:3333".to_string());
        let auth = cfg.stratum_auth.clone();

        info!(
            addr = %addr,
            auth_set = auth.is_some(),
            "connecting to Stratum V2 bridge"
        );

        let (tx, rx) = mpsc::channel::<TemplatePropose>(16);

        tokio::spawn(async move {
            loop {
                match TcpStream::connect(&addr).await {
                    Ok(stream) => {
                        info!(addr = %addr, "connected to Stratum V2 bridge");
                        let mut reader = BufReader::new(stream);
                        let mut line = String::new();

                        loop {
                            line.clear();
                            let n = match reader.read_line(&mut line).await {
                                Ok(n) => n,
                                Err(e) => {
                                    warn!(error = ?e, "error reading from Stratum V2 bridge");
                                    break;
                                }
                            };

                            if n == 0 {
                                info!("Stratum V2 bridge closed connection");
                                break;
                            }

                            let s = line.trim();
                            if s.is_empty() {
                                continue;
                            }

                            match serde_json::from_str::<TemplatePropose>(s) {
                                Ok(tpl) => {
                                    if tx.send(tpl).await.is_err() {
                                        warn!(
                                            "template channel closed, stopping Stratum V2 reader task"
                                        );
                                        return;
                                    }
                                }
                                Err(e) => {
                                    warn!(error = ?e, line = ?s, "failed to parse TemplatePropose JSON from Stratum V2 bridge");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(addr = %addr, error = ?e, "failed to connect to Stratum V2 bridge");
                    }
                }

                sleep(Duration::from_secs(3)).await;
            }
        });

        Self { rx }
    }
}

#[async_trait]
impl TemplateSource for StratumTemplateSource {
    async fn next_template(&mut self) -> Result<Option<(TemplatePropose, Option<GbtExtras>)>> {
        match self.rx.recv().await {
            // Stratum source does not provide GBT extras.
            Some(tpl) => Ok(Some((tpl, None))),
            None => anyhow::bail!("Stratum V2 bridge template channel disconnected"),
        }
    }
}

/// What we show over HTTP for recent templates.
#[derive(Clone, Serialize)]
struct LoggedTemplate {
    id: u64,
    height: u32,
    total_fees: u64,
    backend: String,
    timestamp: u64,
}

/// Serialize a u32 as lowercase hex string (Bitcoin convention for nbits).
#[allow(clippy::trivially_copy_pass_by_ref)] // serde serialize_with requires &T
fn serialize_nbits_hex<S: serde::Serializer>(val: &u32, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{val:08x}"))
}

/// Full template served at `/latest` for the sv2-gateway.
/// Field names match the gateway's `TemplateResponse` struct exactly.
/// `nbits` is numeric (u32) for the gateway; `nbits_hex` is the same value
/// as a hex string for the frontend (Bitcoin convention, R-46 compliant).
#[derive(Clone, Serialize)]
struct LatestTemplate {
    template_id: u64,
    block_height: u32,
    block_version: u32,
    prev_hash: String,
    nbits: u32,
    /// Hex representation of nbits for dashboard display.
    #[serde(serialize_with = "serialize_nbits_hex")]
    nbits_hex: u32,
    min_ntime: u32,
    curtime: u32,
    coinbase_value: u64,
    coinbase_tx_prefix: String,
    coinbase_tx_suffix: String,
    merkle_path: Vec<String>,
    tx_count: u32,
    total_fees: u64,
    source_instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_weight: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    template_weight: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_sigops: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coinbase_sigops: Option<u32>,
    /// PB-19 / Phase 1b: hex of the assembled raw template block for
    /// the Invariant Shield. Absent when assembly failed or the
    /// source cannot assemble (stratum).
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_block_hex: Option<String>,
}

#[derive(Clone, Serialize)]
struct MempoolStats {
    loaded_from: String,
    tx_count: u64,
    bytes: u64,
    usage: u64,
    max: u64,
    min_relay_fee: u64,
    timestamp: u64,
}

type TemplateLog = Arc<RwLock<Vec<LoggedTemplate>>>;
type LatestTemplateState = Arc<RwLock<Option<LatestTemplate>>>;
type MempoolLog = Arc<RwLock<Option<MempoolStats>>>;

/// In-memory share log appended by the /shares endpoint.
type ShareLog = Arc<RwLock<Vec<ShareSubmissionRecord>>>;

/// HMAC secret shared with the gateway for signature verification.
/// Empty means signature verification is disabled.
type ShareHmacSecret = Arc<Vec<u8>>;

const TEMPLATE_LOG_CAP: usize = 500;

/// Maximum length for hex-encoded fields in share submissions.
const MAX_SHARE_HEX_FIELD: usize = 256;
/// Maximum length for free-text string fields in share submissions.
const MAX_SHARE_STRING_FIELD: usize = 256;

/// Convert the GBT `bits` field (big-endian byte vec) to a compact u32 nbits.
fn bits_to_nbits(bits: &[u8]) -> u32 {
    if bits.len() == 4 {
        u32::from_be_bytes([bits[0], bits[1], bits[2], bits[3]])
    } else {
        // Fallback: treat as hex string decoded to bytes.
        0
    }
}

/// Generate a stable per-process instance ID from hostname and PID.
fn instance_id() -> String {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    let pid = std::process::id();
    format!("{host}-{pid}")
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    init_tracing();
    enforce_api_secret();
    enforce_hmac_secret();
    let cli = Cli::parse();
    let cfg_path = cli.config;

    let cfg = TemplateManagerConfig::from_path(&cfg_path)?;
    info!(
        path = %cfg_path,
        backend = %cfg.backend,
        rpc_url = ?cfg.rpc_url,
        rpc_pass_set = cfg.rpc_pass.is_some(),
        "loaded manager config"
    );

    let verifier_addr = env::var("VELDRA_VERIFIER_ADDR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            cfg.verifier_tcp_addr
                .clone()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "127.0.0.1:5001".to_string());

    let poll_secs: u64 = cfg.poll_interval_secs.unwrap_or(5).max(1);

    let http_addr = env::var("VELDRA_MANAGER_HTTP_ADDR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            cfg.http_listen_addr
                .clone()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| "127.0.0.1:8081".to_string());

    if !http_addr.starts_with("127.0.0.1") && !http_addr.starts_with("[::1]") {
        tracing::warn!(
            addr = %http_addr,
            "HTTP server binding to a non-loopback address; ensure network access is intentional"
        );
    }

    info!(
        backend = %cfg.backend,
        poll_secs,
        verifier_addr = %verifier_addr,
        http_addr = %http_addr,
        "template manager starting"
    );

    // ---- SINGLE-INSTANCE LOCK ----
    // Bind HTTP listener *before* starting the manager loop.
    // If this fails, we exit immediately, preventing zombie duplicate senders.
    let listener: TcpListener = TcpListener::bind(&http_addr).await.with_context(|| {
        format!("failed to bind manager HTTP at {http_addr} (already running?)")
    })?;
    info!(addr = %http_addr, "template manager HTTP listening");

    // choose backend + build shared bitcoind RPC client once
    let (source, backend_name, bitcoind_arc): (
        Box<dyn TemplateSource>,
        String,
        Option<Arc<Client>>,
    ) = match cfg.backend.trim().to_ascii_lowercase().as_str() {
        "bitcoind" => {
            let client: Arc<Client> = build_bitcoind_client(&cfg)?; // NOTE the `?`
            let cb_script = hex::decode(&cfg.coinbase_output_script_hex)
                .context("failed to decode coinbase_output_script_hex")?;

            (
                Box::new(BitcoindTemplateSource::new(
                    client.clone(),
                    cb_script,
                    cfg.extranonce_size,
                )) as Box<dyn TemplateSource>,
                "bitcoind".to_string(),
                Some(client),
            )
        }
        "stratum" => (
            Box::new(StratumTemplateSource::from_config(&cfg)) as Box<dyn TemplateSource>,
            "stratum".to_string(),
            None,
        ),
        other => {
            anyhow::bail!("Unsupported backend {other:?} (expected \"bitcoind\" or \"stratum\")")
        }
    };

    let template_log: TemplateLog = Arc::new(RwLock::new(Vec::new()));
    let latest_template: LatestTemplateState = Arc::new(RwLock::new(None));
    let mempool_log: MempoolLog = Arc::new(RwLock::new(None));
    let share_log: ShareLog = Arc::new(RwLock::new(Vec::new()));

    let share_hmac_secret: ShareHmacSecret = Arc::new(
        env::var("VELDRA_SHARE_UPSTREAM_SECRET")
            .unwrap_or_default()
            .into_bytes(),
    );
    let share_log_path: Arc<Option<String>> = Arc::new(
        env::var("VELDRA_SHARE_LOG_PATH")
            .ok()
            .filter(|s| !s.is_empty()),
    );

    // Validate share log path to prevent path traversal (TM-9).
    if let Some(ref p) = *share_log_path {
        if let Err(e) = validate_share_log_path(p) {
            tracing::error!(error = %e, "invalid VELDRA_SHARE_LOG_PATH");
            std::process::exit(1);
        }
        info!(path = %p, "share NDJSON log enabled");
    }

    // Snapshot of boot-time config for GET /settings (all read-only).
    let settings_snapshot: Arc<serde_json::Value> = Arc::new(serde_json::json!({
        "log_level": std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into()),
        "log_format": std::env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "json".into()),
        "backend": cfg.backend,
        "poll_interval_secs": poll_secs,
        "coinbase_output_script_hex": cfg.coinbase_output_script_hex,
        "extranonce_size": cfg.extranonce_size,
        "http_listen_addr": http_addr,
        "verifier_tcp_addr": verifier_addr,
        "rpc_url": cfg.rpc_url.as_deref().unwrap_or(""),
        "rpc_user": cfg.rpc_user.as_deref().unwrap_or(""),
        "rpc_pass_set": cfg.rpc_pass.is_some(),
        "stratum_addr": cfg.stratum_addr.as_deref().unwrap_or(""),
        "stratum_auth_set": cfg.stratum_auth.is_some(),
    }));

    let mgr_config_path: MgrConfigPath = Arc::new(std::path::PathBuf::from(&cfg_path));

    // Prometheus metrics
    let mut metrics_registry = Registry::default();
    let tmgr_metrics = Arc::new(TemplateManagerMetrics::new_registered(
        &mut metrics_registry,
    ));
    let shared_registry: SharedRegistry = Arc::new(metrics_registry);

    // build router once
    let app = build_router(
        template_log.clone(),
        latest_template.clone(),
        mempool_log.clone(),
        share_log,
        share_hmac_secret,
        share_log_path,
        settings_snapshot,
        mgr_config_path,
        shared_registry,
        tmgr_metrics.clone(),
    );

    // run HTTP server (if it dies, we stop)
    let http_task = tokio::spawn(async move { axum::serve(listener, app).await });

    // run manager loop (if it dies, we stop)
    let manager_task = tokio::spawn(run_manager_loop(
        source,
        verifier_addr,
        poll_secs,
        backend_name.clone(),
        template_log,
        latest_template,
        mempool_log,
        bitcoind_arc,
        tmgr_metrics,
    ));

    // If either task exits, fail loudly. In a demo product, silent partial failure is poison.
    tokio::select! {
        r = http_task => {
            let r = r.context("HTTP task join failed")?;
            r.context("HTTP server exited")?;
            anyhow::bail!("HTTP server exited");
        }
        r = manager_task => {
            r.context("manager task join failed")??;
            anyhow::bail!("manager loop exited");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_router(
    template_log: TemplateLog,
    latest_template: LatestTemplateState,
    mempool_log: MempoolLog,
    share_log: ShareLog,
    share_hmac_secret: ShareHmacSecret,
    share_log_path: Arc<Option<String>>,
    settings_snapshot: MgrBootSnapshot,
    config_path: MgrConfigPath,
    metrics_registry: SharedRegistry,
    metrics: SharedTmgrMetrics,
) -> Router {
    // Public routes: /health and /metrics bypass API key auth.
    let public = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(tmgr_metrics_handler));

    // Protected routes: require API key when VELDRA_API_SECRET is set.
    let protected = Router::new()
        .route("/templates", get(get_templates))
        .route("/latest", get(get_latest_template))
        .route("/mempool", get(get_mempool))
        .route("/shares", post(ingest_share))
        .route("/settings", get(get_settings))
        .route("/settings/save", post(save_settings))
        .layer(middleware::from_fn(api_key_middleware));

    public
        .merge(protected)
        .layer(Extension(template_log))
        .layer(Extension(latest_template))
        .layer(Extension(mempool_log))
        .layer(Extension(share_log))
        .layer(Extension(share_hmac_secret))
        .layer(Extension(share_log_path))
        .layer(Extension(settings_snapshot))
        .layer(Extension(config_path))
        .layer(Extension(metrics_registry))
        .layer(Extension(metrics))
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1 MB
}

/// Path to the manager config TOML on disk.
type MgrConfigPath = Arc<std::path::PathBuf>;

/// Boot-time settings snapshot for `pending_restart` detection.
type MgrBootSnapshot = Arc<serde_json::Value>;

async fn get_settings(
    Extension(snapshot): Extension<MgrBootSnapshot>,
    Extension(config_path): Extension<MgrConfigPath>,
) -> Json<serde_json::Value> {
    let mut resp = (*snapshot).clone();

    // Detect pending_restart by comparing boot snapshot against on-disk config.
    let pending_restart = match std::fs::read_to_string(config_path.as_ref().as_path()) {
        Ok(disk_text) => match toml::from_str::<toml::Value>(&disk_text) {
            Ok(disk_toml) => {
                let disk_snapshot = build_mgr_settings_snapshot(&disk_toml);
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

/// Build settings JSON from parsed TOML for comparison with boot snapshot.
fn build_mgr_settings_snapshot(toml_val: &toml::Value) -> serde_json::Value {
    let mgr = toml_val.get("manager");

    let get_str = |key: &str| -> String {
        mgr.and_then(|m| m.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    #[allow(clippy::cast_sign_loss)] // TOML integers are i64; config values are non-negative
    let get_u64 = |key: &str, default: u64| -> u64 {
        mgr.and_then(|m| m.get(key))
            .and_then(toml::Value::as_integer)
            .map_or(default, |i| i as u64)
    };

    serde_json::json!({
        "log_level": std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into()),
        "log_format": std::env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "json".into()),
        "backend": get_str("backend"),
        "poll_interval_secs": get_u64("poll_interval_secs", 5),
        "coinbase_output_script_hex": mgr.and_then(|m| m.get("coinbase_output_script_hex")).and_then(|v| v.as_str()).unwrap_or("51"),
        "extranonce_size": get_u64("extranonce_size", 4),
        "http_listen_addr": std::env::var("VELDRA_MANAGER_HTTP_ADDR").unwrap_or_else(|_| get_str("http_listen_addr")),
        "verifier_tcp_addr": std::env::var("VELDRA_VERIFIER_ADDR").unwrap_or_else(|_| get_str("verifier_tcp_addr")),
        "rpc_url": get_str("rpc_url"),
        "rpc_user": get_str("rpc_user"),
        "rpc_pass_set": mgr.and_then(|m| m.get("rpc_pass")).is_some(),
        "stratum_addr": get_str("stratum_addr"),
        "stratum_auth_set": mgr.and_then(|m| m.get("stratum_auth")).is_some(),
    })
}

/// Editable manager fields accepted by POST /settings/save.
#[derive(Deserialize)]
struct MgrSaveSettingsReq {
    backend: Option<String>,
    poll_interval_secs: Option<u64>,
    coinbase_output_script_hex: Option<String>,
    extranonce_size: Option<u64>,
    rpc_url: Option<String>,
    rpc_user: Option<String>,
    stratum_addr: Option<String>,
}

/// Persist manager settings changes to the TOML config file on disk.
#[allow(clippy::too_many_lines)]
async fn save_settings(
    Extension(config_path): Extension<MgrConfigPath>,
    Json(req): Json<MgrSaveSettingsReq>,
) -> impl IntoResponse {
    if let Err(e) = check_write_throttle() {
        return e;
    }

    // Validate backend if provided.
    if let Some(ref backend) = req.backend {
        let allowed = ["bitcoind", "stratum"];
        let safe_backend = if backend.len() > 64 {
            &backend[..64]
        } else {
            backend.as_str()
        };
        if !allowed.contains(&backend.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("invalid backend: {safe_backend}; expected one of {allowed:?}") }),
                ),
            );
        }
    }

    // Validate extranonce_size if provided.
    if let Some(size) = req.extranonce_size
        && (size == 0 || size > 32)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({ "ok": false, "error": format!("extranonce_size must be 1..=32, got {size}") }),
            ),
        );
    }

    // Validate coinbase_output_script_hex if provided.
    if let Some(ref hex_str) = req.coinbase_output_script_hex
        && hex::decode(hex_str).is_err()
    {
        let safe_hex = if hex_str.len() > 64 {
            &hex_str[..64]
        } else {
            hex_str
        };
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({ "ok": false, "error": format!("coinbase_output_script_hex is not valid hex: {safe_hex}") }),
            ),
        );
    }

    // Read current TOML from disk.
    let toml_text = match std::fs::read_to_string(config_path.as_ref().as_path()) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("failed to read config: {e}") }),
                ),
            );
        }
    };

    let mut doc: toml::Value = match toml::from_str(&toml_text) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("{e}");
            let truncated = if msg.len() > 200 { &msg[..200] } else { &msg };
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("failed to parse config: {truncated}") }),
                ),
            );
        }
    };

    // Patch editable fields into [manager] section.
    #[allow(clippy::cast_possible_wrap, clippy::cast_lossless)]
    if let Some(mgr) = doc.get_mut("manager").and_then(|v| v.as_table_mut()) {
        if let Some(ref val) = req.backend {
            mgr.insert("backend".to_string(), toml::Value::String(val.clone()));
        }
        if let Some(val) = req.poll_interval_secs {
            mgr.insert(
                "poll_interval_secs".to_string(),
                toml::Value::Integer(val as i64),
            );
        }
        if let Some(ref val) = req.coinbase_output_script_hex {
            mgr.insert(
                "coinbase_output_script_hex".to_string(),
                toml::Value::String(val.clone()),
            );
        }
        if let Some(val) = req.extranonce_size {
            mgr.insert(
                "extranonce_size".to_string(),
                toml::Value::Integer(val as i64),
            );
        }
        if let Some(ref val) = req.rpc_url {
            mgr.insert("rpc_url".to_string(), toml::Value::String(val.clone()));
        }
        if let Some(ref val) = req.rpc_user {
            mgr.insert("rpc_user".to_string(), toml::Value::String(val.clone()));
        }
        if let Some(ref val) = req.stratum_addr {
            mgr.insert("stratum_addr".to_string(), toml::Value::String(val.clone()));
        }
    }

    // Re-validate by parsing the patched TOML through the config loader.
    let patched_text = match toml::to_string_pretty(&doc) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("failed to serialize: {e}") }),
                ),
            );
        }
    };

    // Write to a temp file and validate via TemplateManagerConfig::from_path.
    let tmp_validate = config_path.with_extension("toml.validate");
    if let Err(e) = std::fs::write(&tmp_validate, &patched_text) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "ok": false, "error": format!("failed to write temp: {e}") })),
        );
    }

    match TemplateManagerConfig::from_path(&tmp_validate) {
        Ok(_) => {
            let _ = std::fs::remove_file(&tmp_validate);
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_validate);
            let msg = format!("{e}");
            let truncated = if msg.len() > 200 { &msg[..200] } else { &msg };
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "ok": false, "error": format!("validation failed: {truncated}") }),
                ),
            );
        }
    }

    // Atomic write to disk.
    if let Err(e) = reservegrid_common::config_io::atomic_write_toml(config_path.as_ref(), &doc) {
        error!(error = %e, "failed to save manager config to disk");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "ok": false, "error": format!("failed to write config: {e}") }),
            ),
        );
    }

    info!(
        event = "settings_saved",
        path = %config_path.display(),
        "manager config saved to disk"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "restart_required": true })),
    )
}

async fn fetch_mempool_info_with_retries(
    client: Arc<Client>,
    mempool_had_rpc_error: &mut bool,
) -> Option<bitcoincore_rpc::json::GetMempoolInfoResult> {
    let mut attempts = 0;

    loop {
        let client2 = client.clone();
        let res = tokio::task::spawn_blocking(move || client2.get_mempool_info()).await;

        match res {
            Ok(Ok(info)) => {
                if *mempool_had_rpc_error {
                    info!("get_mempool_info RPC recovered");
                    *mempool_had_rpc_error = false;
                }
                return Some(info);
            }
            Ok(Err(e)) => {
                attempts += 1;
                warn!(attempts, error = ?e, "get_mempool_info failed");
            }
            Err(join_err) => {
                attempts += 1;
                error!(attempts, error = ?join_err, "get_mempool_info spawn_blocking join error");
            }
        }

        if attempts >= 3 {
            warn!(
                attempts,
                "get_mempool_info giving up for this poll, will retry next tick"
            );
            *mempool_had_rpc_error = true;
            return None;
        }

        sleep(Duration::from_millis(200)).await;
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_manager_loop(
    mut source: Box<dyn TemplateSource>,
    verifier_addr: String,
    poll_secs: u64,
    backend_name: String,
    template_log: TemplateLog,
    latest_template: LatestTemplateState,
    mempool_log: MempoolLog,
    bitcoind_client: Option<Arc<Client>>,
    metrics: SharedTmgrMetrics,
) -> Result<()> {
    let mut mempool_had_rpc_error = false;

    let connect_timeout = Duration::from_secs(2);
    let verdict_timeout = Duration::from_secs(4);

    loop {
        // ---- template handling ----
        match source.next_template().await {
            Ok(Some((propose, extras))) => {
                metrics.templates_polled_total.inc();
                info!(
                    backend = %backend_name,
                    id = propose.id,
                    height = propose.block_height,
                    prev_hash = %propose.prev_hash,
                    coinbase_value = propose.coinbase_value,
                    total_fees = propose.total_fees,
                    tx_count = propose.tx_count,
                    "new template"
                );

                match timeout(connect_timeout, TcpStream::connect(&verifier_addr)).await {
                    Ok(Ok(stream)) => {
                        match timeout(verdict_timeout, send_and_receive(stream, &propose)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => warn!(
                                template_id = propose.id,
                                verifier_addr = %verifier_addr,
                                error = ?e,
                                "error sending template to verifier"
                            ),
                            Err(_) => warn!(
                                template_id = propose.id,
                                verifier_addr = %verifier_addr,
                                "verifier timed out on send/recv"
                            ),
                        }
                    }
                    Ok(Err(e)) => warn!(
                        verifier_addr = %verifier_addr,
                        error = ?e,
                        "failed to connect to verifier"
                    ),
                    Err(_) => warn!(verifier_addr = %verifier_addr, "connect timeout to verifier"),
                }

                // store for /templates (summary log)
                {
                    let mut log = template_log.write().await;
                    log.push(LoggedTemplate {
                        id: propose.id,
                        height: propose.block_height,
                        total_fees: propose.total_fees,
                        backend: backend_name.clone(),
                        timestamp: now_unix_secs(),
                    });
                    if log.len() > TEMPLATE_LOG_CAP {
                        let drain = log.len() - TEMPLATE_LOG_CAP;
                        log.drain(0..drain);
                    }
                    #[allow(clippy::cast_possible_wrap)]
                    metrics.templates_cached.set(log.len() as i64);
                }

                // store for /latest (full template for gateway)
                {
                    let gbt = extras.unwrap_or(GbtExtras {
                        block_version: 0,
                        nbits: 0,
                        min_ntime: 0,
                        #[allow(clippy::cast_possible_truncation)]
                        // Safe: Unix timestamps fit in u32 until year 2106
                        curtime: now_unix_secs() as u32,
                        coinbase_tx_prefix: String::new(),
                        coinbase_tx_suffix: String::new(),
                        merkle_path: Vec::new(),
                    });
                    let mut slot = latest_template.write().await;
                    *slot = Some(LatestTemplate {
                        template_id: propose.id,
                        block_height: propose.block_height,
                        block_version: gbt.block_version,
                        prev_hash: propose.prev_hash,
                        nbits: gbt.nbits,
                        nbits_hex: gbt.nbits,
                        min_ntime: gbt.min_ntime,
                        curtime: gbt.curtime,
                        coinbase_value: propose.coinbase_value,
                        coinbase_tx_prefix: gbt.coinbase_tx_prefix,
                        coinbase_tx_suffix: gbt.coinbase_tx_suffix,
                        merkle_path: gbt.merkle_path,
                        tx_count: propose.tx_count,
                        total_fees: propose.total_fees,
                        source_instance_id: instance_id(),
                        observed_weight: propose.observed_weight,
                        template_weight: propose.template_weight,
                        total_sigops: propose.total_sigops,
                        coinbase_sigops: propose.coinbase_sigops,
                        raw_block_hex: propose.raw_block_hex.clone(),
                    });
                }
            }
            Ok(None) => {}
            Err(e) => {
                metrics.poll_errors_total.inc();
                error!(error = ?e, "error getting template from source");
            }
        }

        // ---- mempool snapshot when backend == bitcoind ----
        if backend_name == "bitcoind" {
            if let Some(ref client) = bitcoind_client {
                if let Some(info) =
                    fetch_mempool_info_with_retries(client.clone(), &mut mempool_had_rpc_error)
                        .await
                {
                    let stats = MempoolStats {
                        loaded_from: "bitcoind".to_string(),
                        tx_count: info.size as u64,
                        bytes: info.bytes as u64,
                        usage: info.usage as u64,
                        max: info.max_mempool as u64,
                        min_relay_fee: info.mempool_min_fee.to_sat(),
                        timestamp: now_unix_secs(),
                    };

                    let mut slot = mempool_log.write().await;
                    *slot = Some(stats);
                }
            } else {
                error!("bitcoind_client is None while backend_name=bitcoind");
            }
        }

        if backend_name == "bitcoind" {
            sleep(Duration::from_secs(poll_secs)).await;
        }
    }
}

async fn send_and_receive(mut stream: TcpStream, propose: &TemplatePropose) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let json = serde_json::to_string(propose)?;
    timeout(Duration::from_secs(2), writer.write_all(json.as_bytes())).await??;
    timeout(Duration::from_secs(2), writer.write_all(b"\n")).await??;
    timeout(Duration::from_secs(2), writer.flush()).await??;

    let mut line = String::new();
    let bytes_read = timeout(Duration::from_secs(3), reader.read_line(&mut line)).await??;
    if bytes_read == 0 {
        anyhow::bail!("verifier closed connection without sending a verdict");
    }

    let verdict: TemplateVerdict = serde_json::from_str(line.trim())?;
    info!(
        id = verdict.id,
        accepted = verdict.accepted,
        reason_code = ?verdict.reason_code,
        reason_detail = ?verdict.reason_detail,
        "received TemplateVerdict"
    );

    Ok(())
}

// HTTP handlers

async fn health_check() -> &'static str {
    "ok"
}

async fn get_templates(Extension(log): Extension<TemplateLog>) -> Json<Vec<LoggedTemplate>> {
    let log = log.read().await;
    Json(log.clone())
}

async fn get_latest_template(
    Extension(latest): Extension<LatestTemplateState>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let guard = latest.read().await;
    match guard.as_ref() {
        Some(tpl) => Json(tpl.clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({"error": "no_template", "detail": "no template available yet"}),
            ),
        )
            .into_response(),
    }
}

async fn get_mempool(Extension(mem): Extension<MempoolLog>) -> Json<MempoolStats> {
    let mem = mem.read().await;

    let snapshot = mem.clone().unwrap_or_else(|| MempoolStats {
        loaded_from: "unknown".to_string(),
        tx_count: 0,
        bytes: 0,
        usage: 0,
        max: 0,
        min_relay_fee: 0,
        timestamp: now_unix_secs(),
    });

    Json(snapshot)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[allow(clippy::cast_possible_truncation)] // millis since epoch fits u64 for centuries
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

// ── Share ingest ──────────────────────────────────────────────────

/// Inbound share submission from the SV2 gateway.
/// Field names match the gateway's `ShareSubmission` serialization exactly.
#[derive(Debug, Deserialize, Serialize, Clone)]
struct ShareSubmissionRecord {
    share_id_hex: String,
    version: u32,
    prev_hash_wire_hex: String,
    prev_hash_display_hex: String,
    merkle_root_wire_hex: String,
    merkle_root_display_hex: String,
    ntime: u32,
    nbits: u32,
    nonce: u32,
    event_id_hex: String,
    worker_id: String,
    validation_level: String,
    gateway_instance_id: String,
    channel_id: u32,
    sequence_number: u32,
    job_id: u32,
    template_id: u64,
    block_height: u32,
    #[serde(default)]
    pool_account_id: Option<String>,
    timestamp_ms: u64,
    difficulty_u64: u64,
    difficulty_display: f64,
    source_instance_id: String,
    #[serde(default)]
    gateway_signature_hex: String,
}

/// Response returned to the gateway relay.
#[derive(Serialize)]
struct ShareUpstreamResponse {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// POST /shares handler.
///
/// Accepts a `ShareSubmissionRecord` from the gateway, optionally verifies the
/// HMAC gateway signature, appends to the in-memory share log, and writes an
/// NDJSON line to the share log file when `VELDRA_SHARE_LOG_PATH` is set.
#[allow(clippy::too_many_lines)]
async fn ingest_share(
    Extension(share_log): Extension<ShareLog>,
    Extension(hmac_secret): Extension<ShareHmacSecret>,
    Extension(share_log_path): Extension<Arc<Option<String>>>,
    Extension(metrics): Extension<SharedTmgrMetrics>,
    Json(submission): Json<ShareSubmissionRecord>,
) -> Json<ShareUpstreamResponse> {
    metrics.shares_ingested_total.inc();

    // Validate field sizes to prevent abuse (TM-18).
    if submission.share_id_hex.len() > MAX_SHARE_HEX_FIELD
        || submission.prev_hash_wire_hex.len() > MAX_SHARE_HEX_FIELD
        || submission.prev_hash_display_hex.len() > MAX_SHARE_HEX_FIELD
        || submission.merkle_root_wire_hex.len() > MAX_SHARE_HEX_FIELD
        || submission.merkle_root_display_hex.len() > MAX_SHARE_HEX_FIELD
        || submission.event_id_hex.len() > MAX_SHARE_HEX_FIELD
        || submission.gateway_signature_hex.len() > MAX_SHARE_HEX_FIELD
        || submission.worker_id.len() > MAX_SHARE_STRING_FIELD
        || submission.gateway_instance_id.len() > MAX_SHARE_STRING_FIELD
        || submission.source_instance_id.len() > MAX_SHARE_STRING_FIELD
        || submission.validation_level.len() > MAX_SHARE_STRING_FIELD
    {
        warn!("share rejected: one or more fields exceed maximum length");
        return Json(ShareUpstreamResponse {
            accepted: false,
            reason: Some("field_size_exceeded".to_string()),
        });
    }

    // Verify HMAC signature when secret is configured.
    if !hmac_secret.is_empty() {
        if submission.gateway_signature_hex.is_empty() {
            warn!(
                share_id = %submission.share_id_hex,
                "share rejected: missing gateway signature",
            );
            return Json(ShareUpstreamResponse {
                accepted: false,
                reason: Some(GatewayReason::MissingGatewaySignature.as_str().to_string()),
            });
        }

        let Ok(sig_bytes) = hex::decode(&submission.gateway_signature_hex) else {
            warn!(
                share_id = %submission.share_id_hex,
                "share rejected: malformed gateway signature hex",
            );
            return Json(ShareUpstreamResponse {
                accepted: false,
                reason: Some(
                    GatewayReason::MalformedGatewaySignature
                        .as_str()
                        .to_string(),
                ),
            });
        };

        let event_id_bytes = match hex::decode(&submission.event_id_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                warn!(
                    share_id = %submission.share_id_hex,
                    "share rejected: malformed event_id_hex",
                );
                return Json(ShareUpstreamResponse {
                    accepted: false,
                    reason: Some(GatewayReason::MalformedEventId.as_str().to_string()),
                });
            }
        };

        let body_hash = canonical_body_hash(&submission);
        if !verify_gateway_signature(&hmac_secret, &event_id_bytes, &body_hash, &sig_bytes) {
            warn!(
                share_id = %submission.share_id_hex,
                "share rejected: invalid gateway signature",
            );
            return Json(ShareUpstreamResponse {
                accepted: false,
                reason: Some(GatewayReason::InvalidGatewaySignature.as_str().to_string()),
            });
        }
    }

    debug!(
        share_id = %submission.share_id_hex,
        template_id = submission.template_id,
        worker = %submission.worker_id,
        difficulty = submission.difficulty_u64,
        "share accepted",
    );

    // Append NDJSON to the share log file (best effort, logged on failure).
    if let Some(ref path) = *share_log_path
        && let Ok(line) = serde_json::to_string(&submission)
    {
        use tokio::fs::OpenOptions;
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
        {
            Ok(mut f) => {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = f.write_all(line.as_bytes()).await {
                    warn!(error = %e, path = %path, "failed to write share log line");
                }
                if let Err(e) = f.write_all(b"\n").await {
                    warn!(error = %e, path = %path, "failed to write share log newline");
                }
            }
            Err(e) => {
                warn!(error = %e, path = %path, "failed to open share log file");
            }
        }
    }

    // Append to in-memory log (bounded to last 10,000 entries).
    // When the cap is reached, drain down to 8,000 so the buffer
    // does not grow unbounded under sustained load.
    {
        let mut log = share_log.write().await;
        if log.len() >= 10_000 {
            let keep_from = log.len().saturating_sub(8_000);
            log.drain(..keep_from);
        }
        log.push(submission);
    }

    Json(ShareUpstreamResponse {
        accepted: true,
        reason: None,
    })
}

/// SHA-256 over the canonical JSON body, which is the submission serialized
/// with `gateway_signature_hex` emptied.
///
/// PB-37: this MUST reproduce, byte for byte, what
/// `sv2_gateway::shares::sign_submission` hashed on the other side. Two things
/// make that true and both are load bearing. The signature field is cleared
/// before serializing, because the signer cannot hash its own output. And
/// `ShareSubmissionRecord` must stay field-for-field identical to the
/// gateway's `ShareSubmission`, in DECLARATION ORDER, because `serde_json` emits
/// fields in that order; `the_two_wire_structs_serialize_to_identical_bytes`
/// fails loudly if either declaration drifts.
fn canonical_body_hash(submission: &ShareSubmissionRecord) -> [u8; 32] {
    use sha2::Digest;
    let mut canonical = submission.clone();
    canonical.gateway_signature_hex = String::new();
    // Serialization of this struct cannot fail: every field is a plain scalar,
    // String or Option<String>. Fail closed on the impossible branch rather
    // than unwrapping, so a future field that can fail cannot forge a match.
    match serde_json::to_vec(&canonical) {
        Ok(bytes) => sha2::Sha256::digest(&bytes).into(),
        Err(_) => [0u8; 32],
    }
}

/// Verify that `signature` matches HMAC-SHA256(secret, `event_id || body_hash`).
///
/// PB-37: the signer at `sv2_gateway::shares::compute_gateway_signature` binds
/// BOTH the event id and the body hash, and this side used to bind the event id
/// alone, so every correctly signed share was rejected whenever
/// `VELDRA_SHARE_UPSTREAM_SECRET` was set. The signer's form is normative
/// because binding the body is what stops a captured signature being replayed
/// onto a different submission; dropping the body hash here would restore that
/// replay hole even if the two sides agreed again.
fn verify_gateway_signature(
    secret: &[u8],
    event_id: &[u8; 32],
    body_hash: &[u8; 32],
    signature: &[u8],
) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(event_id);
    mac.update(body_hash);
    mac.verify_slice(signature).is_ok()
}

/// Extract `coinbasetxn.sigops` from raw GBT JSON.
/// Returns `None` when the field is absent (older Bitcoin Core or
/// when the `coinbasetxn` capability was not honoured).
#[allow(clippy::cast_possible_truncation)]
fn extract_coinbase_sigops(raw: &serde_json::Value) -> Option<u32> {
    raw.get("coinbasetxn")
        .and_then(|cbtxn| cbtxn.get("sigops"))
        .and_then(serde_json::Value::as_u64)
        .map(|v| v as u32) // Safe: sigops count is limited to a few thousand
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── PB-19 / Phase 1b: raw block assembly ───────────────────────

    #[test]
    fn coinbase_halves_reject_scriptsig_over_100_bytes() {
        // Consensus bad-cb-length caps the coinbase scriptSig at 100
        // bytes; a 252-byte cap ships coinbases Core rejects and the
        // shield flags (v2_invariant_coinbase_script_length). Height
        // push (2) + aux (0) + extranonce (99) = 101: must fail.
        let r = build_coinbase_halves(102, 5_000_000_000, &[0x51], 99, &[], None);
        assert!(r.is_err(), "scriptSig of 101 bytes must be refused");
        // 98 extranonce bytes = exactly 100: allowed.
        let r = build_coinbase_halves(102, 5_000_000_000, &[0x51], 98, &[], None);
        assert!(r.is_ok(), "scriptSig of exactly 100 bytes is valid");
    }

    #[test]
    fn display_hex_to_internal_reverses_byte_order() {
        let display = hex::encode((0..32u8).collect::<Vec<u8>>());
        let internal = display_hex_to_internal(&display).expect("valid hex");
        assert_eq!(internal[0], 31, "internal order is display reversed");
        assert_eq!(internal[31], 0);
        assert!(display_hex_to_internal("zz").is_none());
        assert!(display_hex_to_internal("aabb").is_none(), "wrong length");
    }

    #[test]
    fn assemble_raw_block_hex_produces_shield_clean_block() {
        // Legacy-only template (no txs, no commitment): the assembled
        // hex must parse and satisfy every shield check the verifier
        // will run against it, using the same facade.
        let (prefix, suffix) =
            build_coinbase_halves(102, 5_000_000_000, &[0x51], 8, &[], None).expect("halves");
        let prev_display: String = "ab".repeat(32);
        let hex_str = assemble_raw_block_hex(
            0x2000_0000,
            0x207f_ffff,
            1_700_000_000,
            &prev_display,
            &prefix,
            &suffix,
            8,
            &[],
        )
        .expect("assembly succeeds");
        let raw = hex::decode(&hex_str).expect("valid hex");
        let block = rg_consensus::parse_block(&raw).expect("parses");
        rg_consensus::check_merkle_root_internal(&block).expect("merkle agrees");
        rg_consensus::check_witness_commitment_internal(&block).expect("legacy ok");
        rg_consensus::check_coinbase_bip34_present(&block).expect("height push");
        assert_eq!(rg_consensus::bip34_height(&block).unwrap(), 102);
        rg_consensus::check_coinbase_script_length(&block).expect("script len");
        rg_consensus::check_header_version(&block).expect("version ok");
        assert_eq!(
            rg_consensus::re_derive_coinbase_value(&raw).unwrap(),
            5_000_000_000
        );
        assert_eq!(rg_consensus::tx_count(&block), 1);
    }

    #[test]
    fn assemble_raw_block_hex_returns_none_on_bad_prev_hash() {
        let (prefix, suffix) =
            build_coinbase_halves(102, 5_000_000_000, &[0x51], 8, &[], None).expect("halves");
        assert!(
            assemble_raw_block_hex(4, 0x207f_ffff, 0, "nothex", &prefix, &suffix, 8, &[]).is_none()
        );
    }

    #[test]
    fn bip34_height_zero() {
        let push = bip34_height_push(0);
        assert_eq!(push, vec![0x01, 0x00]);
    }

    #[test]
    fn bip34_height_one() {
        let push = bip34_height_push(1);
        // CScriptNum(1) = [0x01], push opcode = 0x01
        assert_eq!(push, vec![0x01, 0x01]);
    }

    #[test]
    fn bip34_height_127() {
        let push = bip34_height_push(127);
        assert_eq!(push, vec![0x01, 0x7f]);
    }

    #[test]
    fn bip34_height_128_needs_sign_byte() {
        // 128 = 0x80, high bit set so needs 0x00 appended
        let push = bip34_height_push(128);
        assert_eq!(push, vec![0x02, 0x80, 0x00]);
    }

    #[test]
    fn bip34_height_255() {
        // 255 = 0xFF, high bit set
        let push = bip34_height_push(255);
        assert_eq!(push, vec![0x02, 0xff, 0x00]);
    }

    #[test]
    fn bip34_height_256() {
        // 256 = 0x0100 LE = [0x00, 0x01], high bit of 0x01 not set
        let push = bip34_height_push(256);
        assert_eq!(push, vec![0x02, 0x00, 0x01]);
    }

    #[test]
    fn bip34_height_1000000() {
        // 1_000_000 = 0x0F4240, LE = [0x40, 0x42, 0x0f]
        let push = bip34_height_push(1_000_000);
        assert_eq!(push, vec![0x03, 0x40, 0x42, 0x0f]);
    }

    #[test]
    fn coinbase_halves_round_trip() {
        let height = 200u32;
        let value = 5_000_000_000u64;
        let script = vec![0x51]; // OP_TRUE
        let en_size = 4;

        let (prefix, suffix) =
            build_coinbase_halves(height, value, &script, en_size, &[], None).unwrap();

        // Assemble with a dummy extranonce and verify structural invariants.
        let extranonce = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut tx = Vec::new();
        tx.extend_from_slice(&prefix);
        tx.extend_from_slice(&extranonce);
        tx.extend_from_slice(&suffix);

        // Version = 2
        assert_eq!(&tx[0..4], &2u32.to_le_bytes());
        // Input count = 1
        assert_eq!(tx[4], 0x01);
        // Prevout hash = 32 zero bytes
        assert_eq!(&tx[5..37], &[0u8; 32]);
        // Prevout index = 0xFFFFFFFF
        assert_eq!(&tx[37..41], &0xFFFF_FFFFu32.to_le_bytes());

        // scriptSig length
        let height_push = bip34_height_push(height);
        let expected_ss_len = height_push.len() + en_size;
        assert_eq!(tx[41] as usize, expected_ss_len);

        // BIP34 height push starts at byte 42
        assert_eq!(&tx[42..42 + height_push.len()], &height_push[..]);

        // Extranonce follows
        let en_start = 42 + height_push.len();
        assert_eq!(&tx[en_start..en_start + 4], &extranonce);

        // Sequence follows extranonce
        let seq_start = en_start + 4;
        assert_eq!(&tx[seq_start..seq_start + 4], &0xFFFF_FFFFu32.to_le_bytes());

        // Output count
        assert_eq!(tx[seq_start + 4], 0x01);

        // Output value
        let val_start = seq_start + 5;
        assert_eq!(&tx[val_start..val_start + 8], &value.to_le_bytes());

        // Output scriptPubKey length + script
        assert_eq!(tx[val_start + 8], 0x01); // script length
        assert_eq!(tx[val_start + 9], 0x51); // OP_TRUE

        // Locktime
        let lt_start = val_start + 10;
        assert_eq!(&tx[lt_start..lt_start + 4], &0u32.to_le_bytes());

        // No trailing bytes
        assert_eq!(tx.len(), lt_start + 4);
    }

    #[test]
    fn coinbase_halves_different_heights_differ() {
        let script = vec![0x51];
        let (p1, _) = build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], None).unwrap();
        let (p2, _) = build_coinbase_halves(200, 5_000_000_000, &script, 4, &[], None).unwrap();
        assert_ne!(p1, p2, "different heights must produce different prefixes");
    }

    // ── Witness commitment coinbase tests ──

    #[test]
    fn coinbase_halves_no_witness_single_output() {
        let script = vec![0x51];
        let (_, suffix) = build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], None).unwrap();
        // After sequence (4 bytes), output count should be 1.
        assert_eq!(suffix[4], 0x01, "no witness: output count must be 1");
    }

    #[test]
    fn coinbase_halves_with_witness_two_outputs() {
        let script = vec![0x51]; // OP_TRUE
        // Construct a mock witness commitment script:
        // OP_RETURN (0x6a) + PUSH_36 (0x24) + magic (aa21a9ed) + 32 zero bytes
        let mut wc_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        wc_script.extend_from_slice(&[0u8; 32]);

        let (prefix, suffix) =
            build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], Some(&wc_script)).unwrap();

        // Assemble full tx to verify structure.
        let extranonce = [0x01, 0x00, 0x00, 0x00];
        let mut tx = Vec::new();
        tx.extend_from_slice(&prefix);
        tx.extend_from_slice(&extranonce);
        tx.extend_from_slice(&suffix);

        // Output count = 2 (at offset 4 in suffix, which is after sequence).
        assert_eq!(suffix[4], 0x02, "with witness: output count must be 2");

        // Output 0: payout value and script.
        let out0_val_start = 5; // sequence(4) + output_count(1)
        let out0_val = u64::from_le_bytes(
            suffix[out0_val_start..out0_val_start + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(out0_val, 5_000_000_000);
        let out0_script_len = suffix[out0_val_start + 8] as usize;
        assert_eq!(out0_script_len, 1); // OP_TRUE is 1 byte
        assert_eq!(suffix[out0_val_start + 9], 0x51);

        // Output 1: witness commitment (value 0).
        let out1_start = out0_val_start + 9 + out0_script_len;
        let out1_val = u64::from_le_bytes(suffix[out1_start..out1_start + 8].try_into().unwrap());
        assert_eq!(out1_val, 0, "witness commitment output must have value 0");
        let out1_script_len = suffix[out1_start + 8] as usize;
        assert_eq!(out1_script_len, wc_script.len());

        // Verify the witness commitment script bytes.
        let out1_script_start = out1_start + 9;
        assert_eq!(
            &suffix[out1_script_start..out1_script_start + wc_script.len()],
            &wc_script[..]
        );
        // OP_RETURN
        assert_eq!(suffix[out1_script_start], 0x6a);
        // Magic bytes
        assert_eq!(
            &suffix[out1_script_start + 2..out1_script_start + 6],
            &[0xaa, 0x21, 0xa9, 0xed]
        );

        // Locktime at the very end.
        let lt_start = out1_script_start + wc_script.len();
        assert_eq!(
            &suffix[lt_start..lt_start + 4],
            &0u32.to_le_bytes(),
            "locktime must be zero"
        );
        // No trailing bytes.
        assert_eq!(suffix.len(), lt_start + 4);
    }

    #[test]
    fn coinbase_halves_witness_does_not_affect_prefix() {
        let script = vec![0x51];
        let mut wc = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        wc.extend_from_slice(&[0u8; 32]);

        let (prefix_no_wc, _) =
            build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], None).unwrap();
        let (prefix_with_wc, _) =
            build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], Some(&wc)).unwrap();

        assert_eq!(
            prefix_no_wc, prefix_with_wc,
            "witness commitment must not affect the prefix"
        );
    }

    // ── Merkle branch tests ──

    /// Helper: create a display-order txid hex string from a known 32-byte
    /// internal-order hash. Display order is the reverse of internal.
    fn internal_to_display_hex(internal: &[u8; 32]) -> String {
        let mut display = *internal;
        display.reverse();
        hex::encode(display)
    }

    #[test]
    fn merkle_branch_empty_txids() {
        let branch = compute_merkle_branch(&[]).unwrap();
        assert!(branch.is_empty(), "zero txids should produce empty branch");
    }

    #[test]
    fn merkle_branch_single_tx() {
        // One transaction: merkle tree has [coinbase, tx1].
        // Branch for index 0 is [tx1_internal].
        let tx1_internal = [0xAA_u8; 32];
        let tx1_display = internal_to_display_hex(&tx1_internal);

        let branch = compute_merkle_branch(&[tx1_display]).unwrap();
        assert_eq!(branch.len(), 1, "one tx produces one branch element");
        assert_eq!(
            branch[0],
            hex::encode(tx1_internal),
            "branch element must be tx1 in internal byte order"
        );
    }

    #[test]
    fn merkle_branch_two_txs() {
        // Two transactions: tree leaves = [CB, A, B].
        // Odd count (3), so B is duplicated: [CB, A, B, B].
        // Level 0 sibling of CB is A.
        // Level 1: [H(CB,A), H(B,B)] -> sibling of index 0 is H(B,B).
        let a_internal = [0x11_u8; 32];
        let b_internal = [0x22_u8; 32];

        let a_display = internal_to_display_hex(&a_internal);
        let b_display = internal_to_display_hex(&b_internal);

        let branch = compute_merkle_branch(&[a_display, b_display]).unwrap();
        assert_eq!(branch.len(), 2, "two txs produce two branch elements");

        // First element: A in internal order.
        assert_eq!(branch[0], hex::encode(a_internal));

        // Second element: H(B || B).
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&b_internal);
        combined[32..].copy_from_slice(&b_internal);
        let h_bb = sha256d(&combined);
        assert_eq!(branch[1], hex::encode(h_bb));
    }

    #[test]
    fn merkle_branch_three_txs() {
        // Three transactions: tree leaves = [CB, A, B, C] (even count 4).
        // Level 0: sibling of CB (idx 0) is A (idx 1).
        // Level 1: [H(CB,A), H(B,C)] -> sibling of idx 0 is H(B,C).
        let a = [0x11_u8; 32];
        let b = [0x22_u8; 32];
        let c = [0x33_u8; 32];

        let txids: Vec<String> = [a, b, c].iter().map(internal_to_display_hex).collect();

        let branch = compute_merkle_branch(&txids).unwrap();
        assert_eq!(branch.len(), 2);

        // First: A
        assert_eq!(branch[0], hex::encode(a));

        // Second: H(B || C)
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&b);
        combined[32..].copy_from_slice(&c);
        let h_bc = sha256d(&combined);
        assert_eq!(branch[1], hex::encode(h_bc));
    }

    #[test]
    fn merkle_branch_round_trip_with_gateway_root() {
        // Verify that compute_merkle_branch + gateway's compute_merkle_root
        // produce the same root as direct tree computation.
        //
        // Tree: [CB, A, B] with CB = sha256d(prefix || extranonce || suffix)
        let prefix = vec![0x02, 0x00, 0x00, 0x00, 0x01];
        let extranonce = [0xDE, 0xAD, 0xBE, 0xEF];
        let suffix = vec![0xFF, 0xFF, 0xFF, 0xFF];

        let a_internal = [0x44_u8; 32];
        let a_display = internal_to_display_hex(&a_internal);

        let branch = compute_merkle_branch(&[a_display]).unwrap();
        assert_eq!(branch.len(), 1);

        // Compute merkle root the same way the gateway does.
        let mut coinbase = Vec::new();
        coinbase.extend_from_slice(&prefix);
        coinbase.extend_from_slice(&extranonce);
        coinbase.extend_from_slice(&suffix);
        let cb_txid = sha256d(&coinbase);

        // Walk the branch: root = sha256d(cb_txid || branch[0])
        let branch_bytes: Vec<[u8; 32]> = branch
            .iter()
            .map(|h| {
                let b = hex::decode(h).unwrap();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            })
            .collect();

        let mut current = cb_txid;
        for sibling in &branch_bytes {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(sibling);
            current = sha256d(&combined);
        }
        let root_via_branch = current;

        // Compute root directly: sha256d(sha256d(cb_txid || a_internal))
        // No, for a 2-leaf tree: root = sha256d(cb_txid || a_internal)
        let mut direct_combined = [0u8; 64];
        direct_combined[..32].copy_from_slice(&cb_txid);
        direct_combined[32..].copy_from_slice(&a_internal);
        let root_direct = sha256d(&direct_combined);

        assert_eq!(
            root_via_branch, root_direct,
            "merkle root via branch must match direct computation"
        );
    }

    #[test]
    fn merkle_branch_seven_txs() {
        // Seven txs: tree leaves = [CB, T1..T7] = 8 leaves (even, power of 2).
        // This tests a balanced 3-level tree.
        let txs: Vec<[u8; 32]> = (1..=7u8)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0] = i;
                arr
            })
            .collect();

        let txid_hex: Vec<String> = txs.iter().map(internal_to_display_hex).collect();
        let branch = compute_merkle_branch(&txid_hex).unwrap();

        // 8 leaves -> 3 levels -> 3 branch elements.
        assert_eq!(branch.len(), 3, "8 leaves produce 3 branch elements");

        // Level 0: sibling of CB (idx 0) is T1 (idx 1).
        assert_eq!(branch[0], hex::encode(txs[0]));

        // Level 1: sibling is H(T2 || T3)
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&txs[1]);
        combined[32..].copy_from_slice(&txs[2]);
        let h_t2_t3 = sha256d(&combined);
        assert_eq!(branch[1], hex::encode(h_t2_t3));

        // Level 2: sibling is the right subtree hash H(H(T4||T5), H(T6||T7))
        let mut c45 = [0u8; 64];
        c45[..32].copy_from_slice(&txs[3]);
        c45[32..].copy_from_slice(&txs[4]);
        let h_t4_t5 = sha256d(&c45);

        let mut c67 = [0u8; 64];
        c67[..32].copy_from_slice(&txs[5]);
        c67[32..].copy_from_slice(&txs[6]);
        let h_t6_t7 = sha256d(&c67);

        let mut c_right = [0u8; 64];
        c_right[..32].copy_from_slice(&h_t4_t5);
        c_right[32..].copy_from_slice(&h_t6_t7);
        let h_right = sha256d(&c_right);
        assert_eq!(branch[2], hex::encode(h_right));
    }

    #[test]
    fn merkle_branch_invalid_hex_errors() {
        let result = compute_merkle_branch(&["not_valid_hex".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn merkle_branch_wrong_length_errors() {
        // Valid hex but not 32 bytes.
        let result = compute_merkle_branch(&["aabb".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn coinbase_halves_different_values_differ() {
        let script = vec![0x51];
        let (_, s1) = build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], None).unwrap();
        let (_, s2) = build_coinbase_halves(100, 3_000_000_000, &script, 4, &[], None).unwrap();
        assert_ne!(
            s1, s2,
            "different coinbase values must produce different suffixes"
        );
    }

    // ── coinbaseaux tests ──

    #[test]
    fn coinbase_aux_empty_matches_no_aux() {
        let script = vec![0x51];
        let (p1, s1) = build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], None).unwrap();
        let (p2, s2) = build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], None).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn coinbase_aux_appears_in_prefix_after_height() {
        let script = vec![0x51];
        let aux = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let (prefix_no_aux, _) =
            build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], None).unwrap();
        let (prefix_with_aux, _) =
            build_coinbase_halves(100, 5_000_000_000, &script, 4, &aux, None).unwrap();

        // The prefix with aux must be longer by exactly aux.len() bytes.
        assert_eq!(
            prefix_with_aux.len(),
            prefix_no_aux.len() + aux.len(),
            "aux bytes must extend prefix length"
        );

        // The aux bytes appear at the end of the prefix (just before the
        // extranonce slot).
        let tail = &prefix_with_aux[prefix_with_aux.len() - aux.len()..];
        assert_eq!(tail, &aux[..], "aux bytes must appear at end of prefix");
    }

    #[test]
    fn coinbase_aux_updates_scriptsig_length() {
        let script = vec![0x51];
        let aux = vec![0x01, 0x02, 0x03];
        let en_size = 4;
        let height = 100u32;

        let (prefix, _) =
            build_coinbase_halves(height, 5_000_000_000, &script, en_size, &aux, None).unwrap();

        // scriptSig length byte is at offset 41 (4 version + 1 input_count
        // + 32 prevout_hash + 4 prevout_index = 41).
        let scriptsig_len_byte = prefix[41] as usize;

        let height_push = bip34_height_push(height);
        let expected = height_push.len() + aux.len() + en_size;
        assert_eq!(
            scriptsig_len_byte, expected,
            "scriptSig length must include height push + aux + extranonce"
        );
    }

    #[test]
    fn coinbase_aux_does_not_affect_suffix() {
        let script = vec![0x51];
        let aux = vec![0xFF, 0xFE];
        let (_, suffix_no_aux) =
            build_coinbase_halves(100, 5_000_000_000, &script, 4, &[], None).unwrap();
        let (_, suffix_with_aux) =
            build_coinbase_halves(100, 5_000_000_000, &script, 4, &aux, None).unwrap();
        assert_eq!(
            suffix_no_aux, suffix_with_aux,
            "coinbaseaux must not affect the suffix"
        );
    }

    #[test]
    fn coinbase_aux_with_witness_commitment() {
        let script = vec![0x51];
        let aux = vec![0xCA, 0xFE];
        let wc_script = {
            let mut v = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            v.extend_from_slice(&[0xBB; 32]);
            v
        };
        let (prefix, suffix) =
            build_coinbase_halves(100, 5_000_000_000, &script, 4, &aux, Some(&wc_script)).unwrap();

        // Prefix contains aux bytes.
        let tail = &prefix[prefix.len() - aux.len()..];
        assert_eq!(tail, &aux[..]);

        // Suffix has 2 outputs (payout + witness commitment).
        assert_eq!(
            suffix[4], 0x02,
            "output count must be 2 with witness commitment"
        );
    }

    // ── Share ingest tests ──

    // PB-37: `verify_gateway_signature_valid` used to live here. It built its
    // fixture signature with `mac.update(&event_id)` only, which is this side's
    // own convention, so it verified the verifier against itself and stayed
    // green through a month of a broken relay path. It has been deleted rather
    // than repaired; `gateway_signed_share_verifies_at_the_template_manager`
    // does the same job against the gateway's real signer. What remains here is
    // the property that test cannot cover: that the body hash is actually bound.

    #[test]
    fn verify_gateway_signature_invalid() {
        let secret = b"test-secret";
        let event_id = [0xAA; 32];
        let body_hash = [0xBB; 32];
        let bad_sig = [0xFF; 32];

        assert!(!verify_gateway_signature(
            secret, &event_id, &body_hash, &bad_sig
        ));
    }

    /// The replay property the body hash exists for. A signature captured from
    /// one submission must not verify against a different body carrying the
    /// same event id. If this passes with the body hash unbound, the signature
    /// is portable across submissions and PB-37's security rationale is gone.
    #[test]
    fn a_signature_does_not_carry_over_to_a_different_body() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let secret = b"test-secret";
        let event_id = [0xAA; 32];
        let body_hash = [0xBB; 32];
        let other_body_hash = [0xCC; 32];

        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&event_id);
        mac.update(&body_hash);
        let sig = mac.finalize().into_bytes();

        assert!(
            verify_gateway_signature(secret, &event_id, &body_hash, &sig),
            "signature must verify against the body it was made for"
        );
        assert!(
            !verify_gateway_signature(secret, &event_id, &other_body_hash, &sig),
            "signature verified against a DIFFERENT body: the body hash is not \
             bound, so a captured signature is replayable onto another submission"
        );
    }

    #[test]
    fn verify_gateway_signature_wrong_secret() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let event_id = [0xBB; 32];

        let body_hash = [0xCC; 32];
        let mut mac = HmacSha256::new_from_slice(b"secret-a").unwrap();
        mac.update(&event_id);
        mac.update(&body_hash);
        let sig = mac.finalize().into_bytes();

        assert!(!verify_gateway_signature(
            b"secret-b",
            &event_id,
            &body_hash,
            &sig
        ));
    }

    // ── PB-37: the share-relay HMAC is a CROSS-SERVICE contract ────
    //
    // The gateway signs and the template-manager verifies. Every test that
    // existed before these built its fixture with the verifying side's own
    // convention, so the suite certified the two sides agreed while they did
    // not, and the authenticated relay path was broken on main for a month.
    // These two tests exist because X and Y both need to hold: X, the real
    // signer's output must satisfy the real verifier; Y, the two independently
    // declared structs must serialize to the same bytes, because the body hash
    // is computed over those bytes on both sides.

    /// Build the GATEWAY's own submission type, populated identically to
    /// `sample_share_submission` so the two structs are compared like for like.
    fn sample_gateway_submission() -> sv2_gateway::shares::ShareSubmission {
        sv2_gateway::shares::ShareSubmission {
            share_id_hex: "aa".repeat(32),
            version: 0x2000_0000,
            prev_hash_wire_hex: "bb".repeat(32),
            prev_hash_display_hex: "bb".repeat(32),
            merkle_root_wire_hex: "cc".repeat(32),
            merkle_root_display_hex: "cc".repeat(32),
            ntime: 1_700_000_000,
            nbits: 0x1d00_ffff,
            nonce: 42,
            event_id_hex: "dd".repeat(32),
            worker_id: "test-worker".to_string(),
            validation_level: "full".to_string(),
            gateway_instance_id: "gw-01".to_string(),
            channel_id: 1,
            sequence_number: 0,
            job_id: 10,
            template_id: 100,
            block_height: 200,
            pool_account_id: None,
            timestamp_ms: 1_700_000_000_000,
            difficulty_u64: 1,
            difficulty_display: 1.0,
            source_instance_id: "src-01".to_string(),
            gateway_signature_hex: String::new(),
        }
    }

    /// The contract test PB-37 says never existed: sign with the gateway's REAL
    /// signer, ship the JSON it would actually put on the wire, and verify with
    /// the template-manager's REAL verifier. No fixture, no re-implementation of
    /// either side's convention. If this goes red, the authenticated share relay
    /// is broken in production, whichever side moved.
    #[test]
    fn gateway_signed_share_verifies_at_the_template_manager() {
        let secret = b"pb37-cross-service-secret";

        // Gateway side: sign exactly as the running gateway does.
        let mut submission = sample_gateway_submission();
        sv2_gateway::shares::sign_submission(secret, &mut submission);
        assert!(
            !submission.gateway_signature_hex.is_empty(),
            "gateway produced no signature; the test would pass vacuously"
        );

        // The wire: whatever the gateway serializes is what arrives.
        let wire = serde_json::to_string(&submission).unwrap();
        let received: ShareSubmissionRecord = serde_json::from_str(&wire).unwrap();

        // Template-manager side: recover the two inputs it must bind.
        let mut event_id = [0u8; 32];
        event_id.copy_from_slice(&hex::decode(&received.event_id_hex).unwrap());
        let sig = hex::decode(&received.gateway_signature_hex).unwrap();
        let body_hash = canonical_body_hash(&received);

        assert!(
            verify_gateway_signature(secret, &event_id, &body_hash, &sig),
            "a signature produced by the gateway's real signer was rejected by \
             the template-manager's real verifier: the relay path is broken"
        );
    }

    /// Binding the body hash only works while both sides hash the same bytes,
    /// and the two structs are declared independently in two crates with
    /// nothing but a doc comment claiming they match. `serde_json` emits fields
    /// in DECLARATION order, so a reordering, a rename, a type change or an
    /// added field on either side silently breaks every signature in
    /// production. This fails loudly at compile-or-test time instead.
    #[test]
    fn the_two_wire_structs_serialize_to_identical_bytes() {
        let gateway = sample_gateway_submission();
        let tmgr = sample_share_submission();

        let from_gateway = serde_json::to_vec(&gateway).unwrap();
        let from_tmgr = serde_json::to_vec(&tmgr).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&from_gateway),
            String::from_utf8_lossy(&from_tmgr),
            "sv2_gateway::shares::ShareSubmission and ShareSubmissionRecord no \
             longer serialize identically. The share-relay body hash is computed \
             over these bytes on both sides, so this divergence rejects every \
             authenticated share. Reconcile the two declarations."
        );
    }

    /// The verifier recomputes the body hash from what it received, so it must
    /// reproduce the signer's canonical form: the signature field emptied, then
    /// serialized. Pin that the round trip through the wire is lossless.
    #[test]
    fn canonical_body_hash_survives_the_wire_round_trip() {
        use sha2::{Digest, Sha256};
        let mut gateway = sample_gateway_submission();
        gateway.gateway_signature_hex = String::new();
        let signer_bytes = serde_json::to_vec(&gateway).unwrap();
        let signer_hash: [u8; 32] = Sha256::digest(&signer_bytes).into();

        // Now sign it, put it on the wire, and recover the hash at the far end.
        let secret = b"pb37-cross-service-secret";
        sv2_gateway::shares::sign_submission(secret, &mut gateway);
        let wire = serde_json::to_string(&gateway).unwrap();
        let received: ShareSubmissionRecord = serde_json::from_str(&wire).unwrap();

        assert_eq!(
            canonical_body_hash(&received),
            signer_hash,
            "the verifier could not reproduce the signer's body hash after a \
             wire round trip"
        );
    }

    fn sample_share_submission() -> ShareSubmissionRecord {
        ShareSubmissionRecord {
            share_id_hex: "aa".repeat(32),
            version: 0x2000_0000,
            prev_hash_wire_hex: "bb".repeat(32),
            prev_hash_display_hex: "bb".repeat(32),
            merkle_root_wire_hex: "cc".repeat(32),
            merkle_root_display_hex: "cc".repeat(32),
            ntime: 1_700_000_000,
            nbits: 0x1d00_ffff,
            nonce: 42,
            event_id_hex: "dd".repeat(32),
            worker_id: "test-worker".to_string(),
            validation_level: "full".to_string(),
            gateway_instance_id: "gw-01".to_string(),
            channel_id: 1,
            sequence_number: 0,
            job_id: 10,
            template_id: 100,
            block_height: 200,
            pool_account_id: None,
            timestamp_ms: 1_700_000_000_000,
            difficulty_u64: 1,
            difficulty_display: 1.0,
            source_instance_id: "src-01".to_string(),
            gateway_signature_hex: String::new(),
        }
    }

    #[test]
    fn share_submission_record_serde_round_trip() {
        let share = sample_share_submission();
        let json = serde_json::to_string(&share).unwrap();
        let parsed: ShareSubmissionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.share_id_hex, share.share_id_hex);
        assert_eq!(parsed.template_id, share.template_id);
        assert_eq!(parsed.gateway_instance_id, share.gateway_instance_id);
    }

    #[test]
    fn share_upstream_response_accepted_json() {
        let resp = ShareUpstreamResponse {
            accepted: true,
            reason: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"accepted\":true"));
        assert!(!json.contains("reason"));
    }

    #[test]
    fn share_upstream_response_rejected_json() {
        let resp = ShareUpstreamResponse {
            accepted: false,
            reason: Some(GatewayReason::InvalidGatewaySignature.as_str().to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"accepted\":false"));
        assert!(json.contains(GatewayReason::InvalidGatewaySignature.as_str()));
    }

    // ── Coinbase sigops extraction tests ──

    #[test]
    fn extract_coinbase_sigops_present() {
        let raw = serde_json::json!({
            "coinbasetxn": { "sigops": 4 }
        });
        assert_eq!(extract_coinbase_sigops(&raw), Some(4));
    }

    #[test]
    fn extract_coinbase_sigops_missing_field() {
        let raw = serde_json::json!({
            "coinbasetxn": { "data": "deadbeef" }
        });
        assert_eq!(extract_coinbase_sigops(&raw), None);
    }

    #[test]
    fn extract_coinbase_sigops_no_coinbasetxn() {
        let raw = serde_json::json!({
            "transactions": []
        });
        assert_eq!(extract_coinbase_sigops(&raw), None);
    }
}
