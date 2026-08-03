use std::time::{SystemTime, UNIX_EPOCH};

use rg_consensus::ConsensusViolation;
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, VerdictReason};
use serde::{Deserialize, Serialize};

/// Bitcoin consensus constants.
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
pub const MAX_BLOCK_SIGOPS: u32 = 80_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum FeeTier {
    Low,
    Mid,
    High,
}

impl FeeTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            FeeTier::Low => "low",
            FeeTier::Mid => "mid",
            FeeTier::High => "high",
        }
    }
}

/// An observe only safety finding that did not cause rejection.
#[derive(Debug, Clone)]
pub struct SafetyWarning {
    pub reason: VerdictReason,
    pub detail: String,
}

/// Result of policy evaluation against a template.
///
/// `reason` carries the canonical `rg_protocol::VerdictReason` directly —
/// no intermediate local enum, no mapping step.
#[derive(Debug, Clone)]
pub struct EvalResult {
    /// `None` = accepted. `Some(reason)` = rejected.
    pub reason: Option<VerdictReason>,
    /// Human-readable detail string (thresholds, actual values).
    pub detail: Option<String>,
    /// Fee tier selected for this evaluation.
    pub fee_tier: FeeTier,
    /// Effective minimum average fee used for the decision.
    pub min_avg_fee_used: u64,
    /// Observe only safety warnings (never cause rejection on their own).
    pub warnings: Vec<SafetyWarning>,
    /// `true` when the v2.0 Invariant Shield pass was reached but the
    /// template omitted `raw_block_hex`. The caller increments
    /// `verifier_shield_skipped_total` to make the Phase 1 rollout
    /// visibility explicit. `false` for rejected-before-shield and for
    /// shield-ran paths (agreed or rejected).
    pub shield_skipped: bool,
    /// PB-18(a): what the Class M (Phase 2 mempool ground truth)
    /// check actually did during this evaluation. Reported by the
    /// evaluation path itself so the ingress metrics block labels
    /// `verifier_phase2_checks_total` from ground truth instead of
    /// re-deriving it from `reason` plus a second snapshot read.
    pub phase2: Phase2Attribution,
}

fn default_max_weight_ratio() -> f64 {
    0.999
}

fn default_warn_sigops_ratio() -> f64 {
    0.95
}

fn default_warn_coinbase_sigops_max() -> u32 {
    400
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySafety {
    #[serde(default = "default_max_weight_ratio")]
    pub max_weight_ratio: f64,

    #[serde(default)]
    pub enforce_weight_ratio: bool,

    #[serde(default)]
    pub max_template_age_ms: Option<u64>,

    #[serde(default)]
    pub enforce_template_age: bool,

    #[serde(default = "default_warn_sigops_ratio")]
    pub warn_sigops_ratio: f64,

    #[serde(default = "default_warn_coinbase_sigops_max")]
    pub warn_coinbase_sigops_max: u32,
}

impl Default for PolicySafety {
    fn default() -> Self {
        Self {
            max_weight_ratio: default_max_weight_ratio(),
            enforce_weight_ratio: false,
            max_template_age_ms: None,
            enforce_template_age: false,
            warn_sigops_ratio: default_warn_sigops_ratio(),
            warn_coinbase_sigops_max: default_warn_coinbase_sigops_max(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u16,

    #[serde(default = "default_required_prevhash_len")]
    pub required_prevhash_len: usize,

    #[serde(default)]
    pub min_total_fees: u64,

    #[serde(default = "default_max_tx_count")]
    pub max_tx_count: u32,

    #[serde(default = "default_low_mempool_tx")]
    pub low_mempool_tx: u64,

    #[serde(default = "default_high_mempool_tx")]
    pub high_mempool_tx: u64,

    #[serde(default)]
    pub min_avg_fee_lo: u64,
    #[serde(default)]
    pub min_avg_fee_mid: u64,
    #[serde(default)]
    pub min_avg_fee_hi: u64,

    #[serde(default = "default_reject_empty_templates")]
    pub reject_empty_templates: bool,

    #[serde(default = "default_reject_coinbase_zero")]
    pub reject_coinbase_zero: bool,

    #[serde(default = "default_unknown_mempool_as_high")]
    pub unknown_mempool_as_high: bool,

    #[serde(default)]
    pub safety: PolicySafety,

    /// v2.0 Invariant Shield Phase 2 mempool ground truth (ADR-003).
    /// Sub-table at `[policy.mempool]`. All fields are optional with
    /// defaults so older configs continue to load unchanged; the
    /// shield's Class M check stays disabled until `enforce = true`.
    #[serde(default)]
    pub mempool: PolicyMempool,
}

/// v2.0 Invariant Shield Phase 2 (ADR-003 D-18) policy keys.
///
/// Lives at `[policy.mempool]` in `policy.toml`. Defaults match
/// the locked decisions in EXECLOG D-18: 4% tolerance, 10-second
/// poll interval, 60-second fail-stale window, per-tx detail off.
/// Operators set `enforce = true` to activate the Class M check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMempool {
    /// Master enable for the Class M (mempool ground truth) check.
    /// Default `false` so the shield ships in Phase 1 behavior; flip
    /// to `true` once `rpc_url` / `rpc_user` / `rpc_pass` are wired.
    #[serde(default)]
    pub enforce: bool,

    /// Percentage of template txs that may be unknown to the
    /// verifier's mempool view before rejection. ADR-003 D-18.2
    /// default 4.0. Tunable per operator data; tuning trigger and
    /// acceptance metric documented in EXECLOG D-18.
    #[serde(default = "default_mempool_tolerance_pct")]
    pub tolerance_pct: f64,

    /// `getrawmempool` poll cadence in seconds. Default 10.
    #[serde(default = "default_mempool_poll_interval_secs")]
    pub poll_interval_secs: u64,

    /// Fail-stale window (ADR-003 D3, default 60). The mempool view
    /// state machine keys off this value twice: a view refreshed
    /// within `max_stale_secs` is `Fresh`; between `max_stale_secs`
    /// and `2 * max_stale_secs` it is `Stale` — still served and
    /// still enforcing (a tolerance-exceeded template hard-rejects;
    /// the stale age is advisory only for templates that agree);
    /// past `2 * max_stale_secs` it is `Degraded` and the Class M
    /// check is skipped entirely.
    #[serde(default = "default_mempool_max_stale_secs")]
    pub max_stale_secs: u64,

    /// When `true`, emit one verdict record per missing tx with the
    /// txid in the detail string. When `false` (default), emit one
    /// aggregate record listing up to 10 representative txids and
    /// the total unknown count.
    #[serde(default)]
    pub per_tx_detail: bool,

    /// Bitcoind JSON-RPC endpoint. Required when `enforce = true`.
    #[serde(default)]
    pub rpc_url: String,

    /// Bitcoind JSON-RPC basic-auth user. Required when `enforce = true`.
    #[serde(default)]
    pub rpc_user: String,

    /// Bitcoind JSON-RPC basic-auth password. Required when
    /// `enforce = true`. Also acceptable via the
    /// `VELDRA_BITCOIND_RPC_PASS` env var; main.rs reads the env
    /// var first and only falls back to this field if the var is
    /// unset, to keep secrets out of policy.toml on disk.
    #[serde(default)]
    pub rpc_pass: String,
}

impl Default for PolicyMempool {
    fn default() -> Self {
        Self {
            enforce: false,
            tolerance_pct: default_mempool_tolerance_pct(),
            poll_interval_secs: default_mempool_poll_interval_secs(),
            max_stale_secs: default_mempool_max_stale_secs(),
            per_tx_detail: false,
            rpc_url: String::new(),
            rpc_user: String::new(),
            rpc_pass: String::new(),
        }
    }
}

fn default_mempool_tolerance_pct() -> f64 {
    4.0
}

fn default_mempool_poll_interval_secs() -> u64 {
    10
}

fn default_mempool_max_stale_secs() -> u64 {
    60
}

fn default_protocol_version() -> u16 {
    PROTOCOL_VERSION
}

fn default_required_prevhash_len() -> usize {
    64
}

fn default_max_tx_count() -> u32 {
    10_000
}

fn default_low_mempool_tx() -> u64 {
    50
}

fn default_high_mempool_tx() -> u64 {
    500
}

fn default_reject_empty_templates() -> bool {
    true
}

fn default_reject_coinbase_zero() -> bool {
    false
}

fn default_unknown_mempool_as_high() -> bool {
    true
}

fn is_hex(s: &str) -> bool {
    s.as_bytes().iter().all(|&b| b.is_ascii_hexdigit())
}

/// Check basic template validity: version, `prev_hash`, and basic constraints.
fn check_basic_validity(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    fee_tier: FeeTier,
    min_avg_fee_used: u64,
) -> Option<EvalResult> {
    if template.version != cfg.protocol_version {
        return Some(EvalResult {
            reason: Some(VerdictReason::ProtocolVersionMismatch),
            detail: Some(format!(
                "protocol_version got={} expected={}",
                template.version, cfg.protocol_version
            )),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
            phase2: Phase2Attribution::NotRun,
        });
    }

    if template.prev_hash.len() != cfg.required_prevhash_len {
        return Some(EvalResult {
            reason: Some(VerdictReason::PrevHashLenMismatch),
            detail: Some(format!(
                "prev_hash len={} expected={}",
                template.prev_hash.len(),
                cfg.required_prevhash_len
            )),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
            phase2: Phase2Attribution::NotRun,
        });
    }

    if !is_hex(&template.prev_hash) {
        return Some(EvalResult {
            reason: Some(VerdictReason::InvalidPrevHash),
            detail: Some("prev_hash contains non-hex characters".to_string()),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
            phase2: Phase2Attribution::NotRun,
        });
    }

    None
}

/// Check template constraints: tx count, total fees, and average fees.
fn check_template_constraints(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    fee_tier: FeeTier,
    min_avg_fee_used: u64,
) -> Option<EvalResult> {
    if cfg.reject_empty_templates && template.tx_count == 0 {
        return Some(EvalResult {
            reason: Some(VerdictReason::EmptyTemplateRejected),
            detail: Some("empty template rejected by policy".to_string()),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
            phase2: Phase2Attribution::NotRun,
        });
    }

    if cfg.reject_coinbase_zero && template.coinbase_value == 0 && template.tx_count > 0 {
        return Some(EvalResult {
            reason: Some(VerdictReason::CoinbaseValueZeroRejected),
            detail: Some("coinbase_value=0 rejected by policy".to_string()),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
            phase2: Phase2Attribution::NotRun,
        });
    }

    if template.tx_count > cfg.max_tx_count {
        return Some(EvalResult {
            reason: Some(VerdictReason::TxCountExceeded),
            detail: Some(format!(
                "tx_count={} > max_tx_count={}",
                template.tx_count, cfg.max_tx_count
            )),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
            phase2: Phase2Attribution::NotRun,
        });
    }

    if template.total_fees < cfg.min_total_fees {
        return Some(EvalResult {
            reason: Some(VerdictReason::TotalFeesBelowMinimum),
            detail: Some(format!(
                "total_fees={} < min_total_fees={}",
                template.total_fees, cfg.min_total_fees
            )),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
            phase2: Phase2Attribution::NotRun,
        });
    }

    if min_avg_fee_used > 0 && template.tx_count > 0 {
        // Floor division is the strict direction: floor(total/tx) < min
        // holds exactly when total < min * tx, so a true average even
        // fractionally below the threshold rejects. Ceiling division
        // rounds a below-threshold average up to the threshold and
        // wrongly accepts (total_fees=15001, tx_count=3,
        // min_avg_fee=5001: true avg 5000.33, ceil 5001, would pass).
        // Floor also matches `compute_avg_fee_sats_per_tx`, so the
        // logged average agrees with the decision average.
        let tx = u64::from(template.tx_count);
        let avg = template.total_fees / tx;
        if avg < min_avg_fee_used {
            return Some(EvalResult {
                reason: Some(VerdictReason::AvgFeeBelowMinimum),
                detail: Some(format!(
                    "avg_fee={avg} < min_avg_fee_used={min_avg_fee_used}"
                )),
                fee_tier,
                min_avg_fee_used,
                warnings: vec![],
                shield_skipped: false,
                phase2: Phase2Attribution::NotRun,
            });
        }
    }

    None
}

/// Check consensus safety constraints: weight ratio, template age, sigops.
fn check_safety_constraints(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    now_ms: u64,
    warnings: &mut Vec<SafetyWarning>,
    fee_tier: FeeTier,
    min_avg_fee_used: u64,
) -> Option<EvalResult> {
    // Weight ratio: use template_weight (canonical) or observed_weight (legacy)
    let effective_weight = template.template_weight.or(template.observed_weight);
    if let Some(weight) = effective_weight {
        #[allow(clippy::cast_precision_loss)]
        let ratio = weight as f64 / MAX_BLOCK_WEIGHT as f64;
        if ratio > cfg.safety.max_weight_ratio {
            let detail = format!(
                "weight_ratio={:.4} > max_weight_ratio={:.4} (weight={} max={})",
                ratio, cfg.safety.max_weight_ratio, weight, MAX_BLOCK_WEIGHT
            );
            if cfg.safety.enforce_weight_ratio {
                return Some(EvalResult {
                    reason: Some(VerdictReason::WeightRatioExceeded),
                    detail: Some(detail),
                    fee_tier,
                    min_avg_fee_used,
                    warnings: warnings.clone(),
                    shield_skipped: false,
                    phase2: Phase2Attribution::NotRun,
                });
            }
            warnings.push(SafetyWarning {
                reason: VerdictReason::WeightRatioExceeded,
                detail,
            });
        }
    }

    // Template staleness
    if let (Some(created), Some(max_age)) =
        (template.created_at_unix_ms, cfg.safety.max_template_age_ms)
    {
        let age_ms = now_ms.saturating_sub(created);
        if age_ms > max_age {
            let detail = format!("template_age_ms={age_ms} > max_template_age_ms={max_age}");
            if cfg.safety.enforce_template_age {
                return Some(EvalResult {
                    reason: Some(VerdictReason::TemplateStale),
                    detail: Some(detail),
                    fee_tier,
                    min_avg_fee_used,
                    warnings: warnings.clone(),
                    shield_skipped: false,
                    phase2: Phase2Attribution::NotRun,
                });
            }
            warnings.push(SafetyWarning {
                reason: VerdictReason::TemplateStale,
                detail,
            });
        }
    }

    // Sigops budget warning (observe only in 0.2.2)
    if let Some(sigops) = template.total_sigops {
        #[allow(clippy::cast_precision_loss)]
        let ratio = f64::from(sigops) / f64::from(MAX_BLOCK_SIGOPS);
        if ratio > cfg.safety.warn_sigops_ratio {
            warnings.push(SafetyWarning {
                reason: VerdictReason::SigopsBudgetWarning,
                detail: format!(
                    "sigops_ratio={:.4} > warn_sigops_ratio={:.4} (sigops={} max={})",
                    ratio, cfg.safety.warn_sigops_ratio, sigops, MAX_BLOCK_SIGOPS
                ),
            });
        }
    }

    // Coinbase sigops anomaly (observe only in 0.2.2)
    if let Some(cb_sigops) = template.coinbase_sigops
        && cb_sigops > cfg.safety.warn_coinbase_sigops_max
    {
        warnings.push(SafetyWarning {
            reason: VerdictReason::CoinbaseSigopsAbnormal,
            detail: format!(
                "coinbase_sigops={cb_sigops} > warn_coinbase_sigops_max={}",
                cfg.safety.warn_coinbase_sigops_max
            ),
        });
    }

    None
}

fn now_unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |_| 0,
        |duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
    )
}

impl PolicyConfig {
    pub fn default_with_protocol(protocol_version: u16) -> Self {
        PolicyConfig {
            protocol_version,
            required_prevhash_len: 64,
            min_total_fees: 0,
            max_tx_count: 10_000,
            low_mempool_tx: 50,
            high_mempool_tx: 500,
            min_avg_fee_lo: 0,
            min_avg_fee_mid: 500,
            min_avg_fee_hi: 2_000,
            reject_empty_templates: true,
            reject_coinbase_zero: false,
            unknown_mempool_as_high: true,
            safety: PolicySafety::default(),
            mempool: PolicyMempool::default(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::anyhow;

        if self.protocol_version != PROTOCOL_VERSION {
            anyhow::bail!(
                "policy.protocol_version={} does not match binary PROTOCOL_VERSION={}",
                self.protocol_version,
                PROTOCOL_VERSION
            );
        }

        if self.required_prevhash_len == 0 {
            return Err(anyhow!("required_prevhash_len must be > 0"));
        }

        if self.max_tx_count == 0 {
            return Err(anyhow!("max_tx_count must be > 0"));
        }

        if self.low_mempool_tx > self.high_mempool_tx {
            return Err(anyhow!(
                "low_mempool_tx ({}) must be <= high_mempool_tx ({})",
                self.low_mempool_tx,
                self.high_mempool_tx
            ));
        }

        // Fee tier ordering: lo <= mid <= hi. Inverted tiers silently
        // produce confusing rejection patterns.
        if self.min_avg_fee_lo > self.min_avg_fee_mid {
            return Err(anyhow!(
                "min_avg_fee_lo ({}) must be <= min_avg_fee_mid ({})",
                self.min_avg_fee_lo,
                self.min_avg_fee_mid
            ));
        }
        if self.min_avg_fee_mid > self.min_avg_fee_hi {
            return Err(anyhow!(
                "min_avg_fee_mid ({}) must be <= min_avg_fee_hi ({})",
                self.min_avg_fee_mid,
                self.min_avg_fee_hi
            ));
        }

        if !(self.safety.max_weight_ratio.is_finite()
            && self.safety.max_weight_ratio > 0.0
            && self.safety.max_weight_ratio <= 1.0)
        {
            return Err(anyhow!(
                "safety.max_weight_ratio ({}) must be a finite number in (0, 1]",
                self.safety.max_weight_ratio
            ));
        }

        if !(self.safety.warn_sigops_ratio.is_finite()
            && self.safety.warn_sigops_ratio > 0.0
            && self.safety.warn_sigops_ratio <= 1.0)
        {
            return Err(anyhow!(
                "safety.warn_sigops_ratio ({}) must be a finite number in (0, 1]",
                self.safety.warn_sigops_ratio
            ));
        }

        Ok(())
    }

    pub fn effective_min_avg_fee_dynamic(&self, mempool_tx: Option<u64>) -> (u64, FeeTier) {
        match mempool_tx {
            Some(tx) => {
                if tx < self.low_mempool_tx {
                    (self.min_avg_fee_lo, FeeTier::Low)
                } else if tx < self.high_mempool_tx {
                    (self.min_avg_fee_mid, FeeTier::Mid)
                } else {
                    (self.min_avg_fee_hi, FeeTier::High)
                }
            }
            None => {
                if self.unknown_mempool_as_high {
                    (self.min_avg_fee_hi, FeeTier::High)
                } else {
                    (self.min_avg_fee_mid, FeeTier::Mid)
                }
            }
        }
    }
}

/// Outcome of the v2.0 Invariant Shield pass (ADR-002 Phase 1).
///
/// The shield is the last stage of `evaluate_dynamic`. It re-derives
/// consensus critical values from the raw block bytes supplied on the
/// wire as `raw_block_hex` and compares them against the declared
/// template fields. The outcome feeds back into `EvalResult` plus the
/// `verifier_shield_skipped_total` metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldOutcome {
    /// Template omitted `raw_block_hex`. Shield pass did not run. The
    /// caller counts the skip so Phase 1 rollout coverage is observable.
    Skipped,
    /// Shield ran and every re-derivation agreed with the declared
    /// value. Template continues toward acceptance.
    Agreed,
    /// Shield ran and detected a disagreement. The carried reason is a
    /// canonical `v2_invariant_*` `VerdictReason` and the detail string
    /// is human readable only.
    Rejected {
        reason: VerdictReason,
        detail: String,
    },
}

/// PB-18(a): what the Class M (Phase 2 mempool ground truth) check
/// actually did during this evaluation, reported by the evaluation
/// path itself so the ingress metrics cannot misattribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase2Attribution {
    /// Class M never executed: no mempool snapshot supplied, no
    /// `raw_block_hex`, or an earlier check rejected the template
    /// before the shield ran.
    NotRun,
    /// Ran against a fresh view and the template agreed.
    Agreed,
    /// Ran against a stale-but-served view (advisory) and agreed.
    Stale,
    /// Skipped because the view was Degraded (primed then aged out).
    SkippedDegraded,
    /// Skipped because the view was Unprimed (boot window, PB-13).
    SkippedUnprimed,
    /// Rejected with a Class M reason code.
    Rejected,
}

/// Map a `ConsensusViolation` returned by the rg-consensus facade to
/// the canonical `VerdictReason` variant that mirrors the same
/// `snake_case` reason code string. The mapping is exhaustive by
/// construction; reason code drift across crates is caught by the
/// `snake_case` round trip tests in `rg-protocol` and `rg-consensus`.
///
/// `ConsensusViolation::NotImplemented` is a shield-disabled sentinel
/// and MUST NOT reach this function once Phase 1 has landed. If it
/// does, the facade has been misconfigured; we surface it as
/// `InternalError` so the observability pipeline flags the drift
/// rather than silently routing a sentinel onto the wire.
fn consensus_violation_to_verdict_reason(v: &ConsensusViolation) -> VerdictReason {
    match v {
        ConsensusViolation::DecodeFailed { .. } => VerdictReason::V2InvariantDecodeFailed,
        ConsensusViolation::CoinbaseValueMismatch { .. } => {
            VerdictReason::V2InvariantCoinbaseValueMismatch
        }
        ConsensusViolation::TemplateWeightMismatch { .. } => {
            VerdictReason::V2InvariantTemplateWeightMismatch
        }
        ConsensusViolation::MerkleRootMismatch { .. } => {
            VerdictReason::V2InvariantMerkleRootMismatch
        }
        ConsensusViolation::WitnessCommitmentMissing => {
            VerdictReason::V2InvariantWitnessCommitmentMissing
        }
        ConsensusViolation::WitnessCommitmentMismatch { .. } => {
            VerdictReason::V2InvariantWitnessCommitmentMismatch
        }
        ConsensusViolation::SigopsMismatch { .. } => VerdictReason::V2InvariantSigopsMismatch,
        ConsensusViolation::CoinbaseSigopsMismatch { .. } => {
            VerdictReason::V2InvariantCoinbaseSigopsMismatch
        }
        ConsensusViolation::TxCountMismatch { .. } => VerdictReason::V2InvariantTxCountMismatch,
        ConsensusViolation::CoinbaseScriptLength => VerdictReason::V2InvariantCoinbaseScriptLength,
        ConsensusViolation::CoinbaseOutputCount => VerdictReason::V2InvariantCoinbaseOutputCount,
        ConsensusViolation::CoinbaseBip34Missing => VerdictReason::V2InvariantCoinbaseBip34Missing,
        ConsensusViolation::CoinbaseHeightMismatch { .. } => {
            VerdictReason::V2InvariantCoinbaseHeightMismatch
        }
        ConsensusViolation::WeightExceedsMax => VerdictReason::V2InvariantWeightExceedsMax,
        ConsensusViolation::SigopsExceedMax => VerdictReason::V2InvariantSigopsExceedMax,
        ConsensusViolation::CoinbaseValueExceedsMax => {
            VerdictReason::V2InvariantCoinbaseValueExceedsMax
        }
        ConsensusViolation::NonCoinbaseNullPrevout => VerdictReason::V2InvariantNontcbNullPrevout,
        ConsensusViolation::CoinbasePrevoutNotNull => {
            VerdictReason::V2InvariantCoinbasePrevoutNotNull
        }
        ConsensusViolation::HeaderVersionLow => VerdictReason::V2InvariantHeaderVersionLow,
        ConsensusViolation::DuplicateTx => VerdictReason::V2InvariantDuplicateTx,
        // v2.0 Invariant Shield Phase 2 (ADR-003)
        ConsensusViolation::MempoolTxUnknown { .. } => VerdictReason::V2InvariantMempoolTxUnknown,
        ConsensusViolation::MempoolToleranceExceeded { .. } => {
            VerdictReason::V2InvariantMempoolToleranceExceeded
        }
        ConsensusViolation::MempoolUnavailable => VerdictReason::V2InvariantMempoolUnavailable,
        ConsensusViolation::MempoolViewStale { .. } => VerdictReason::V2InvariantMempoolViewStale,
        ConsensusViolation::NotImplemented => VerdictReason::InternalError,
    }
}

/// Run the v2.0 Invariant Shield pass against a template.
///
/// Scope: 20 invariants wired. Tier 1 + Tier 2 shipped in Phase 1 #4b;
/// seven Tier 3 belt-and-suspenders checks landed in Phase 1.5,
/// completing ADR-002's ratified table of 18. PB-20 then added an
/// eighth Tier 3 check, `CoinbasePrevoutNotNull`, which WIDENS that
/// table to 19 rather than completing it (ADR-002 Amendment 1). PB-21
/// then added a ninth Tier 3 check, `CoinbaseValueExceedsMax`, which
/// widens it again to 20 (ADR-002 Amendment 2).
///
/// Wired invariants:
///
/// Class S (standalone internal-consistency):
///   - `MerkleRootMismatch`         `header.merkle_root` vs computed
///   - `WitnessCommitmentMissing`   segwit txs without commitment
///   - `WitnessCommitmentMismatch`  commitment vs computed
///   - `CoinbaseBip34Missing`       coinbase script begins with height push
///
/// Class D (declared-mismatch, runs only when declared field is `Some`;
/// wire conventions per PB-19: `tx_count` and `template_weight` cover
/// NON-coinbase transactions, sigops arrive in BIP-141 cost units and
/// are checked one-sided against the legacy x4 provable floor):
///   - `CoinbaseValueMismatch`      always (declared field non-Option)
///   - `TemplateWeightMismatch`     when `template_weight.is_some()`
///   - `TxCountMismatch`            always (declared field non-Option)
///   - `SigopsMismatch`             when `total_sigops.is_some()`
///   - `CoinbaseSigopsMismatch`     when `coinbase_sigops.is_some()`
///   - `CoinbaseHeightMismatch`     always (declared field non-Option)
///
/// Tier 3 (standalone consensus ceilings, Phase 1.5; listed in the
/// order the `tier3_checks` array runs them):
///   - `CoinbaseScriptLength`       coinbase script 2..=100 bytes
///   - `CoinbaseOutputCount`        coinbase must pay at least one output
///   - `WeightExceedsMax`           4,000,000 WU ceiling (BIP-141)
///   - `SigopsExceedMax`            80,000 sigop-cost ceiling (BIP-141)
///   - `CoinbaseValueExceedsMax`    `MAX_MONEY` ceiling on coinbase value (PB-21)
///   - `NonCoinbaseNullPrevout`     null prevout outside the coinbase
///   - `CoinbasePrevoutNotNull`     `txdata[0]` IS a coinbase (PB-20)
///   - `HeaderVersionLow`           header version below the BIP-65 floor
///   - `DuplicateTx`                repeated txid in the block body
///
/// First violation wins, short-circuit. The shield deserializes
/// `raw_block_hex` once via `rg_consensus::parse_block` and reuses
/// the resulting `ParsedBlock` across every per-invariant check.
///
/// When `raw_block_hex` is `None` the shield is silently skipped and
/// the caller increments `verifier_shield_skipped_total` via the
/// `shield_skipped` field on `EvalResult`. When the hex decode fails
/// the shield emits `v2_invariant_decode_failed` so bad gateway
/// encodings surface loudly rather than silently bypassing the shield.
// Ten Tier 1+2 invariants make the body length cross the default 100-line
// `clippy::too_many_lines` threshold. Splitting into per-check helpers
// would scatter the short-circuit return chain across many small fns
// without improving readability; an explicit allow with this rationale
// reads better. Phase 2 adds a Class M (mempool ground truth) section
// at the tail; same rationale.
pub fn check_invariant_shield(template: &TemplatePropose) -> ShieldOutcome {
    check_invariant_shield_inner(template, None).0
}

/// Format the canonical `V2InvariantMempoolToleranceExceeded`
/// rejection detail string. Pure function so callers (the shield
/// inner plus integration tests) share the exact format.
/// `txids_to_emit` is whatever subset the caller chose: the
/// `SAMPLE_UNKNOWN_CAP`-bounded sample under aggregate mode, or the
/// full unknown list under per-tx detail mode.
pub fn format_mempool_tolerance_detail(
    unknown_count: u32,
    total: u32,
    txids_to_emit: &[[u8; 32]],
) -> String {
    use std::fmt::Write as _;
    let mut detail =
        format!("mempool tolerance exceeded: {unknown_count}/{total} txs unknown to verifier view");
    if !txids_to_emit.is_empty() {
        // Txids arrive in internal byte order; operators correlate
        // against bitcoin-cli and explorers, which use display order
        // (byte reversed). Emit display order.
        let sample_str: String = txids_to_emit
            .iter()
            .map(|t| {
                let mut display = *t;
                display.reverse();
                hex::encode(display)
            })
            .collect::<Vec<_>>()
            .join(",");
        let _ = write!(detail, " sample=[{sample_str}]");
    }
    detail
}

/// PB-18(c): wire budget for per-tx detail mode. Caps the number of
/// txids emitted into the `sample=[…]` field of the
/// `v2_invariant_mempool_tolerance_exceeded` rejection detail so the
/// final verdict NDJSON line stays safely under
/// `rg_protocol::gateway::MAX_INTERNAL_LINE_BYTES` (20 MiB).
/// Arithmetic: each txid emits as 64 hex chars plus a 1-byte comma
/// separator, so 10,000 txids occupy at most 10,000 * 65 = 650,000
/// bytes (~650 KB) in the `sample=` field, leaving over 19 MiB of
/// headroom for the rest of the verdict JSON envelope. Deliberately
/// far above `SAMPLE_UNKNOWN_CAP` (10) so aggregate mode is never
/// affected and small per-tx lists pass through uncapped.
pub const PER_TX_DETAIL_EMIT_CAP: usize = 10_000;

/// Bounded wrapper around [`format_mempool_tolerance_detail`]:
/// truncates `txids_to_emit` to [`PER_TX_DETAIL_EMIT_CAP`] entries
/// and appends a ` (truncated N of M)` marker when the cap was hit,
/// so per-tx detail mode can never push the verdict NDJSON line over
/// the wire budget. At or below the cap it delegates unchanged.
pub fn format_mempool_tolerance_detail_bounded(
    unknown_count: u32,
    total: u32,
    txids_to_emit: &[[u8; 32]],
) -> String {
    use std::fmt::Write as _;
    if txids_to_emit.len() <= PER_TX_DETAIL_EMIT_CAP {
        return format_mempool_tolerance_detail(unknown_count, total, txids_to_emit);
    }
    let mut detail = format_mempool_tolerance_detail(
        unknown_count,
        total,
        &txids_to_emit[..PER_TX_DETAIL_EMIT_CAP],
    );
    let _ = write!(
        detail,
        " (truncated {PER_TX_DETAIL_EMIT_CAP} of {})",
        txids_to_emit.len()
    );
    detail
}

/// Phase 2 entry point. Runs the full Phase 1 + Class M shield
/// against a mempool snapshot. `tolerance_pct` is the operator-tuned
/// threshold from `policy.toml` `[policy.mempool] tolerance_pct`
/// (default 4.0 per ADR-003 D-18.2). `per_tx_detail` mirrors
/// `[policy.mempool] per_tx_detail`: when `true`, the rejection
/// detail string carries every unknown txid in the `sample=[…]`
/// list rather than the bounded `SAMPLE_UNKNOWN_CAP` sample.
/// Wire format stays 1:1 (one `TemplateVerdict` per accepted
/// `TemplatePropose`); `per_tx_detail` expands the existing
/// `reason_detail` field rather than introducing multi-verdict
/// emission. ADR-003 Phase 2 #3.5.
pub fn check_invariant_shield_with_mempool(
    template: &TemplatePropose,
    mempool: &crate::mempool_view::MempoolSnapshot,
    tolerance_pct: f64,
    per_tx_detail: bool,
) -> ShieldOutcome {
    check_invariant_shield_inner(template, Some((mempool, tolerance_pct, per_tx_detail))).0
}

/// Signature shared by every Tier 3 standalone check in the
/// rg-consensus facade.
type Tier3Check = fn(&rg_consensus::ParsedBlock) -> Result<(), ConsensusViolation>;

/// Internal shield pass. Returns the outcome together with the
/// PB-18(a) [`Phase2Attribution`]: every return site that fires
/// before the Class M section reports `NotRun` because the mempool
/// check never executed for that template.
#[allow(clippy::too_many_lines)]
fn check_invariant_shield_inner(
    template: &TemplatePropose,
    mempool: Option<(&crate::mempool_view::MempoolSnapshot, f64, bool)>,
) -> (ShieldOutcome, Phase2Attribution) {
    let Some(hex_str) = template.raw_block_hex.as_deref() else {
        return (ShieldOutcome::Skipped, Phase2Attribution::NotRun);
    };

    let raw_block = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(e) => {
            return (
                ShieldOutcome::Rejected {
                    reason: VerdictReason::V2InvariantDecodeFailed,
                    detail: format!("raw_block_hex decode failed: {e}"),
                },
                Phase2Attribution::NotRun,
            );
        }
    };

    // All Class S checks and every Class D accessor below except
    // CoinbaseValueMismatch operate on this ParsedBlock without
    // re-parsing. CoinbaseValueMismatch's `re_derive_coinbase_value`
    // takes `raw_block` directly and deserializes it a second time
    // internally, so this is not a single deserialize overall.
    let parsed = match rg_consensus::parse_block(&raw_block) {
        Ok(p) => p,
        Err(v) => {
            return (
                ShieldOutcome::Rejected {
                    reason: consensus_violation_to_verdict_reason(&v),
                    detail: v.to_string(),
                },
                Phase2Attribution::NotRun,
            );
        }
    };

    // ── Class D: CoinbaseValueMismatch (always comparable) ────────
    match rg_consensus::re_derive_coinbase_value(&raw_block) {
        Ok(re_derived) => {
            if re_derived != template.coinbase_value {
                return (
                    ShieldOutcome::Rejected {
                        reason: VerdictReason::V2InvariantCoinbaseValueMismatch,
                        detail: format!(
                            "coinbase_value declared={} re_derived={}",
                            template.coinbase_value, re_derived
                        ),
                    },
                    Phase2Attribution::NotRun,
                );
            }
        }
        Err(v) => {
            return (
                ShieldOutcome::Rejected {
                    reason: consensus_violation_to_verdict_reason(&v),
                    detail: v.to_string(),
                },
                Phase2Attribution::NotRun,
            );
        }
    }

    // ── Class D: TemplateWeightMismatch (when declared) ───────────
    // Wire contract (PB-19): `template_weight` is the sum of
    // NON-coinbase tx weights (the GBT convention every producer and
    // the pre-shield policy layer use), so the comparison excludes
    // the coinbase and header contributions.
    if let Some(declared) = template.template_weight {
        let re_derived = rg_consensus::non_coinbase_tx_weight(&parsed);
        if re_derived != declared {
            return (
                ShieldOutcome::Rejected {
                    reason: VerdictReason::V2InvariantTemplateWeightMismatch,
                    detail: format!("template_weight declared={declared} re_derived={re_derived}"),
                },
                Phase2Attribution::NotRun,
            );
        }
    }

    // ── Class S: MerkleRootMismatch ───────────────────────────────
    if let Err(v) = rg_consensus::check_merkle_root_internal(&parsed) {
        return (
            ShieldOutcome::Rejected {
                reason: consensus_violation_to_verdict_reason(&v),
                detail: v.to_string(),
            },
            Phase2Attribution::NotRun,
        );
    }

    // ── Class S: WitnessCommitment{Missing,Mismatch} ──────────────
    if let Err(v) = rg_consensus::check_witness_commitment_internal(&parsed) {
        return (
            ShieldOutcome::Rejected {
                reason: consensus_violation_to_verdict_reason(&v),
                detail: v.to_string(),
            },
            Phase2Attribution::NotRun,
        );
    }

    // ── Class S: CoinbaseBip34Missing ─────────────────────────────
    if let Err(v) = rg_consensus::check_coinbase_bip34_present(&parsed) {
        return (
            ShieldOutcome::Rejected {
                reason: consensus_violation_to_verdict_reason(&v),
                detail: v.to_string(),
            },
            Phase2Attribution::NotRun,
        );
    }

    // ── Class D: TxCountMismatch (always comparable) ──────────────
    // Wire contract (PB-19): `tx_count` counts NON-coinbase
    // transactions (the producer convention the fee and
    // empty-template policies already rely on), so the block body
    // count is compared minus its coinbase.
    {
        let re_derived = rg_consensus::tx_count(&parsed).saturating_sub(1);
        if re_derived != template.tx_count {
            return (
                ShieldOutcome::Rejected {
                    reason: VerdictReason::V2InvariantTxCountMismatch,
                    detail: format!(
                        "tx_count declared={} re_derived={}",
                        template.tx_count, re_derived
                    ),
                },
                Phase2Attribution::NotRun,
            );
        }
    }

    // ── Class D: SigopsMismatch (when declared; one-sided) ────────
    // Wire contract (PB-19): `total_sigops` arrives in BIP-141
    // sigop-COST units over the NON-coinbase transactions (GBT
    // `transactions[]` convention). Exact cost cannot be re-derived
    // without the spent prevouts, but legacy count x4 is a provable
    // lower bound of true cost (P2SH and witness sigops only add),
    // so `legacy x4 > declared` is a violation with zero false
    // positives and still catches the real attack: declaring fewer
    // sigops than the block provably carries.
    //
    // The floor must be summed over the same inclusion set as the
    // declaration. `rg_consensus::total_sigops` is the whole-block
    // figure and belongs to the consensus ceiling check; using it
    // here leaked the coinbase's own sigops into a non-coinbase
    // comparison and rejected honest templates whenever the payout
    // script carried a CHECKSIG.
    if let Some(declared) = template.total_sigops {
        let legacy = rg_consensus::non_coinbase_sigops(&parsed);
        let floor = u64::from(legacy).saturating_mul(4);
        if floor > u64::from(declared) {
            return (
                ShieldOutcome::Rejected {
                    reason: VerdictReason::V2InvariantSigopsMismatch,
                    detail: format!(
                        "total_sigops declared_cost={declared} below provable floor={floor} \
                         (legacy count {legacy} x4)"
                    ),
                },
                Phase2Attribution::NotRun,
            );
        }
    }

    // ── Class D: CoinbaseSigopsMismatch (when declared; one-sided) ─
    // Same cost-floor bound restricted to the coinbase. Residual
    // assumption: the declared value describes a coinbase at least
    // as sigop-heavy as the assembled one (stock Core omits
    // `coinbasetxn`, so this check is skipped in practice today).
    if let Some(declared) = template.coinbase_sigops {
        let legacy = rg_consensus::coinbase_sigops(&parsed);
        let floor = u64::from(legacy).saturating_mul(4);
        if floor > u64::from(declared) {
            return (
                ShieldOutcome::Rejected {
                    reason: VerdictReason::V2InvariantCoinbaseSigopsMismatch,
                    detail: format!(
                        "coinbase_sigops declared_cost={declared} below provable floor={floor} \
                         (legacy count {legacy} x4)"
                    ),
                },
                Phase2Attribution::NotRun,
            );
        }
    }

    // ── Class D: CoinbaseHeightMismatch (always comparable) ───────
    match rg_consensus::bip34_height(&parsed) {
        Ok(re_derived) => {
            if re_derived != template.block_height {
                return (
                    ShieldOutcome::Rejected {
                        reason: VerdictReason::V2InvariantCoinbaseHeightMismatch,
                        detail: format!(
                            "block_height declared={} re_derived={}",
                            template.block_height, re_derived
                        ),
                    },
                    Phase2Attribution::NotRun,
                );
            }
        }
        Err(v) => {
            return (
                ShieldOutcome::Rejected {
                    reason: consensus_violation_to_verdict_reason(&v),
                    detail: v.to_string(),
                },
                Phase2Attribution::NotRun,
            );
        }
    }

    // ── Tier 3: belt-and-suspenders checks (Phase 1.5) ────────────
    // Standalone consensus ceilings and structural rules. No declared
    // field needed; each check reads only the parsed block. First
    // violation wins, matching the Class S and Class D short-circuit
    // discipline above.
    //
    // Order is no longer ADR-002 table order: PB-21's
    // `check_coinbase_value_max` runs right after `check_weight_max`
    // and `check_sigops_max`, alongside them in the ceiling family
    // (ADR-002 Amendment 2), rather than at the table position after
    // `check_coinbase_null_prevout`. Order is behaviorally significant
    // here (first violation wins) and is intentionally left as-is.
    let tier3_checks: [Tier3Check; 9] = [
        rg_consensus::check_coinbase_script_length,
        rg_consensus::check_coinbase_output_count,
        rg_consensus::check_weight_max,
        rg_consensus::check_sigops_max,
        rg_consensus::check_coinbase_value_max,
        rg_consensus::check_non_coinbase_null_prevout,
        rg_consensus::check_coinbase_null_prevout,
        rg_consensus::check_header_version,
        rg_consensus::check_duplicate_tx,
    ];
    for check in tier3_checks {
        if let Err(v) = check(&parsed) {
            return (
                ShieldOutcome::Rejected {
                    reason: consensus_violation_to_verdict_reason(&v),
                    detail: v.to_string(),
                },
                Phase2Attribution::NotRun,
            );
        }
    }

    // ── Class M: mempool ground truth (Phase 2 / ADR-003) ─────────
    // Runs only when the caller supplied a mempool snapshot plus a
    // tolerance threshold. Every Phase 1 check has already passed
    // by this point. Class M is strictly additive: a Skipped
    // mempool snapshot leaves the verdict at Agreed, an
    // Agreed/Stale mempool snapshot leaves the verdict at Agreed,
    // and only ToleranceExceeded converts to Rejected.
    let mut phase2 = Phase2Attribution::NotRun;
    if let Some((snapshot, tolerance_pct, per_tx_detail)) = mempool {
        let txids = rg_consensus::template_txids(&parsed);
        match crate::mempool_view::evaluate(snapshot, &txids, tolerance_pct) {
            crate::mempool_view::MempoolCheckOutcome::Agreed { .. } => {
                phase2 = Phase2Attribution::Agreed;
            }
            crate::mempool_view::MempoolCheckOutcome::Stale { .. } => {
                // Stale produces an advisory at the metric layer
                // but does not reject.
                phase2 = Phase2Attribution::Stale;
            }
            crate::mempool_view::MempoolCheckOutcome::Skipped => {
                // `evaluate` skips only for `Degraded` and `Unprimed`
                // views; the snapshot state disambiguates which, so
                // PB-13 keeps the boot window out of
                // `verifier_phase2_degraded_total`.
                phase2 = match snapshot.state {
                    crate::mempool_view::MempoolState::Degraded => {
                        Phase2Attribution::SkippedDegraded
                    }
                    _ => Phase2Attribution::SkippedUnprimed,
                };
            }
            crate::mempool_view::MempoolCheckOutcome::ToleranceExceeded {
                unknown_count,
                total,
                sample_unknown,
            } => {
                // Per-tx detail mode emits every unknown txid; default
                // (aggregate) mode emits the existing bounded sample.
                // sample_unknown from mempool_view::evaluate is already
                // capped at SAMPLE_UNKNOWN_CAP, so per-tx mode
                // recomputes the full list against the snapshot.
                let txids_to_emit: Vec<[u8; 32]> = if per_tx_detail {
                    txids
                        .iter()
                        .filter(|t| !snapshot.txids.contains(*t))
                        .copied()
                        .collect()
                } else {
                    sample_unknown
                };
                let detail =
                    format_mempool_tolerance_detail_bounded(unknown_count, total, &txids_to_emit);
                return (
                    ShieldOutcome::Rejected {
                        reason: VerdictReason::V2InvariantMempoolToleranceExceeded,
                        detail,
                    },
                    Phase2Attribution::Rejected,
                );
            }
        }
    }

    (ShieldOutcome::Agreed, phase2)
}

/// Convenience wrapper: evaluate with no mempool context.
pub fn evaluate(template: &TemplatePropose, cfg: &PolicyConfig) -> EvalResult {
    evaluate_dynamic(template, cfg, None, now_unix_ms())
}

/// Phase 2 entry point. Same as [`evaluate_dynamic`] but with an
/// explicit mempool snapshot for the Class M (mempool ground truth)
/// check. Pass `None` to disable Class M for this evaluation; pass
/// `Some(snapshot)` to run the full Phase 1 + Phase 2 shield.
///
/// `tolerance_pct` is the operator-tunable threshold from
/// `[policy.mempool] tolerance_pct` (default 4.0 per ADR-003 D-18.2).
pub fn evaluate_dynamic_phase2(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    mempool_snapshot: Option<&crate::mempool_view::MempoolSnapshot>,
    mempool_tx: Option<u64>,
    now_ms: u64,
) -> EvalResult {
    evaluate_dynamic_inner(template, cfg, mempool_snapshot, mempool_tx, now_ms)
}

/// Core policy evaluation. Returns an `EvalResult` whose `reason` field
/// carries the canonical `rg_protocol::VerdictReason` directly — no
/// intermediate local enum, no mapping layer.
///
/// `now_ms` is the current unix timestamp in milliseconds, passed explicitly
/// to keep the function deterministic for testing.
///
/// Phase 1 entry point. Equivalent to
/// [`evaluate_dynamic_phase2`] with `mempool_snapshot = None`.
pub fn evaluate_dynamic(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    mempool_tx: Option<u64>,
    now_ms: u64,
) -> EvalResult {
    evaluate_dynamic_inner(template, cfg, None, mempool_tx, now_ms)
}

#[allow(clippy::too_many_lines)]
fn evaluate_dynamic_inner(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    mempool_snapshot: Option<&crate::mempool_view::MempoolSnapshot>,
    mempool_tx: Option<u64>,
    now_ms: u64,
) -> EvalResult {
    let (min_avg_fee_used, fee_tier) = cfg.effective_min_avg_fee_dynamic(mempool_tx);

    // Check basic validity (version, prev_hash)
    if let Some(result) = check_basic_validity(template, cfg, fee_tier, min_avg_fee_used) {
        return result;
    }

    // Check template constraints (tx count, total fees, avg fees)
    if let Some(result) = check_template_constraints(template, cfg, fee_tier, min_avg_fee_used) {
        return result;
    }

    // ── v0.2.2 consensus safety checks ──
    let mut warnings: Vec<SafetyWarning> = Vec::new();
    if let Some(result) = check_safety_constraints(
        template,
        cfg,
        now_ms,
        &mut warnings,
        fee_tier,
        min_avg_fee_used,
    ) {
        return result;
    }

    // ── v2.0 Invariant Shield (ADR-002 Phase 1 + ADR-003 Phase 2) ──
    // Runs after safety so earlier policy rejects short circuit first
    // and the shield only sees templates that have already passed every
    // prior check. Strictly additive: templates that omit raw_block_hex
    // bypass the shield without altering the prior verdict path.
    //
    // When `mempool_snapshot` is Some, the shield runs the full
    // Phase 1 + Phase 2 chain. When None, only Phase 1 runs (legacy
    // behavior, used by tests and any caller that has not wired the
    // Phase 2 mempool view).
    let (shield_outcome, phase2) = check_invariant_shield_inner(
        template,
        mempool_snapshot.map(|snap| (snap, cfg.mempool.tolerance_pct, cfg.mempool.per_tx_detail)),
    );
    let shield_skipped = match shield_outcome {
        ShieldOutcome::Skipped => true,
        ShieldOutcome::Agreed => false,
        ShieldOutcome::Rejected { reason, detail } => {
            return EvalResult {
                reason: Some(reason),
                detail: Some(detail),
                fee_tier,
                min_avg_fee_used,
                warnings,
                shield_skipped: false,
                phase2,
            };
        }
    };

    EvalResult {
        reason: None,
        detail: None,
        fee_tier,
        min_avg_fee_used,
        warnings,
        shield_skipped,
        phase2,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rg_protocol::VerdictReason;

    /// Helper: build a valid `TemplatePropose` with sensible defaults.
    fn base_template() -> TemplatePropose {
        TemplatePropose {
            version: PROTOCOL_VERSION,
            id: 1,
            block_height: 100,
            prev_hash: "a".repeat(64),
            coinbase_value: 5000,
            tx_count: 10,
            total_fees: 50_000,
            observed_weight: None,
            created_at_unix_ms: None,
            total_sigops: None,
            coinbase_sigops: None,
            template_weight: None,
            gateway_instance_id: None,
            raw_block_hex: None,
        }
    }

    // --- tier_naming_consistent ---

    #[test]
    fn fee_tier_as_str_returns_canonical_values() {
        assert_eq!(FeeTier::Low.as_str(), "low");
        assert_eq!(FeeTier::Mid.as_str(), "mid");
        assert_eq!(FeeTier::High.as_str(), "high");
    }

    #[test]
    fn fee_tier_as_str_only_canonical() {
        let valid = ["low", "mid", "high"];
        for tier in [FeeTier::Low, FeeTier::Mid, FeeTier::High] {
            assert!(
                valid.contains(&tier.as_str()),
                "FeeTier::{:?} returned non-canonical: {}",
                tier,
                tier.as_str()
            );
        }
    }

    // --- policy_context_tier_values ---

    #[test]
    fn eval_result_fee_tier_is_canonical() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let template = base_template();

        let valid_tiers = ["low", "mid", "high"];
        let ts = now_unix_ms();

        for mempool_tx in [Some(0), Some(100), Some(1000), None] {
            let result = evaluate_dynamic(&template, &cfg, mempool_tx, ts);
            assert!(
                valid_tiers.contains(&result.fee_tier.as_str()),
                "Non-canonical tier for mempool_tx={:?}: {}",
                mempool_tx,
                result.fee_tier.as_str()
            );
        }
    }

    // --- eval_result_exhaustive: every policy rejection is a valid VerdictReason ---

    #[test]
    #[allow(clippy::too_many_lines)]
    fn eval_result_reasons_are_all_valid_verdict_reasons() {
        let cfg = PolicyConfig {
            protocol_version: PROTOCOL_VERSION,
            required_prevhash_len: 64,
            min_total_fees: 100,
            max_tx_count: 5,
            low_mempool_tx: 10,
            high_mempool_tx: 100,
            min_avg_fee_lo: 0,
            min_avg_fee_mid: 500,
            min_avg_fee_hi: 2000,
            reject_empty_templates: true,
            reject_coinbase_zero: true,
            unknown_mempool_as_high: true,
            safety: PolicySafety::default(),
            mempool: PolicyMempool::default(),
        };

        let ts = now_unix_ms();

        // Trigger each policy rejection reason.
        let cases: Vec<(TemplatePropose, VerdictReason)> = vec![
            // ProtocolVersionMismatch
            (
                TemplatePropose {
                    version: 99,
                    id: 1,
                    ..base_template()
                },
                VerdictReason::ProtocolVersionMismatch,
            ),
            // PrevHashLenMismatch
            (
                TemplatePropose {
                    id: 2,
                    prev_hash: "aa".to_string(),
                    ..base_template()
                },
                VerdictReason::PrevHashLenMismatch,
            ),
            // InvalidPrevHash
            (
                TemplatePropose {
                    id: 3,
                    prev_hash: "g".repeat(64),
                    ..base_template()
                },
                VerdictReason::InvalidPrevHash,
            ),
            // EmptyTemplateRejected
            (
                TemplatePropose {
                    id: 4,
                    tx_count: 0,
                    total_fees: 0,
                    ..base_template()
                },
                VerdictReason::EmptyTemplateRejected,
            ),
            // CoinbaseValueZeroRejected
            (
                TemplatePropose {
                    id: 5,
                    coinbase_value: 0,
                    tx_count: 1,
                    total_fees: 5000,
                    ..base_template()
                },
                VerdictReason::CoinbaseValueZeroRejected,
            ),
            // TxCountExceeded
            (
                TemplatePropose {
                    id: 6,
                    tx_count: 100,
                    total_fees: 500_000,
                    ..base_template()
                },
                VerdictReason::TxCountExceeded,
            ),
            // TotalFeesBelowMinimum
            (
                TemplatePropose {
                    id: 7,
                    tx_count: 1,
                    total_fees: 0,
                    ..base_template()
                },
                VerdictReason::TotalFeesBelowMinimum,
            ),
            // AvgFeeBelowMinimum (use high tier: mempool_tx=None, unknown_as_high=true)
            (
                TemplatePropose {
                    id: 8,
                    tx_count: 1,
                    total_fees: 200,
                    ..base_template()
                },
                VerdictReason::AvgFeeBelowMinimum,
            ),
        ];

        for (template, expected_reason) in &cases {
            let result = evaluate_dynamic(template, &cfg, None, ts);
            assert_eq!(
                result.reason,
                Some(*expected_reason),
                "Template id={} expected {:?} got {:?}",
                template.id,
                expected_reason,
                result.reason
            );
            if let Some(reason) = &result.reason {
                assert!(
                    VerdictReason::ALL_CODES.contains(&reason.as_str()),
                    "reason {:?} as_str={} not in ALL_CODES",
                    reason,
                    reason.as_str()
                );
            }
        }
    }

    // --- accepted path returns None reason ---

    #[test]
    fn accepted_template_has_no_reason() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let template = base_template();
        let result = evaluate(&template, &cfg);
        assert!(
            result.reason.is_none(),
            "accepted template should have reason=None"
        );
        assert!(
            result.detail.is_none(),
            "accepted template should have detail=None"
        );
    }

    // ── v0.2.2 consensus safety tests ──

    #[test]
    fn weight_ratio_exceeded_enforced() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_weight_ratio: 0.999,
                enforce_weight_ratio: true,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            template_weight: Some(3_999_000), // ratio = 0.99975, exceeds 0.999
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert_eq!(result.reason, Some(VerdictReason::WeightRatioExceeded));
    }

    #[test]
    fn weight_ratio_exceeded_observe_only() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_weight_ratio: 0.999,
                enforce_weight_ratio: false,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            template_weight: Some(3_999_000),
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none(), "observe only should not reject");
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].reason,
            VerdictReason::WeightRatioExceeded
        );
    }

    #[test]
    fn weight_ratio_under_limit_no_warning() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_weight_ratio: 0.999,
                enforce_weight_ratio: true,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            template_weight: Some(3_000_000), // ratio = 0.75, well under limit
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn template_stale_enforced() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_template_age_ms: Some(5_000),
                enforce_template_age: true,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let now = now_unix_ms();
        let template = TemplatePropose {
            created_at_unix_ms: Some(now.saturating_sub(10_000)), // 10s old, limit is 5s
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now);
        assert_eq!(result.reason, Some(VerdictReason::TemplateStale));
    }

    #[test]
    fn template_stale_observe_only() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_template_age_ms: Some(5_000),
                enforce_template_age: false,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let now = now_unix_ms();
        let template = TemplatePropose {
            created_at_unix_ms: Some(now.saturating_sub(10_000)),
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now);
        assert!(result.reason.is_none(), "observe only should not reject");
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].reason, VerdictReason::TemplateStale);
    }

    #[test]
    fn sigops_warning_fires_above_threshold() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                warn_sigops_ratio: 0.95,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            total_sigops: Some(77_000), // 96.25% of 80,000
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].reason,
            VerdictReason::SigopsBudgetWarning
        );
    }

    #[test]
    fn sigops_warning_silent_below_threshold() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                warn_sigops_ratio: 0.95,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            total_sigops: Some(64_000), // 80% of 80,000
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn coinbase_sigops_anomaly_detection() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                warn_coinbase_sigops_max: 400,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            coinbase_sigops: Some(500),
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].reason,
            VerdictReason::CoinbaseSigopsAbnormal
        );
    }

    #[test]
    fn new_fields_backward_compatible_serde() {
        // TemplatePropose without the v0.2.2 fields should deserialize fine.
        let json = r#"{
            "version": 2,
            "id": 1,
            "block_height": 100,
            "prev_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "coinbase_value": 5000,
            "tx_count": 10,
            "total_fees": 50000
        }"#;
        let t: TemplatePropose = serde_json::from_str(json).unwrap();
        assert!(t.total_sigops.is_none());
        assert!(t.coinbase_sigops.is_none());
        assert!(t.template_weight.is_none());
        assert!(t.observed_weight.is_none());
        assert!(t.created_at_unix_ms.is_none());
        assert!(t.raw_block_hex.is_none());
    }

    // ── v2.0 Invariant Shield tests (ADR-002 Phase 1) ──

    /// Mainnet genesis block raw hex. Hardcoded rather than serialized
    /// via rust-bitcoin at test time so pool-verifier keeps depending
    /// only on `rg-consensus` at its facade boundary (ADR-002). The
    /// facade itself verifies that this constant round-trips through
    /// `re_derive_*` to the expected coinbase value and weight.
    const GENESIS_RAW_HEX: &str = concat!(
        "0100000000000000000000000000000000000000000000000000000000000000",
        "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa",
        "4b1e5e4a29ab5f49ffff001d1dac2b7c01010000000100000000000000000000",
        "00000000000000000000000000000000000000000000ffffffff4d04ffff001d",
        "0104455468652054696d65732030332f4a616e2f32303039204368616e63656c",
        "6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066",
        "6f722062616e6b73ffffffff0100f2052a0100000043410467",
        "8afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649",
        "f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
        "00000000",
    );

    /// Genesis coinbase value: the 50 BTC subsidy at height 0.
    const GENESIS_COINBASE_SATS: u64 = 50 * 100_000_000;

    /// Compute the genesis block weight through the facade itself.
    /// Using `re_derive_template_weight` here keeps pool-verifier free
    /// of a direct `bitcoin` dev-dependency and exercises the same
    /// code path the shield runs in production.
    fn genesis_weight_via_facade() -> u64 {
        let bytes = hex::decode(GENESIS_RAW_HEX).expect("GENESIS_RAW_HEX decodes");
        rg_consensus::re_derive_template_weight(&bytes).expect("genesis weight re-derives")
    }

    #[test]
    fn genesis_raw_hex_constant_round_trips_through_facade() {
        // Sanity check the hardcoded constant: if the hex ever drifts,
        // every downstream shield test breaks with a cryptic decode
        // failure. This test names the drift clearly.
        let bytes = hex::decode(GENESIS_RAW_HEX).expect("GENESIS_RAW_HEX decodes");
        let coinbase = rg_consensus::re_derive_coinbase_value(&bytes)
            .expect("coinbase value re-derives from GENESIS_RAW_HEX");
        assert_eq!(coinbase, GENESIS_COINBASE_SATS);
    }

    #[test]
    fn shield_skipped_without_raw_block_hex() {
        let outcome = check_invariant_shield(&base_template());
        assert_eq!(outcome, ShieldOutcome::Skipped);
    }

    #[test]
    fn shield_decode_failed_on_bad_hex() {
        let t = TemplatePropose {
            raw_block_hex: Some("not_hex_at_all".to_string()),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantDecodeFailed);
            }
            other => panic!("expected Rejected(V2InvariantDecodeFailed) got {other:?}"),
        }
    }

    #[test]
    fn shield_decode_failed_on_garbage_bytes() {
        // Valid hex that does not deserialize as a block.
        let t = TemplatePropose {
            raw_block_hex: Some("ffffffffffffff".to_string()),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantDecodeFailed);
            }
            other => panic!("expected Rejected(V2InvariantDecodeFailed) got {other:?}"),
        }
    }

    #[test]
    fn shield_coinbase_value_mismatch_rejects() {
        let t = TemplatePropose {
            // Declared coinbase != genesis 50 BTC.
            coinbase_value: 1,
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, detail } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbaseValueMismatch);
                assert!(
                    detail.contains("declared=1"),
                    "detail missing declared value: {detail}"
                );
            }
            other => panic!("expected Rejected(V2InvariantCoinbaseValueMismatch) got {other:?}"),
        }
    }

    #[test]
    fn shield_template_weight_mismatch_rejects() {
        let weight = genesis_weight_via_facade();
        let t = TemplatePropose {
            coinbase_value: GENESIS_COINBASE_SATS,
            template_weight: Some(weight + 1),
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantTemplateWeightMismatch);
            }
            other => panic!("expected Rejected(V2InvariantTemplateWeightMismatch) got {other:?}"),
        }
    }

    /// Build a `TemplatePropose` whose declared fields all agree with
    /// the genesis block bytes. Every Tier 1+2 invariant lands Agreed
    /// on it; since Phase 1.5 the Tier 3 section rejects it with
    /// `HeaderVersionLow` (genesis is a version-1 block), so shield
    /// happy-path tests use `regtest_segwit_template` instead and
    /// genesis serves the Tier 1+2 mismatch tests, which short-circuit
    /// before Tier 3 runs.
    ///
    /// `tx_count` is 1 (genesis is coinbase-only). `block_height` is
    /// `GENESIS_BIP34_HEIGHT` because the BIP-34 decoder reads the
    /// difficulty bits push at the start of the genesis coinbase
    /// script and reports them as the integer 0x1d00ffff. Genesis
    /// predates BIP-34 so this is a quirk of the test fixture, not a
    /// real height; production templates always carry the actual
    /// height in the BIP-34 push and the shield enforces the match.
    const GENESIS_BIP34_HEIGHT: u32 = 0x1d00_ffff;

    fn genesis_template() -> TemplatePropose {
        TemplatePropose {
            coinbase_value: GENESIS_COINBASE_SATS,
            // Producer convention (PB-19): non-coinbase count and
            // non-coinbase weight sum; genesis is coinbase-only.
            tx_count: 0,
            block_height: GENESIS_BIP34_HEIGHT,
            template_weight: Some(0),
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        }
    }

    #[test]
    fn avg_fee_rejects_below_threshold_average_at_rounding_boundary() {
        // total_fees=15001 over tx_count=3 is a true average of
        // 5000.33, strictly below a 5001 sats floor: must reject.
        // Ceiling division rounds the average up to exactly the
        // threshold and wrongly accepts; floor division is the
        // strict direction. total_fees=15003 sits exactly at the
        // threshold and must pass.
        let cfg = PolicyConfig {
            min_avg_fee_hi: 5001,
            unknown_mempool_as_high: true,
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };
        let below = TemplatePropose {
            total_fees: 15_001,
            tx_count: 3,
            ..base_template()
        };
        let result = evaluate(&below, &cfg);
        assert_eq!(
            result.reason,
            Some(VerdictReason::AvgFeeBelowMinimum),
            "true average below the floor must reject"
        );

        let at_threshold = TemplatePropose {
            total_fees: 15_003,
            tx_count: 3,
            ..base_template()
        };
        let result = evaluate(&at_threshold, &cfg);
        assert!(
            result.reason.is_none(),
            "average exactly at the floor must pass, got {:?}",
            result.reason
        );
    }

    #[test]
    fn mempool_tolerance_detail_renders_txids_in_display_order() {
        // Operators correlate rejection details against bitcoin-cli
        // and explorers, which print txids in display order (byte
        // reversed relative to internal order). The sample field must
        // match that convention.
        let mut txid = [0u8; 32];
        txid[0] = 0xaa;
        let detail = format_mempool_tolerance_detail(1, 10, &[txid]);
        let mut display = txid;
        display.reverse();
        let expected = hex::encode(display);
        assert!(
            detail.contains(&expected),
            "sample txid must render in display order, got: {detail}"
        );
    }

    #[test]
    fn shield_rejects_header_version_low_on_genesis() {
        // Genesis is a version-1 block, below the BIP-65 version-4
        // floor. Tier 3 (Phase 1.5) turns it into the canonical
        // header-version rejection: the wiring proof that the Tier 3
        // section runs inside the shield.
        match check_invariant_shield(&genesis_template()) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantHeaderVersionLow);
            }
            other => panic!("expected Rejected(V2InvariantHeaderVersionLow) got {other:?}"),
        }
    }

    #[test]
    fn shield_agrees_when_template_weight_absent() {
        // No declared template_weight means the weight re-derivation
        // is skipped; every other check must still pass.
        let t = TemplatePropose {
            template_weight: None,
            ..regtest_segwit_template()
        };
        assert_eq!(check_invariant_shield(&t), ShieldOutcome::Agreed);
    }

    #[test]
    fn shield_tx_count_mismatch_rejects() {
        let t = TemplatePropose {
            tx_count: 999,
            ..genesis_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, detail } => {
                assert_eq!(reason, VerdictReason::V2InvariantTxCountMismatch);
                assert!(
                    detail.contains("declared=999"),
                    "detail missing declared value: {detail}"
                );
            }
            other => panic!("expected Rejected(V2InvariantTxCountMismatch) got {other:?}"),
        }
    }

    #[test]
    fn shield_total_sigops_mismatch_rejects() {
        // One-sided check (PB-19). `total_sigops` is declared over the
        // NON-coinbase transactions, so the attack to catch is
        // under-declaring the sigops the block BODY provably carries.
        // The body tx below pays to P2PKH: one legacy sigop, provable
        // cost floor 4. Declaring 0 understates it and must reject.
        //
        // This deliberately no longer uses `genesis_template()`.
        // Genesis is coinbase-only, so its single sigop lives in the
        // coinbase and a non-coinbase declaration of 0 is HONEST
        // there. Asserting a rejection on genesis asserted the
        // coinbase leaking into a non-coinbase comparison, not the
        // attack, which is how the leak survived review (R-183: cross
        // the producer/verifier seam with a shape production emits).
        let cb = production_shaped_coinbase_p2pkh();
        let raw = rg_consensus::assemble_template_block(&rg_consensus::TemplateBlockParts {
            version: 0x2000_0000,
            prev_hash: [0x44; 32],
            time: 1_700_000_000,
            bits: 0x207f_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[p2pkh_body_tx()],
        })
        .expect("assembles");
        let t = TemplatePropose {
            coinbase_value: 5_000_000_000,
            tx_count: 1,
            block_height: 102,
            template_weight: None,
            total_sigops: Some(0),
            coinbase_sigops: Some(4),
            raw_block_hex: Some(hex::encode(raw)),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, detail } => {
                assert_eq!(reason, VerdictReason::V2InvariantSigopsMismatch);
                assert!(
                    detail.contains("floor=4"),
                    "floor must come from the body tx alone, not the coinbase: {detail}"
                );
            }
            other => panic!("expected Rejected(V2InvariantSigopsMismatch) got {other:?}"),
        }
    }

    #[test]
    fn shield_coinbase_sigops_mismatch_rejects() {
        // One-sided check (PB-19): the genesis coinbase carries one
        // legacy sigop, floor 4; declaring 0 understates it.
        let t = TemplatePropose {
            coinbase_sigops: Some(0),
            ..genesis_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbaseSigopsMismatch);
            }
            other => panic!("expected Rejected(V2InvariantCoinbaseSigopsMismatch) got {other:?}"),
        }
    }

    #[test]
    fn shield_block_height_mismatch_rejects() {
        let t = TemplatePropose {
            block_height: 100,
            ..genesis_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, detail } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbaseHeightMismatch);
                assert!(
                    detail.contains("declared=100"),
                    "detail missing declared value: {detail}"
                );
            }
            other => panic!("expected Rejected(V2InvariantCoinbaseHeightMismatch) got {other:?}"),
        }
    }

    #[test]
    fn shield_total_sigops_skipped_when_declared_none() {
        // Class D checks skip individually when the declared field is
        // None; the shield must still reach Agreed on a block that
        // passes everything else.
        let t = TemplatePropose {
            total_sigops: None,
            coinbase_sigops: None,
            ..regtest_segwit_template()
        };
        assert_eq!(check_invariant_shield(&t), ShieldOutcome::Agreed);
    }

    #[test]
    fn shield_merkle_root_mismatch_rejects_on_tampered_header() {
        // Flip one bit in the serialized merkle root byte at offset 36
        // (header start at 0; merkle root spans bytes 36..68).
        // GENESIS_RAW_HEX byte 36 is hex chars 72..74.
        let mut hex = GENESIS_RAW_HEX.to_string();
        let mut bytes = hex::decode(&hex).unwrap();
        bytes[36] ^= 0x01;
        hex = hex::encode(&bytes);
        let t = TemplatePropose {
            raw_block_hex: Some(hex),
            ..genesis_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantMerkleRootMismatch);
            }
            other => panic!("expected Rejected(V2InvariantMerkleRootMismatch) got {other:?}"),
        }
    }

    #[test]
    fn shield_does_not_override_earlier_safety_rejection() {
        // Shield runs after safety. A stale template that also carries
        // a valid raw_block_hex must still reject with TemplateStale,
        // not propagate an Agreed outcome past safety.
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_template_age_ms: Some(1_000),
                enforce_template_age: true,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };
        let now = now_unix_ms();
        let t = TemplatePropose {
            coinbase_value: GENESIS_COINBASE_SATS,
            created_at_unix_ms: Some(now.saturating_sub(5_000)),
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        let result = evaluate_dynamic(&t, &cfg, None, now);
        assert_eq!(result.reason, Some(VerdictReason::TemplateStale));
        // Shield never ran because safety short-circuited first.
        assert!(!result.shield_skipped);
    }

    #[test]
    fn evaluate_dynamic_sets_shield_skipped_when_hex_absent() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let result = evaluate(&base_template(), &cfg);
        assert!(result.reason.is_none());
        assert!(result.shield_skipped);
    }

    #[test]
    fn evaluate_dynamic_clears_shield_skipped_when_shield_runs() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        // Use the regtest fixture so every shield check, Tier 3
        // included, agrees (tx_count, block_height, header version).
        let result = evaluate(&regtest_segwit_template(), &cfg);
        assert!(result.reason.is_none(), "got reason: {:?}", result.reason);
        assert!(!result.shield_skipped);
    }

    #[test]
    fn evaluate_dynamic_emits_shield_reject_as_verdict_reason() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let t = TemplatePropose {
            coinbase_value: 1,
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        let result = evaluate(&t, &cfg);
        assert_eq!(
            result.reason,
            Some(VerdictReason::V2InvariantCoinbaseValueMismatch)
        );
        assert!(!result.shield_skipped);
    }

    #[test]
    fn shield_violation_mapping_is_distinct_across_invariants() {
        // Catch silent collapses to a single VerdictReason across the
        // 24 shield variants. NotImplemented is the shield-disabled
        // sentinel and intentionally routes to InternalError.
        let mut seen: Vec<VerdictReason> = ConsensusViolation::ALL
            .iter()
            .filter(|v| !matches!(v, ConsensusViolation::NotImplemented))
            .map(consensus_violation_to_verdict_reason)
            .collect();
        let before = seen.len();
        seen.sort_by_key(VerdictReason::as_str);
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "consensus_violation_to_verdict_reason collapsed two variants onto one reason"
        );
    }

    // ── Regtest segwit block fixture (ADR-002 Phase 1 #4b I-C) ────
    //
    // The fixture closes the genesis-only test gap. Genesis is
    // pre-segwit so it cannot exercise the witness commitment
    // present-and-matches branch nor the
    // `WitnessCommitmentMissing` rejection path. The regtest block
    // below is a freshly mined post-segwit block at height 102 with
    // one coinbase tx plus one segwit transaction sending 0.5 BTC
    // back to ourselves. The block has a well-formed BIP-141
    // witness commitment in the coinbase OP_RETURN.
    //
    // Provenance: mined locally on `lncm/bitcoind:v27.0` regtest via
    // `docker compose exec bitcoind bitcoin-cli -regtest
    // generatetoaddress`. See `docs/lessons.md` R-154 for why we
    // hardcode the bytes rather than depend on `bitcoin` as a
    // dev-dependency.

    const REGTEST_SEGWIT_BLOCK_HEX: &str =
        include_str!("../tests/fixtures/regtest_segwit_block.hex");
    const REGTEST_SEGWIT_BLOCK_HEIGHT: u32 = 102;
    const REGTEST_SEGWIT_COINBASE_SATS: u64 = 5_000_000_141;
    /// Producer convention (PB-19): non-coinbase transaction count.
    /// The fixture block body is coinbase plus one segwit tx.
    const REGTEST_SEGWIT_TX_COUNT: u32 = 1;

    /// Build a `TemplatePropose` whose declared fields all agree
    /// with the regtest segwit block fixture, in the PB-19 producer
    /// conventions: non-coinbase tx count and weight sum, sigops in
    /// cost units (declared here as the legacy x4 floor, the honest
    /// lower-bound shape). Re-derive via the facade so the fixture
    /// never drifts from the accounting.
    fn regtest_segwit_template() -> TemplatePropose {
        let bytes =
            hex::decode(REGTEST_SEGWIT_BLOCK_HEX.trim()).expect("REGTEST_SEGWIT_BLOCK_HEX decodes");
        let parsed = rg_consensus::parse_block(&bytes).expect("regtest block parses");
        let weight = rg_consensus::non_coinbase_tx_weight(&parsed);
        let total_cost_floor =
            u32::try_from(u64::from(rg_consensus::non_coinbase_sigops(&parsed)) * 4)
                .expect("fixture sigop cost fits u32");
        let coinbase_cost_floor =
            u32::try_from(u64::from(rg_consensus::coinbase_sigops(&parsed)) * 4)
                .expect("fixture coinbase sigop cost fits u32");

        TemplatePropose {
            coinbase_value: REGTEST_SEGWIT_COINBASE_SATS,
            tx_count: REGTEST_SEGWIT_TX_COUNT,
            block_height: REGTEST_SEGWIT_BLOCK_HEIGHT,
            template_weight: Some(weight),
            total_sigops: Some(total_cost_floor),
            coinbase_sigops: Some(coinbase_cost_floor),
            raw_block_hex: Some(REGTEST_SEGWIT_BLOCK_HEX.trim().to_string()),
            ..base_template()
        }
    }

    /// Legacy-serialize the coinbase template-manager's
    /// `build_coinbase_halves` produces for height 102, a
    /// 5,000,000,000 sat payout to `OP_TRUE`, an 8-byte zero-filled
    /// extranonce slot, and no witness commitment. Byte-for-byte the
    /// production shape, hand-rolled here because pool-verifier
    /// carries no assembler of its own (R-154).
    fn production_shaped_coinbase() -> Vec<u8> {
        let mut cb = Vec::new();
        cb.extend_from_slice(&2u32.to_le_bytes()); // tx version
        cb.push(0x01); // input count
        cb.extend_from_slice(&[0u8; 32]); // null prevout hash
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // prevout index
        cb.push(0x0a); // scriptSig len: 2 (BIP-34 push) + 8 (extranonce)
        cb.extend_from_slice(&[0x01, 0x66]); // BIP-34 push of height 102
        cb.extend_from_slice(&[0u8; 8]); // zero-filled extranonce
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sequence
        cb.push(0x01); // output count
        cb.extend_from_slice(&5_000_000_000u64.to_le_bytes()); // payout value
        cb.push(0x01); // script len
        cb.push(0x51); // OP_TRUE
        cb.extend_from_slice(&0u32.to_le_bytes()); // locktime
        cb
    }

    #[test]
    fn shield_agrees_on_production_shaped_propose_end_to_end() {
        // PB-19 contract test. A propose declared exactly the way
        // template-manager declares its fields (tx_count and
        // template_weight over NON-coinbase transactions, sigops in
        // BIP-141 cost units) carrying a facade-assembled
        // raw_block_hex must land Agreed. The three Phase 1b
        // launch blockers (weight, tx_count, and sigops contract
        // drift between producer and shield) were invisible to every
        // test that did not cross this seam with production
        // semantics.
        let cb = production_shaped_coinbase();
        let parts = rg_consensus::TemplateBlockParts {
            version: 0x2000_0000,
            prev_hash: [0x44; 32],
            time: 1_700_000_000,
            bits: 0x207f_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[],
        };
        let raw = rg_consensus::assemble_template_block(&parts).expect("assembles");
        let t = TemplatePropose {
            coinbase_value: 5_000_000_000,
            // Producer semantics: non-coinbase transaction count.
            tx_count: 0,
            block_height: 102,
            // Producer semantics: sum of non-coinbase tx weights.
            template_weight: Some(0),
            // Producer semantics: BIP-141 sigop cost of the GBT txs.
            total_sigops: Some(0),
            coinbase_sigops: Some(0),
            raw_block_hex: Some(hex::encode(raw)),
            ..base_template()
        };
        assert_eq!(
            check_invariant_shield(&t),
            ShieldOutcome::Agreed,
            "a production-shaped propose must pass its own shield"
        );
    }

    /// Same production shape as [`production_shaped_coinbase`] but
    /// paying to a P2PKH `scriptPubKey` instead of `OP_TRUE`. Every
    /// shipped config still pays to `OP_TRUE`
    /// (`deploy/manager-setup-b.toml`, `dev/manager.toml`,
    /// `dev/manager-shadow.toml`), which carries zero legacy sigops
    /// and so cannot exercise the coinbase term of the sigop floor.
    /// `dev/manager.toml` tells the operator to swap in a real payout
    /// script at mainnet, so the sigop-bearing coinbase is the shape
    /// that actually ships. R-183: the contract test must cross the
    /// producer/verifier seam with the payout shape production uses.
    fn production_shaped_coinbase_p2pkh() -> Vec<u8> {
        let mut cb = Vec::new();
        cb.extend_from_slice(&2u32.to_le_bytes()); // tx version
        cb.push(0x01); // input count
        cb.extend_from_slice(&[0u8; 32]); // null prevout hash
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // prevout index
        cb.push(0x0a); // scriptSig len: 2 (BIP-34 push) + 8 (extranonce)
        cb.extend_from_slice(&[0x01, 0x66]); // BIP-34 push of height 102
        cb.extend_from_slice(&[0u8; 8]); // zero-filled extranonce
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sequence
        cb.push(0x01); // output count
        cb.extend_from_slice(&5_000_000_000u64.to_le_bytes()); // payout value
        cb.push(0x19); // script len 25 (P2PKH)
        cb.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 PUSHBYTES_20
        cb.extend_from_slice(&[0xab; 20]); // pubkey hash
        cb.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
        cb.extend_from_slice(&0u32.to_le_bytes()); // locktime
        cb
    }

    /// A minimal legacy body transaction paying to P2PKH: one legacy
    /// sigop in the output, non-null prevout so the Tier 3
    /// null-prevout check passes, empty scriptSig so the input adds
    /// none. Used to give a test block a non-coinbase sigop the
    /// Class D floor must actually see.
    fn p2pkh_body_tx() -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&2u32.to_le_bytes()); // version
        tx.push(0x01); // input count
        tx.extend_from_slice(&[0x11; 32]); // non-null prevout hash
        tx.extend_from_slice(&0u32.to_le_bytes()); // prevout index
        tx.push(0x00); // empty scriptSig
        tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sequence
        tx.push(0x01); // output count
        tx.extend_from_slice(&1_000u64.to_le_bytes()); // value
        tx.push(0x19); // script len 25 (P2PKH)
        tx.extend_from_slice(&[0x76, 0xa9, 0x14]);
        tx.extend_from_slice(&[0xcd; 20]);
        tx.extend_from_slice(&[0x88, 0xac]);
        tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
        tx
    }

    #[test]
    fn shield_agrees_on_sigop_bearing_coinbase_payout() {
        // The declared `total_sigops` wire contract is BIP-141 cost
        // over the NON-coinbase transactions (rg-protocol field docs,
        // PB-19), and the producer honours it by summing GBT
        // `transactions[].sigops`, which excludes the coinbase. The
        // shield's provable floor must therefore also exclude the
        // coinbase, or a sigop-bearing payout script inflates the
        // floor above an honest declaration and the shield rejects a
        // template it should agree with.
        //
        // This template is honest in every field: no non-coinbase
        // transactions, so declared cost is 0; the coinbase's single
        // OP_CHECKSIG is declared at its true BIP-141 cost of 4, so
        // the separate coinbase check is satisfied and this test
        // isolates the total_sigops comparison.
        let cb = production_shaped_coinbase_p2pkh();
        let parts = rg_consensus::TemplateBlockParts {
            version: 0x2000_0000,
            prev_hash: [0x44; 32],
            time: 1_700_000_000,
            bits: 0x207f_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[],
        };
        let raw = rg_consensus::assemble_template_block(&parts).expect("assembles");
        let t = TemplatePropose {
            coinbase_value: 5_000_000_000,
            tx_count: 0,
            block_height: 102,
            template_weight: Some(0),
            total_sigops: Some(0),
            coinbase_sigops: Some(4),
            raw_block_hex: Some(hex::encode(raw)),
            ..base_template()
        };
        assert_eq!(
            check_invariant_shield(&t),
            ShieldOutcome::Agreed,
            "an honest propose with a sigop-bearing coinbase payout must pass its own shield"
        );
    }

    /// Find the BIP-141 witness commitment magic in a serialized
    /// block and apply `f` to the 6-byte commitment header start
    /// position. Re-computes and updates the header merkle root so
    /// downstream checks reach past the merkle root gate. Returns
    /// the modified block hex.
    fn modify_witness_commitment(hex_str: &str, f: impl FnOnce(&mut [u8], usize)) -> String {
        let mut bytes = hex::decode(hex_str.trim()).expect("hex decodes");
        // OP_RETURN OP_PUSHBYTES_36 magic is 0x6a 0x24 0xaa 0x21 0xa9 0xed.
        let pattern = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        let idx = bytes
            .windows(pattern.len())
            .position(|w| w == pattern)
            .expect("witness commitment magic not found in block");
        f(&mut bytes, idx);
        fixup_merkle_root_in_block(&mut bytes);
        hex::encode(bytes)
    }

    /// Re-derive the merkle root from the tampered body and write
    /// it back into the header at offset 36..68. Without this, any
    /// byte tamper inside coinbase or non-coinbase txs trips the
    /// shield's `MerkleRootMismatch` check before it can reach the
    /// deeper invariant the test is targeting. Block header merkle
    /// root is in the same internal byte order that
    /// `re_derive_merkle_root` returns, so a direct copy is correct.
    fn fixup_merkle_root_in_block(bytes: &mut [u8]) {
        let new_root = rg_consensus::re_derive_merkle_root(bytes)
            .expect("merkle root re-derives after tampering");
        bytes[36..68].copy_from_slice(&new_root);
    }

    #[test]
    fn regtest_segwit_block_has_witness_data() {
        // Sanity check: the fixture really does carry segwit data.
        // If the fixture file ever drifts to a non-segwit block, the
        // witness commitment tests below silently lose coverage.
        let bytes = hex::decode(REGTEST_SEGWIT_BLOCK_HEX.trim()).unwrap();
        let commit = rg_consensus::re_derive_witness_commitment(&bytes)
            .expect("regtest witness commitment derives");
        assert!(
            commit.is_some(),
            "regtest fixture must carry a witness commitment"
        );
    }

    #[test]
    fn shield_agrees_on_regtest_segwit_block() {
        // Real-world happy path. Exercises every Tier 1+2 check
        // including the witness commitment present-and-matches branch
        // that genesis cannot reach.
        assert_eq!(
            check_invariant_shield(&regtest_segwit_template()),
            ShieldOutcome::Agreed
        );
    }

    #[test]
    fn shield_witness_commitment_missing_when_op_return_tampered() {
        // Replace the OP_RETURN opcode (0x6a) with OP_NOP (0x61) so
        // the extractor no longer recognizes the commitment output.
        // The block still deserializes (script bytes are arbitrary),
        // has_segwit is still true, but the extractor returns None.
        let tampered = modify_witness_commitment(REGTEST_SEGWIT_BLOCK_HEX, |bytes, idx| {
            bytes[idx] = 0x61; // OP_NOP
        });
        let t = TemplatePropose {
            raw_block_hex: Some(tampered),
            ..regtest_segwit_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantWitnessCommitmentMissing);
            }
            other => {
                panic!("expected Rejected(V2InvariantWitnessCommitmentMissing) got {other:?}")
            }
        }
    }

    #[test]
    fn shield_witness_commitment_mismatch_when_commitment_byte_tampered() {
        // Flip one bit in the 32-byte commitment. The OP_RETURN
        // structure stays well-formed so the extractor returns
        // Some(declared); the extractor's value disagrees with the
        // BIP-141 computed commitment so the shield rejects.
        let tampered = modify_witness_commitment(REGTEST_SEGWIT_BLOCK_HEX, |bytes, idx| {
            // The commitment starts at idx + 6 (OP_RETURN + push len
            // + 4 magic bytes). Flip the first commitment byte.
            bytes[idx + 6] ^= 0x01;
        });
        let t = TemplatePropose {
            raw_block_hex: Some(tampered),
            ..regtest_segwit_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantWitnessCommitmentMismatch);
            }
            other => {
                panic!("expected Rejected(V2InvariantWitnessCommitmentMismatch) got {other:?}")
            }
        }
    }

    #[test]
    fn shield_coinbase_bip34_missing_when_first_byte_tampered() {
        // Tamper the first byte of the coinbase scriptSig so the
        // BIP-34 decoder rejects the integer push. The BIP-34 push
        // for height 102 starts with opcode 0x01 (push one byte)
        // followed by 0x66 (=102). Replace the push opcode with
        // 0x00 (OP_0) which the decoder rejects.
        //
        // After tampering, the body merkle root no longer matches
        // the header's merkle_root; we fix that up so the shield
        // reaches the BIP-34 check past the merkle gate.
        let mut bytes = hex::decode(REGTEST_SEGWIT_BLOCK_HEX.trim()).unwrap();
        // Locate the coinbase scriptSig start by scanning past the
        // header (80 bytes), tx count varint (1 byte for our
        // 2-tx block), coinbase version (4), segwit marker+flag (2),
        // input count varint (1), prevout (32+4), scriptSig length
        // varint (1). For our regtest block these fields are all
        // single-byte varints so the push opcode lives at offset
        // 80 + 1 + 4 + 2 + 1 + 36 + 1 = 125.
        let push_opcode_offset = 125;
        // Sanity-check: the push opcode at this offset should be in
        // the BIP-34 direct-push range (0x01..=0x04). If the fixture
        // ever changes shape this assertion makes the drift loud.
        assert!(
            (0x01..=0x04).contains(&bytes[push_opcode_offset]),
            "fixture shape changed: byte at offset 125 is {:#x}, expected BIP-34 push opcode",
            bytes[push_opcode_offset]
        );
        bytes[push_opcode_offset] = 0x00;
        fixup_merkle_root_in_block(&mut bytes);
        let tampered = hex::encode(bytes);
        let t = TemplatePropose {
            raw_block_hex: Some(tampered),
            ..regtest_segwit_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbaseBip34Missing);
            }
            other => panic!("expected Rejected(V2InvariantCoinbaseBip34Missing) got {other:?}"),
        }
    }

    /// Rewrite the coinbase prevout in the serialized regtest
    /// fixture and fix up the merkle root, which is what an attacker
    /// controlling `raw_block_hex` would do anyway since the header
    /// is theirs too.
    ///
    /// Offsets, same derivation the BIP-34 test above documents:
    /// header 80, tx count varint 1, coinbase version 4, segwit
    /// marker+flag 2, input count varint 1 => prevout txid at
    /// 88..120 and prevout index at 120..124.
    fn tamper_coinbase_prevout(txid: [u8; 32], vout: u32) -> String {
        let mut bytes = hex::decode(REGTEST_SEGWIT_BLOCK_HEX.trim()).unwrap();
        assert_eq!(
            &bytes[88..120],
            &[0u8; 32],
            "fixture shape changed: bytes 88..120 are not the coinbase's null prevout txid"
        );
        assert_eq!(
            &bytes[120..124],
            &0xFFFF_FFFFu32.to_le_bytes(),
            "fixture shape changed: bytes 120..124 are not the 0xFFFFFFFF prevout index"
        );
        bytes[88..120].copy_from_slice(&txid);
        bytes[120..124].copy_from_slice(&vout.to_le_bytes());
        fixup_merkle_root_in_block(&mut bytes);
        hex::encode(bytes)
    }

    // ── PB-20: txdata[0] must actually BE a coinbase ──────────────

    #[test]
    fn shield_rejects_pb20_non_coinbase_at_index_zero() {
        // The exact shape the PB-20 review executed and recorded as
        // returning Agreed: index 0 spends prevout 0x11..11:7, so
        // every skip(1) "non-coinbase" accessor silently reads the
        // wrong set. Nothing before Tier 3 notices, because the
        // tamper leaves weight, sigops, tx_count, coinbase value and
        // the BIP-34 height push untouched and the merkle root is
        // fixed up.
        let t = TemplatePropose {
            raw_block_hex: Some(tamper_coinbase_prevout([0x11; 32], 7)),
            ..regtest_segwit_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbasePrevoutNotNull);
            }
            other => panic!("expected Rejected(V2InvariantCoinbasePrevoutNotNull) got {other:?}"),
        }
    }

    #[test]
    fn shield_rejects_pb20_shape_with_coinbase_sigops_omitted() {
        // PB-20 records that the shape also passed with
        // coinbase_sigops absent, which is the stock-Core shape
        // (Core omits `coinbasetxn`). Pin that the rejection does
        // not depend on the attacker volunteering that field.
        let t = TemplatePropose {
            raw_block_hex: Some(tamper_coinbase_prevout([0x11; 32], 7)),
            coinbase_sigops: None,
            total_sigops: None,
            ..regtest_segwit_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbasePrevoutNotNull);
            }
            other => panic!("expected Rejected(V2InvariantCoinbasePrevoutNotNull) got {other:?}"),
        }
    }

    #[test]
    fn shield_rejects_pb20_half_coinbase_null_txid_wrong_index() {
        // All-zero txid but index 0, the case a txid-only check
        // would wave through.
        let t = TemplatePropose {
            raw_block_hex: Some(tamper_coinbase_prevout([0u8; 32], 0)),
            ..regtest_segwit_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbasePrevoutNotNull);
            }
            other => panic!("expected Rejected(V2InvariantCoinbasePrevoutNotNull) got {other:?}"),
        }
    }

    /// Transaction 0 with TWO inputs: `input[0]` carries the null
    /// prevout that makes it read as a coinbase, `input[1]` spends a
    /// real outpoint. `tamper_coinbase_prevout` cannot build this,
    /// because a second input changes the serialized length and that
    /// helper rewrites the existing prevout in place against fixed
    /// offsets. Assembling from parts is the construction that fits,
    /// and it computes the merkle root over the body it built, so no
    /// `fixup_merkle_root_in_block` pass is needed and Class S has
    /// nothing to catch.
    ///
    /// Legacy serialization throughout with no commitment output, so
    /// `assemble_template_block` attaches no BIP-141 reserved witness
    /// and the witness-commitment checks stay out of the way.
    fn two_input_index_zero_coinbase() -> Vec<u8> {
        let mut cb = Vec::new();
        cb.extend_from_slice(&2u32.to_le_bytes()); // tx version
        cb.push(0x02); // input count: two, which is the whole point
        // input[0]: the null prevout an attacker leaves in place so
        // every index-0 reader still sees a coinbase.
        cb.extend_from_slice(&[0u8; 32]); // null prevout hash
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // prevout index
        cb.push(0x0a); // scriptSig len: 2 (BIP-34 push) + 8 (extranonce)
        cb.extend_from_slice(&[0x01, 0x66]); // BIP-34 push of height 102
        cb.extend_from_slice(&[0u8; 8]); // zero-filled extranonce
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sequence
        // input[1]: a real outpoint. This is the value-spending input
        // no coinbase may carry, and it is invisible to every check
        // that reads only `input[0]`.
        cb.extend_from_slice(&[0x11; 32]); // non-null prevout hash
        cb.extend_from_slice(&0u32.to_le_bytes()); // prevout index
        cb.push(0x00); // empty scriptSig, contributes no sigops
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sequence
        cb.push(0x01); // output count
        cb.extend_from_slice(&5_000_000_000u64.to_le_bytes()); // payout value
        cb.push(0x01); // script len
        cb.push(0x51); // OP_TRUE
        cb.extend_from_slice(&0u32.to_le_bytes()); // locktime
        cb
    }

    #[test]
    fn shield_rejects_pb20_two_input_index_zero() {
        // The attack shape none of the three tests above reach.
        // `check_non_coinbase_null_prevout` iterates `skip(1)`, so it
        // structurally cannot see any input of transaction 0, and
        // nothing else in the shield looks past `input[0]`: the BIP-34
        // height push and the coinbase script length both read
        // `input.first()`, and the coinbase value reads the outputs.
        // The second input disturbs none of them, so before PB-20 this
        // template reached `Agreed`. Only the exactly-one-input arm of
        // `check_coinbase_null_prevout` catches it.
        let cb = two_input_index_zero_coinbase();
        let parts = rg_consensus::TemplateBlockParts {
            version: 0x2000_0000,
            prev_hash: [0x44; 32],
            time: 1_700_000_000,
            bits: 0x207f_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[],
        };
        let raw = rg_consensus::assemble_template_block(&parts).expect("assembles");
        let t = TemplatePropose {
            coinbase_value: 5_000_000_000,
            // Producer semantics throughout: non-coinbase counts.
            tx_count: 0,
            block_height: 102,
            template_weight: Some(0),
            total_sigops: Some(0),
            coinbase_sigops: Some(0),
            raw_block_hex: Some(hex::encode(raw)),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbasePrevoutNotNull);
            }
            other => panic!("expected Rejected(V2InvariantCoinbasePrevoutNotNull) got {other:?}"),
        }
    }

    #[test]
    fn shield_still_agrees_on_the_untampered_fixture() {
        // Guard against the new Tier 3 check rejecting honest
        // templates: the same fixture, unmodified, must still pass.
        // Without this the three tests above would also pass if
        // check_coinbase_null_prevout rejected everything.
        assert!(
            matches!(
                check_invariant_shield(&regtest_segwit_template()),
                ShieldOutcome::Agreed
            ),
            "PB-20 check must not reject the honest regtest fixture"
        );
    }

    // ── PB-21: coinbase value must stay inside MoneyRange ─────────
    //
    // The Class D coinbase-value comparison re-derives the total from
    // `raw_block_hex`, which is attacker controlled, and nothing in
    // the workspace bounded either an individual output or the sum.
    // An attacker who declares the same out-of-range number the
    // outputs add up to matched the re-derivation and reached
    // `Agreed`.

    /// Same production shape as [`production_shaped_coinbase`] but
    /// with caller-chosen output values, so a test can put an
    /// out-of-range or overflowing payout in the coinbase. Every
    /// other byte is the shipped shape, which keeps the output value
    /// the only variable. Assembling from parts computes the merkle
    /// root over the body it builds, so Class S has nothing to catch
    /// and the template reaches the coinbase-value checks.
    fn coinbase_with_output_values(values: &[u64]) -> Vec<u8> {
        assert!(
            !values.is_empty() && values.len() < 0xFD,
            "helper emits a single-byte output count varint"
        );
        let mut cb = Vec::new();
        cb.extend_from_slice(&2u32.to_le_bytes()); // tx version
        cb.push(0x01); // input count
        cb.extend_from_slice(&[0u8; 32]); // null prevout hash
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // prevout index
        cb.push(0x0a); // scriptSig len: 2 (BIP-34 push) + 8 (extranonce)
        cb.extend_from_slice(&[0x01, 0x66]); // BIP-34 push of height 102
        cb.extend_from_slice(&[0u8; 8]); // zero-filled extranonce
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sequence
        cb.push(u8::try_from(values.len()).expect("output count fits a byte"));
        for v in values {
            cb.extend_from_slice(&v.to_le_bytes()); // payout value
            cb.push(0x01); // script len
            cb.push(0x51); // OP_TRUE
        }
        cb.extend_from_slice(&0u32.to_le_bytes()); // locktime
        cb
    }

    /// An otherwise honest propose carrying a coinbase that pays
    /// `values`, declaring `declared` as its coinbase value. Passing
    /// the true sum as `declared` is what makes the Class D
    /// comparison agree and pushes the question onto the ceiling.
    fn template_with_coinbase_values(values: &[u64], declared: u64) -> TemplatePropose {
        let cb = coinbase_with_output_values(values);
        let parts = rg_consensus::TemplateBlockParts {
            version: 0x2000_0000,
            prev_hash: [0x44; 32],
            time: 1_700_000_000,
            bits: 0x207f_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[],
        };
        let raw = rg_consensus::assemble_template_block(&parts).expect("assembles");
        TemplatePropose {
            coinbase_value: declared,
            // Producer semantics throughout: non-coinbase counts.
            tx_count: 0,
            block_height: 102,
            template_weight: Some(0),
            total_sigops: Some(0),
            coinbase_sigops: Some(0),
            raw_block_hex: Some(hex::encode(raw)),
            ..base_template()
        }
    }

    #[test]
    fn shield_rejects_pb21_two_output_overflow() {
        // The PB-21 repro. Two outputs of 0xC000_0000_0000_0000 sum
        // to 2^64, which the unchecked `.sum()` inside
        // `re_derive_coinbase_value` could not represent: the
        // debug/CI profile panicked outright, so a remote peer could
        // stop the verifier on demand, and the release profile
        // wrapped to 2^63, which the attacker declares here so the
        // Class D comparison matches and the shield agrees to a
        // block paying about 1.8e19 sats.
        let t = template_with_coinbase_values(
            &[0xC000_0000_0000_0000, 0xC000_0000_0000_0000],
            9_223_372_036_854_775_808,
        );
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbaseValueExceedsMax);
            }
            other => panic!(
                "expected Rejected(V2InvariantCoinbaseValueExceedsMax) on the overflow shape, got {other:?}"
            ),
        }
    }

    #[test]
    fn shield_rejects_pb21_single_output_above_max_money() {
        // No overflow at all: one output of MAX_MONEY + 1, declared
        // honestly, so Class D re-derives exactly what was declared
        // and waves it through. Only a MoneyRange ceiling catches it.
        let t = template_with_coinbase_values(&[2_100_000_000_000_001], 2_100_000_000_000_001);
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbaseValueExceedsMax);
            }
            other => panic!(
                "expected Rejected(V2InvariantCoinbaseValueExceedsMax) on a single out-of-range output, got {other:?}"
            ),
        }
    }

    #[test]
    fn shield_rejects_pb21_sum_above_max_money() {
        // Both outputs are individually inside MoneyRange, so a
        // per-output check alone would wave this through. Only the
        // total is out of range.
        let t = template_with_coinbase_values(
            &[2_000_000_000_000_000, 200_000_000_000_000],
            2_200_000_000_000_000,
        );
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbaseValueExceedsMax);
            }
            other => panic!(
                "expected Rejected(V2InvariantCoinbaseValueExceedsMax) on an out-of-range total, got {other:?}"
            ),
        }
    }

    #[test]
    fn shield_still_agrees_on_honest_coinbase_values() {
        // The honest side. Without this the three tests above would
        // also pass if the new ceiling rejected everything: a normal
        // subsidy plus fees, and exactly MAX_MONEY, which Core's
        // inclusive `MoneyRange` accepts.
        let subsidy_plus_fees = template_with_coinbase_values(&[3_125_000_000, 141], 3_125_000_141);
        assert_eq!(
            check_invariant_shield(&subsidy_plus_fees),
            ShieldOutcome::Agreed,
            "a normal subsidy plus fees coinbase must still pass"
        );
        let exactly_max_money =
            template_with_coinbase_values(&[2_100_000_000_000_000], 2_100_000_000_000_000);
        assert_eq!(
            check_invariant_shield(&exactly_max_money),
            ShieldOutcome::Agreed,
            "MoneyRange is inclusive: exactly MAX_MONEY must still pass"
        );
        assert_eq!(
            check_invariant_shield(&regtest_segwit_template()),
            ShieldOutcome::Agreed,
            "PB-21 ceiling must not reject the honest regtest fixture"
        );
    }

    // ── PB-18(a): Phase 2 Class M attribution ─────────────────────
    //
    // `EvalResult.phase2` must report what the Class M check actually
    // did during the evaluation, so the ingress metrics block cannot
    // misattribute templates where Class M never ran and cannot
    // mislabel on a view-state flip between two snapshot reads.

    fn attribution_snapshot(
        state: crate::mempool_view::MempoolState,
        txids: Vec<[u8; 32]>,
    ) -> crate::mempool_view::MempoolSnapshot {
        crate::mempool_view::MempoolSnapshot {
            state,
            txids: std::sync::Arc::new(txids.into_iter().collect()),
            age_secs: 0,
            size: 0,
        }
    }

    /// Non-coinbase txids of the regtest segwit fixture, in internal
    /// byte order, derived through the facade like production does.
    fn regtest_segwit_txids() -> Vec<[u8; 32]> {
        let bytes =
            hex::decode(REGTEST_SEGWIT_BLOCK_HEX.trim()).expect("REGTEST_SEGWIT_BLOCK_HEX decodes");
        let parsed = rg_consensus::parse_block(&bytes).expect("regtest block parses");
        rg_consensus::template_txids(&parsed)
    }

    #[test]
    fn phase2_attribution_not_run_without_raw_block_hex() {
        // Class M cannot run when the template omits raw_block_hex,
        // even though a fresh snapshot was supplied.
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let snap = attribution_snapshot(crate::mempool_view::MempoolState::Fresh, vec![]);
        let result = evaluate_dynamic_phase2(&base_template(), &cfg, Some(&snap), Some(100), 0);
        assert!(result.reason.is_none(), "got {:?}", result.reason);
        assert_eq!(result.phase2, Phase2Attribution::NotRun);
    }

    #[test]
    fn phase2_attribution_not_run_without_snapshot() {
        // Shield runs Phase 1 only when no snapshot is supplied;
        // Class M never executed.
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let result = evaluate_dynamic_phase2(&regtest_segwit_template(), &cfg, None, Some(100), 0);
        assert!(result.reason.is_none(), "got {:?}", result.reason);
        assert_eq!(result.phase2, Phase2Attribution::NotRun);
    }

    #[test]
    fn phase2_attribution_not_run_on_pre_shield_rejection() {
        // A pre-shield rejection (protocol version mismatch) means
        // Class M never ran, regardless of the supplied snapshot.
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let snap = attribution_snapshot(
            crate::mempool_view::MempoolState::Fresh,
            regtest_segwit_txids(),
        );
        let t = TemplatePropose {
            version: 99,
            ..regtest_segwit_template()
        };
        let result = evaluate_dynamic_phase2(&t, &cfg, Some(&snap), Some(100), 0);
        assert_eq!(result.reason, Some(VerdictReason::ProtocolVersionMismatch));
        assert_eq!(result.phase2, Phase2Attribution::NotRun);
    }

    #[test]
    fn phase2_attribution_agreed_on_fresh_full_overlap() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let snap = attribution_snapshot(
            crate::mempool_view::MempoolState::Fresh,
            regtest_segwit_txids(),
        );
        let result =
            evaluate_dynamic_phase2(&regtest_segwit_template(), &cfg, Some(&snap), Some(100), 0);
        assert!(result.reason.is_none(), "got {:?}", result.reason);
        assert_eq!(result.phase2, Phase2Attribution::Agreed);
    }

    #[test]
    fn phase2_attribution_rejected_on_tolerance_exceeded() {
        // Empty fresh view, 1/1 template txs unknown, above 4%.
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let snap = attribution_snapshot(crate::mempool_view::MempoolState::Fresh, vec![]);
        let result =
            evaluate_dynamic_phase2(&regtest_segwit_template(), &cfg, Some(&snap), Some(100), 0);
        assert_eq!(
            result.reason,
            Some(VerdictReason::V2InvariantMempoolToleranceExceeded)
        );
        assert_eq!(result.phase2, Phase2Attribution::Rejected);
    }

    #[test]
    fn phase2_attribution_skipped_degraded() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let snap = attribution_snapshot(crate::mempool_view::MempoolState::Degraded, vec![]);
        let result =
            evaluate_dynamic_phase2(&regtest_segwit_template(), &cfg, Some(&snap), Some(100), 0);
        assert!(result.reason.is_none(), "got {:?}", result.reason);
        assert_eq!(result.phase2, Phase2Attribution::SkippedDegraded);
    }

    #[test]
    fn phase2_attribution_skipped_unprimed() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let snap = attribution_snapshot(crate::mempool_view::MempoolState::Unprimed, vec![]);
        let result =
            evaluate_dynamic_phase2(&regtest_segwit_template(), &cfg, Some(&snap), Some(100), 0);
        assert!(result.reason.is_none(), "got {:?}", result.reason);
        assert_eq!(result.phase2, Phase2Attribution::SkippedUnprimed);
    }

    #[test]
    fn phase2_attribution_stale_on_stale_view_agreement() {
        // Stale-but-served view with full overlap: advisory Stale.
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let snap = attribution_snapshot(
            crate::mempool_view::MempoolState::Stale,
            regtest_segwit_txids(),
        );
        let result =
            evaluate_dynamic_phase2(&regtest_segwit_template(), &cfg, Some(&snap), Some(100), 0);
        assert!(result.reason.is_none(), "got {:?}", result.reason);
        assert_eq!(result.phase2, Phase2Attribution::Stale);
    }

    #[test]
    fn phase2_attribution_rejected_on_stale_view_tolerance_exceeded() {
        // A Stale view still hard-rejects above tolerance
        // (stale_state_still_rejects_above_threshold); attribution
        // must follow the rejection, not the view state.
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let snap = attribution_snapshot(crate::mempool_view::MempoolState::Stale, vec![]);
        let result =
            evaluate_dynamic_phase2(&regtest_segwit_template(), &cfg, Some(&snap), Some(100), 0);
        assert_eq!(
            result.reason,
            Some(VerdictReason::V2InvariantMempoolToleranceExceeded)
        );
        assert_eq!(result.phase2, Phase2Attribution::Rejected);
    }
}
