use serde::{Deserialize, Serialize};

pub mod gateway;

pub const PROTOCOL_VERSION: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplatePropose {
    pub version: u16,
    pub id: u64,

    pub block_height: u32,

    /// 64 hex chars (32 bytes). Keep as String for now to avoid custom serde,
    /// but validate length and hex in the verifier.
    pub prev_hash: String,

    pub coinbase_value: u64,
    /// Number of NON-coinbase transactions in the template (the GBT
    /// `transactions` array length). The coinbase is never counted;
    /// the shield's re-derivation subtracts it before comparing
    /// (PB-19 wire contract).
    pub tx_count: u32,
    pub total_fees: u64,

    /// Forward compatible fields. Older senders omit them.
    #[serde(default)]
    pub observed_weight: Option<u64>,

    #[serde(default)]
    pub created_at_unix_ms: Option<u64>,

    /// Consensus safety fields (v0.2.2). Older senders omit them.
    ///
    /// PB-19 wire contract: BIP-141 sigop COST units over the
    /// non-coinbase transactions (the GBT `transactions[].sigops`
    /// convention). The shield checks this one-sided against the
    /// provable legacy x4 floor; exact cost is not re-derivable
    /// without the spent prevouts.
    #[serde(default)]
    pub total_sigops: Option<u32>,

    /// BIP-141 sigop cost units, coinbase only. See `total_sigops`.
    #[serde(default)]
    pub coinbase_sigops: Option<u32>,

    /// Sum of NON-coinbase transaction weights in weight units (the
    /// GBT `transactions[].weight` convention; excludes the coinbase
    /// and header). PB-19 wire contract.
    #[serde(default)]
    pub template_weight: Option<u64>,

    /// Identity of the gateway instance that sent this proposal. Enables the
    /// verifier to route verdicts correctly in multi-gateway deployments and
    /// prevents split-brain where verdicts from one gateway are consumed by
    /// another. Optional for backward compatibility.
    #[serde(default)]
    pub gateway_instance_id: Option<String>,

    /// Lowercase hex encoding of the raw serialized block bytes for the
    /// v2.0 Invariant Shield (ADR-002 Phase 1). When present the verifier
    /// runs the rg-consensus re-derivations and rejects on mismatch with
    /// a canonical `v2_invariant_*` reason code. When absent the shield
    /// pass is silently skipped and the verifier increments
    /// `verifier_shield_skipped_total`. Older senders omit the field;
    /// backward compatible via `#[serde(default)]`.
    #[serde(default)]
    pub raw_block_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVerdict {
    pub version: u16,
    pub id: u64,

    pub accepted: bool,

    /// Machine readable reason for rejects.
    #[serde(default)]
    pub reason_code: Option<VerdictReason>,

    /// Human readable detail (log lines, thresholds, etc).
    #[serde(default)]
    pub reason_detail: Option<String>,

    /// Useful for "traceable rejects": what policy decision was applied.
    #[serde(default)]
    pub policy_context: Option<PolicyContext>,
}

/// Canonical machine-readable reason codes for template rejections.
///
/// `rg-protocol` is the **single source of truth** for these codes.
/// The `#[serde(rename_all = "snake_case")]` attribute and the `as_str()`
/// method MUST agree — verified by tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictReason {
    /// template.version != `PROTOCOL_VERSION` or `policy.protocol_version`
    ProtocolVersionMismatch,

    /// `prev_hash` not hex
    InvalidPrevHash,

    /// `prev_hash` length != `required_prevhash_len`
    PrevHashLenMismatch,

    /// `coinbase_value` == 0 and `reject_coinbase_zero` enabled (non-empty templates)
    CoinbaseValueZeroRejected,

    /// `tx_count` == 0 and `reject_empty_templates` enabled
    EmptyTemplateRejected,

    /// `tx_count` > `max_tx_count`
    TxCountExceeded,

    /// `total_fees` < `min_total_fees`
    TotalFeesBelowMinimum,

    /// (`total_fees` / `tx_count`) < effective min avg fee
    AvgFeeBelowMinimum,

    /// policy file could not be parsed/validated
    PolicyLoadError,

    /// verifier could not fetch mempool stats (degraded / fallback path)
    MempoolBackendUnavailable,

    /// unexpected internal failure
    InternalError,

    // ── v0.2.2 consensus safety ──
    /// template weight / `max_block_weight` > `safety.max_weight_ratio`
    WeightRatioExceeded,

    /// template age > `safety.max_template_age_ms`
    TemplateStale,

    /// `total_sigops` approaching consensus limit (observe only in 0.2.2)
    SigopsBudgetWarning,

    /// `coinbase_sigops` outside expected range (observe only in 0.2.2)
    CoinbaseSigopsAbnormal,

    // ── v2.0 Invariant Shield (ADR-002 Phase 1, 20 codes) ──
    //
    // Each variant below mirrors a `ConsensusViolation` variant in the
    // `rg-consensus` facade crate. Canonical `snake_case` strings are
    // PINNED via explicit `#[serde(rename = "...")]` attributes because
    // serde's automatic snake_case conversion of CamelCase that starts
    // with a digit pair (`V2InvariantX`) is not guaranteed to insert
    // the underscore after the digit. Explicit renames remove that
    // ambiguity and keep R-13 (canonical reason code strings) safe by
    // construction rather than by test catch-up.
    /// Coinbase value disagrees with re-derived.
    #[serde(rename = "v2_invariant_coinbase_value_mismatch")]
    V2InvariantCoinbaseValueMismatch,

    /// Declared `template_weight` disagrees with re-derived.
    #[serde(rename = "v2_invariant_template_weight_mismatch")]
    V2InvariantTemplateWeightMismatch,

    /// Merkle root does not match re-derived.
    #[serde(rename = "v2_invariant_merkle_root_mismatch")]
    V2InvariantMerkleRootMismatch,

    /// Witness commitment missing when segwit transactions are present.
    #[serde(rename = "v2_invariant_witness_commitment_missing")]
    V2InvariantWitnessCommitmentMissing,

    /// Witness commitment value does not match re-derived.
    #[serde(rename = "v2_invariant_witness_commitment_mismatch")]
    V2InvariantWitnessCommitmentMismatch,

    /// Total sigops disagrees with re-derived.
    #[serde(rename = "v2_invariant_sigops_mismatch")]
    V2InvariantSigopsMismatch,

    /// Coinbase sigops disagrees with re-derived.
    #[serde(rename = "v2_invariant_coinbase_sigops_mismatch")]
    V2InvariantCoinbaseSigopsMismatch,

    /// Transaction count disagrees with re-derived.
    #[serde(rename = "v2_invariant_tx_count_mismatch")]
    V2InvariantTxCountMismatch,

    /// Coinbase script length outside BIP-34 constraints.
    #[serde(rename = "v2_invariant_coinbase_script_length")]
    V2InvariantCoinbaseScriptLength,

    /// Coinbase output count outside protocol constraints.
    #[serde(rename = "v2_invariant_coinbase_output_count")]
    V2InvariantCoinbaseOutputCount,

    /// Coinbase missing height push (BIP-34).
    #[serde(rename = "v2_invariant_coinbase_bip34_missing")]
    V2InvariantCoinbaseBip34Missing,

    /// Coinbase height push disagrees with header height.
    #[serde(rename = "v2_invariant_coinbase_height_mismatch")]
    V2InvariantCoinbaseHeightMismatch,

    /// Block weight exceeds consensus maximum.
    #[serde(rename = "v2_invariant_weight_exceeds_max")]
    V2InvariantWeightExceedsMax,

    /// Block sigops exceed consensus maximum.
    #[serde(rename = "v2_invariant_sigops_exceed_max")]
    V2InvariantSigopsExceedMax,

    /// Non coinbase transaction carries a null prevout.
    /// A coinbase output value, or their total, falls outside
    /// Bitcoin's `MoneyRange`, or the total does not fit `u64`
    /// (PB-21).
    #[serde(rename = "v2_invariant_coinbase_value_exceeds_max")]
    V2InvariantCoinbaseValueExceedsMax,

    #[serde(rename = "v2_invariant_nontcb_null_prevout")]
    V2InvariantNontcbNullPrevout,

    /// `txdata[0]` is not a coinbase, so every `skip(1)` "non-coinbase"
    /// derivation in the shield would be reading the wrong set (PB-20).
    #[serde(rename = "v2_invariant_coinbase_prevout_not_null")]
    V2InvariantCoinbasePrevoutNotNull,

    /// Block header version below active soft fork floor.
    #[serde(rename = "v2_invariant_header_version_low")]
    V2InvariantHeaderVersionLow,

    /// Duplicate transaction in block body.
    #[serde(rename = "v2_invariant_duplicate_tx")]
    V2InvariantDuplicateTx,

    /// Raw block bytes fail to deserialize.
    #[serde(rename = "v2_invariant_decode_failed")]
    V2InvariantDecodeFailed,

    // ── v2.0 Invariant Shield Phase 2 (ADR-003) ──
    //
    // Phase 2 introduces an external mempool view check (Class M)
    // that runs after Class S (standalone) and Class D (declared
    // mismatch) checks in the shield short-circuit chain. The four
    // variants below cover the failure modes per ADR-003 D-18.
    /// A specific template tx is not in the verifier's mempool view.
    #[serde(rename = "v2_invariant_mempool_tx_unknown")]
    V2InvariantMempoolTxUnknown,

    /// Template's unknown-tx ratio exceeded the configured tolerance
    /// threshold (default 4%).
    #[serde(rename = "v2_invariant_mempool_tolerance_exceeded")]
    V2InvariantMempoolToleranceExceeded,

    /// Bitcoind RPC unreachable beyond the fail-stale window.
    #[serde(rename = "v2_invariant_mempool_unavailable")]
    V2InvariantMempoolUnavailable,

    /// Mempool view age exceeded the staleness threshold during a
    /// refresh attempt that did not yet trigger fail-stale.
    #[serde(rename = "v2_invariant_mempool_view_stale")]
    V2InvariantMempoolViewStale,
}

impl VerdictReason {
    /// Every variant, for exhaustive iteration in tests and mappings.
    pub const ALL: &[VerdictReason] = &[
        VerdictReason::ProtocolVersionMismatch,
        VerdictReason::InvalidPrevHash,
        VerdictReason::PrevHashLenMismatch,
        VerdictReason::CoinbaseValueZeroRejected,
        VerdictReason::EmptyTemplateRejected,
        VerdictReason::TxCountExceeded,
        VerdictReason::TotalFeesBelowMinimum,
        VerdictReason::AvgFeeBelowMinimum,
        VerdictReason::PolicyLoadError,
        VerdictReason::MempoolBackendUnavailable,
        VerdictReason::InternalError,
        VerdictReason::WeightRatioExceeded,
        VerdictReason::TemplateStale,
        VerdictReason::SigopsBudgetWarning,
        VerdictReason::CoinbaseSigopsAbnormal,
        // v2.0 Invariant Shield (ADR-002)
        VerdictReason::V2InvariantCoinbaseValueMismatch,
        VerdictReason::V2InvariantTemplateWeightMismatch,
        VerdictReason::V2InvariantMerkleRootMismatch,
        VerdictReason::V2InvariantWitnessCommitmentMissing,
        VerdictReason::V2InvariantWitnessCommitmentMismatch,
        VerdictReason::V2InvariantSigopsMismatch,
        VerdictReason::V2InvariantCoinbaseSigopsMismatch,
        VerdictReason::V2InvariantTxCountMismatch,
        VerdictReason::V2InvariantCoinbaseScriptLength,
        VerdictReason::V2InvariantCoinbaseOutputCount,
        VerdictReason::V2InvariantCoinbaseBip34Missing,
        VerdictReason::V2InvariantCoinbaseHeightMismatch,
        VerdictReason::V2InvariantWeightExceedsMax,
        VerdictReason::V2InvariantSigopsExceedMax,
        VerdictReason::V2InvariantCoinbaseValueExceedsMax,
        VerdictReason::V2InvariantNontcbNullPrevout,
        VerdictReason::V2InvariantCoinbasePrevoutNotNull,
        VerdictReason::V2InvariantHeaderVersionLow,
        VerdictReason::V2InvariantDuplicateTx,
        VerdictReason::V2InvariantDecodeFailed,
        // v2.0 Invariant Shield Phase 2 (ADR-003)
        VerdictReason::V2InvariantMempoolTxUnknown,
        VerdictReason::V2InvariantMempoolToleranceExceeded,
        VerdictReason::V2InvariantMempoolUnavailable,
        VerdictReason::V2InvariantMempoolViewStale,
    ];

    /// All canonical `snake_case` reason code strings, for test enumeration
    /// and schema validation. Order matches `ALL`.
    pub const ALL_CODES: &[&str] = &[
        "protocol_version_mismatch",
        "invalid_prev_hash",
        "prev_hash_len_mismatch",
        "coinbase_value_zero_rejected",
        "empty_template_rejected",
        "tx_count_exceeded",
        "total_fees_below_minimum",
        "avg_fee_below_minimum",
        "policy_load_error",
        "mempool_backend_unavailable",
        "internal_error",
        "weight_ratio_exceeded",
        "template_stale",
        "sigops_budget_warning",
        "coinbase_sigops_abnormal",
        // v2.0 Invariant Shield (ADR-002)
        "v2_invariant_coinbase_value_mismatch",
        "v2_invariant_template_weight_mismatch",
        "v2_invariant_merkle_root_mismatch",
        "v2_invariant_witness_commitment_missing",
        "v2_invariant_witness_commitment_mismatch",
        "v2_invariant_sigops_mismatch",
        "v2_invariant_coinbase_sigops_mismatch",
        "v2_invariant_tx_count_mismatch",
        "v2_invariant_coinbase_script_length",
        "v2_invariant_coinbase_output_count",
        "v2_invariant_coinbase_bip34_missing",
        "v2_invariant_coinbase_height_mismatch",
        "v2_invariant_weight_exceeds_max",
        "v2_invariant_sigops_exceed_max",
        "v2_invariant_coinbase_value_exceeds_max",
        "v2_invariant_nontcb_null_prevout",
        "v2_invariant_coinbase_prevout_not_null",
        "v2_invariant_header_version_low",
        "v2_invariant_duplicate_tx",
        "v2_invariant_decode_failed",
        // v2.0 Invariant Shield Phase 2 (ADR-003)
        "v2_invariant_mempool_tx_unknown",
        "v2_invariant_mempool_tolerance_exceeded",
        "v2_invariant_mempool_unavailable",
        "v2_invariant_mempool_view_stale",
    ];

    /// Returns all canonical `snake_case` reason code strings.
    /// Convenience wrapper over `ALL_CODES`.
    pub fn all_codes() -> &'static [&'static str] {
        Self::ALL_CODES
    }

    /// Canonical `snake_case` string for this reason code.
    ///
    /// This is the stable contract for logs, exports, dashboards, and metrics.
    /// Must match `#[serde(rename_all = "snake_case")]` — enforced by tests.
    pub fn as_str(&self) -> &'static str {
        match self {
            VerdictReason::ProtocolVersionMismatch => "protocol_version_mismatch",
            VerdictReason::InvalidPrevHash => "invalid_prev_hash",
            VerdictReason::PrevHashLenMismatch => "prev_hash_len_mismatch",
            VerdictReason::CoinbaseValueZeroRejected => "coinbase_value_zero_rejected",
            VerdictReason::EmptyTemplateRejected => "empty_template_rejected",
            VerdictReason::TxCountExceeded => "tx_count_exceeded",
            VerdictReason::TotalFeesBelowMinimum => "total_fees_below_minimum",
            VerdictReason::AvgFeeBelowMinimum => "avg_fee_below_minimum",
            VerdictReason::PolicyLoadError => "policy_load_error",
            VerdictReason::MempoolBackendUnavailable => "mempool_backend_unavailable",
            VerdictReason::InternalError => "internal_error",
            VerdictReason::WeightRatioExceeded => "weight_ratio_exceeded",
            VerdictReason::TemplateStale => "template_stale",
            VerdictReason::SigopsBudgetWarning => "sigops_budget_warning",
            VerdictReason::CoinbaseSigopsAbnormal => "coinbase_sigops_abnormal",
            // v2.0 Invariant Shield (ADR-002)
            VerdictReason::V2InvariantCoinbaseValueMismatch => {
                "v2_invariant_coinbase_value_mismatch"
            }
            VerdictReason::V2InvariantTemplateWeightMismatch => {
                "v2_invariant_template_weight_mismatch"
            }
            VerdictReason::V2InvariantMerkleRootMismatch => "v2_invariant_merkle_root_mismatch",
            VerdictReason::V2InvariantWitnessCommitmentMissing => {
                "v2_invariant_witness_commitment_missing"
            }
            VerdictReason::V2InvariantWitnessCommitmentMismatch => {
                "v2_invariant_witness_commitment_mismatch"
            }
            VerdictReason::V2InvariantSigopsMismatch => "v2_invariant_sigops_mismatch",
            VerdictReason::V2InvariantCoinbaseSigopsMismatch => {
                "v2_invariant_coinbase_sigops_mismatch"
            }
            VerdictReason::V2InvariantTxCountMismatch => "v2_invariant_tx_count_mismatch",
            VerdictReason::V2InvariantCoinbaseScriptLength => "v2_invariant_coinbase_script_length",
            VerdictReason::V2InvariantCoinbaseOutputCount => "v2_invariant_coinbase_output_count",
            VerdictReason::V2InvariantCoinbaseBip34Missing => "v2_invariant_coinbase_bip34_missing",
            VerdictReason::V2InvariantCoinbaseHeightMismatch => {
                "v2_invariant_coinbase_height_mismatch"
            }
            VerdictReason::V2InvariantWeightExceedsMax => "v2_invariant_weight_exceeds_max",
            VerdictReason::V2InvariantSigopsExceedMax => "v2_invariant_sigops_exceed_max",
            VerdictReason::V2InvariantCoinbaseValueExceedsMax => {
                "v2_invariant_coinbase_value_exceeds_max"
            }
            VerdictReason::V2InvariantNontcbNullPrevout => "v2_invariant_nontcb_null_prevout",
            VerdictReason::V2InvariantCoinbasePrevoutNotNull => {
                "v2_invariant_coinbase_prevout_not_null"
            }
            VerdictReason::V2InvariantHeaderVersionLow => "v2_invariant_header_version_low",
            VerdictReason::V2InvariantDuplicateTx => "v2_invariant_duplicate_tx",
            VerdictReason::V2InvariantDecodeFailed => "v2_invariant_decode_failed",
            // v2.0 Invariant Shield Phase 2 (ADR-003)
            VerdictReason::V2InvariantMempoolTxUnknown => "v2_invariant_mempool_tx_unknown",
            VerdictReason::V2InvariantMempoolToleranceExceeded => {
                "v2_invariant_mempool_tolerance_exceeded"
            }
            VerdictReason::V2InvariantMempoolUnavailable => "v2_invariant_mempool_unavailable",
            VerdictReason::V2InvariantMempoolViewStale => "v2_invariant_mempool_view_stale",
        }
    }
}

impl std::fmt::Display for VerdictReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyContext {
    #[serde(default)]
    pub fee_tier: Option<String>, // "low" | "mid" | "high" or "unknown"

    #[serde(default)]
    pub min_avg_fee_used: Option<u64>,

    #[serde(default)]
    pub min_total_fees_used: Option<u64>,

    #[serde(default)]
    pub reject_coinbase_zero: Option<bool>,

    #[serde(default)]
    pub unknown_mempool_as_high: Option<bool>,

    #[serde(default)]
    pub max_weight_ratio: Option<f64>,

    #[serde(default)]
    pub max_template_age_ms: Option<u64>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn as_str_matches_serde_for_all_variants() {
        for variant in VerdictReason::ALL {
            let serde_json = serde_json::to_string(variant).unwrap();
            let expected = format!("\"{}\"", variant.as_str());
            assert_eq!(
                serde_json, expected,
                "as_str() drift for {variant:?}: serde={serde_json} as_str={expected}",
            );
        }
    }

    #[test]
    fn all_constant_covers_every_variant() {
        // If a variant is added to the enum but not to ALL, this count will
        // mismatch and the serde round-trip test below will not cover it.
        // 15 original (v1.x) + 20 v2.0 Invariant Shield (ADR-002,
        // 18 ratified plus PB-20's coinbase_prevout_not_null and
        // PB-21's coinbase_value_exceeds_max)
        // + 4 mempool ground truth (ADR-003 Phase 2) = 39.
        assert_eq!(
            VerdictReason::ALL.len(),
            39,
            "VerdictReason::ALL length mismatch — did you add a variant?"
        );
    }

    #[test]
    fn serde_round_trip_all_variants() {
        for variant in VerdictReason::ALL {
            let json = serde_json::to_string(variant).unwrap();
            let back: VerdictReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back, "serde round-trip failed for {variant:?}");
        }
    }

    #[test]
    fn display_matches_as_str() {
        for variant in VerdictReason::ALL {
            assert_eq!(
                variant.to_string(),
                variant.as_str(),
                "Display drift for {variant:?}",
            );
        }
    }

    #[test]
    fn all_strings_are_snake_case() {
        for variant in VerdictReason::ALL {
            let s = variant.as_str();
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "reason code {variant:?} is not snake_case: {s}",
            );
        }
    }

    #[test]
    fn all_codes_matches_all_variants() {
        assert_eq!(
            VerdictReason::ALL.len(),
            VerdictReason::ALL_CODES.len(),
            "ALL and ALL_CODES length mismatch"
        );
        for (variant, code) in VerdictReason::ALL
            .iter()
            .zip(VerdictReason::ALL_CODES.iter())
        {
            assert_eq!(variant.as_str(), *code, "ALL_CODES drift for {variant:?}");
        }
    }

    #[test]
    fn all_codes_fn_returns_all_codes_const() {
        assert_eq!(VerdictReason::all_codes(), VerdictReason::ALL_CODES);
    }
}
