//! v2.0 Invariant Shield facade.
//!
//! `rg-consensus` re-derives consensus critical values from raw block
//! bytes. Callers compare the re-derived value against the declared
//! value supplied by the template-manager and emit the matching
//! `v2_invariant_*` reason code on mismatch.
//!
//! # Design invariants (ADR-002)
//!
//! 1. No upstream parser type crosses the API boundary. The facade
//!    returns only `u64`, `u32`, `[u8; 32]`, `Option<[u8; 32]>`.
//! 2. Every error variant maps to a single canonical `snake_case`
//!    reason code string with the `v2_invariant_` prefix. The
//!    mapping is exhaustive and tested.
//! 3. Reason code strings are owned by `rg-protocol::VerdictReason`
//!    and `reservegrid-common::ReasonCode`. The `as_reason_code()`
//!    method returns the canonical string; the enum variant is
//!    matched to the same `snake_case` string by the downstream
//!    round-trip tests.
//!
//! ADR-002 Phase 1 action item #3 landed 2026-04-21: the five
//! public functions below now re-derive against rust-bitcoin
//! 0.32.8. The `NotImplemented` variant remains in the enum as a
//! shield-disabled sentinel for callers that opt to link against
//! the facade without wiring a parser; no facade function emits it.

#![forbid(unsafe_code)]

use std::fmt;

use bitcoin::Block;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256d;

// ─────────────────────────────────────────────────────────────────────
// ConsensusViolation: the single error type crossing the facade
// ─────────────────────────────────────────────────────────────────────

/// Every failure mode the Invariant Shield can report.
///
/// Each variant maps 1:1 to a canonical reason code string under the
/// `v2_invariant_` prefix. The mapping lives in
/// [`ConsensusViolation::as_reason_code`] and is the authoritative
/// source for this crate. `rg-protocol::VerdictReason` and
/// `reservegrid-common::ReasonCode` mirror the same strings; drift is
/// caught by `snake_case` round-trip tests in those crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusViolation {
    /// Raw block bytes failed to deserialize.
    DecodeFailed {
        /// Human readable decode detail (does not cross the wire).
        detail: &'static str,
    },

    /// Coinbase value disagrees with re-derived.
    CoinbaseValueMismatch { declared: u64, re_derived: u64 },

    /// Declared template weight disagrees with re-derived.
    TemplateWeightMismatch { declared: u64, re_derived: u64 },

    /// Merkle root does not match re-derived.
    MerkleRootMismatch {
        declared: [u8; 32],
        re_derived: [u8; 32],
    },

    /// Witness commitment missing when segwit transactions are present.
    WitnessCommitmentMissing,

    /// Witness commitment value does not match re-derived.
    WitnessCommitmentMismatch {
        declared: [u8; 32],
        re_derived: [u8; 32],
    },

    /// Total sigops disagrees with re-derived.
    SigopsMismatch { declared: u32, re_derived: u32 },

    /// Coinbase sigops disagrees with re-derived.
    CoinbaseSigopsMismatch { declared: u32, re_derived: u32 },

    /// Transaction count disagrees with re-derived.
    TxCountMismatch { declared: u32, re_derived: u32 },

    /// Coinbase script length outside BIP-34 constraints.
    CoinbaseScriptLength,

    /// Coinbase output count outside protocol constraints.
    CoinbaseOutputCount,

    /// Coinbase missing height push (BIP-34).
    CoinbaseBip34Missing,

    /// Coinbase height push disagrees with header height.
    CoinbaseHeightMismatch { declared: u32, re_derived: u32 },

    /// Block weight exceeds consensus maximum.
    WeightExceedsMax,

    /// Block sigops exceed consensus maximum.
    SigopsExceedMax,

    /// A coinbase output value, or the total of them, falls outside
    /// Bitcoin's `MoneyRange` of 0 through 21,000,000 BTC, or the
    /// true total does not fit `u64` at all.
    CoinbaseValueExceedsMax,

    /// Non coinbase transaction carries a null prevout.
    NonCoinbaseNullPrevout,

    /// `txdata[0]` is not a coinbase: its first input does not carry
    /// the null previous output (all-zero txid, index `0xFFFFFFFF`),
    /// or it has no inputs, or the body has no transactions at all,
    /// or it carries more than the single input a coinbase may have.
    CoinbasePrevoutNotNull,

    /// Block header version below active soft fork floor.
    HeaderVersionLow,

    /// Duplicate transaction in block body.
    DuplicateTx,

    /// A specific template transaction is not present in the
    /// verifier's mempool view (Phase 2 Class M check).
    ///
    /// Per ADR-003, the per-tx detail mode emits one verdict record
    /// per missing tx with the txid in `reason_detail`. The default
    /// aggregate mode emits a single
    /// [`ConsensusViolation::MempoolToleranceExceeded`] when the
    /// unknown ratio crosses the configured tolerance threshold.
    MempoolTxUnknown {
        /// Transaction id of the missing tx, internal byte order.
        txid: [u8; 32],
    },

    /// The number of template transactions absent from the
    /// verifier's mempool view exceeded the configured tolerance
    /// threshold (Phase 2 Class M check).
    ///
    /// Aggregate-mode counterpart to `MempoolTxUnknown`. The default
    /// 4% threshold lives in `policy.toml` as `mempool_tolerance_pct`;
    /// see ADR-003 D-18.2 for tuning rationale.
    MempoolToleranceExceeded {
        /// Number of template txs not found in the verifier's view.
        unknown_count: u32,
        /// Total number of transactions in the template (excluding coinbase).
        total: u32,
    },

    /// Bitcoind RPC has been unreachable beyond the configured
    /// fail-stale window (Phase 2 Class M check).
    ///
    /// Per ADR-003 D-18.4, the verifier serves the last known
    /// mempool view up to `mempool_max_stale_secs` (default 60s).
    /// Beyond that, the Phase 2 check is skipped and templates fall
    /// through to Phase 1 behavior; this variant accompanies the
    /// resulting verdict to record the degraded path.
    MempoolUnavailable,

    /// The mempool view age exceeded the staleness threshold during
    /// a refresh attempt that did not yet trigger fail-stale
    /// (Phase 2 Class M check).
    ///
    /// Observability variant. Fires when a refresh is overdue but
    /// the view is still being served because the configured
    /// `mempool_max_stale_secs` window has not yet expired.
    MempoolViewStale {
        /// Age of the served mempool view in seconds.
        age_secs: u64,
    },

    /// Facade is scaffolded but the underlying parser is not yet
    /// wired. Callers treat this as a shield-disabled signal and MUST
    /// NOT emit a `v2_invariant_*` reason code from it; the dedicated
    /// `as_reason_code()` mapping routes it to a degraded sentinel
    /// for observability.
    NotImplemented,
}

impl ConsensusViolation {
    /// Every variant, for exhaustive iteration in tests and mappings.
    /// Order matches [`ConsensusViolation::ALL_CODES`].
    pub const ALL: &[ConsensusViolation] = &[
        ConsensusViolation::DecodeFailed {
            detail: "enumeration_placeholder",
        },
        ConsensusViolation::CoinbaseValueMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::TemplateWeightMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::MerkleRootMismatch {
            declared: [0; 32],
            re_derived: [0; 32],
        },
        ConsensusViolation::WitnessCommitmentMissing,
        ConsensusViolation::WitnessCommitmentMismatch {
            declared: [0; 32],
            re_derived: [0; 32],
        },
        ConsensusViolation::SigopsMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::CoinbaseSigopsMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::TxCountMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::CoinbaseScriptLength,
        ConsensusViolation::CoinbaseOutputCount,
        ConsensusViolation::CoinbaseBip34Missing,
        ConsensusViolation::CoinbaseHeightMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::WeightExceedsMax,
        ConsensusViolation::SigopsExceedMax,
        ConsensusViolation::CoinbaseValueExceedsMax,
        ConsensusViolation::NonCoinbaseNullPrevout,
        ConsensusViolation::CoinbasePrevoutNotNull,
        ConsensusViolation::HeaderVersionLow,
        ConsensusViolation::DuplicateTx,
        ConsensusViolation::MempoolTxUnknown { txid: [0; 32] },
        ConsensusViolation::MempoolToleranceExceeded {
            unknown_count: 0,
            total: 0,
        },
        ConsensusViolation::MempoolUnavailable,
        ConsensusViolation::MempoolViewStale { age_secs: 0 },
        ConsensusViolation::NotImplemented,
    ];

    /// All canonical reason code strings carried by the 24 shield
    /// violation variants (20 Phase 1 + 4 Phase 2 Class M).
    /// `NotImplemented` intentionally routes to a separate degraded
    /// sentinel and is not in this list.
    ///
    /// This list is the single source of truth compared against
    /// `rg-protocol::VerdictReason` during cross-crate drift tests.
    pub const ALL_CODES: &[&str] = &[
        "v2_invariant_decode_failed",
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
        "v2_invariant_mempool_tx_unknown",
        "v2_invariant_mempool_tolerance_exceeded",
        "v2_invariant_mempool_unavailable",
        "v2_invariant_mempool_view_stale",
    ];

    /// Degraded sentinel emitted when the shield is scaffolded but
    /// the parser is not wired. Kept distinct from the 24 invariant
    /// codes so dashboards can alert on "shield disabled" separately
    /// from "shield disagreed".
    pub const NOT_IMPLEMENTED_CODE: &str = "v2_invariant_not_implemented";

    /// Canonical `snake_case` reason code string for this violation.
    ///
    /// The 24 invariant variants map to the canonical strings in
    /// [`ConsensusViolation::ALL_CODES`]. `NotImplemented` maps to
    /// [`ConsensusViolation::NOT_IMPLEMENTED_CODE`] so it never
    /// collides with a real invariant mismatch in export data.
    pub fn as_reason_code(&self) -> &'static str {
        match self {
            ConsensusViolation::DecodeFailed { .. } => "v2_invariant_decode_failed",
            ConsensusViolation::CoinbaseValueMismatch { .. } => {
                "v2_invariant_coinbase_value_mismatch"
            }
            ConsensusViolation::TemplateWeightMismatch { .. } => {
                "v2_invariant_template_weight_mismatch"
            }
            ConsensusViolation::MerkleRootMismatch { .. } => "v2_invariant_merkle_root_mismatch",
            ConsensusViolation::WitnessCommitmentMissing => {
                "v2_invariant_witness_commitment_missing"
            }
            ConsensusViolation::WitnessCommitmentMismatch { .. } => {
                "v2_invariant_witness_commitment_mismatch"
            }
            ConsensusViolation::SigopsMismatch { .. } => "v2_invariant_sigops_mismatch",
            ConsensusViolation::CoinbaseSigopsMismatch { .. } => {
                "v2_invariant_coinbase_sigops_mismatch"
            }
            ConsensusViolation::TxCountMismatch { .. } => "v2_invariant_tx_count_mismatch",
            ConsensusViolation::CoinbaseScriptLength => "v2_invariant_coinbase_script_length",
            ConsensusViolation::CoinbaseOutputCount => "v2_invariant_coinbase_output_count",
            ConsensusViolation::CoinbaseBip34Missing => "v2_invariant_coinbase_bip34_missing",
            ConsensusViolation::CoinbaseHeightMismatch { .. } => {
                "v2_invariant_coinbase_height_mismatch"
            }
            ConsensusViolation::WeightExceedsMax => "v2_invariant_weight_exceeds_max",
            ConsensusViolation::SigopsExceedMax => "v2_invariant_sigops_exceed_max",
            ConsensusViolation::CoinbaseValueExceedsMax => {
                "v2_invariant_coinbase_value_exceeds_max"
            }
            ConsensusViolation::NonCoinbaseNullPrevout => "v2_invariant_nontcb_null_prevout",
            ConsensusViolation::CoinbasePrevoutNotNull => "v2_invariant_coinbase_prevout_not_null",
            ConsensusViolation::HeaderVersionLow => "v2_invariant_header_version_low",
            ConsensusViolation::DuplicateTx => "v2_invariant_duplicate_tx",
            ConsensusViolation::MempoolTxUnknown { .. } => "v2_invariant_mempool_tx_unknown",
            ConsensusViolation::MempoolToleranceExceeded { .. } => {
                "v2_invariant_mempool_tolerance_exceeded"
            }
            ConsensusViolation::MempoolUnavailable => "v2_invariant_mempool_unavailable",
            ConsensusViolation::MempoolViewStale { .. } => "v2_invariant_mempool_view_stale",
            ConsensusViolation::NotImplemented => Self::NOT_IMPLEMENTED_CODE,
        }
    }
}

impl fmt::Display for ConsensusViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_reason_code())
    }
}

impl std::error::Error for ConsensusViolation {}

// ─────────────────────────────────────────────────────────────────────
// Facade API
//
// The five functions below are the load-bearing surface per ADR-002
// Option A. Callers MUST depend on `rg-consensus::re_derive_*`, never
// on any upstream parser crate directly.
// ─────────────────────────────────────────────────────────────────────

/// Re-derive the total coinbase output value from the raw block
/// bytes. Callers compare against the declared coinbase value and
/// emit `v2_invariant_coinbase_value_mismatch` on disagreement.
///
/// The output values are attacker chosen `u64`s off `raw_block_hex`,
/// so the total is summed with `checked_add` rather than `sum()`
/// (PB-21). An unchecked `sum()` panicked under the debug and CI
/// overflow checks, which let a remote peer stop the verifier on
/// demand, and wrapped under release, which handed the attacker a
/// small number to declare against a coinbase paying an enormous one.
///
/// A total that does not fit `u64` is reported as
/// [`ConsensusViolation::CoinbaseValueExceedsMax`] rather than as a
/// decode failure: the bytes decoded fine, and a sum too large for
/// `u64` is by construction far above `MAX_MONEY`. The `MoneyRange`
/// ceiling itself belongs to Tier 3 [`check_coinbase_value_max`], so
/// this function still returns the true total for any block whose
/// outputs are merely large, and the ceiling decides its fate.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] if the bytes cannot
/// be parsed, or [`ConsensusViolation::CoinbaseValueExceedsMax`] if
/// the coinbase output total does not fit `u64`.
pub fn re_derive_coinbase_value(raw_block: &[u8]) -> Result<u64, ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;
    let coinbase = block
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;
    coinbase
        .output
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value.to_sat()))
        .ok_or(ConsensusViolation::CoinbaseValueExceedsMax)
}

/// Re-derive block weight from the raw block bytes per BIP-141
/// accounting (base size times 3 plus total size).
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure.
pub fn re_derive_template_weight(raw_block: &[u8]) -> Result<u64, ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;
    Ok(block.weight().to_wu())
}

/// Re-derive the transaction merkle root from the block body.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure or
/// on an empty block body with no merkle root.
pub fn re_derive_merkle_root(raw_block: &[u8]) -> Result<[u8; 32], ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;
    let root = block
        .compute_merkle_root()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "merkle_root_empty_block",
        })?;
    Ok(root.to_byte_array())
}

/// Re-derive the witness commitment. Returns `None` when the block
/// carries no witness data anywhere (coinbase included) and
/// therefore requires no commitment; returns `Some` with the 32
/// byte commitment otherwise.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure.
pub fn re_derive_witness_commitment(
    raw_block: &[u8],
) -> Result<Option<[u8; 32]>, ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;

    // Bitcoin Core's unexpected-witness rule counts every
    // transaction including the coinbase: a block with witness data
    // anywhere and no commitment is invalid, so the commitment
    // requirement scan must not skip the coinbase.
    let has_witness = block
        .txdata
        .iter()
        .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()));

    if !has_witness {
        return Ok(None);
    }

    let witness_root = block
        .witness_root()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "witness_root_empty_block",
        })?;

    // BIP-141: witness reserved value is the first (and only)
    // stack element of the coinbase input witness. Missing or
    // malformed witness stacks fall back to 32 zero bytes; the
    // caller flags the resulting commitment mismatch via its own
    // invariant code. The shield only derives; it does not judge.
    let coinbase = block
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;
    let reserved: [u8; 32] = coinbase
        .input
        .first()
        .and_then(|i| i.witness.iter().next())
        .and_then(|w| <[u8; 32]>::try_from(w).ok())
        .unwrap_or([0u8; 32]);

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&witness_root.to_byte_array());
    buf[32..].copy_from_slice(&reserved);
    Ok(Some(sha256d::Hash::hash(&buf).to_byte_array()))
}

/// Count total sigops in the block using legacy plus witness
/// accounting. Callers compare against the declared sigops count.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure.
///
/// # TODO
///
/// Phase 1 counts legacy sigops only (`Script::count_sigops_legacy`
/// across every `script_sig` and `script_pubkey`). Accurate
/// BIP-141 sigop cost (P2SH scale plus witness scale factor) is a
/// follow up; see `Script::count_sigops` and the sigop cost docs
/// in rust-bitcoin. A legacy count is not a strict upper bound for
/// BIP-141 cost on the same block, so a caller emitting
/// `v2_invariant_sigops_mismatch` against an accurate declared
/// count may surface a false positive until this is tightened.
pub fn count_sigops(raw_block: &[u8]) -> Result<u32, ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;
    let mut total: u64 = 0;
    for tx in &block.txdata {
        for input in &tx.input {
            total = total.saturating_add(input.script_sig.count_sigops_legacy() as u64);
        }
        for output in &tx.output {
            total = total.saturating_add(output.script_pubkey.count_sigops_legacy() as u64);
        }
    }
    Ok(u32::try_from(total).unwrap_or(u32::MAX))
}

// ─────────────────────────────────────────────────────────────────────
// ParsedBlock and single-parse facade (ADR-002 Phase 1 #4b)
//
// `ParsedBlock` is an opaque newtype around `bitcoin::Block`. The
// pool-verifier shield calls `parse_block` once per template and
// passes the resulting `ParsedBlock` to every per-invariant check.
// This avoids the N-deserializations cost of the older `&[u8]`
// facade when running many checks against the same template.
//
// R-154 dep narrowness: `ParsedBlock` does not expose `bitcoin`
// types. Callers receive only `u32`, `[u8; 32]`, and
// `Result<(), ConsensusViolation>`. The newtype's inner field stays
// private so no caller can extract a `bitcoin::Block`.
// ─────────────────────────────────────────────────────────────────────

/// Parsed block wrapper. Construct via [`parse_block`]. Pass by
/// reference into the per-invariant check and re-derive functions.
///
/// The inner `bitcoin::Block` is private and never crosses the
/// crate boundary. Adding a public method that returns `&Block` or
/// `Block` would breach ADR-002 Option A. Add scoped accessors
/// instead.
pub struct ParsedBlock(Block);

/// Deserialize a raw block once. Subsequent shield checks operate
/// on the returned [`ParsedBlock`] without re-parsing.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure.
pub fn parse_block(raw: &[u8]) -> Result<ParsedBlock, ConsensusViolation> {
    deserialize(raw)
        .map(ParsedBlock)
        .map_err(|_| ConsensusViolation::DecodeFailed {
            detail: "block_deserialize",
        })
}

// ─── Class S: standalone internal-consistency checks ───────────────

/// Verify the block header `merkle_root` matches the `sha256d`
/// merkle root computed over the block body.
///
/// Catches tampering of the header field independent of any
/// declared value in `TemplatePropose`.
///
/// # Errors
///
/// Returns [`ConsensusViolation::MerkleRootMismatch`] when the
/// header value disagrees with the body computation. Returns
/// [`ConsensusViolation::DecodeFailed`] on an empty block body
/// where no merkle root can be computed.
pub fn check_merkle_root_internal(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let computed = block
        .0
        .compute_merkle_root()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "merkle_root_empty_block",
        })?;
    let declared = block.0.header.merkle_root;
    if declared != computed {
        return Err(ConsensusViolation::MerkleRootMismatch {
            declared: declared.to_byte_array(),
            re_derived: computed.to_byte_array(),
        });
    }
    Ok(())
}

/// Verify the coinbase witness commitment matches the BIP-141
/// witness root commitment computed over the block body.
///
/// Outcomes:
/// - Legacy block (no witness data anywhere): returns `Ok(())`.
/// - Witness data present, commitment in coinbase `OP_RETURN`
///   matches the computed value: returns `Ok(())`.
/// - Witness data present and commitment missing: returns
///   [`ConsensusViolation::WitnessCommitmentMissing`].
/// - Witness data present and commitment disagrees with computed
///   value: returns [`ConsensusViolation::WitnessCommitmentMismatch`].
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] when the block has
/// no coinbase or no witness root computable.
pub fn check_witness_commitment_internal(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let coinbase = block
        .0
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;

    // Bitcoin Core's unexpected-witness rule counts every
    // transaction including the coinbase: a block with witness data
    // anywhere and no commitment is invalid, so the commitment
    // requirement scan must not skip the coinbase.
    let has_witness = block
        .0
        .txdata
        .iter()
        .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()));

    let declared = extract_witness_commitment_from_coinbase(coinbase);

    match (has_witness, declared) {
        (false, _) => Ok(()),
        (true, None) => Err(ConsensusViolation::WitnessCommitmentMissing),
        (true, Some(decl)) => {
            let witness_root = block
                .0
                .witness_root()
                .ok_or(ConsensusViolation::DecodeFailed {
                    detail: "witness_root_empty_block",
                })?;

            // BIP-141: witness reserved value is the first stack
            // element of the coinbase input witness. Missing or
            // malformed falls back to 32 zero bytes.
            let reserved: [u8; 32] = coinbase
                .input
                .first()
                .and_then(|i| i.witness.iter().next())
                .and_then(|w| <[u8; 32]>::try_from(w).ok())
                .unwrap_or([0u8; 32]);

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&witness_root.to_byte_array());
            buf[32..].copy_from_slice(&reserved);
            let computed = sha256d::Hash::hash(&buf).to_byte_array();

            if decl == computed {
                Ok(())
            } else {
                Err(ConsensusViolation::WitnessCommitmentMismatch {
                    declared: decl,
                    re_derived: computed,
                })
            }
        }
    }
}

/// Verify the coinbase script begins with a BIP-34 height push.
///
/// The shield does not validate the height value here; that is the
/// declaration-mismatch check via [`bip34_height`]. This function
/// only enforces presence: a coinbase that omits the BIP-34 push
/// breaches the post-block-227836 consensus rule.
///
/// # Errors
///
/// Returns [`ConsensusViolation::CoinbaseBip34Missing`] when the
/// coinbase script does not begin with a valid integer push, or
/// [`ConsensusViolation::DecodeFailed`] on a malformed coinbase.
pub fn check_coinbase_bip34_present(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let _ = bip34_height(block)?;
    Ok(())
}

// ─── Class D: re-derive accessors for declared-mismatch checks ─────

/// Number of transactions in the block. Caller compares against
/// `TemplatePropose.tx_count` and emits
/// `v2_invariant_tx_count_mismatch` on disagreement.
///
/// The conversion saturates to `u32::MAX`; any block with more than
/// 4 billion transactions is structurally impossible under the
/// current weight limit.
pub fn tx_count(block: &ParsedBlock) -> u32 {
    u32::try_from(block.0.txdata.len()).unwrap_or(u32::MAX)
}

/// Total legacy sigops summed across every input `script_sig` and
/// every output `script_pubkey` in the block, **including the
/// coinbase**.
///
/// Unit semantics match [`count_sigops`]: legacy count, not BIP-141
/// sigop cost.
///
/// Inclusion set (PB-19, pinned here because this crate exposes two
/// sigop accessors whose only difference is the set they sum, which is
/// exactly the difference that went unnoticed once): this is the
/// WHOLE-block figure, which is what the consensus ceiling in
/// [`check_sigops_max`] must measure. It is NOT
/// the right operand for the Class D comparison against
/// `TemplatePropose::total_sigops`, whose wire contract is BIP-141
/// cost over the NON-coinbase transactions only (the GBT
/// `transactions[]` convention). Use [`non_coinbase_sigops`] there;
/// summing the coinbase into a floor compared against a non-coinbase
/// declaration rejects honest templates whenever the payout script
/// carries sigops.
pub fn total_sigops(block: &ParsedBlock) -> u32 {
    sum_legacy_sigops(block.0.txdata.iter())
}

/// Sum legacy sigops (scriptSig plus scriptPubKey) over an arbitrary
/// set of transactions, saturating at `u32::MAX`.
///
/// This exists because `total_sigops`, `non_coinbase_sigops`, and
/// `coinbase_sigops` all need it and differ ONLY in the set they
/// iterate. Three verbatim copies of this loop is what PB-19's
/// inclusion-set defect hid inside: the arithmetic was never the
/// thing that varied, the set was. Keeping the arithmetic here once
/// and the set at each call site makes the difference the only thing
/// a reader has to check.
fn sum_legacy_sigops<'a>(txs: impl Iterator<Item = &'a bitcoin::Transaction>) -> u32 {
    let mut total: u64 = 0;
    for tx in txs {
        for input in &tx.input {
            total = total.saturating_add(input.script_sig.count_sigops_legacy() as u64);
        }
        for output in &tx.output {
            total = total.saturating_add(output.script_pubkey.count_sigops_legacy() as u64);
        }
    }
    u32::try_from(total).unwrap_or(u32::MAX)
}

/// Sum of BIP-141 weights of the non-coinbase transactions, in
/// weight units. This matches the producer-side declaration
/// convention for `TemplatePropose::template_weight` (the sum of GBT
/// `transactions[].weight`, which excludes the coinbase and the
/// header), so the shield's Class D comparison uses this accessor
/// rather than whole-block weight (PB-19).
///
/// The `skip(1)` precondition is established by
/// [`check_coinbase_null_prevout`]; see the note on
/// [`non_coinbase_sigops`].
///
/// The `.sum()` below is unchecked but cannot overflow `u64`: its only
/// production caller is pool-verifier, whose HTTP layer caps every
/// request body at 1 MiB (`RequestBodyLimitLayer` in
/// `services/pool-verifier/src/http.rs:103`) before `raw_block_hex`
/// is decoded, so the parsed block is bounded to well under 1 MiB and
/// BIP-141 weight is at most roughly 4x serialized size, many orders
/// of magnitude below `u64::MAX`.
pub fn non_coinbase_tx_weight(block: &ParsedBlock) -> u64 {
    block
        .0
        .txdata
        .iter()
        .skip(1)
        .map(|t| t.weight().to_wu())
        .sum()
}

/// Legacy sigops summed across the non-coinbase transactions. Equals
/// [`total_sigops`] minus [`coinbase_sigops`] except at the `u32`
/// saturation boundary, where each figure clamps independently. This
/// matches the producer-side declaration convention for
/// `TemplatePropose::total_sigops` (the sum of GBT
/// `transactions[].sigops`, which excludes the coinbase), so the
/// shield's Class D sigop floor uses this accessor rather than the
/// whole-block figure (PB-19).
///
/// Unit semantics match [`total_sigops`]: legacy count, not BIP-141
/// sigop cost. The caller scales the legacy count by the BIP-141
/// factor of 4 to reach the provable cost floor.
///
/// This exists because the Class D comparison and the consensus
/// ceiling check need different inclusion sets: `check_sigops_max`
/// measures the whole block against the consensus limit, while the
/// Class D floor must line up with a declaration the producer built
/// from non-coinbase transactions alone.
///
/// Precondition shared with [`non_coinbase_tx_weight`] and
/// [`check_non_coinbase_null_prevout`]: `skip(1)` means "not the first
/// transaction". It means "not the coinbase" only because
/// [`check_coinbase_null_prevout`] asserts `txdata[0]` really is a
/// coinbase (PB-20). That check runs inside the shield's Tier 3 array,
/// so on any template the shield admitted all three derivations are
/// over the set they claim. Unwiring it puts all three back on an
/// unchecked assumption over attacker-controlled bytes.
pub fn non_coinbase_sigops(block: &ParsedBlock) -> u32 {
    sum_legacy_sigops(block.0.txdata.iter().skip(1))
}

/// Legacy sigops summed across the coinbase transaction only.
/// Caller compares against `TemplatePropose.coinbase_sigops` and
/// emits `v2_invariant_coinbase_sigops_mismatch` on disagreement.
///
/// Unit semantics match [`total_sigops`].
pub fn coinbase_sigops(block: &ParsedBlock) -> u32 {
    // `take(1)` on an empty body yields nothing and sums to 0, which
    // is what the previous `first()`-with-early-return did.
    sum_legacy_sigops(block.0.txdata.iter().take(1))
}

/// Extract the BIP-34 block height from the coinbase script.
///
/// BIP-34 mandates that the coinbase script begins with a serialized
/// `CScriptNum` push of the block height. This function decodes that
/// push and returns the height as a `u32`.
///
/// # Errors
///
/// Returns [`ConsensusViolation::CoinbaseBip34Missing`] when the
/// coinbase script does not begin with a valid integer push or the
/// integer is negative. Returns [`ConsensusViolation::DecodeFailed`]
/// when the block has no coinbase.
pub fn bip34_height(block: &ParsedBlock) -> Result<u32, ConsensusViolation> {
    let coinbase = block
        .0
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;
    let input = coinbase
        .input
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "coinbase_has_no_input",
        })?;
    let bytes = input.script_sig.as_bytes();
    decode_bip34_height(bytes).ok_or(ConsensusViolation::CoinbaseBip34Missing)
}

// ─── Tier 3: belt-and-suspenders checks (ADR-002 Phase 1.5) ────────
//
// Standalone consensus ceilings and structural rules. Unlike Class D
// these need no declared field from `TemplatePropose`; unlike Class S
// they guard absolute consensus limits rather than internal
// consistency. Deferred from Phase 1 #4b as Tier 3 per the ADR-002
// criticality tiering, wired in Phase 1.5.

/// Consensus maximum block weight in weight units (BIP-141).
const MAX_BLOCK_WEIGHT_WU: u64 = 4_000_000;

/// Consensus maximum block sigop cost (BIP-141).
const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// Total satoshis that will ever exist: 21,000,000 BTC at 100,000,000
/// sats each. Bitcoin Core's `MoneyRange(nValue)` is
/// `0 <= nValue <= MAX_MONEY`, applied per output and again on a
/// transaction's output total, and this constant is that ceiling.
const MAX_MONEY_SATS: u64 = 21_000_000 * 100_000_000;

/// BIP-141 scale factor mapping legacy sigops to sigop cost.
const WITNESS_SCALE_FACTOR: u64 = 4;

/// Consensus lower bound on the coinbase `script_sig` length in
/// bytes (Bitcoin's original `CheckTransaction` coinbase
/// script-size rule, `bad-cb-length`).
const MIN_COINBASE_SCRIPT_LEN: usize = 2;

/// Consensus upper bound on the coinbase `script_sig` length in
/// bytes (same `bad-cb-length` rule as the lower bound).
const MAX_COINBASE_SCRIPT_LEN: usize = 100;

/// Minimum block header version since BIP-65 lock-in (version 4).
/// BIP-9 style top-bits versions (`0x2000_0000` and up) clear the
/// floor; only genuinely low legacy versions (1 through 3) and
/// negative versions fall below it.
const HEADER_VERSION_FLOOR: i32 = 4;

/// Verify the coinbase `script_sig` length sits inside the
/// consensus range of 2 through 100 bytes (Bitcoin Core
/// `bad-cb-length`; BIP-34 separately mandates the height push,
/// checked by [`check_coinbase_bip34_present`]).
///
/// # Errors
///
/// Returns [`ConsensusViolation::CoinbaseScriptLength`] when the
/// length is outside the range, or
/// [`ConsensusViolation::DecodeFailed`] when the block has no
/// coinbase or the coinbase has no input.
pub fn check_coinbase_script_length(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let coinbase = block
        .0
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;
    let input = coinbase
        .input
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "coinbase_has_no_input",
        })?;
    let len = input.script_sig.len();
    if !(MIN_COINBASE_SCRIPT_LEN..=MAX_COINBASE_SCRIPT_LEN).contains(&len) {
        return Err(ConsensusViolation::CoinbaseScriptLength);
    }
    Ok(())
}

/// Verify the coinbase carries at least one output. A transaction
/// with an empty output vector is invalid under consensus rules and
/// a coinbase with no outputs pays nobody, which no honest template
/// builder emits.
///
/// # Errors
///
/// Returns [`ConsensusViolation::CoinbaseOutputCount`] on an empty
/// output vector, or [`ConsensusViolation::DecodeFailed`] when the
/// block has no coinbase.
pub fn check_coinbase_output_count(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let coinbase = block
        .0
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;
    if coinbase.output.is_empty() {
        return Err(ConsensusViolation::CoinbaseOutputCount);
    }
    Ok(())
}

/// Verify total block weight does not exceed the 4,000,000 WU
/// consensus maximum (BIP-141).
///
/// # Errors
///
/// Returns [`ConsensusViolation::WeightExceedsMax`] when the block
/// weight crosses the ceiling.
pub fn check_weight_max(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    if block.0.weight().to_wu() > MAX_BLOCK_WEIGHT_WU {
        return Err(ConsensusViolation::WeightExceedsMax);
    }
    Ok(())
}

/// Verify block sigops do not exceed the consensus maximum.
///
/// Unit semantics follow [`total_sigops`]: the facade counts legacy
/// sigops, so the comparison scales the legacy count by the BIP-141
/// factor of 4 against the 80,000 sigop-cost ceiling. Legacy count
/// times 4 is a lower bound for true BIP-141 cost (P2SH and witness
/// sigops add to it), so this check never fires on a block that a
/// full accounting would accept.
///
/// # Errors
///
/// Returns [`ConsensusViolation::SigopsExceedMax`] when the scaled
/// legacy count crosses the ceiling.
pub fn check_sigops_max(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let scaled = u64::from(total_sigops(block)).saturating_mul(WITNESS_SCALE_FACTOR);
    if scaled > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusViolation::SigopsExceedMax);
    }
    Ok(())
}

/// Verify every coinbase output value, and their total, sit inside
/// Bitcoin's `MoneyRange` of 0 through `MAX_MONEY` sats (PB-21).
///
/// The third member of the Tier 3 ceiling family, beside
/// [`check_weight_max`] and [`check_sigops_max`], and the one the
/// ratified table was missing: no bound on coinbase value existed
/// anywhere in the workspace. `raw_block_hex` is attacker controlled,
/// so the values are attacker chosen `u64`s, and the Class D
/// coinbase-value comparison only asks whether the declaration
/// matches the block. An attacker who declares the same out-of-range
/// number his outputs add up to satisfies that comparison exactly.
///
/// Both halves of Core's `MoneyRange` discipline are enforced,
/// because they catch different shapes. A single output above
/// `MAX_MONEY` needs the per-output test, since one output alone
/// overflows nothing. A total above `MAX_MONEY` needs the sum test,
/// since each output can be individually legal.
///
/// The running total uses `checked_add` and treats overflow as the
/// same violation rather than saturating. Given the per-output bound
/// checked first, reaching that branch would take more than 2^12
/// outputs of `MAX_MONEY` and no block can hold them, but a
/// saturating fallback here would be a silent wrong answer, and this
/// is exactly the arithmetic PB-21 was.
///
/// # Errors
///
/// Returns [`ConsensusViolation::CoinbaseValueExceedsMax`] when any
/// coinbase output exceeds `MAX_MONEY`, when their total does, or
/// when that total does not fit `u64`. A block with no coinbase
/// yields [`ConsensusViolation::DecodeFailed`], matching its Tier 3
/// siblings [`check_coinbase_script_length`] and
/// [`check_coinbase_output_count`].
pub fn check_coinbase_value_max(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let coinbase = block
        .0
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;
    let mut total: u64 = 0;
    for output in &coinbase.output {
        let value = output.value.to_sat();
        if value > MAX_MONEY_SATS {
            return Err(ConsensusViolation::CoinbaseValueExceedsMax);
        }
        total = total
            .checked_add(value)
            .ok_or(ConsensusViolation::CoinbaseValueExceedsMax)?;
    }
    if total > MAX_MONEY_SATS {
        return Err(ConsensusViolation::CoinbaseValueExceedsMax);
    }
    Ok(())
}

/// Verify no non-coinbase transaction carries a null previous
/// output. A null prevout outside the coinbase position would mint
/// value out of nothing; consensus forbids it.
///
/// The `skip(1)` precondition is established by
/// [`check_coinbase_null_prevout`], which owns index 0 and is the only
/// reason this function's exclusion of it is sound; see the note on
/// [`non_coinbase_sigops`].
///
/// # Errors
///
/// Returns [`ConsensusViolation::NonCoinbaseNullPrevout`] on the
/// first offending input.
pub fn check_non_coinbase_null_prevout(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    for tx in block.0.txdata.iter().skip(1) {
        for input in &tx.input {
            if input.previous_output.is_null() {
                return Err(ConsensusViolation::NonCoinbaseNullPrevout);
            }
        }
    }
    Ok(())
}

/// Verify `txdata[0]` actually IS a coinbase (PB-20).
///
/// This crate exposes three accessors that derive a "non-coinbase"
/// set by skipping index 0 ([`non_coinbase_sigops`],
/// [`non_coinbase_tx_weight`], [`check_non_coinbase_null_prevout`]),
/// plus a `tx_count`-minus-one convention in the verifier. `skip(1)`
/// means "not the first transaction"; it means "not the coinbase"
/// only if index 0 is a coinbase, and nothing asserted that.
/// `raw_block_hex` is attacker controlled on the wire, so this check
/// turns the shared assumption into a checked precondition and every
/// `skip(1)` above becomes provably correct.
///
/// A coinbase is defined here as exactly one input whose previous
/// output is null. In `bitcoin` 0.32.8 `OutPoint::is_null()` is
/// equality against `OutPoint::null()`, whose `vout` is `u32::MAX`,
/// so it already covers the `0xFFFFFFFF` index; the unit test
/// `outpoint_is_null_subsumes_the_0xffffffff_index` pins that rather
/// than leaving it to a reading of the dependency.
///
/// This is deliberately structural only. It does not re-check the
/// BIP-34 height push or the script length, which
/// [`check_coinbase_script_length`] and [`bip34_height`] already own.
///
/// # Errors
///
/// Returns [`ConsensusViolation::CoinbasePrevoutNotNull`] when the
/// body is empty, when index 0 has no inputs, when it has more than
/// one input, or when that single input's prevout is not null.
pub fn check_coinbase_null_prevout(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let Some(coinbase) = block.0.txdata.first() else {
        return Err(ConsensusViolation::CoinbasePrevoutNotNull);
    };
    // Exactly one input: a second input spends a real outpoint no
    // matter what input[0] claims, which is the value-minting shape
    // check_non_coinbase_null_prevout exists to forbid elsewhere.
    let [input] = coinbase.input.as_slice() else {
        return Err(ConsensusViolation::CoinbasePrevoutNotNull);
    };
    if !input.previous_output.is_null() {
        return Err(ConsensusViolation::CoinbasePrevoutNotNull);
    }
    Ok(())
}

/// Verify the block header version meets the BIP-65 floor of 4.
/// Historic version 1 through 3 blocks predate the active soft fork
/// set; a new template carrying one signals a broken or hostile
/// template builder.
///
/// # Errors
///
/// Returns [`ConsensusViolation::HeaderVersionLow`] when the
/// consensus-encoded version is below the floor.
pub fn check_header_version(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    if block.0.header.version.to_consensus() < HEADER_VERSION_FLOOR {
        return Err(ConsensusViolation::HeaderVersionLow);
    }
    Ok(())
}

/// Verify no transaction id appears twice in the block body.
/// Duplicate txids enable the CVE-2012-2459 merkle malleation
/// family and never occur in an honest template.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DuplicateTx`] on the first
/// repeated txid.
pub fn check_duplicate_tx(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let mut seen = std::collections::HashSet::with_capacity(block.0.txdata.len());
    for tx in &block.0.txdata {
        if !seen.insert(tx.compute_txid()) {
            return Err(ConsensusViolation::DuplicateTx);
        }
    }
    Ok(())
}

// ─── Template block assembly (PB-19 / ADR-002 Phase 1b) ────────────
//
// The shield re-derives; Phase 1b needs the mirror image: the
// template-manager must SHIP raw block bytes so the shield has
// something to re-derive from. Assembly stays behind the facade for
// the same R-154 reason parsing does: exactly one crate owns
// rust-bitcoin, and only plain types cross the boundary.

/// Inputs for [`assemble_template_block`]. Every field is a plain
/// type; the coinbase arrives in legacy (non-witness) serialization
/// exactly as the SV2 job path builds it (`prefix || extranonce ||
/// suffix` with the extranonce slot zero-filled).
pub struct TemplateBlockParts<'a> {
    /// Block header version, consensus encoding (GBT `version`).
    pub version: i32,
    /// Previous block hash in INTERNAL byte order (display hex from
    /// GBT must be byte-reversed by the caller).
    pub prev_hash: [u8; 32],
    /// Header timestamp (GBT `curtime`).
    pub time: u32,
    /// Compact difficulty target (GBT `bits` as consensus `u32`).
    pub bits: u32,
    /// Legacy-serialized coinbase transaction.
    pub coinbase_legacy: &'a [u8],
    /// Raw serialized non-coinbase transactions (GBT
    /// `transactions[].data`), witness encoding preserved.
    pub txs_raw: &'a [Vec<u8>],
}

/// Assemble an unmined template block from its parts: attach the
/// BIP-141 reserved witness to the coinbase when a commitment output
/// is present, compute the header merkle root over the body, and
/// serialize with a zero nonce.
///
/// Fail-fast contract: a witness-carrying transaction set with no
/// commitment output in the coinbase is refused rather than shipped,
/// because Bitcoin Core rejects such a block (unexpected-witness) and
/// the shield would flag it downstream anyway.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] when the coinbase or
/// any transaction fails to deserialize, or
/// [`ConsensusViolation::WitnessCommitmentMissing`] per the fail-fast
/// contract above.
pub fn assemble_template_block(
    parts: &TemplateBlockParts<'_>,
) -> Result<Vec<u8>, ConsensusViolation> {
    use bitcoin::consensus::serialize;

    let mut coinbase: bitcoin::Transaction =
        deserialize(parts.coinbase_legacy).map_err(|_| ConsensusViolation::DecodeFailed {
            detail: "coinbase_deserialize",
        })?;

    let mut txdata: Vec<bitcoin::Transaction> = Vec::with_capacity(1 + parts.txs_raw.len());
    let mut any_witness = false;
    for raw in parts.txs_raw {
        let tx: bitcoin::Transaction =
            deserialize(raw).map_err(|_| ConsensusViolation::DecodeFailed {
                detail: "template_tx_deserialize",
            })?;
        any_witness = any_witness || tx.input.iter().any(|i| !i.witness.is_empty());
        txdata.push(tx);
    }

    let has_commitment = extract_witness_commitment_from_coinbase(&coinbase).is_some();
    if any_witness && !has_commitment {
        return Err(ConsensusViolation::WitnessCommitmentMissing);
    }
    if has_commitment {
        // BIP-141 reserved value: exactly one 32-byte zero element,
        // matching what bitcoind's `default_witness_commitment`
        // commits to.
        let input = coinbase
            .input
            .first_mut()
            .ok_or(ConsensusViolation::DecodeFailed {
                detail: "coinbase_has_no_input",
            })?;
        input.witness = bitcoin::Witness::from_slice(&[[0u8; 32]]);
    }

    let mut all_txs = Vec::with_capacity(1 + txdata.len());
    all_txs.push(coinbase);
    all_txs.extend(txdata);

    let mut block = Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(parts.version),
            prev_blockhash: bitcoin::BlockHash::from_byte_array(parts.prev_hash),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: parts.time,
            bits: bitcoin::CompactTarget::from_consensus(parts.bits),
            nonce: 0,
        },
        txdata: all_txs,
    };
    let merkle = block
        .compute_merkle_root()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "merkle_root_empty_block",
        })?;
    block.header.merkle_root = merkle;

    Ok(serialize(&block))
}

// ─── Class M accessors: mempool ground truth (Phase 2 / ADR-003) ──

/// Return the list of non-coinbase transaction ids in the block, in
/// internal byte order. The coinbase tx is intentionally excluded
/// because it never appears in the network mempool.
///
/// Pool-verifier's Phase 2 Class M check iterates these txids
/// against the verifier's mempool view, counting how many are
/// unknown. R-154 facade narrowness preserved: returns
/// `Vec<[u8; 32]>` rather than any `bitcoin::Txid` type.
pub fn template_txids(block: &ParsedBlock) -> Vec<[u8; 32]> {
    block
        .0
        .txdata
        .iter()
        .skip(1)
        .map(|tx| tx.compute_txid().to_byte_array())
        .collect()
}

// ─── Internal helpers ──────────────────────────────────────────────

/// Locate the BIP-141 witness commitment output in a coinbase.
/// Returns the 32-byte commitment when present.
///
/// Format per BIP-141: `OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <32 bytes>`.
/// When more than one output matches the pattern, BIP-141 assigns
/// the commitment to the one with the highest output index; Bitcoin
/// Core's `GetWitnessCommitmentIndex` keeps the last match and the
/// shield must agree or it diverges on blocks Core accepts.
fn extract_witness_commitment_from_coinbase(coinbase: &bitcoin::Transaction) -> Option<[u8; 32]> {
    const OP_RETURN: u8 = 0x6a;
    const OP_PUSHBYTES_36: u8 = 0x24;
    const MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

    for output in coinbase.output.iter().rev() {
        let bytes = output.script_pubkey.as_bytes();
        if bytes.len() >= 38
            && bytes[0] == OP_RETURN
            && bytes[1] == OP_PUSHBYTES_36
            && bytes[2..6] == MAGIC
        {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes[6..38]);
            return Some(out);
        }
    }
    None
}

/// Decode a BIP-34 minimal `CScriptNum` push from the start of a
/// coinbase script. Returns `None` for missing, oversized, negative,
/// or non-minimal encodings.
///
/// Layout: opcode byte indicating push length (`0x01`..=`0x04`),
/// followed by that many little endian bytes representing a signed
/// integer. The most significant byte's high bit is the sign;
/// negative heights are rejected.
fn decode_bip34_height(script: &[u8]) -> Option<u32> {
    let len_byte = *script.first()?;
    // Reject opcodes outside the direct push range. BIP-34 uses
    // CScriptNum which serializes 1..=4 bytes for any block height
    // up to ~2^31. Block heights past that are far beyond the
    // foreseeable chain.
    if !(0x01..=0x04).contains(&len_byte) {
        return None;
    }
    let len = len_byte as usize;
    if script.len() < 1 + len {
        return None;
    }
    let payload = &script[1..=len];
    // Reject negative (sign bit on the MSB of the most significant
    // byte) and reject zero-length / leading-zero non-minimal forms.
    let last = *payload.last()?;
    if last & 0x80 != 0 {
        return None;
    }
    if len > 1 && last == 0 && (payload[len - 2] & 0x80 == 0) {
        // Non-minimal encoding: leading zero is only allowed when
        // disambiguating a sign bit. We saw last byte == 0 with the
        // previous byte's MSB clear, so the leading zero is redundant.
        return None;
    }
    let mut value: u64 = 0;
    for (i, &b) in payload.iter().enumerate() {
        let mask: u64 = if i == len - 1 { 0x7f } else { 0xff };
        value |= (u64::from(b) & mask) << (i * 8);
    }
    u32::try_from(value).ok()
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The 24 shield variants (20 Phase 1 plus 4 Phase 2 Class M)
    /// must each map to a distinct canonical code listed in
    /// `ALL_CODES`, and `ALL_CODES` must have length 24.
    ///
    /// Phase 1 went from 18 to 19 with PB-20's
    /// `v2_invariant_coinbase_prevout_not_null`, and from 19 to 20
    /// with PB-21's `v2_invariant_coinbase_value_exceeds_max`. Both
    /// widen ADR-002's ratified table rather than completing it.
    #[test]
    fn all_codes_has_twenty_four_invariant_entries() {
        assert_eq!(
            ConsensusViolation::ALL_CODES.len(),
            24,
            "ALL_CODES length must match ADR-002 Phase 1 + ADR-003 Phase 2 check set"
        );
    }

    #[test]
    fn all_has_twenty_five_entries_scaffold_plus_shield() {
        // 24 shield variants plus NotImplemented sentinel.
        assert_eq!(
            ConsensusViolation::ALL.len(),
            25,
            "ALL length drift: did you add a variant?"
        );
    }

    #[test]
    fn every_variant_has_distinct_reason_code() {
        let mut codes: Vec<&'static str> = ConsensusViolation::ALL
            .iter()
            .map(ConsensusViolation::as_reason_code)
            .collect();
        let before = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(
            before,
            codes.len(),
            "reason code drift: two variants share a canonical string"
        );
    }

    #[test]
    fn all_codes_are_snake_case_with_prefix() {
        for code in ConsensusViolation::ALL_CODES {
            assert!(
                code.starts_with("v2_invariant_"),
                "ALL_CODES entry missing v2_invariant_ prefix: {code}"
            );
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "ALL_CODES entry is not snake_case: {code}"
            );
        }
    }

    #[test]
    fn not_implemented_code_is_outside_all_codes() {
        // NotImplemented is a degraded sentinel, not a real
        // invariant mismatch. It must not collide with the 24.
        assert!(
            !ConsensusViolation::ALL_CODES.contains(&ConsensusViolation::NOT_IMPLEMENTED_CODE),
            "NOT_IMPLEMENTED_CODE must be distinct from the 24 shield codes",
        );
        assert!(
            ConsensusViolation::NOT_IMPLEMENTED_CODE.starts_with("v2_invariant_"),
            "NOT_IMPLEMENTED_CODE must share the v2_invariant_ prefix",
        );
    }

    /// Helper: serialize the mainnet genesis block to the on wire
    /// form the facade expects.
    fn genesis_bytes() -> Vec<u8> {
        use bitcoin::Network;
        use bitcoin::blockdata::constants::genesis_block;
        use bitcoin::consensus::serialize;
        serialize(&genesis_block(Network::Bitcoin))
    }

    #[test]
    fn garbage_bytes_surface_decode_failed_on_every_function() {
        let junk: &[u8] = &[0xff; 16];
        assert!(matches!(
            re_derive_coinbase_value(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
        assert!(matches!(
            re_derive_template_weight(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
        assert!(matches!(
            re_derive_merkle_root(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
        assert!(matches!(
            re_derive_witness_commitment(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
        assert!(matches!(
            count_sigops(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
    }

    #[test]
    fn genesis_coinbase_value_is_fifty_btc() {
        let bytes = genesis_bytes();
        let v = re_derive_coinbase_value(&bytes).expect("genesis parses");
        assert_eq!(v, 50 * 100_000_000, "genesis coinbase value in sats");
    }

    #[test]
    fn genesis_weight_matches_rust_bitcoin() {
        use bitcoin::Network;
        use bitcoin::blockdata::constants::genesis_block;
        let bytes = genesis_bytes();
        let declared = genesis_block(Network::Bitcoin).weight().to_wu();
        let re_derived = re_derive_template_weight(&bytes).expect("genesis parses");
        assert_eq!(declared, re_derived);
    }

    #[test]
    fn genesis_merkle_root_matches_rust_bitcoin() {
        use bitcoin::Network;
        use bitcoin::blockdata::constants::genesis_block;
        let bytes = genesis_bytes();
        let declared = genesis_block(Network::Bitcoin)
            .compute_merkle_root()
            .expect("genesis has a merkle root")
            .to_byte_array();
        let re_derived = re_derive_merkle_root(&bytes).expect("genesis parses");
        assert_eq!(declared, re_derived);
    }

    #[test]
    fn genesis_has_no_witness_commitment() {
        let bytes = genesis_bytes();
        let c = re_derive_witness_commitment(&bytes).expect("genesis parses");
        assert!(
            c.is_none(),
            "pre segwit genesis must not carry a commitment"
        );
    }

    #[test]
    fn genesis_legacy_sigops_is_small() {
        let bytes = genesis_bytes();
        let n = count_sigops(&bytes).expect("genesis parses");
        // Genesis coinbase carries one scriptSig push and a single
        // P2PK output: legacy sigops are strictly bounded.
        assert!(n < 10, "genesis legacy sigops unexpectedly large: {n}");
    }

    // ── ParsedBlock single-parse tests (Phase 1 #4b I-A) ──────────

    #[test]
    fn parse_block_accepts_genesis() {
        let bytes = genesis_bytes();
        let _block = parse_block(&bytes).expect("genesis parses");
    }

    #[test]
    fn parse_block_rejects_junk() {
        let junk: &[u8] = &[0xff; 16];
        assert!(matches!(
            parse_block(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
    }

    #[test]
    fn check_merkle_root_internal_passes_on_genesis() {
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        check_merkle_root_internal(&block).expect("genesis merkle root agrees");
    }

    #[test]
    fn check_merkle_root_internal_rejects_tampered_header() {
        // Tamper byte 36 of the serialized block (start of merkle
        // root in the header). Re-parsing produces a block whose
        // declared merkle root no longer matches the body hash.
        let mut bytes = genesis_bytes();
        bytes[36] ^= 0x01;
        let block = parse_block(&bytes).unwrap();
        assert!(matches!(
            check_merkle_root_internal(&block),
            Err(ConsensusViolation::MerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn check_witness_commitment_internal_passes_on_legacy_block() {
        // Genesis is pre-segwit; the check returns Ok regardless of
        // any commitment presence in the coinbase script.
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        check_witness_commitment_internal(&block).expect("legacy block needs no commitment");
    }

    #[test]
    fn tx_count_on_genesis_is_one() {
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        assert_eq!(tx_count(&block), 1);
    }

    #[test]
    fn total_sigops_on_genesis_matches_count_sigops() {
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        let parsed_total = total_sigops(&block);
        let raw_total = count_sigops(&bytes).unwrap();
        assert_eq!(
            parsed_total, raw_total,
            "ParsedBlock total_sigops must agree with count_sigops"
        );
    }

    #[test]
    fn non_coinbase_sigops_excludes_the_coinbase() {
        // Genesis is coinbase-only and its payout is a bare-pubkey
        // CHECKSIG, so the whole-block figure is non-zero while the
        // non-coinbase figure must be zero. This is the asymmetry the
        // Class D sigop floor depends on: a sigop-bearing payout must
        // not raise a floor compared against a declaration the
        // producer built from non-coinbase transactions alone.
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        assert_eq!(
            total_sigops(&block),
            coinbase_sigops(&block),
            "genesis carries only the coinbase, so whole-block == coinbase"
        );
        assert!(
            coinbase_sigops(&block) > 0,
            "genesis payout must carry sigops or this test proves nothing"
        );
        assert_eq!(
            non_coinbase_sigops(&block),
            0,
            "non_coinbase_sigops must exclude the coinbase"
        );
    }

    #[test]
    fn non_coinbase_sigops_is_total_minus_coinbase_on_a_multi_tx_block() {
        // The invariant that keeps the two accessors honest against
        // each other on a block that actually has a body. Both the
        // coinbase and the single body transaction pay to P2PKH, so
        // each contributes exactly one legacy sigop and a split that
        // silently included or dropped the coinbase would be visible.
        let p2pkh = |v: &mut Vec<u8>| {
            v.push(0x19);
            v.extend_from_slice(&[0x76, 0xa9, 0x14]);
            v.extend_from_slice(&[0xcd; 20]);
            v.extend_from_slice(&[0x88, 0xac]);
        };

        let mut cb = Vec::new();
        cb.extend_from_slice(&2u32.to_le_bytes());
        cb.push(0x01);
        cb.extend_from_slice(&[0u8; 32]);
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        cb.push(0x02);
        cb.extend_from_slice(&[0x01, 0x66]); // BIP-34 push of height 102
        cb.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        cb.push(0x01);
        cb.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        p2pkh(&mut cb);
        cb.extend_from_slice(&0u32.to_le_bytes());

        let mut tx = Vec::new();
        tx.extend_from_slice(&2u32.to_le_bytes());
        tx.push(0x01);
        tx.extend_from_slice(&[0x11; 32]); // non-null prevout
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.push(0x00); // empty scriptSig
        tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        tx.push(0x01);
        tx.extend_from_slice(&1_000u64.to_le_bytes());
        p2pkh(&mut tx);
        tx.extend_from_slice(&0u32.to_le_bytes());

        let raw = assemble_template_block(&TemplateBlockParts {
            version: 0x2000_0000,
            prev_hash: [0x44; 32],
            time: 1_700_000_000,
            bits: 0x207f_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[tx],
        })
        .expect("assembles");
        let block = parse_block(&raw).expect("parses");

        assert_eq!(
            coinbase_sigops(&block),
            1,
            "P2PKH coinbase payout is 1 sigop"
        );
        assert_eq!(non_coinbase_sigops(&block), 1, "the body tx is 1 sigop");
        assert_eq!(total_sigops(&block), 2, "whole block is both");
        assert_eq!(
            u64::from(non_coinbase_sigops(&block)) + u64::from(coinbase_sigops(&block)),
            u64::from(total_sigops(&block)),
            "non_coinbase + coinbase must reconstruct the whole-block figure"
        );
    }

    #[test]
    fn coinbase_sigops_on_genesis_equals_total() {
        // Genesis has exactly one transaction (the coinbase). All
        // sigops are coinbase sigops.
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        assert_eq!(coinbase_sigops(&block), total_sigops(&block));
    }

    #[test]
    fn decode_bip34_height_decodes_valid_pushes() {
        // 1-byte: push 0x42 -> 66
        assert_eq!(decode_bip34_height(&[0x01, 0x42]), Some(66));
        // 2-byte little endian: push 0x3412 -> 0x1234 = 4660
        assert_eq!(decode_bip34_height(&[0x02, 0x34, 0x12]), Some(0x1234));
        // 3-byte: push 0x563412 -> 0x123456 = 1193046
        assert_eq!(
            decode_bip34_height(&[0x03, 0x56, 0x34, 0x12]),
            Some(0x0012_3456)
        );
        // 4-byte covers up to ~2^31. Block 800000 = 0x000c3500.
        assert_eq!(
            decode_bip34_height(&[0x03, 0x00, 0x35, 0x0c]),
            Some(800_000)
        );
    }

    #[test]
    fn decode_bip34_height_rejects_negative_msb() {
        // Sign bit on the MSB of the most significant byte: rejected.
        assert_eq!(decode_bip34_height(&[0x01, 0x80]), None);
        assert_eq!(decode_bip34_height(&[0x02, 0x00, 0x80]), None);
    }

    #[test]
    fn decode_bip34_height_rejects_non_minimal_zero_padding() {
        // Last byte == 0 with the previous byte's MSB clear is
        // non-minimal: rejected.
        assert_eq!(decode_bip34_height(&[0x02, 0x42, 0x00]), None);
    }

    #[test]
    fn decode_bip34_height_rejects_invalid_opcode() {
        // 0x05 is outside the direct-push range we accept.
        assert_eq!(
            decode_bip34_height(&[0x05, 0x00, 0x00, 0x00, 0x00, 0x00]),
            None
        );
        // OP_0 (0x00) is rejected: BIP-34 requires an integer push.
        assert_eq!(decode_bip34_height(&[0x00]), None);
    }

    #[test]
    fn decode_bip34_height_handles_truncated_script() {
        // Length byte says push 4 but only 2 bytes follow.
        assert_eq!(decode_bip34_height(&[0x04, 0x00, 0x00]), None);
        // Empty script.
        assert_eq!(decode_bip34_height(&[]), None);
    }

    #[test]
    fn extract_witness_commitment_finds_well_formed_op_return() {
        use bitcoin::Transaction;
        use bitcoin::consensus::deserialize;
        // Build a fake coinbase whose first output is a textbook
        // witness commitment: OP_RETURN(0x6a) PUSH36(0x24)
        // magic(0xaa21a9ed) + 32 commitment bytes.
        let bytes = genesis_bytes();
        let block: Block = deserialize(&bytes).unwrap();
        let mut coinbase: Transaction = block.txdata[0].clone();
        let mut commit = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        let expected: [u8; 32] = [0x42; 32];
        commit.extend_from_slice(&expected);
        coinbase.output.push(bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::from(commit),
        });
        assert_eq!(
            extract_witness_commitment_from_coinbase(&coinbase),
            Some(expected)
        );
    }

    // ── Template block assembly (PB-19 / ADR-002 Phase 1b) ─────────

    /// Helper: legacy-serialize a minimal coinbase paying `value` to
    /// an `OP_TRUE` output, with a BIP-34 push of `height` plus
    /// `extranonce` zero bytes in the scriptSig, and optionally a
    /// BIP-141 commitment output carrying `commitment`.
    fn legacy_coinbase_bytes(
        height_push: &[u8],
        extranonce: usize,
        value: u64,
        commitment: Option<[u8; 32]>,
    ) -> Vec<u8> {
        use bitcoin::consensus::serialize;
        let mut script_sig = height_push.to_vec();
        script_sig.extend(std::iter::repeat_n(0u8, extranonce));
        let mut outputs = vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: bitcoin::ScriptBuf::from(vec![0x51u8]),
        }];
        if let Some(c) = commitment {
            let mut wc = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            wc.extend_from_slice(&c);
            outputs.push(bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::from(wc),
            });
        }
        let cb = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from(script_sig),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: outputs,
        };
        serialize(&cb)
    }

    /// Helper: a minimal segwit transaction (one witness element)
    /// spending the given prevout, serialized with witness.
    fn segwit_tx_bytes(prevout: bitcoin::OutPoint) -> Vec<u8> {
        use bitcoin::consensus::serialize;
        let mut tx = simple_tx(prevout);
        tx.input[0].witness = bitcoin::Witness::from_slice(&[[0x42u8; 32]]);
        serialize(&tx)
    }

    #[test]
    fn assemble_legacy_only_block_passes_every_shield_check() {
        // Coinbase-only, no witness anywhere, no commitment needed.
        let cb = legacy_coinbase_bytes(&[0x01, 0x66], 4, 5_000_000_000, None);
        let parts = TemplateBlockParts {
            version: 4,
            prev_hash: [0x11; 32],
            time: 1_700_000_000,
            bits: 0x2070_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[],
        };
        let raw = assemble_template_block(&parts).expect("assembles");
        let block = parse_block(&raw).expect("assembled block parses");
        check_merkle_root_internal(&block).expect("merkle root agrees");
        check_witness_commitment_internal(&block).expect("no commitment needed");
        check_coinbase_bip34_present(&block).expect("height push present");
        assert_eq!(bip34_height(&block).unwrap(), 0x66);
        check_coinbase_script_length(&block).expect("script in range");
        check_coinbase_output_count(&block).expect("one output");
        check_weight_max(&block).expect("tiny block");
        check_sigops_max(&block).expect("no sigops");
        check_non_coinbase_null_prevout(&block).expect("only coinbase");
        check_header_version(&block).expect("version 4");
        check_duplicate_tx(&block).expect("single tx");
        assert_eq!(re_derive_coinbase_value(&raw).unwrap(), 5_000_000_000);
        assert_eq!(tx_count(&block), 1);
    }

    #[test]
    fn assemble_segwit_block_commitment_agrees_with_shield() {
        use bitcoin::consensus::deserialize;
        // Build the segwit tx first so the expected commitment can be
        // computed over the real wtxids with the zero reserved value,
        // exactly what bitcoind's default_witness_commitment does.
        let cb_txid_placeholder = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
            vout: 0,
        };
        let tx_raw = segwit_tx_bytes(cb_txid_placeholder);
        let tx: bitcoin::Transaction = deserialize(&tx_raw).unwrap();

        // wtxid merkle with coinbase slot zeroed (BIP-141).
        let leaves = [[0u8; 32], tx.compute_wtxid().to_byte_array()];
        let mut cat = [0u8; 64];
        cat[..32].copy_from_slice(&leaves[0]);
        cat[32..].copy_from_slice(&leaves[1]);
        let witness_root = sha256d::Hash::hash(&cat).to_byte_array();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&witness_root);
        // reserved value = 32 zero bytes, already zeroed in buf[32..].
        let commitment = sha256d::Hash::hash(&buf).to_byte_array();

        let cb = legacy_coinbase_bytes(&[0x02, 0x34, 0x12], 8, 2_500_000_000, Some(commitment));
        let parts = TemplateBlockParts {
            version: 0x2000_0000,
            prev_hash: [0x33; 32],
            time: 1_700_000_100,
            bits: 0x2070_ffff,
            coinbase_legacy: &cb,
            txs_raw: std::slice::from_ref(&tx_raw),
        };
        let raw = assemble_template_block(&parts).expect("assembles");
        let block = parse_block(&raw).expect("parses");
        check_merkle_root_internal(&block).expect("merkle agrees");
        check_witness_commitment_internal(&block)
            .expect("assembled commitment must satisfy the shield");
        assert_eq!(tx_count(&block), 2);
        assert_eq!(template_txids(&block).len(), 1);
    }

    #[test]
    fn assemble_rejects_witness_txs_without_commitment() {
        let cb = legacy_coinbase_bytes(&[0x01, 0x66], 4, 5_000_000_000, None);
        let tx_raw = segwit_tx_bytes(bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
            vout: 0,
        });
        let parts = TemplateBlockParts {
            version: 4,
            prev_hash: [0x11; 32],
            time: 1_700_000_000,
            bits: 0x2070_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[tx_raw],
        };
        assert_eq!(
            assemble_template_block(&parts),
            Err(ConsensusViolation::WitnessCommitmentMissing),
            "assembling an invalid block must fail fast, not ship"
        );
    }

    #[test]
    fn assemble_rejects_garbage_inputs() {
        let junk: &[u8] = &[0xff; 8];
        let parts = TemplateBlockParts {
            version: 4,
            prev_hash: [0; 32],
            time: 0,
            bits: 0x2070_ffff,
            coinbase_legacy: junk,
            txs_raw: &[],
        };
        assert!(matches!(
            assemble_template_block(&parts),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));

        let cb = legacy_coinbase_bytes(&[0x01, 0x66], 4, 1, None);
        let parts = TemplateBlockParts {
            version: 4,
            prev_hash: [0; 32],
            time: 0,
            bits: 0x2070_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[vec![0xff; 8]],
        };
        assert!(matches!(
            assemble_template_block(&parts),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
    }

    #[test]
    fn assemble_header_fields_round_trip() {
        use bitcoin::consensus::deserialize;
        let cb = legacy_coinbase_bytes(&[0x01, 0x66], 4, 5_000_000_000, None);
        let parts = TemplateBlockParts {
            version: 4,
            prev_hash: [0xab; 32],
            time: 1_699_999_999,
            bits: 0x1d00_ffff,
            coinbase_legacy: &cb,
            txs_raw: &[],
        };
        let raw = assemble_template_block(&parts).unwrap();
        let block: Block = deserialize(&raw).unwrap();
        assert_eq!(block.header.version.to_consensus(), 4);
        assert_eq!(block.header.prev_blockhash.to_byte_array(), [0xab; 32]);
        assert_eq!(block.header.time, 1_699_999_999);
        assert_eq!(block.header.bits.to_consensus(), 0x1d00_ffff);
        assert_eq!(block.header.nonce, 0, "template blocks are unmined");
    }

    #[test]
    fn witness_commitment_extractor_prefers_highest_output_index() {
        use bitcoin::Transaction;
        use bitcoin::consensus::deserialize;
        // BIP-141: "If there are more than one scriptPubKey matching
        // the pattern, the one with highest output index is assumed
        // to be the commitment." Bitcoin Core keeps the last match;
        // the shield must agree or it diverges on blocks Core
        // accepts.
        let bytes = genesis_bytes();
        let block: Block = deserialize(&bytes).unwrap();
        let mut coinbase: Transaction = block.txdata[0].clone();
        for fill in [0x11u8, 0x42u8] {
            let mut commit = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            commit.extend_from_slice(&[fill; 32]);
            coinbase.output.push(bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::from(commit),
            });
        }
        assert_eq!(
            extract_witness_commitment_from_coinbase(&coinbase),
            Some([0x42; 32]),
            "highest output index must win"
        );
    }

    #[test]
    fn witness_commitment_missing_when_only_coinbase_has_witness() {
        // Bitcoin Core's unexpected-witness rule counts every
        // transaction including the coinbase: any witness data in a
        // block without a commitment is invalid. A scan that skips
        // the coinbase false-accepts that block.
        let mut b = genesis_block_mut();
        b.txdata[0].input[0].witness = bitcoin::Witness::from_slice(&[[0u8; 32]]);
        assert_eq!(
            check_witness_commitment_internal(&ParsedBlock(b)),
            Err(ConsensusViolation::WitnessCommitmentMissing)
        );
    }

    #[test]
    fn extract_witness_commitment_returns_none_on_legacy_coinbase() {
        // Genesis coinbase has no OP_RETURN witness commitment.
        let bytes = genesis_bytes();
        let block: Block = deserialize(&bytes).unwrap();
        let coinbase = &block.txdata[0];
        assert_eq!(extract_witness_commitment_from_coinbase(coinbase), None);
    }

    // ── Tier 3 belt-and-suspenders checks (ADR-002 Phase 1.5) ──────

    /// Helper: deserialize the mainnet genesis block into a mutable
    /// `bitcoin::Block` so Tier 3 tests can build synthetic
    /// violation vectors. Checks under test are standalone, so a
    /// mutated body does not need a recomputed header merkle root.
    fn genesis_block_mut() -> Block {
        use bitcoin::consensus::deserialize;
        deserialize(&genesis_bytes()).unwrap()
    }

    /// Helper: minimal non-coinbase transaction spending `prevout`.
    fn simple_tx(prevout: bitcoin::OutPoint) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: prevout,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn coinbase_script_length_passes_on_genesis() {
        let block = parse_block(&genesis_bytes()).unwrap();
        check_coinbase_script_length(&block).expect("genesis coinbase script is 77 bytes");
    }

    #[test]
    fn coinbase_script_length_rejects_oversize() {
        let mut b = genesis_block_mut();
        b.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from(vec![0x51u8; 101]);
        assert_eq!(
            check_coinbase_script_length(&ParsedBlock(b)),
            Err(ConsensusViolation::CoinbaseScriptLength)
        );
    }

    #[test]
    fn coinbase_script_length_rejects_undersize() {
        let mut b = genesis_block_mut();
        b.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from(vec![0x51u8; 1]);
        assert_eq!(
            check_coinbase_script_length(&ParsedBlock(b)),
            Err(ConsensusViolation::CoinbaseScriptLength)
        );
    }

    #[test]
    fn coinbase_output_count_passes_on_genesis() {
        let block = parse_block(&genesis_bytes()).unwrap();
        check_coinbase_output_count(&block).expect("genesis coinbase has one output");
    }

    #[test]
    fn coinbase_output_count_rejects_empty_outputs() {
        let mut b = genesis_block_mut();
        b.txdata[0].output.clear();
        assert_eq!(
            check_coinbase_output_count(&ParsedBlock(b)),
            Err(ConsensusViolation::CoinbaseOutputCount)
        );
    }

    #[test]
    fn weight_max_passes_on_genesis() {
        let block = parse_block(&genesis_bytes()).unwrap();
        check_weight_max(&block).expect("genesis weight is far below 4M WU");
    }

    #[test]
    fn weight_max_rejects_oversized_block() {
        // A single ~1.1 MB non-witness output pushes base weight
        // (size * 4) past the 4,000,000 WU consensus ceiling.
        let mut b = genesis_block_mut();
        b.txdata[0].output[0].script_pubkey = bitcoin::ScriptBuf::from(vec![0x6au8; 1_100_000]);
        assert_eq!(
            check_weight_max(&ParsedBlock(b)),
            Err(ConsensusViolation::WeightExceedsMax)
        );
    }

    #[test]
    fn sigops_max_passes_on_genesis() {
        let block = parse_block(&genesis_bytes()).unwrap();
        check_sigops_max(&block).expect("genesis sigops are far below the ceiling");
    }

    #[test]
    fn sigops_max_rejects_excess() {
        // 20,001 OP_CHECKSIG bytes = 20,001 legacy sigops = 80,004
        // sigop cost after the BIP-141 x4 scale, over the 80,000 max.
        let mut b = genesis_block_mut();
        b.txdata[0].output[0].script_pubkey = bitcoin::ScriptBuf::from(vec![0xacu8; 20_001]);
        assert_eq!(
            check_sigops_max(&ParsedBlock(b)),
            Err(ConsensusViolation::SigopsExceedMax)
        );
    }

    #[test]
    fn null_prevout_passes_on_coinbase_only_block() {
        let block = parse_block(&genesis_bytes()).unwrap();
        check_non_coinbase_null_prevout(&block).expect("coinbase-only block has no violation");
    }

    #[test]
    fn null_prevout_rejects_noncoinbase_null() {
        let mut b = genesis_block_mut();
        b.txdata.push(simple_tx(bitcoin::OutPoint::null()));
        assert_eq!(
            check_non_coinbase_null_prevout(&ParsedBlock(b)),
            Err(ConsensusViolation::NonCoinbaseNullPrevout)
        );
    }

    #[test]
    fn null_prevout_passes_on_regular_second_tx() {
        let mut b = genesis_block_mut();
        let cb_txid = b.txdata[0].compute_txid();
        b.txdata.push(simple_tx(bitcoin::OutPoint {
            txid: cb_txid,
            vout: 0,
        }));
        check_non_coinbase_null_prevout(&ParsedBlock(b))
            .expect("regular prevout in second tx is fine");
    }

    #[test]
    fn sigop_accessors_reconcile_across_shapes() {
        // Rule-of-three extraction guard (PB-20). The three
        // accessors share one summing helper and differ only in the
        // set they iterate, so total must equal coinbase plus
        // non-coinbase on every shape. An extraction slip that fed
        // the wrong iterator to any of them breaks this identity.
        // Well below the u32 saturation boundary, where the three
        // clamp independently and the identity does not hold.
        //
        // Known blind spot, so do not read this test as covering more
        // than it does: the identity is invariant under ANY change to
        // the shared `sum_legacy_sigops` body, because that one body
        // feeds all three sides. Deleting the `script_sig` arm scales
        // every figure down together and the identity still holds. The
        // absolute values live in
        // `sigop_accessors_count_script_sig_and_script_pubkey`; the
        // independent-clamp contract, which is the only thing that
        // separates `non_coinbase_sigops` from `total - coinbase`,
        // lives in
        // `sigop_accessors_clamp_independently_at_the_u32_boundary`.
        let mut shapes: Vec<bitcoin::Block> = Vec::new();

        shapes.push(genesis_block_mut()); // coinbase only

        let mut two = genesis_block_mut(); // coinbase + one spending tx
        let cb = two.txdata[0].compute_txid();
        two.txdata
            .push(simple_tx(bitcoin::OutPoint { txid: cb, vout: 0 }));
        shapes.push(two);

        let mut heavy = genesis_block_mut(); // sigops on both sides
        heavy.txdata[0].output[0].script_pubkey = bitcoin::ScriptBuf::from(vec![0xacu8; 5]);
        let hcb = heavy.txdata[0].compute_txid();
        let mut spender = simple_tx(bitcoin::OutPoint { txid: hcb, vout: 0 });
        spender.output[0].script_pubkey = bitcoin::ScriptBuf::from(vec![0xaeu8; 3]);
        heavy.txdata.push(spender);
        shapes.push(heavy);

        let mut empty = genesis_block_mut(); // no transactions at all
        empty.txdata.clear();
        shapes.push(empty);

        for (i, b) in shapes.into_iter().enumerate() {
            let p = ParsedBlock(b);
            assert_eq!(
                u64::from(total_sigops(&p)),
                u64::from(coinbase_sigops(&p)) + u64::from(non_coinbase_sigops(&p)),
                "shape {i}: total != coinbase + non_coinbase"
            );
        }
    }

    #[test]
    fn sigop_accessors_count_script_sig_and_script_pubkey() {
        // Absolute values, hand computed, over a shape where BOTH
        // terms of `sum_legacy_sigops` are non-zero on BOTH sides of
        // the coinbase split. Before this test no shipped test
        // exercised a `script_sig` carrying a legacy sigop at all, so
        // deleting the `script_sig` arm of the shared body passed the
        // whole suite: the reconcile test above only asserts an
        // identity, and every other sigop test puts its opcodes in a
        // `script_pubkey`.
        //
        // 0xac is OP_CHECKSIG, worth one legacy sigop each, and a run
        // of them decodes as that many opcodes because none of them
        // pushes. Genesis is only the carrier here; every script that
        // contributes is overwritten below, so the expected figures do
        // not depend on what genesis happens to contain.
        let mut b = genesis_block_mut();
        b.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from(vec![0xacu8; 3]);
        b.txdata[0].output[0].script_pubkey = bitcoin::ScriptBuf::from(vec![0xacu8; 2]);
        let cb_txid = b.txdata[0].compute_txid();
        let mut spender = simple_tx(bitcoin::OutPoint {
            txid: cb_txid,
            vout: 0,
        });
        spender.input[0].script_sig = bitcoin::ScriptBuf::from(vec![0xacu8; 7]);
        spender.output[0].script_pubkey = bitcoin::ScriptBuf::from(vec![0xacu8; 4]);
        b.txdata.push(spender);
        let p = ParsedBlock(b);

        // coinbase: 3 in the scriptSig + 2 in the scriptPubKey.
        assert_eq!(
            coinbase_sigops(&p),
            5,
            "coinbase must count both its scriptSig and its scriptPubKey"
        );
        // body tx: 7 in the scriptSig + 4 in the scriptPubKey.
        assert_eq!(
            non_coinbase_sigops(&p),
            11,
            "non-coinbase must count both its scriptSig and its scriptPubKey"
        );
        assert_eq!(total_sigops(&p), 16, "whole block is 5 + 11");
        // The four terms are pairwise distinct, so a body that dropped
        // any one arm lands on a different number rather than on
        // another legal-looking total.
        assert_eq!(
            count_sigops(&bitcoin::consensus::serialize(&p.0)).expect("re-serializes"),
            16,
            "the raw-bytes accessor must agree with the parsed one"
        );
    }

    #[test]
    #[ignore = "allocates ~205 MiB of script bytes; run with --ignored"]
    fn sigop_accessors_clamp_independently_at_the_u32_boundary() {
        // The documented contract on `non_coinbase_sigops` is that it
        // equals `total_sigops` minus `coinbase_sigops` EXCEPT at the
        // u32 boundary, where each figure clamps independently. That
        // exception is the only observable difference between the
        // shipped body and a `total - coinbase` collapse, so it is the
        // only thing that can hold the accessor to summing its own set.
        //
        // Ignored by default because reaching the boundary is
        // inherently expensive: OP_CHECKMULTISIG (0xae) is the densest
        // legacy opcode at MAX_PUBKEYS_PER_MULTISIG = 20 sigops per
        // byte, so 2^32 sigops costs ~205 MiB of script bytes and two
        // full scans of it. There is no cheap construction; the
        // arithmetic bound is the cost.
        const PER_BYTE: u64 = 20;
        // 20 * 214_748_364 = 4_294_967_280, which is u32::MAX - 15:
        // large enough that adding the coinbase's 20 crosses the
        // boundary, small enough that this figure does not clamp on
        // its own.
        const BODY_BYTES: usize = 214_748_364;
        const BODY_SIGOPS: u32 = 4_294_967_280;
        assert_eq!(PER_BYTE * BODY_BYTES as u64, u64::from(BODY_SIGOPS));

        let mut b = genesis_block_mut();
        b.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::new();
        b.txdata[0].output[0].script_pubkey = bitcoin::ScriptBuf::from(vec![0xaeu8; 1]);
        let cb_txid = b.txdata[0].compute_txid();
        let mut spender = simple_tx(bitcoin::OutPoint {
            txid: cb_txid,
            vout: 0,
        });
        spender.input[0].script_sig = bitcoin::ScriptBuf::from(vec![0xaeu8; BODY_BYTES]);
        b.txdata.push(spender);
        let p = ParsedBlock(b);

        assert_eq!(coinbase_sigops(&p), 20, "one OP_CHECKMULTISIG");
        assert_eq!(
            total_sigops(&p),
            u32::MAX,
            "20 + 4_294_967_280 exceeds u32::MAX, so the whole-block figure clamps"
        );
        // The collapse would return u32::MAX - 20 = 4_294_967_275 here.
        assert_eq!(
            non_coinbase_sigops(&p),
            BODY_SIGOPS,
            "non_coinbase_sigops must sum its own set, not subtract the coinbase from a clamped total"
        );
        assert!(
            u64::from(coinbase_sigops(&p)) + u64::from(non_coinbase_sigops(&p))
                > u64::from(total_sigops(&p)),
            "this shape is past the boundary, so the reconcile identity must NOT hold here"
        );
    }

    // ── PB-20: txdata[0] must actually BE a coinbase ──────────────
    // Every `skip(1)` consumer in this crate reads index 0 as "the
    // coinbase" without anyone checking it. raw_block_hex is
    // attacker controlled, so the assumption needs a check of its
    // own.

    #[test]
    fn coinbase_null_prevout_passes_on_genesis() {
        let block = parse_block(&genesis_bytes()).unwrap();
        check_coinbase_null_prevout(&block).expect("genesis txdata[0] is a real coinbase");
    }

    #[test]
    fn coinbase_null_prevout_rejects_pb20_attack_shape() {
        // The exact shape the PB-20 review executed: index 0 spends a
        // real outpoint, so `skip(1)` silently excludes a transaction
        // that is not a coinbase from every non-coinbase accessor.
        let mut b = genesis_block_mut();
        b.txdata[0].input[0].previous_output = bitcoin::OutPoint {
            txid: "1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .expect("literal txid parses"),
            vout: 7,
        };
        assert_eq!(
            check_coinbase_null_prevout(&ParsedBlock(b)),
            Err(ConsensusViolation::CoinbasePrevoutNotNull)
        );
    }

    #[test]
    fn coinbase_null_prevout_rejects_null_txid_with_wrong_index() {
        // Half a coinbase: all-zero txid but a vout that is not
        // 0xFFFFFFFF. This is the case the check would miss if it
        // compared only the txid.
        let mut b = genesis_block_mut();
        b.txdata[0].input[0].previous_output = bitcoin::OutPoint {
            txid: bitcoin::hashes::Hash::all_zeros(),
            vout: 0,
        };
        assert_eq!(
            check_coinbase_null_prevout(&ParsedBlock(b)),
            Err(ConsensusViolation::CoinbasePrevoutNotNull)
        );
    }

    #[test]
    fn coinbase_null_prevout_rejects_empty_txdata() {
        // A body with no transactions has no coinbase to vouch for.
        let mut b = genesis_block_mut();
        b.txdata.clear();
        assert_eq!(
            check_coinbase_null_prevout(&ParsedBlock(b)),
            Err(ConsensusViolation::CoinbasePrevoutNotNull)
        );
    }

    #[test]
    fn coinbase_null_prevout_rejects_inputless_coinbase() {
        // `input[0]` is indexed by the check; an empty input vector
        // must be a violation, never a panic.
        let mut b = genesis_block_mut();
        b.txdata[0].input.clear();
        assert_eq!(
            check_coinbase_null_prevout(&ParsedBlock(b)),
            Err(ConsensusViolation::CoinbasePrevoutNotNull)
        );
    }

    #[test]
    fn coinbase_null_prevout_rejects_multi_input_coinbase() {
        // A real coinbase carries exactly one input. A second input
        // means index 0 is spending value, whatever input[0] says.
        let mut b = genesis_block_mut();
        let cb_txid = b.txdata[0].compute_txid();
        b.txdata[0].input.push(bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: cb_txid,
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        });
        assert_eq!(
            check_coinbase_null_prevout(&ParsedBlock(b)),
            Err(ConsensusViolation::CoinbasePrevoutNotNull)
        );
    }

    #[test]
    fn outpoint_is_null_subsumes_the_0xffffffff_index() {
        // PB-20 specifies "is_null() AND index 0xFFFFFFFF". Pin that
        // the second clause is redundant in bitcoin =0.32.8 rather
        // than trusting a reading of the dependency: is_null() is
        // equality against OutPoint::null(), whose vout is u32::MAX.
        assert!(bitcoin::OutPoint::null().is_null());
        assert_eq!(bitcoin::OutPoint::null().vout, 0xFFFF_FFFF);
        let wrong_index = bitcoin::OutPoint {
            txid: bitcoin::hashes::Hash::all_zeros(),
            vout: 0xFFFF_FFFE,
        };
        assert!(!wrong_index.is_null());
    }

    // ── PB-21: coinbase value must stay inside MoneyRange ─────────
    // `raw_block_hex` is attacker controlled, so the coinbase output
    // values are attacker chosen u64s. Nothing bounded them and
    // nothing bounded their sum.

    /// Helper: serialize a block whose coinbase pays exactly the
    /// given output values to `OP_TRUE`. Genesis supplies every other
    /// byte, so the output values are the only thing under test.
    fn block_with_coinbase_output_values(values: &[u64]) -> Vec<u8> {
        use bitcoin::consensus::serialize;
        let mut b = genesis_block_mut();
        b.txdata[0].output = values
            .iter()
            .map(|v| bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(*v),
                script_pubkey: bitcoin::ScriptBuf::from(vec![0x51u8]),
            })
            .collect();
        serialize(&b)
    }

    #[test]
    fn re_derive_coinbase_value_rejects_pb21_two_output_overflow() {
        // The PB-21 repro. Two outputs of 0xC000_0000_0000_0000 sum
        // to 2^63 + 2^63, which does not fit u64. The unchecked
        // `.sum()` this replaced panicked under the debug/CI overflow
        // checks and wrapped to 2^63 under release, and a wrapped
        // value an attacker can also declare re-derives as a match.
        let raw =
            block_with_coinbase_output_values(&[0xC000_0000_0000_0000, 0xC000_0000_0000_0000]);
        assert_eq!(
            re_derive_coinbase_value(&raw),
            Err(ConsensusViolation::CoinbaseValueExceedsMax),
            "a coinbase whose output sum does not fit u64 must not re-derive to a value"
        );
    }

    #[test]
    fn re_derive_coinbase_value_rejects_u64_max_pair() {
        // Wrapping is not the only bad shape: u64::MAX plus 1 also
        // overflows, and saturating instead of failing would hand the
        // attacker u64::MAX to declare.
        let raw = block_with_coinbase_output_values(&[u64::MAX, 1]);
        assert_eq!(
            re_derive_coinbase_value(&raw),
            Err(ConsensusViolation::CoinbaseValueExceedsMax),
            "u64::MAX + 1 sats must not re-derive to a value"
        );
    }

    #[test]
    fn genesis_and_subsidy_shapes_still_re_derive() {
        // The honest side. If the guard above rejected everything,
        // the two tests before it would pass for the wrong reason.
        assert_eq!(
            re_derive_coinbase_value(&genesis_bytes()).expect("genesis re-derives"),
            50 * 100_000_000
        );
        let subsidy_plus_fees = block_with_coinbase_output_values(&[3_125_000_000, 141]);
        assert_eq!(
            re_derive_coinbase_value(&subsidy_plus_fees).expect("subsidy + fees re-derives"),
            3_125_000_141
        );
    }

    #[test]
    fn coinbase_value_max_rejects_single_output_above_max_money() {
        // MoneyRange is per output as well as on the sum: one output
        // of MAX_MONEY + 1 is out of range without the sum
        // overflowing anything.
        let raw = block_with_coinbase_output_values(&[2_100_000_000_000_001]);
        let block = parse_block(&raw).expect("block parses");
        assert_eq!(
            check_coinbase_value_max(&block),
            Err(ConsensusViolation::CoinbaseValueExceedsMax),
            "a single coinbase output above MAX_MONEY must be a violation"
        );
    }

    #[test]
    fn coinbase_value_max_rejects_sum_above_max_money() {
        // Both outputs are individually inside MoneyRange. Only the
        // total is out of range, which is the case a per-output check
        // alone would wave through.
        let raw = block_with_coinbase_output_values(&[2_000_000_000_000_000, 200_000_000_000_000]);
        let block = parse_block(&raw).expect("block parses");
        assert_eq!(
            check_coinbase_value_max(&block),
            Err(ConsensusViolation::CoinbaseValueExceedsMax),
            "a coinbase whose outputs total above MAX_MONEY must be a violation"
        );
    }

    #[test]
    fn coinbase_value_max_accepts_honest_shapes() {
        // Genesis, a post-halving subsidy plus fees, and exactly
        // MAX_MONEY (Core's MoneyRange is inclusive) must all pass.
        for raw in [
            genesis_bytes(),
            block_with_coinbase_output_values(&[3_125_000_000, 141]),
            block_with_coinbase_output_values(&[2_100_000_000_000_000]),
        ] {
            let block = parse_block(&raw).expect("block parses");
            check_coinbase_value_max(&block).expect("honest coinbase value is inside MoneyRange");
        }
    }

    #[test]
    fn header_version_low_rejects_genesis_v1() {
        // Genesis is a version-1 block: below the BIP-65 v4 floor.
        let block = parse_block(&genesis_bytes()).unwrap();
        assert_eq!(
            check_header_version(&block),
            Err(ConsensusViolation::HeaderVersionLow)
        );
    }

    #[test]
    fn header_version_four_passes() {
        let mut b = genesis_block_mut();
        b.header.version = bitcoin::block::Version::from_consensus(4);
        check_header_version(&ParsedBlock(b)).expect("version 4 meets the floor");
    }

    #[test]
    fn header_version_top_bits_passes() {
        // Modern BIP-9 style version (0x20000000) is above the floor.
        let mut b = genesis_block_mut();
        b.header.version = bitcoin::block::Version::from_consensus(0x2000_0000);
        check_header_version(&ParsedBlock(b)).expect("BIP-9 top-bits version meets the floor");
    }

    #[test]
    fn duplicate_tx_rejects_repeated_body_tx() {
        let mut b = genesis_block_mut();
        let cb_txid = b.txdata[0].compute_txid();
        let tx = simple_tx(bitcoin::OutPoint {
            txid: cb_txid,
            vout: 0,
        });
        b.txdata.push(tx.clone());
        b.txdata.push(tx);
        assert_eq!(
            check_duplicate_tx(&ParsedBlock(b)),
            Err(ConsensusViolation::DuplicateTx)
        );
    }

    #[test]
    fn duplicate_tx_passes_on_distinct_txs() {
        let mut b = genesis_block_mut();
        let cb_txid = b.txdata[0].compute_txid();
        b.txdata.push(simple_tx(bitcoin::OutPoint {
            txid: cb_txid,
            vout: 0,
        }));
        b.txdata.push(simple_tx(bitcoin::OutPoint {
            txid: cb_txid,
            vout: 1,
        }));
        check_duplicate_tx(&ParsedBlock(b)).expect("distinct txids pass");
    }
}
