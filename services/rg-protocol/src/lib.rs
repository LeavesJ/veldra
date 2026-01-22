use serde::{Deserialize, Serialize};

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
    pub tx_count: u32,
    pub total_fees: u64,

    /// Forward compatible fields. Older senders omit them.
    #[serde(default)]
    pub observed_weight: Option<u64>,

    #[serde(default)]
    pub created_at_unix_ms: Option<u64>,
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

    /// Useful for “traceable rejects”: what policy decision was applied.
    #[serde(default)]
    pub policy_context: Option<PolicyContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictReason {
    /// template.version != PROTOCOL_VERSION or policy.protocol_version
    ProtocolVersionMismatch,

    /// prev_hash not hex
    InvalidPrevHash,

    /// prev_hash length != required_prevhash_len
    PrevHashLenMismatch,

    /// coinbase_value == 0 and reject_coinbase_zero enabled (non-empty templates)
    CoinbaseValueZeroRejected,

    /// tx_count == 0 and reject_empty_templates enabled
    EmptyTemplateRejected,

    /// tx_count > max_tx_count
    TxCountExceeded,

    /// total_fees < min_total_fees
    TotalFeesBelowMinimum,

    /// (total_fees / tx_count) < effective min avg fee
    AvgFeeBelowMinimum,

    /// policy file could not be parsed/validated
    PolicyLoadError,

    /// verifier could not fetch mempool stats (degraded / fallback path)
    MempoolBackendUnavailable,

    /// unexpected internal failure
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyContext {
    #[serde(default)]
    pub fee_tier: Option<String>, // "lo" | "mid" | "hi" or "unknown"

    #[serde(default)]
    pub min_avg_fee_used: Option<u64>,

    #[serde(default)]
    pub min_total_fees_used: Option<u64>,

    #[serde(default)]
    pub reject_coinbase_zero: Option<bool>,

    #[serde(default)]
    pub unknown_mempool_as_high: Option<bool>,
}
