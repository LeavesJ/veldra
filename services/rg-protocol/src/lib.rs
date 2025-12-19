use serde::{Deserialize, Serialize};
pub const PROTOCOL_VERSION: u16 = 1;

/// Versioned template proposal from a Template Manager to a Pool Verifier.
#[derive(Debug, Serialize, Deserialize)]
pub struct TemplatePropose {
    pub version: u16,
    pub id: u64,
    pub block_height: u32,
    pub prev_hash: String,
    pub coinbase_value: u64,

    pub tx_count: u32,
    pub total_fees: u64,
}

/// Verdict from Pool Verifier back to Template Manager.
#[derive(Debug, Serialize, Deserialize)]
pub struct TemplateVerdict {
    pub version: u16,
    pub id: u64,
    pub accepted: bool,
    pub reason: Option<String>,
}
