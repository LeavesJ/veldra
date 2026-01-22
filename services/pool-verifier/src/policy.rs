use rg_protocol::{PROTOCOL_VERSION, TemplatePropose};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerdictReason {
    Ok,
    ProtocolVersionMismatch { got: u16, expected: u16 },
    PrevHashLenMismatch { len: usize, expected: usize },
    InvalidPrevHash,
    EmptyTemplateRejected,
    CoinbaseValueZeroRejected,
    TotalFeesBelowMinimum { total: u64, min_required: u64 },
    TxCountExceeded { count: u32, max_allowed: u32 },
    AvgFeeBelowMinimum { avg: u64, min_required: u64 },
}

fn default_max_weight_ratio() -> f64 {
    0.999
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySafety {
    #[serde(default = "default_max_weight_ratio")]
    pub max_weight_ratio: f64,
}

impl Default for PolicySafety {
    fn default() -> Self {
        Self {
            max_weight_ratio: default_max_weight_ratio(),
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
            safety: PolicySafety {
                max_weight_ratio: 0.999,
            },
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

        if !(self.safety.max_weight_ratio > 0.0 && self.safety.max_weight_ratio <= 1.0) {
            return Err(anyhow!(
                "safety.max_weight_ratio ({}) must be in (0, 1]",
                self.safety.max_weight_ratio
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

pub fn evaluate(template: &TemplatePropose, cfg: &PolicyConfig) -> VerdictReason {
    evaluate_dynamic(template, cfg, None).0
}

pub fn evaluate_dynamic(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    mempool_tx: Option<u64>,
) -> (VerdictReason, FeeTier, u64) {
    let (min_avg_fee_used, tier) = cfg.effective_min_avg_fee_dynamic(mempool_tx);

    if template.version != cfg.protocol_version {
        return (
            VerdictReason::ProtocolVersionMismatch {
                got: template.version,
                expected: cfg.protocol_version,
            },
            tier,
            min_avg_fee_used,
        );
    }

    if template.prev_hash.len() != cfg.required_prevhash_len {
        return (
            VerdictReason::PrevHashLenMismatch {
                len: template.prev_hash.len(),
                expected: cfg.required_prevhash_len,
            },
            tier,
            min_avg_fee_used,
        );
    }

    if !is_hex(&template.prev_hash) {
        return (VerdictReason::InvalidPrevHash, tier, min_avg_fee_used);
    }

    if cfg.reject_empty_templates && template.tx_count == 0 {
        return (VerdictReason::EmptyTemplateRejected, tier, min_avg_fee_used);
    }

    if cfg.reject_coinbase_zero && template.coinbase_value == 0 && template.tx_count > 0 {
        return (
            VerdictReason::CoinbaseValueZeroRejected,
            tier,
            min_avg_fee_used,
        );
    }

    if template.tx_count > cfg.max_tx_count {
        return (
            VerdictReason::TxCountExceeded {
                count: template.tx_count,
                max_allowed: cfg.max_tx_count,
            },
            tier,
            min_avg_fee_used,
        );
    }

    if template.total_fees < cfg.min_total_fees {
        return (
            VerdictReason::TotalFeesBelowMinimum {
                total: template.total_fees,
                min_required: cfg.min_total_fees,
            },
            tier,
            min_avg_fee_used,
        );
    }

    if min_avg_fee_used > 0 && template.tx_count > 0 {
        let avg = template.total_fees / template.tx_count as u64;
        if avg < min_avg_fee_used {
            return (
                VerdictReason::AvgFeeBelowMinimum {
                    avg,
                    min_required: min_avg_fee_used,
                },
                tier,
                min_avg_fee_used,
            );
        }
    }

    (VerdictReason::Ok, tier, min_avg_fee_used)
}
