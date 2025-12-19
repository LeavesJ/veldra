use serde::{Serialize, Deserialize};
use rg_protocol::TemplatePropose;

#[derive(Debug, Clone, Copy, Serialize)]
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

#[derive(Debug, Clone)]
pub enum VerdictReason {
    Ok,
    UnsupportedVersion {
        got: u16,
        expected: u16,
    },
    PrevHashWrongLen {
        len: usize,
        expected: usize,
    },
    CoinbaseZero,
    TotalFeesTooLow {
        total: u64,
        min_required: u64,
    },
    TooManyTransactions {
        count: u32,
        max_allowed: u32,
    },
    AverageFeeTooLow {
        avg: u64,
        min_required: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub protocol_version: u16,
    pub required_prevhash_len: usize,

    pub min_total_fees: u64,
    pub max_tx_count: u32,
    pub min_avg_fee: u64,

    pub low_mempool_tx: u64,
    pub high_mempool_tx: u64,

    pub tx_count_mid_threshold: u64,
    pub tx_count_hi_threshold: u64,

    pub min_avg_fee_lo: u64,
    pub min_avg_fee_mid: u64,
    pub min_avg_fee_hi: u64,

    // safety
    pub max_weight_ratio: f64,

    // NEW
    #[serde(default = "default_reject_empty_templates")]
    pub reject_empty_templates: bool,
}

fn default_reject_empty_templates() -> bool {
        true  // or false if you want legacy behavior; I recommend true for safety
    }

impl PolicyConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let cfg: PolicyConfig = toml::from_str(&contents)?;
        Ok(cfg)
    }

    pub fn default_with_protocol(protocol_version: u16) -> Self {
        PolicyConfig {
            protocol_version,
            required_prevhash_len: 64,

            min_total_fees: 0,
            max_tx_count: 10_000,
            min_avg_fee: 0,

            low_mempool_tx: 50,
            high_mempool_tx: 500,

            tx_count_mid_threshold: 10,
            tx_count_hi_threshold: 50,

            min_avg_fee_lo: 0,
            min_avg_fee_mid: 500,
            min_avg_fee_hi: 2_000,

            max_weight_ratio: 0.999,
            reject_empty_templates: true,   // make the dev default strict
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::anyhow;

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

        if self.tx_count_mid_threshold > self.tx_count_hi_threshold {
            return Err(anyhow!(
                "tx_count_mid_threshold ({}) must be <= tx_count_hi_threshold ({})",
                self.tx_count_mid_threshold,
                self.tx_count_hi_threshold
            ));
        }

        Ok(())
    }

    /// Old static helper, kept for compatibility if anything still calls it.
    /// Uses mempool_tx as selector, returns only the floor.
    pub fn effective_min_avg_fee(&self, mempool_tx: u64) -> u64 {
        if mempool_tx < self.low_mempool_tx {
            self.min_avg_fee_lo
        } else if mempool_tx < self.high_mempool_tx {
            self.min_avg_fee_mid
        } else {
            self.min_avg_fee_hi
        }
    }

    /// Dynamic helper for TCP server and dashboard.
    /// Returns (floor, tier) based on mempool tx count.
    pub fn effective_min_avg_fee_dynamic(
        &self,
        mempool_tx: Option<u64>,
    ) -> (u64, FeeTier) {
        let tx = mempool_tx.unwrap_or(0);
        if tx < self.low_mempool_tx {
            (self.min_avg_fee_lo, FeeTier::Low)
        } else if tx < self.high_mempool_tx {
            (self.min_avg_fee_mid, FeeTier::Mid)
        } else {
            (self.min_avg_fee_hi, FeeTier::High)
        }
    }
}

/// Legacy evaluator. Still returns only VerdictReason and ignores mempool.
/// Keep it for now in case any other code uses it.
pub fn evaluate(template: &TemplatePropose, cfg: &PolicyConfig) -> VerdictReason {
    if template.version != cfg.protocol_version {
        return VerdictReason::UnsupportedVersion {
            got: template.version,
            expected: cfg.protocol_version,
        };
    }

    if template.prev_hash.len() != cfg.required_prevhash_len {
        return VerdictReason::PrevHashWrongLen {
            len: template.prev_hash.len(),
            expected: cfg.required_prevhash_len,
        };
    }

    if template.coinbase_value == 0 {
        return VerdictReason::CoinbaseZero;
    }

    if template.total_fees < cfg.min_total_fees {
        return VerdictReason::TotalFeesTooLow {
            total: template.total_fees,
            min_required: cfg.min_total_fees,
        };
    }

    if template.tx_count > cfg.max_tx_count {
        return VerdictReason::TooManyTransactions {
            count: template.tx_count,
            max_allowed: cfg.max_tx_count,
        };
    }

    // Static min_avg_fee, only if nonzero
    if cfg.min_avg_fee > 0 && template.tx_count > 0 {
        let avg = template.total_fees / template.tx_count as u64;
        if avg < cfg.min_avg_fee {
            return VerdictReason::AverageFeeTooLow {
                avg,
                min_required: cfg.min_avg_fee,
            };
        }
    }

    VerdictReason::Ok
}
