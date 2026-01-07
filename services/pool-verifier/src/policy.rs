use rg_protocol::TemplatePropose;
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
    UnsupportedVersion { got: u16, expected: u16 },
    PrevHashWrongLen { len: usize, expected: usize },
    EmptyTemplate,

    // NOTE: kept as a reason code, but the policy below is now configurable + relaxed.
    CoinbaseZero,

    TotalFeesTooLow { total: u64, min_required: u64 },
    TooManyTransactions { count: u32, max_allowed: u32 },
    AverageFeeTooLow { avg: u64, min_required: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub protocol_version: u16,
    pub required_prevhash_len: usize,

    pub min_total_fees: u64,
    pub max_tx_count: u32,
    pub min_avg_fee: u64,

    // tier thresholds (mempool tx count)
    pub low_mempool_tx: u64,
    pub high_mempool_tx: u64,

    // legacy / optional thresholds you may still use elsewhere
    pub tx_count_mid_threshold: u64,
    pub tx_count_hi_threshold: u64,

    // tier floors (avg fee per tx, in sats/tx)
    pub min_avg_fee_lo: u64,
    pub min_avg_fee_mid: u64,
    pub min_avg_fee_hi: u64,

    // safety
    pub max_weight_ratio: f64,

    // flags
    #[serde(default = "default_reject_empty_templates")]
    pub reject_empty_templates: bool,

    // RELAXED: default false for regtest/demo sanity.
    // If true, we only reject coinbase_value==0 when the template is NON-empty.
    // (Empty templates are handled by reject_empty_templates.)
    #[serde(default = "default_reject_coinbase_zero")]
    pub reject_coinbase_zero: bool,
}

fn default_reject_empty_templates() -> bool {
    true
}

fn default_reject_coinbase_zero() -> bool {
    false
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

            reject_empty_templates: true,
            reject_coinbase_zero: false, // DEMO-friendly default
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

        // fee floors ordering is not strictly required, but it’s usually intended
        // (allow equal too).
        // If you want to enforce, uncomment:
        // if !(self.min_avg_fee_lo <= self.min_avg_fee_mid && self.min_avg_fee_mid <= self.min_avg_fee_hi) {
        //     return Err(anyhow!("min_avg_fee_lo <= min_avg_fee_mid <= min_avg_fee_hi must hold"));
        // }

        Ok(())
    }

    /// Old static helper (kept). Uses mempool_tx as selector, returns only the floor.
    pub fn effective_min_avg_fee(&self, mempool_tx: u64) -> u64 {
        if mempool_tx < self.low_mempool_tx {
            self.min_avg_fee_lo
        } else if mempool_tx < self.high_mempool_tx {
            self.min_avg_fee_mid
        } else {
            self.min_avg_fee_hi
        }
    }

    /// Dynamic helper: returns (floor, tier) based on mempool tx count.
    pub fn effective_min_avg_fee_dynamic(&self, mempool_tx: Option<u64>) -> (u64, FeeTier) {
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

/// Legacy evaluator.
/// Still ignores mempool and returns only VerdictReason.
/// FIXED:
/// - EmptyTemplate can trigger (if enabled)
/// - CoinbaseZero is now optional + relaxed (only rejects non-empty templates)
pub fn evaluate(template: &TemplatePropose, cfg: &PolicyConfig) -> VerdictReason {
    // protocol
    if template.version != cfg.protocol_version {
        return VerdictReason::UnsupportedVersion {
            got: template.version,
            expected: cfg.protocol_version,
        };
    }

    // prevhash sanity
    if template.prev_hash.len() != cfg.required_prevhash_len {
        return VerdictReason::PrevHashWrongLen {
            len: template.prev_hash.len(),
            expected: cfg.required_prevhash_len,
        };
    }

    // empty template check FIRST (so it doesn't get masked by CoinbaseZero)
    if cfg.reject_empty_templates && template.tx_count == 0 {
        return VerdictReason::EmptyTemplate;
    }

    // relaxed coinbase==0 rule
    if cfg.reject_coinbase_zero && template.coinbase_value == 0 && template.tx_count > 0 {
        return VerdictReason::CoinbaseZero;
    }

    // hard constraints
    if template.tx_count > cfg.max_tx_count {
        return VerdictReason::TooManyTransactions {
            count: template.tx_count,
            max_allowed: cfg.max_tx_count,
        };
    }

    if template.total_fees < cfg.min_total_fees {
        return VerdictReason::TotalFeesTooLow {
            total: template.total_fees,
            min_required: cfg.min_total_fees,
        };
    }

    // static min_avg_fee (sats/tx) if configured
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

/// Dynamic evaluator (use this in your TCP verifier path / dashboard path).
/// Returns:
/// - reason
/// - tier chosen
/// - min_avg_fee_used (so you can log it cleanly)
pub fn evaluate_dynamic(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    mempool_tx: Option<u64>,
) -> (VerdictReason, FeeTier, u64) {
    // compute tier floor up front for logging
    let (min_avg_fee_used, tier) = cfg.effective_min_avg_fee_dynamic(mempool_tx);

    // protocol
    if template.version != cfg.protocol_version {
        return (
            VerdictReason::UnsupportedVersion {
                got: template.version,
                expected: cfg.protocol_version,
            },
            tier,
            min_avg_fee_used,
        );
    }

    // prevhash sanity
    if template.prev_hash.len() != cfg.required_prevhash_len {
        return (
            VerdictReason::PrevHashWrongLen {
                len: template.prev_hash.len(),
                expected: cfg.required_prevhash_len,
            },
            tier,
            min_avg_fee_used,
        );
    }

    // empty templates first
    if cfg.reject_empty_templates && template.tx_count == 0 {
        return (VerdictReason::EmptyTemplate, tier, min_avg_fee_used);
    }

    // relaxed coinbase==0 rule
    if cfg.reject_coinbase_zero && template.coinbase_value == 0 && template.tx_count > 0 {
        return (VerdictReason::CoinbaseZero, tier, min_avg_fee_used);
    }

    // hard constraints
    if template.tx_count > cfg.max_tx_count {
        return (
            VerdictReason::TooManyTransactions {
                count: template.tx_count,
                max_allowed: cfg.max_tx_count,
            },
            tier,
            min_avg_fee_used,
        );
    }

    if template.total_fees < cfg.min_total_fees {
        return (
            VerdictReason::TotalFeesTooLow {
                total: template.total_fees,
                min_required: cfg.min_total_fees,
            },
            tier,
            min_avg_fee_used,
        );
    }

    // dynamic avg-fee floor (sats/tx) based on mempool tier
    if min_avg_fee_used > 0 && template.tx_count > 0 {
        let avg = template.total_fees / template.tx_count as u64;
        if avg < min_avg_fee_used {
            return (
                VerdictReason::AverageFeeTooLow {
                    avg,
                    min_required: min_avg_fee_used,
                },
                tier,
                min_avg_fee_used,
            );
        }
    }

    // optional: also enforce the legacy static min_avg_fee if you want BOTH.
    // In practice this is usually redundant, so keep it off unless you explicitly want it.
    // if cfg.min_avg_fee > 0 && template.tx_count > 0 {
    //     let avg = template.total_fees / template.tx_count as u64;
    //     if avg < cfg.min_avg_fee {
    //         return (
    //             VerdictReason::AverageFeeTooLow { avg, min_required: cfg.min_avg_fee },
    //             tier,
    //             min_avg_fee_used,
    //         );
    //     }
    // }

    (VerdictReason::Ok, tier, min_avg_fee_used)
}
