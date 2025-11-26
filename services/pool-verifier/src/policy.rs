use rg_protocol::TemplatePropose;
use serde::{Deserialize, Serialize};

/// High level result of running pool policy on a template.
#[derive(Debug)]
pub enum VerdictReason {
    Ok,
    UnsupportedVersion { got: u16, expected: u16 },
    PrevHashWrongLen { len: usize, expected: usize },
    CoinbaseZero,
    TotalFeesTooLow { total: u64, min_required: u64 },
    TooManyTransactions { count: u32, max_allowed: u32 },
}

/// Config for policy. Later this can come from a file or env.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub protocol_version: u16,
    pub required_prevhash_len: usize,
    pub min_total_fees: u64,   // sats
    pub max_tx_count: u32,
}

impl PolicyConfig {
    pub fn default_with_protocol(protocol_version: u16) -> Self {
        PolicyConfig {
            protocol_version,
            required_prevhash_len: 64,
            // you can tweak these thresholds
            min_total_fees: 1,      // set to 0 if you want id=1 accepted on empty mempool
            max_tx_count: 10_000,
        }
    }
}

/// Run all policy checks on a proposed template and return the reason.
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

    VerdictReason::Ok
}

use std::fs;

impl PolicyConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let cfg: PolicyConfig = toml::from_str(&contents)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rg_protocol::TemplatePropose;

    fn good_prevhash() -> String {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    }

    fn base_cfg() -> PolicyConfig {
        PolicyConfig {
            protocol_version: 1,
            required_prevhash_len: 64,
            min_total_fees: 1_000,
            max_tx_count: 10_000,
        }
    }

    fn base_template() -> TemplatePropose {
        TemplatePropose {
            version: 1,
            id: 42,
            block_height: 100,
            prev_hash: good_prevhash(),
            coinbase_value: 6_2500_0000,
            tx_count: 3,
            total_fees: 2_000,
        }
    }

    #[test]
    fn accepts_good_template() {
        let cfg = base_cfg();
        let tpl = base_template();
        matches!(evaluate(&tpl, &cfg), VerdictReason::Ok);
    }

    #[test]
    fn rejects_wrong_version() {
        let cfg = base_cfg();
        let mut tpl = base_template();
        tpl.version = 2;
        matches!(evaluate(&tpl, &cfg), VerdictReason::UnsupportedVersion { .. });
    }

    #[test]
    fn rejects_bad_prevhash_length() {
        let cfg = base_cfg();
        let mut tpl = base_template();
        tpl.prev_hash = "abc123".to_string();
        matches!(evaluate(&tpl, &cfg), VerdictReason::PrevHashWrongLen { .. });
    }

    #[test]
    fn rejects_zero_coinbase() {
        let cfg = base_cfg();
        let mut tpl = base_template();
        tpl.coinbase_value = 0;
        matches!(evaluate(&tpl, &cfg), VerdictReason::CoinbaseZero);
    }

    #[test]
    fn rejects_low_fees() {
        let cfg = base_cfg();
        let mut tpl = base_template();
        tpl.total_fees = 0;
        matches!(evaluate(&tpl, &cfg), VerdictReason::TotalFeesTooLow { .. });
    }

    #[test]
    fn rejects_too_many_txs() {
        let mut cfg = base_cfg();
        cfg.max_tx_count = 10;

        let mut tpl = base_template();
        tpl.tx_count = 11;
        matches!(evaluate(&tpl, &cfg), VerdictReason::TooManyTransactions { .. });
    }
}
