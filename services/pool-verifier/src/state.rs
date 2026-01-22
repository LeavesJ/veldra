use anyhow::{Context, anyhow};
use rg_protocol::PROTOCOL_VERSION;

use pool_verifier::policy::PolicyConfig;

#[derive(Debug, Clone)]
pub struct PolicyHolder {
    pub config: PolicyConfig,
    pub toml_text: String,
}

#[derive(Clone)]
pub struct AppState {
    pub policy: std::sync::Arc<std::sync::RwLock<PolicyHolder>>,
}

fn enforce_protocol(cfg: &PolicyConfig) -> anyhow::Result<()> {
    if cfg.protocol_version != PROTOCOL_VERSION {
        return Err(anyhow!(
            "policy.protocol_version={} does not match binary PROTOCOL_VERSION={}",
            cfg.protocol_version,
            PROTOCOL_VERSION
        ));
    }
    Ok(())
}

fn parse_policy_from_policy_table(contents: &str) -> anyhow::Result<PolicyConfig> {
    let v: toml::Value = toml::from_str(contents).context("parse TOML as value")?;

    let policy_v = v
        .get("policy")
        .cloned()
        .ok_or_else(|| anyhow!("missing [policy] table at top level"))?;

    let cfg: PolicyConfig = policy_v
        .try_into()
        .context("deserialize PolicyConfig from [policy] table")?;

    Ok(cfg)
}

pub fn load_initial_policy(path: &str) -> anyhow::Result<PolicyHolder> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read policy file failed: {}", path))?;

    let cfg = parse_policy_from_policy_table(&contents)
        .with_context(|| format!("policy parse failed for {}", path))?;

    cfg.validate().context("policy validation failed")?;
    enforce_protocol(&cfg)?;

    Ok(PolicyHolder {
        config: cfg,
        toml_text: contents,
    })
}

pub fn safe_initial_policy(path: &str) -> PolicyHolder {
    match load_initial_policy(path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[policy] load failed: {e:?}");
            eprintln!("[policy] entering degraded mode with built-in default policy");

            // Use the repo-provided constructor (PolicyConfig is not Default).
            let mut cfg: PolicyConfig = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);

            // Only override what is required for safe, permissive degraded operation.
            cfg.required_prevhash_len = 64;
            cfg.min_total_fees = 0;
            cfg.max_tx_count = u32::MAX;

            cfg.reject_empty_templates = false;
            cfg.reject_coinbase_zero = false;
            cfg.unknown_mempool_as_high = true;

            cfg.safety.max_weight_ratio = 0.999;

            // If validation still requires tier fields (depends on your PolicyConfig::validate),
            // fill them with a consistent zeroed set.
            if let Err(v) = cfg.validate() {
                eprintln!("[policy] built-in default policy validation failed: {v:?}");
                eprintln!("[policy] forcing zeroed fee-tier fields to satisfy validation");

                cfg.low_mempool_tx = 0;
                cfg.high_mempool_tx = 0;
                cfg.min_avg_fee_lo = 0;
                cfg.min_avg_fee_mid = 0;
                cfg.min_avg_fee_hi = 0;

                // Re-run validation, but do not panic in degraded mode.
                if let Err(v2) = cfg.validate() {
                    eprintln!("[policy] degraded policy still failed validation: {v2:?}");
                }
            }

            PolicyHolder {
                config: cfg,
                toml_text: "# policy load failed; running with built-in defaults\n".to_string(),
            }
        }
    }
}
