use anyhow::{Context, anyhow};
use rg_protocol::PROTOCOL_VERSION;
use tracing::{error, warn};

use pool_verifier::mempool_view::MempoolView;
use pool_verifier::policy::PolicyConfig;
use pool_verifier::second_chance::SecondChance;

#[derive(Debug, Clone)]
pub struct PolicyHolder {
    pub config: PolicyConfig,
    pub toml_text: String,
}

#[derive(Clone)]
pub struct AppState {
    pub policy: std::sync::Arc<std::sync::RwLock<PolicyHolder>>,

    /// Phase 2 mempool view. `None` when `[policy.mempool] enforce`
    /// is `false` (default); the shield then runs Phase 1 only.
    /// `Some(view)` when the polling task is wired at startup;
    /// `evaluate_dynamic_phase2` reads a snapshot per template and
    /// passes it straight to `check_invariant_shield_inner`.
    /// `check_invariant_shield_with_mempool` is a single-expression
    /// wrapper over that same inner function, called only from
    /// `tests/phase2_eval.rs`.
    pub mempool_view: Option<std::sync::Arc<MempoolView>>,

    /// PB-40 second-chance lookup. Wired together with
    /// `mempool_view` and `None` in exactly the same cases, but kept
    /// as its own field rather than folded into the view because the
    /// two ask bitcoind different questions: the view polls
    /// `getrawmempool` on a cadence, this asks about specific
    /// transactions plus recent blocks at the moment a template is
    /// about to be rejected.
    pub second_chance: Option<std::sync::Arc<SecondChance>>,
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
        .with_context(|| format!("read policy file failed: {path}"))?;

    let cfg = parse_policy_from_policy_table(&contents)
        .with_context(|| format!("policy parse failed for {path}"))?;

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
            error!(error = ?e, "policy load failed");
            error!(
                "entering degraded mode with built-in default policy — \
                 all templates will be accepted without fee enforcement"
            );

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
                warn!(error = ?v, "built-in default policy validation failed");
                warn!("forcing zeroed fee-tier fields to satisfy validation");

                cfg.low_mempool_tx = 0;
                cfg.high_mempool_tx = 0;
                cfg.min_avg_fee_lo = 0;
                cfg.min_avg_fee_mid = 0;
                cfg.min_avg_fee_hi = 0;

                // Re-run validation, but do not panic in degraded mode.
                if let Err(v2) = cfg.validate() {
                    error!(error = ?v2, "degraded policy still failed validation");
                }
            }

            PolicyHolder {
                config: cfg,
                toml_text: "# policy load failed; running with built-in defaults\n".to_string(),
            }
        }
    }
}
