use std::sync::{Arc, RwLock};

use pool_verifier::policy::PolicyConfig;
use rg_protocol::PROTOCOL_VERSION;

#[derive(Clone)]
pub struct AppState {
    pub policy: Arc<RwLock<PolicyHolder>>,
}

pub struct PolicyHolder {
    pub config: PolicyConfig,
    pub toml_text: String,
}

// path is &str here so you can call with &policy_path (String)
pub fn load_initial_policy(path: &str) -> anyhow::Result<PolicyHolder> {
    match PolicyConfig::from_file(path) {
        Ok(cfg) => {
            println!("Loaded policy: {:?}", cfg);
            if let Err(e) = cfg.validate() {
                anyhow::bail!("Policy validation failed: {e:?}");
            }

            // best effort read of the raw TOML text
            let toml_text = std::fs::read_to_string(path)
                .unwrap_or_else(|_| format!("# could not read {path}\n# {cfg:?}"));

            Ok(PolicyHolder { config: cfg, toml_text })
        }
        Err(e) => {
            println!(
                "Failed to load policy at {} (using default_with_protocol): {e:?}",
                path
            );
            let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
            if let Err(e) = cfg.validate() {
                anyhow::bail!("Default policy validation failed: {e:?}");
            }
            let toml_text = format!("# default policy\n# {cfg:?}");
            Ok(PolicyHolder { config: cfg, toml_text })
        }
    }
}
