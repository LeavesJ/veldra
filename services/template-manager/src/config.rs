use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct TemplateManagerConfig {
    /// "bitcoind" or "stratum"
    pub backend: String,

    /// RPC URL for bitcoind when backend == "bitcoind"
    pub rpc_url: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_pass: Option<String>,

    /// Stratum endpoint like "127.0.0.1:3333" when backend == "stratum"
    pub stratum_addr: Option<String>,

    /// Some auth token or username for Stratum if needed
    pub stratum_auth: Option<String>,

    /// Poll interval seconds
    pub poll_interval_secs: Option<u64>,
}

impl TemplateManagerConfig {
    pub fn from_path<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let cfg: TemplateManagerConfig = toml::from_str(&contents)?;
        Ok(cfg)
    }
}
