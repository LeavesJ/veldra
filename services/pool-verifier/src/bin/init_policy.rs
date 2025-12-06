use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use pool_verifier::policy::PolicyConfig; // adjust path if your policy module is not reexported
use rg_protocol::PROTOCOL_VERSION;

/// Simple helper to read a line and trim it
fn read_line(prompt: &str) -> io::Result<String> {
    print!("{prompt}: ");
    io::stdout().flush()?;

    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

/// Parse u64 with default if empty
fn read_u64_with_default(prompt: &str, default: u64) -> io::Result<u64> {
    let full = format!("{prompt} [{default}]");
    let s = read_line(&full)?;
    if s.is_empty() {
        Ok(default)
    } else {
        s.parse::<u64>().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid number: {e}"))
        })
    }
}

/// Parse u32 with default if empty
fn read_u32_with_default(prompt: &str, default: u32) -> io::Result<u32> {
    let full = format!("{prompt} [{default}]");
    let s = read_line(&full)?;
    if s.is_empty() {
        Ok(default)
    } else {
        s.parse::<u32>().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid number: {e}"))
        })
    }
}

fn main() -> anyhow::Result<()> {
    println!("Veldra pool verifier policy wizard");
    println!("This will create or overwrite policy.toml in the current directory\n");

    let path = Path::new("policy.toml");
    if path.exists() {
        println!("Warning: policy.toml already exists and will be overwritten");
        let answer = read_line("Type YES to continue or anything else to abort")?;
        if answer != "YES" {
            println!("Aborted");
            return Ok(());
        }
    }

    // Basic floors
    let min_total_fees = read_u64_with_default(
        "Minimum total fees in sats for any template (0 for none)",
        0,
    )?;

    let max_tx_count = read_u32_with_default(
        "Maximum number of transactions allowed in a template (0 for no limit)",
        0,
    )?;

    // Mempool thresholds in number of transactions
    println!("\nDynamic fee tiers based on mempool size (in number of transactions)");
    let low_mempool_tx = read_u64_with_default(
        "Low mempool upper bound (tx_count <= low is low tier)",
        500,
    )?;
    let high_mempool_tx = read_u64_with_default(
        "High mempool lower bound (tx_count >= high is high tier)",
        50_000,
    )?;

    // Fee floors in sats per tx for each tier
    println!("\nMinimum average fee per transaction (sats per tx) for each tier");
    let min_avg_fee_lo = read_u64_with_default(
        "Low tier min average fee (0 recommended for regtest)",
        0,
    )?;
    let min_avg_fee_mid = read_u64_with_default(
        "Mid tier min average fee",
        1_000,
    )?;
    let min_avg_fee_hi = read_u64_with_default(
        "High tier min average fee",
        5_000,
    )?;

    // Build config
    let mut cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
    cfg.min_total_fees = min_total_fees;
    cfg.max_tx_count = max_tx_count;
    cfg.low_mempool_tx = low_mempool_tx;
    cfg.high_mempool_tx = high_mempool_tx;
    cfg.min_avg_fee_lo = min_avg_fee_lo;
    cfg.min_avg_fee_mid = min_avg_fee_mid;
    cfg.min_avg_fee_hi = min_avg_fee_hi;

    // Validate with your existing validate()
    cfg.validate()?;

    // Serialize to TOML
    let toml = toml::to_string_pretty(&cfg)?;
    let mut file = File::create(path)?;
    file.write_all(toml.as_bytes())?;

    println!("\nWrote policy.toml:");
    println!("{toml}");

    Ok(())
}
