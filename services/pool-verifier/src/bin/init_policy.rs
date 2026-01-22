use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use anyhow::Result;

use pool_verifier::policy::PolicyConfig;
use rg_protocol::PROTOCOL_VERSION;

fn read_line(prompt: &str) -> io::Result<String> {
    print!("{prompt}: ");
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

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

fn read_bool_with_default(prompt: &str, default: bool) -> io::Result<bool> {
    let full = format!("{prompt} [{}]", if default { "Y" } else { "N" });
    let s = read_line(&full)?.to_ascii_lowercase();
    if s.is_empty() {
        Ok(default)
    } else {
        Ok(matches!(s.as_str(), "y" | "yes" | "true" | "1"))
    }
}

#[derive(serde::Serialize)]
struct Wrapper<'a> {
    policy: &'a PolicyConfig,
}

fn main() -> Result<()> {
    println!("Veldra pool verifier policy wizard");
    println!("This will create or overwrite config/policy.toml\n");

    std::fs::create_dir_all("config")?;
    let path = Path::new("config/policy.toml");

    if path.exists() {
        println!("Warning: config/policy.toml already exists and will be overwritten.");
        println!("Type YES to continue.");
        let answer = read_line("Confirm")?;
        if answer != "YES" {
            println!("Aborted");
            return Ok(());
        }
    }

    let min_total_fees = read_u64_with_default(
        "Minimum total fees in sats for any template (0 for none)",
        0,
    )?;

    let max_tx_raw = read_u32_with_default("Maximum number of transactions (0 = unlimited)", 0)?;
    let max_tx_count = if max_tx_raw == 0 {
        u32::MAX
    } else {
        max_tx_raw
    };

    println!("\nDynamic fee tiers based on mempool size (tx count)");
    let mut low_mempool_tx = read_u64_with_default("Low tier upper bound (tx < low)", 1_000)?;
    let mut high_mempool_tx = read_u64_with_default("High tier lower bound (tx ≥ high)", 5_000)?;
    if high_mempool_tx < low_mempool_tx {
        std::mem::swap(&mut low_mempool_tx, &mut high_mempool_tx);
    }

    println!("\nMinimum average fee per transaction (sats per tx) for each tier");
    let min_avg_fee_lo = read_u64_with_default("Low tier floor", 0)?;
    let min_avg_fee_mid = read_u64_with_default("Mid tier floor", 1_000)?;
    let min_avg_fee_hi = read_u64_with_default("High tier floor", 5_000)?;

    let unknown_mempool_as_high = read_bool_with_default(
        "If mempool backend is unavailable, treat tier as high",
        true,
    )?;

    let reject_coinbase_zero =
        read_bool_with_default("Reject coinbase_value == 0 for non empty templates", false)?;

    let reject_empty_templates =
        read_bool_with_default("Reject empty templates (tx_count == 0)", true)?;

    let mut cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);

    cfg.min_total_fees = min_total_fees;
    cfg.max_tx_count = max_tx_count;
    cfg.low_mempool_tx = low_mempool_tx;
    cfg.high_mempool_tx = high_mempool_tx;
    cfg.min_avg_fee_lo = min_avg_fee_lo;
    cfg.min_avg_fee_mid = min_avg_fee_mid;
    cfg.min_avg_fee_hi = min_avg_fee_hi;

    cfg.unknown_mempool_as_high = unknown_mempool_as_high;
    cfg.reject_coinbase_zero = reject_coinbase_zero;
    cfg.reject_empty_templates = reject_empty_templates;

    cfg.validate()?;

    let toml_text = toml::to_string_pretty(&Wrapper { policy: &cfg })?;
    let mut file = File::create(path)?;
    file.write_all(toml_text.as_bytes())?;
    file.sync_all()?;

    println!("\nWrote config/policy.toml:\n{toml_text}");

    Ok(())
}
