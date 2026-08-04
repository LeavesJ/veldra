use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader as StdBufReader, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use pool_verifier::second_chance::MempoolAdjudicationRecord;
use reservegrid_common::DeployMode;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Represents a single verdict logged to memory and disk.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoggedVerdict {
    pub(crate) log_id: u64,
    pub(crate) template_id: u64,
    pub(crate) height: u32,
    pub(crate) total_fees: u64,
    pub(crate) tx_count: u32,
    pub(crate) accepted: bool,

    // Back-compat + UI
    pub(crate) reason: Option<String>,

    // New structured fields (old NDJSON lines will still parse)
    #[serde(default)]
    pub(crate) reason_code: Option<String>,
    #[serde(default)]
    pub(crate) reason_detail: Option<String>,

    pub(crate) timestamp: u64,

    pub(crate) min_avg_fee_used: u64,
    pub(crate) fee_tier: String, // "low" | "mid" | "high"
    #[serde(default)]
    pub(crate) tier_source: String, // "measured" | "fallback"
    pub(crate) avg_fee_sats_per_tx: u64,

    // v0.2.2 consensus safety fields
    #[serde(default)]
    pub(crate) template_weight: Option<u64>,
    #[serde(default)]
    pub(crate) total_sigops: Option<u32>,
    #[serde(default)]
    pub(crate) coinbase_sigops: Option<u32>,
    #[serde(default)]
    pub(crate) created_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub(crate) safety_warnings: Vec<String>,

    /// PB-40: what bitcoind said about the transactions the polled
    /// mempool view did not contain, captured at rejection time.
    ///
    /// `None` for every template Class M did not reject, which is
    /// almost all of them. Present, it is the ONLY adjudicable record
    /// of the rejection: re-querying these txids days later reports
    /// them absent whether or not they were ever real, because the
    /// mempool tail churns within minutes. Absent this field a T+7
    /// review scores every rejection a true positive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mempool_adjudication: Option<MempoolAdjudicationRecord>,
}

/// Statistics response for the API.
#[derive(Serialize)]
pub(crate) struct StatsResponse {
    pub(crate) total: u64,
    pub(crate) accepted: u64,
    pub(crate) rejected: u64,
    pub(crate) by_reason: BTreeMap<String, u64>,
    pub(crate) by_tier: BTreeMap<String, u64>,
    pub(crate) last: Option<LoggedVerdict>,
}

/// Shared verdict log in memory.
pub(crate) type VerdictLog = Arc<Mutex<Vec<LoggedVerdict>>>;

/// Shared log ID counter.
pub(crate) type LogIdCounter = Arc<AtomicU64>;

/// Deploy mode for verdict persistence.
pub(crate) static DEPLOY_MODE: OnceLock<DeployMode> = OnceLock::new();

/// Track count of verdict write errors.
pub(crate) static LOG_WRITE_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Last time mempool was successfully contacted.
pub(crate) static LAST_MEMPOOL_OK_UNIX: AtomicU64 = AtomicU64::new(0);

/// Path to the verdict log file on disk.
pub(crate) const VERDICT_LOG_PATH: &str = "data/verdicts.log";

/// Maximum size of a single verdict log file before rotation.
pub(crate) const VERDICT_LOG_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// Number of rotated verdict log files to keep.
pub(crate) const VERDICT_LOG_ROTATIONS: usize = 5;

/// Default maximum entries in the in-memory verdict log.
pub(crate) const DEFAULT_VERDICT_LOG_MAX_ENTRIES: usize = 1000;

/// Resolve the in-memory verdict log max entries from env or default.
pub(crate) fn verdict_log_max_entries() -> usize {
    std::env::var("VELDRA_VERDICT_LOG_MAX_ENTRIES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_VERDICT_LOG_MAX_ENTRIES)
}

/// Load verdicts from disk into memory.
pub(crate) fn load_verdict_log() -> (VerdictLog, LogIdCounter) {
    let mut list = Vec::new();
    let mut max_id = 0u64;

    if let Ok(file) = File::open(VERDICT_LOG_PATH) {
        let reader = StdBufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<LoggedVerdict>(line) {
                max_id = max_id.max(v.log_id);
                list.push(v);
            }
        }
    }

    // Cap to configured max entries on load (FIFO eviction of oldest).
    let max_entries = verdict_log_max_entries();
    if list.len() > max_entries {
        let excess = list.len() - max_entries;
        list.drain(0..excess);
    }

    let log = Arc::new(Mutex::new(list));
    let counter = Arc::new(AtomicU64::new(max_id + 1));
    (log, counter)
}

/// Rotate verdict log if it exceeds max size.
pub(crate) fn rotate_verdict_log_if_needed() {
    let Ok(meta) = std::fs::metadata(VERDICT_LOG_PATH) else {
        return;
    };

    if meta.len() < VERDICT_LOG_MAX_BYTES {
        return;
    }

    for i in (1..=VERDICT_LOG_ROTATIONS).rev() {
        let src = if i == 1 {
            VERDICT_LOG_PATH.to_string()
        } else {
            format!("{VERDICT_LOG_PATH}.{}", i - 1)
        };
        let dst = format!("{VERDICT_LOG_PATH}.{i}");

        // Skip exists() check to avoid TOCTOU; try rename directly.
        if let Err(e) = std::fs::remove_file(&dst)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(dst, error = %e, "verdict log rotation: remove_file failed");
        }
        match std::fs::rename(&src, &dst) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // src does not exist for this rotation slot, expected.
            }
            Err(e) => {
                warn!(src, dst, error = %e, "verdict log rotation: rename failed");
            }
        }
    }
}

/// Append a verdict to the disk log, respecting deploy mode.
pub(crate) fn append_verdict_to_disk(v: &LoggedVerdict) {
    let mode = DEPLOY_MODE.get().copied().unwrap_or(DeployMode::Shadow);
    if !mode.persist_verdicts() {
        return;
    }

    let res = (|| {
        rotate_verdict_log_if_needed();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(VERDICT_LOG_PATH)?;

        let line = serde_json::to_string(v)?;
        writeln!(file, "{line}")?;

        file.flush()?;
        file.sync_data()?;

        Ok::<(), anyhow::Error>(())
    })();

    if let Err(e) = res {
        let errors = LOG_WRITE_ERRORS.fetch_add(1, Ordering::Relaxed) + 1;
        // PB-40: this used to bump the counter and return. On the
        // Setup B node `data/verdicts.log` was root-owned, so every
        // append failed, silently, for weeks: the file sat stale from
        // 2026-06-08 while the process reported healthy and the
        // operator had no way to know the durable verdict record had
        // stopped. Invariant 3 forbids a durability write that
        // swallows its error, and this is the log the PB-40 evidence
        // is written to, so the failure has to be loud where it
        // happens.
        warn!(
            error = %e,
            path = VERDICT_LOG_PATH,
            log_write_errors = errors,
            log_id = v.log_id,
            "verdict durability write FAILED; this verdict is not on disk. Check that the \
             path exists and is writable by the verifier's uid"
        );
    }
}

/// Get current timestamp in seconds since `UNIX_EPOCH`.
pub(crate) fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Get current timestamp in milliseconds since `UNIX_EPOCH`.
pub(crate) fn current_timestamp_ms() -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}
