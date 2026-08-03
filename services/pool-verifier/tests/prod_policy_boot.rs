//! Boot-outcome tests for the shipped `deploy/policy-prod.toml`.
//!
//! `deploy/policy-prod.toml` is the file `docker-compose.setup-b.yml`
//! mounts at `/config/policy-prod.toml` on the Class M soak node, and
//! it ships `[policy.mempool] enforce = true` next to a placeholder
//! `rpc_url`. A placeholder is a non-empty string, so an emptiness
//! check passes it, the mempool view is never built, and the verifier
//! reports healthy while checking nothing. Invariant 4: a config
//! default that validates but cannot work is worse than a missing key,
//! because a missing key fails loudly at boot.
//!
//! These tests assert the boot outcome of the real binary, not an
//! internal predicate.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Repo-root-relative path to a shipped deploy artifact.
fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

/// Scratch cwd so the binary's `data/` bootstrap never dirties the
/// working tree. Removed on drop even when the test panics.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("rg-{label}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Boot the real `pool-verifier` against `policy_path` and report
/// whether it exited on its own, plus whatever it wrote to stderr.
/// Kills the child if it is still running at the deadline, so a
/// regression leaks neither a process nor a bound port.
fn boot_outcome(policy_path: &Path, tcp_port: u16, http_port: u16) -> (Option<i32>, String) {
    let scratch = ScratchDir::new("prodpolicy");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pool-verifier"))
        .current_dir(&scratch.path)
        .env("VELDRA_POLICY_FILE", policy_path)
        .env("VELDRA_VERIFIER_ADDR", format!("127.0.0.1:{tcp_port}"))
        .env("VELDRA_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
        .env("VELDRA_API_SECRET_OPTIONAL", "1")
        .env("VELDRA_VERIFIER_CONFIG", scratch.path.join("verifier.toml"))
        .env("VELDRA_LOG_FILTER", "info")
        .env_remove("VELDRA_BITCOIND_RPC_PASS")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pool-verifier");

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };

    let output = child.wait_with_output().expect("collect child output");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (status.and_then(|s| s.code()), stderr)
}

/// The shipped production policy carries `enforce = true` with a
/// `TODO_SET_*` `rpc_url`. Starting in that state gives an operator a
/// verifier that answers `/health`, climbs `verdicts_total`, and runs
/// no Class M check at all. Startup must fail instead.
#[test]
fn shipped_prod_policy_with_placeholder_rpc_url_fails_boot() {
    let policy = repo_path("deploy/policy-prod.toml");
    assert!(
        policy.exists(),
        "deploy/policy-prod.toml missing at {}",
        policy.display()
    );

    let (code, stderr) = boot_outcome(&policy, 39_231, 39_232);

    assert_eq!(
        code,
        Some(1),
        "verifier must exit non-zero on a placeholder rpc_url with enforce = true; \
         stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("rpc_url"),
        "the boot failure must name the offending key; stderr was:\n{stderr}"
    );
}
