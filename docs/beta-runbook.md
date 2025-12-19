# Veldra Pool Verifier Beta Runbook

This runbook explains how to bring up the Veldra pool verifier stack, what each component does, how to interpret the dashboard, and how to run basic drills on regtest before touching a live pool.

---

## 1. Architecture at a glance

The prototype stack has three main pieces:

1. bitcoind or Stratum backend  

   - Either Bitcoin Core on regtest or testnet  
   - Or a Stratum v2 bridge that supplies candidate block templates  

2. template manager  

   - Pulls templates from the backend  
   - Wraps them into Veldra `TemplatePropose` messages  
   - Sends each template to the pool verifier over TCP JSON  
   - Logs templates and mempool snapshots for the dashboard  

3. pool verifier  

   - Loads `policy.toml` into an internal `PolicyConfig`  
   - For each proposed template, decides `Accept` or `Reject` plus a reason  
   - Logs every verdict along with fee tier information  
   - Serves an HTML dashboard and JSON endpoints for stats  

Very short chain:

bitcoind or Stratum source → template manager → pool verifier → dashboard and logs

---

## 2. Quickstart on regtest

This is the reference path that should always work on your development machine.

### 2.1 Prerequisites

- A Unix like environment  
- `bitcoind` installed and on `PATH`  
- Rust toolchain and `cargo` installed  
- `git` installed  

### 2.2 Start the full stack

From your repo root (the `Veldra` directory):

    cd Veldra
    ./scripts/dev-regtest.sh

The script does roughly the following:

1. Sets `ROOT_DIR` to the repo directory  
2. Starts `bitcoind` in regtest mode  
3. Ensures a wallet exists, currently named `veldra_wallet`  
4. Builds `pool-verifier` and `template-manager` in dev profile  
5. Starts `pool-verifier`  
6. Starts `template-manager`  
7. Wires them together for a closed regtest loop  

To stop the stack, interrupt the script in the terminal. The helper script also has cleanup logic that kills child processes. If any process survives, you can kill it manually or restart the script.

---

## 3. Configuration and environment

All service configuration is controlled through environment variables with a `VELDRA_` prefix plus `policy.toml`.

Key points:

- The regtest script already sets reasonable defaults.  
- For a real deployment you will edit that script or use your own systemd units with explicit `Environment=` lines.  

You do not need to guess exact variable names from memory. For each binary, from its service directory:

    cargo run -- --help

Use the help output and the `config` source files in each service to confirm the current list of environment variables and flags. New config will continue this pattern.

Things you will typically configure for a live pilot:

- Network selection such as `regtest`, `testnet`, `mainnet`.  
- RPC endpoint and credentials for Bitcoin Core if you use direct `getblocktemplate`.  
- Host and port for Stratum sources if you use a Stratum bridge.  
- Location of `policy.toml`.  
- Bind address and port for the verifier HTTP dashboard.  
- Log directory and log level.  

The exact variable names come from the code and help output. Treat those as the source of truth.

---

## 4. `policy.toml` and dynamic fee tiers

The verifier reads a policy file on startup. That file defines:

- General acceptance rules.  
- Dynamic fee tiers.  
- Other structural constraints that we add later.  

The current prototype supports dynamic fee tiers. Internally the policy includes values similar to:

- `min_avg_fee_lo`  
- `min_avg_fee_mid`  
- `min_avg_fee_hi`  

The verifier computes an `effective_min_avg_fee` for each template based on mempool conditions and the tier thresholds. That value is recorded in the verdict log as `min_avg_fee_used` along with the tier.

### 4.1 Location

Typical locations:

- For development, a `policy.toml` in the repo root or a `config` directory.  
- For production, a dedicated config path, mounted or managed by your ops tools.  

The verifier binary accepts a flag or environment variable pointing to this file. Confirm the exact configuration knob with `--help`.

### 4.2 Example schematic policy

This example shows the shape rather than exact field names. Use it as a mental model and adapt it to what your current `PolicyConfig` expects.

    [policy]
    name        = "default"
    description = "Baseline dynamic fee tier policy for Veldra"
    mode        = "regtest"  # or "live"

    [policy.fee_tiers]
    # Minimum average fee in sats per vbyte for each tier
    min_avg_fee_lo  = 1.0
    min_avg_fee_mid = 5.0
    min_avg_fee_hi  = 15.0

    [policy.mempool_tiers]
    # How the mempool size controls which fee tier is active
    lo_max_txs  = 5_000
    mid_max_txs = 50_000
    # above mid_max_txs, the high tier applies

    [policy.safety]
    max_weight_ratio       = 0.999
    reject_empty_templates = true

If your running build rejects this file on startup, read the error message and adjust the field names or structure until validation passes. The `PolicyConfig` type in the verifier code is the authoritative reference.

---

## 5. Dashboard overview

The pool verifier exposes a live HTML dashboard. The binary prints the listening address on startup, for example:

    HTTP server listening on http://127.0.0.1:8080

Visit that address in a browser. The page aggregates information from:

- Template verdict logs.  
- Mempool snapshots.  
- Policy metadata.  

You should expect several logical panels or cards.

### 5.1 Mode badge

At the top of the page you will see a badge that reflects the current operating mode. Examples:

- `regtest`  
- `sim`  
- `live`  

Treat that badge as a sanity check. When attached to a real pool you want that to match your intention.

### 5.2 Throughput and verdict counts

A throughput or summary card shows:

- Templates per second or per minute.  
- Total templates processed.  
- Accepted and rejected counts.  
- Possibly a moving window such as the last hundred templates.  

This tells you whether the verifier is keeping up with the template firehose and what fraction of templates fail policy.

### 5.3 Effective fee tier panel

This panel reflects the dynamic fee tier logic:

- Current mempool transaction count from `MempoolStats`.  
- Current active tier label, such as `low`, `mid`, `high`.  
- Corresponding `min_avg_fee_used` value in sats per vbyte.  
- The boundaries that separate tiers.  

If mempool size increases beyond a threshold, expect the active tier to jump and the minimum fee requirement to rise. If mempool drains, it should relax.

### 5.4 Latest verdict card

This card shows details for the most recent template:

- Timestamp.  
- Template identifier or hash, truncated.  
- Backend type, for example `bitcoind` or `stratum`.  
- Average fee per vbyte in the template.  
- Verdict: `Accept` or `Reject`.  
- Detailed reason code if rejected.  
- `min_avg_fee_used` and fee tier for the decision.  

Use this to spot obvious misconfigurations. If `min_avg_fee_used` is very high and almost everything is rejected, your policy is too strict for current mempool conditions.

### 5.5 Mempool panel with staleness indicator

The template manager takes periodic snapshots from `bitcoind` when it is using the `bitcoind` backend. The dashboard exposes:

- Transaction count.  
- Mempool size in bytes and optionally megabytes.  
- Age of the latest snapshot.  
- A staleness status such as `fresh`, `stale`, `dead`.  

Expected behavior:

- `fresh` means snapshots are recent and the mempool feed is healthy.  
- `stale` means snapshots are delayed and you should check connectivity to `bitcoind`.  
- `dead` means the verifier has not seen a usable mempool update in a long time.  

During a drill where you intentionally kill `bitcoind`, this card should move out of the `fresh` state and clearly communicate that templates are assessed with outdated or missing mempool information.

### 5.6 Recent templates table

A table lists the most recent templates.

Columns typically include:

- Time.  
- Template id or hash prefix.  
- Backend name.  
- Average fee per vbyte.  
- Fee tier used.  
- Verdict.  
- Reason.  

Look here for patterns. For example:

- If many consecutive templates are rejected for `fee_too_low` during a congested period, the policy is doing its job.  
- If rejections are due to unexpected reasons, such as a weight limit that seems wrong, you may have a bug or misconfigured threshold.  

### 5.7 Aggregate stats by reason and by tier

The stats endpoint feeds an aggregate view that the dashboard renders. It counts:

- Verdict reasons such as `ok`, `fee_too_low`, `policy_error`.  
- Templates per fee tier, to show how often each tier is active.  

Use these aggregates in two ways:

- As a health check: templates should fall into expected buckets.  
- As feedback for policy adjustment: if the high tier is active most of the time, your thresholds for mempool congestion may be too conservative.  

---

## 6. Regtest drills

Before plugging into any real pool infrastructure, run these drills until they feel boring.

### 6.1 Basic bring up and block generation

1. Start the stack:

       cd Veldra
       ./scripts/dev-regtest.sh

2. In another terminal, create a fresh address from the regtest wallet:

       bitcoin-cli -regtest -rpcwallet=veldra_wallet getnewaddress

3. Mine 101 blocks to mature coinbase:

       bitcoin-cli -regtest -rpcwallet=veldra_wallet generatetoaddress 101 "<address>"

4. Watch the dashboard.

   - The mode badge should show a regtest mode.  
   - Templates and verdicts should start to appear.  
   - Mempool should be mostly empty and in a relaxed fee tier.  

### 6.2 Mempool congestion drill

1. Use the same wallet to create many small transactions:

       for i in $(seq 1 50); do
         bitcoin-cli -regtest -rpcwallet=veldra_wallet sendtoaddress "<address>" 0.1
       done

2. Do not mine blocks for a short while. Let the mempool fill.

3. Watch the dashboard.

   - Mempool transaction count should increase.  
   - The active fee tier may climb from low to mid or high.  
   - If your policy sets strict `min_avg_fee` for the higher tiers, some templates should start to fail for `fee_too_low` reasons.  

4. Mine a few more blocks and confirm that the mempool drains and the fee tier relaxes again.

### 6.3 Bitcoind failure and recovery drill

1. Start the stack normally. Confirm that mempool status is fresh.  

2. Kill `bitcoind` manually:

       pkill -f bitcoind

3. Keep the verifier and template manager running. The dashboard should show:

   - Mempool staleness climbing.  
   - A transition from fresh to stale or worse.  

4. Restart `bitcoind` and let the stack reconnect. Confirm that:

   - New mempool snapshots appear.  
   - Staleness drops back to normal.  
   - The verifier continues to process templates after recovery.  

This drill verifies that the retry and reconnection logic behaves correctly from an operator perspective.

### 6.4 Policy sensitivity drill

1. Open `policy.toml` and change the high tier minimum fee to an absurdly high value, for example:

       min_avg_fee_hi = 1000.0

2. Restart the verifier so it reloads the policy.  

3. Repeat the mempool congestion drill. Observe that when the high tier activates almost all templates are rejected for `fee_too_low`.  

4. Restore reasonable values and restart.  

This builds intuition for how policy settings change system behavior.

---

## 7. Notes for future production pilots

For a pool pilot, you will adjust these aspects beyond the regtest script.

### 7.1 Network and backend

- Decide on `testnet` or a small subset of mainnet hashpower for early trials.  
- Choose whether template manager talks directly to `bitcoind` with `getblocktemplate` or to a Stratum v2 bridge that receives candidate templates from your existing infrastructure.  

### 7.2 Policy management

- Keep `policy.toml` in version control.  
- Treat it like any other production config.  
- Require code review for policy changes once money is at stake.  

### 7.3 Deployment and observability

- Package each service as a systemd unit or container image.  
- Feed the JSON stats endpoints into your observability stack.  
- Set alerts for:

  - Mempool staleness.  
  - Template backlog.  
  - Unexpected spikes in rejection rates.  
  - Dashboard unavailability.  

Once this runbook matches what you see locally, it becomes the baseline document that an external pool operator can follow for a beta deployment, with only pool specific wiring changed.
