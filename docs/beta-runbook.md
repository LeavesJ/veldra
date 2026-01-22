# Veldra Pool Verifier Runbook (v0.2.0)

This runbook explains how to bring up the Veldra pool verifier stack, what each component does, how to interpret the dashboard, and how to run basic drills on regtest before touching any live pool infrastructure.

---

## 1. Architecture at a glance

The v0.2.0 prototype stack has three main pieces:

1. Backend template source

   - Regtest: Bitcoin Core (bitcoind) provides candidate templates and mempool snapshots.
   - Stratum synthetic mode: an sv2 bridge emits synthetic templates over a local Stratum style endpoint.

2. Template manager

   - Pulls templates from the backend
   - Wraps each template into a Veldra `TemplatePropose` message
   - Sends each template to the pool verifier over TCP JSON
   - Exposes HTTP endpoints for health, recent templates, and mempool snapshots (backend dependent)

3. Pool verifier

   - Loads a policy TOML into an internal `PolicyConfig`
   - For each proposed template, decides `Accept` or `Reject`
   - Emits stable, machine readable `reason_code` plus a human oriented `reason_detail`
   - Logs verdicts for auditability and serves an operator dashboard and HTTP APIs

Very short chain:

backend source → template manager → pool verifier → dashboard and logs

---

## 2. Quickstart on regtest

This is the reference path and should be the default for local development.

### 2.1 Prerequisites

- Unix like environment
- `bitcoind` and `bitcoin-cli` installed and on `PATH`
- Rust toolchain and `cargo`
- `git`

### 2.2 Start the full stack

From repo root:

    ./scripts/dev-regtest.sh

What the script does:

1. Starts `bitcoind` in regtest mode using a dedicated demo datadir
2. Ensures a wallet exists (default name: `veldra_wallet`)
3. Waits for RPC readiness
4. Builds `pool-verifier` and `template-manager` (dev profile)
5. Starts `pool-verifier` (HTTP and TCP)
6. Starts `template-manager` (bitcoind backend)
7. Mines initial blocks so demo scripts can spend immediately

Stop the stack by interrupting the script. It terminates child processes and stops the regtest bitcoind instance for the demo datadir.

### 2.3 Demo traffic scripts

After `dev-regtest.sh` is running, choose one:

Deterministic staged outcomes:

    ./scripts/dev-demo-phases.sh

Continuous noisy mempool dynamics:

    ./scripts/dev-traffic.sh

Manual regtest interaction uses the wrapper:

    ./scripts/dev-bitcoin-cli.sh getbalance

---

## 3. Quickstart in Stratum synthetic mode

This path runs without bitcoind templates. It is meant for synthetic Stratum style template flow and verifier UI testing.

Start:

    ./scripts/dev-stratum.sh

This brings up:

- `pool-verifier` (HTTP + TCP)
- `sv2-bridge` (synthetic template source)
- `template-manager` in Stratum backend mode

Regtest traffic scripts do not apply in this mode. Load is controlled by the bridge parameters and the manager Stratum config.

---

## 4. Configuration and environment

The stack is configured through `VELDRA_` environment variables plus a policy TOML.

### 4.1 Pool verifier env vars

Common knobs:

- `VELDRA_HTTP_ADDR`  
  Dashboard and HTTP API bind, e.g. `127.0.0.1:8080`

- `VELDRA_VERIFIER_ADDR`  
  TCP JSON bind for verifier requests, e.g. `127.0.0.1:5001`

- `VELDRA_POLICY_FILE`  
  Absolute path to the policy TOML

- `VELDRA_MEMPOOL_URL`  
  Mempool stats source URL (typically the template manager `/mempool` endpoint)  
  In Stratum synthetic mode you can set this to empty to disable mempool dependency.

- `VELDRA_DASH_MODE`  
  Mode badge string displayed in the dashboard

Treat the service `config.rs` plus `--help` output as authoritative for the exact config set.

### 4.2 Template manager env vars

Common knobs:

- `VELDRA_MANAGER_CONFIG`  
  Absolute path to manager TOML config

- `VELDRA_MANAGER_HTTP_ADDR`  
  Manager HTTP bind, e.g. `127.0.0.1:8081`

- `VELDRA_VERIFIER_ADDR`  
  Verifier TCP address to send `TemplatePropose` to

### 4.3 sv2 bridge env vars (Stratum synthetic mode)

Common knobs:

- `VELDRA_BRIDGE_ADDR`  
  Bridge bind, e.g. `127.0.0.1:3333`

Other bridge parameters are defined in `services/sv2-bridge`. Use that service’s help output or source as the reference.

---

## 5. Policy TOML (v0.2.0 flat schema)

The verifier reads a policy TOML at startup. v0.2.0 uses a flat schema under a single `[policy]` table.

Key semantics:

- `protocol_version` is an explicit compatibility boundary and must match the running build.
- Dynamic fee tiers compute an effective minimum average fee per template based on mempool conditions and tier thresholds.
- Degraded mode when mempool stats are missing is controlled by `unknown_mempool_as_high`.
- `reject_coinbase_zero` allows optional enforcement of coinbase value sanity checks.

### 5.1 Canonical policy shape

Example policy (shape matches v0.2.0):

    [policy]
    protocol_version = 2
    required_prevhash_len = 64

    min_total_fees = 0
    max_tx_count = 10000
    min_avg_fee = 0

    low_mempool_tx = 5
    high_mempool_tx = 20

    tx_count_mid_threshold = 0
    tx_count_hi_threshold = 50

    min_avg_fee_lo = 5
    min_avg_fee_mid = 15
    min_avg_fee_hi = 20

    max_weight_ratio = 0.999
    reject_empty_templates = true

    unknown_mempool_as_high = true
    reject_coinbase_zero = false

If the verifier rejects your policy at startup, the error message is authoritative. Fix the field names or values until the policy validates.

### 5.2 Policy profiles in `config/`

Recommended minimal set:

- `config/policy.toml`  
  Default baseline policy

- `config/demo-showcase-policy.toml`  
  Tuned for `dev-demo-phases.sh` outcomes

Optional profiles if you actively use them:

- `config/demo-open-policy.toml`  
  Permissive baseline throughput and UI

- `config/demo-strict-policy.toml`  
  Deliberately strict to demonstrate rejects under stress

---

## 6. Dashboard and HTTP endpoints

The pool verifier serves an HTML dashboard and HTTP endpoints. When running locally, the verifier prints its bind address, for example:

    HTTP server listening on http://127.0.0.1:8080

### 6.1 Mode badge

The dashboard shows a mode badge such as `regtest` or `stratum-synthetic`. Treat this as a deployment sanity check.

### 6.2 Throughput and verdict counts

Expect a summary section showing:

- Total templates processed
- Accept and reject counts
- Recent activity window, depending on the current UI

This indicates whether the verifier is keeping up and whether policy is overly strict.

### 6.3 Latest verdict detail

The latest verdict section typically includes:

- Template id or fingerprint prefix
- Backend type (bitcoind or Stratum)
- Template average fee
- Verdict decision: Accept or Reject
- `reason_code` (stable machine readable label)
- `reason_detail` (human oriented detail)
- Fee tier and effective fee requirement used for the decision

### 6.4 Mempool panel and staleness

In regtest bitcoind mode, template manager provides periodic mempool snapshots. The dashboard reflects:

- Mempool tx count and size
- Snapshot age
- Staleness indicator

Healthy: snapshots update frequently. If snapshots stall, the staleness indicator should trend toward stale or dead, and tier decisions should follow degraded mode logic.

### 6.5 Recent templates table

A table of recent templates is used to spot patterns:

- Repeated rejects by the same `reason_code`
- Tier transitions correlating with mempool growth
- Differences between bitcoind and Stratum sourced templates

### 6.6 Aggregate stats

The stats aggregation is designed to be stable:

- Buckets prefer `reason_code` first
- Falls back to legacy `reason` only if required
- Keeps metrics stable across wording changes

### 6.7 Bounded export endpoints

The verifier provides bounded exports for operator safety:

- `/verdicts/log?tail=N` returns the last N log lines and is hard capped to prevent huge responses
- `/verdicts.csv?limit=N` returns a bounded CSV export

Exact caps are enforced by the server.

---

## 7. Regtest drills

Run these drills until the behavior is boring and predictable.

### 7.1 Basic bring up and sanity

1. Start the stack:

       ./scripts/dev-regtest.sh

2. Open the dashboard:

       http://127.0.0.1:8080

3. Confirm:

   - Mode badge shows regtest mode
   - Templates and verdicts appear
   - Mempool feed is present and not stale

### 7.2 Deterministic staged demo

1. Start regtest stack in one terminal:

       ./scripts/dev-regtest.sh

2. In another terminal, run:

       ./scripts/dev-demo-phases.sh

3. Observe:

   - Empty mempool behavior (policy dependent)
   - Fee based rejects under low fee batches
   - Accepts under high fee batches (if policy thresholds are tuned accordingly)
   - Tier transitions under larger load
   - Tx count rejects if demo policy constrains `max_tx_count`

### 7.3 Noisy mempool dynamics drill

1. Start regtest stack:

       ./scripts/dev-regtest.sh

2. Run continuous traffic:

       ./scripts/dev-traffic.sh

3. Observe:

   - Mempool growth and partial clearing
   - Tier transitions and corresponding `min_avg_fee` enforcement
   - Stable aggregation by `reason_code`

### 7.4 Backend failure and recovery drill (regtest)

This drill checks staleness visibility and degraded mode behavior.

1. Start regtest stack and confirm mempool is fresh.

2. Kill bitcoind for the demo datadir (method depends on your script implementation).

3. Observe:

   - Mempool staleness increases
   - Tier selection uses `unknown_mempool_as_high` behavior

4. Restart the stack and confirm:

   - Mempool snapshots resume
   - Staleness returns to fresh
   - Templates continue to be processed

### 7.5 Policy sensitivity drill

1. Increase fee thresholds in the active policy:

   - Raise `min_avg_fee_hi` above typical demo fees

2. Restart the verifier so it reloads policy.

3. Run a congestion or staged demo and confirm:

   - Rejections move into fee related `reason_code` buckets
   - Stats aggregation remains stable

4. Restore reasonable values and restart.

---

## 8. Notes for future production pilots

### 8.1 Network and backend

- Choose testnet or a controlled mainnet slice for early trials.
- Decide whether template manager should pull from bitcoind or receive templates via Stratum v2 infrastructure.

### 8.2 Policy management discipline

- Keep policy TOMLs in version control.
- Require review for policy changes once incentives are real.
- Track policy changes as releases, not ad hoc edits.

### 8.3 Deployment and observability

For a pilot:

- Package services as systemd units or containers.
- Monitor:
  - Mempool feed staleness
  - Template processing rate
  - Reject rates by `reason_code`
  - Dashboard availability
- Alert on:
  - sustained staleness
  - spikes in rejects
  - sustained drop in throughput
