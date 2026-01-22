# Veldra — ReserveGrid OS

**ReserveGrid OS** is Veldra’s policy driven verification layer for Bitcoin mining pools. It inspects candidate block templates against an operator defined policy and returns an **ACCEPT** or **REJECT** verdict with a machine readable reason code and policy context, plus an operator facing dashboard for observability.

This repository is a **beta prototype** optimized for legibility and fast evaluation. It is designed to be swapped into a pool pipeline with minimal ceremony.

---

## Demo and repo links
- **Repo:** https://github.com/LeavesJ/veldra
- **Website:** https://veldra.org
- **Contact (personal):** jarrondeng@gmail.com
- **Contact (work):** jarrondeng@veldra.org

---

## What ReserveGrid OS does
- Evaluates candidate block templates against a configurable `policy.toml`
- Returns a verdict over a simple TCP line delimited JSON protocol: `TemplatePropose -> TemplateVerdict`
- Logs verdicts to disk as NDJSON for audit and debugging
- Provides an operator dashboard with:
  - throughput and accept rate
  - dynamic fee tier behavior driven by mempool conditions
  - aggregates by reject reason code and tier
  - current active policy view and policy validation errors
  - bounded exports for logs and CSV

---

## What ReserveGrid OS does not do
- It does not mine blocks
- It does not replace a pool payout system
- It does not force policy on chain
- It is not a consensus change
- It is not a custody product

ReserveGrid OS is an ops layer control surface. Pools remain in control.

---

## Services
ReserveGrid OS consists of two services plus shared protocol types.

### 1. pool verifier
- TCP server that receives `TemplatePropose` and returns `TemplateVerdict`
- HTTP server for dashboard and operator endpoints
- Loads an initial policy from TOML and holds the active policy in memory
- Emits stable, machine readable reject reason codes with supporting policy context

### 2. template manager
- Fetches templates from a backend and forwards them to the verifier
- Backends:
  - `bitcoind` via `getblocktemplate` (regtest demo path)
  - `stratum` via a local bridge that emits `TemplatePropose` as line delimited JSON
- Exposes a small HTTP endpoint for mempool stats used by the verifier tier logic
- Uses an HTTP bind as a single instance lock to prevent duplicate senders

### 3. rg protocol
- Shared protocol structs and versioning
- `TemplatePropose` and `TemplateVerdict` message types
- Protocol version constant used across services

---

## Repository layout
- `services/pool-verifier/`
  - `src/main.rs` (HTTP dashboard, TCP server, bounded exports)
  - `src/policy.rs` (PolicyConfig, validation, evaluation, reason codes)
  - `src/state.rs` (shared app state and policy holder)
  - `data/` (verdict logs at runtime, excluded from git)
- `services/template-manager/`
  - `src/main.rs` (backends, manager loop, HTTP server)
  - `src/config.rs` (manager config)
  - `manager.toml` (example config)
- `services/rg-protocol/`
  - shared message structs and protocol versioning
- `config/`
  - `beta-policy.toml` (example policy file used in regtest)
- `scripts/`
  - `dev-regtest.sh` (start the full stack)
  - `dev-traffic.sh` (optional traffic generator, if present)
  - `clear-verdicts.sh` (optional log cleanup)

---

## Architecture overview
High level flow:

    (bitcoind or stratum bridge)
              |
              v
       template-manager
       (fetch templates)
              |
              |  TCP line delimited JSON: TemplatePropose
              v
         pool-verifier  -------->  HTTP dashboard (/)
         (evaluate)              HTTP API (/stats, /policy, exports)
              |
              |  TCP line delimited JSON: TemplateVerdict
              v
    (template-manager accepts or rejects upstream)

Where this sits in a real pool:
- Between the pool template source and the pool job distribution system
- Or as a sidecar gate that must approve templates before jobs are published to miners

---

## Quickstart

### 1. Prerequisites
- Rust toolchain (stable)
- `bitcoind` and `bitcoin-cli` installed locally
- macOS or Linux recommended for the scripts

### 2. Build
From repo root:

    cargo build

Or build services individually:

    cd services/pool-verifier && cargo build
    cd services/template-manager && cargo build

---

## 3. Run the regtest demo

### 3.1 One command start
From repo root:

    ./scripts/dev-regtest.sh

Expected behavior:
1. Starts `bitcoind` in regtest mode
2. Ensures a regtest wallet exists
3. Builds `pool-verifier` and `template-manager`
4. Starts `pool-verifier`
   - HTTP at `127.0.0.1:8080`
   - TCP at `127.0.0.1:5001`
5. Starts `template-manager`
   - HTTP at `127.0.0.1:8081`
6. Optional traffic generator patterns depending on your script version

### 3.2 Open the dashboard
Open:

- http://127.0.0.1:8080

You should see:
- throughput increasing
- recent templates updating
- aggregates changing as accepts and rejects happen

### 3.3 Manual run

#### 3.3.1 Start bitcoind (regtest)
    bitcoind -regtest \
      -server=1 \
      -rpcuser=veldra \
      -rpcpassword=very_secure_password \
      -rpcport=18443 \
      -fallbackfee=0.0001 \
      -maxmempool=300

#### 3.3.2 Start template manager
    cd services/template-manager

    export VELDRA_MANAGER_HTTP_ADDR="127.0.0.1:8081"
    export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"
    export VELDRA_MANAGER_CONFIG="./manager.toml"

    cargo run

#### 3.3.3 Start pool verifier
    cd services/pool-verifier
    mkdir -p data

    export VELDRA_HTTP_ADDR="127.0.0.1:8080"
    export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"
    export VELDRA_MEMPOOL_URL="http://127.0.0.1:8081/mempool"
    export VELDRA_DASH_MODE="regtest-bitcoind"
    export VELDRA_POLICY_FILE="../../config/beta-policy.toml"

    cargo run

#### 3.3.4 Sanity checks
    curl -s "http://127.0.0.1:8080/health"
    curl -s "http://127.0.0.1:8080/meta"
    curl -s "http://127.0.0.1:8080/policy"
    curl -s "http://127.0.0.1:8080/stats"

---

## 4. Policy management

### 4.1 Policy file
The verifier reads an initial policy from:

- `VELDRA_POLICY_FILE` (path to a TOML file)

On startup:
- the policy is parsed
- validated
- installed as the active policy
- the verifier refuses to run if validation fails

### 4.2 Dynamic fee tiers
ReserveGrid OS supports dynamic fee tiers:
- the verifier fetches mempool tx count from `VELDRA_MEMPOOL_URL` (template-manager endpoint)
- it selects a tier based on thresholds
- it applies the tier specific fee floor

Degraded mode behavior:
- when mempool fetch fails, the verifier chooses a conservative tier based on `unknown_mempool_as_high`

### 4.3 Policy wizard
The dashboard includes a policy wizard that:
- edits tier thresholds and fee floors
- generates TOML
- can optionally apply policy live (if enabled in your build)

Intended apply flow:
1. Parse TOML into `PolicyConfig`
2. Validate
3. Swap into shared state
4. Subsequent verdicts use the new policy

---

## 5. Policy schema
`PolicyConfig` is the source of truth. Example shape:

    [policy]
    protocol_version = 2
    required_prevhash_len = 64

    min_avg_fee_lo  = 1
    min_avg_fee_mid = 2000
    min_avg_fee_hi  = 5000

    low_mempool_tx  = 0
    high_mempool_tx = 50

    min_total_fees = 0
    max_tx_count   = 10000

    reject_empty_templates = true
    max_weight_ratio = 0.999

    unknown_mempool_as_high = true
    reject_coinbase_zero = true

Notes:
- In this prototype, “avg fee” is computed as `total_fees / tx_count` (sats per tx)
- If `tx_count == 0`, avg fee is treated as 0 unless you reject empty templates

---

## 6. HTTP API
Base: http://127.0.0.1:8080

Common endpoints:
- `/`  
  HTML dashboard
- `/health`  
  liveness check
- `/meta`  
  dashboard mode label
- `/stats`  
  aggregate counters and last verdict summary
- `/policy`  
  active policy (the policy actually used for evaluation)
- `/verdicts`  
  in memory verdict window (JSON)
- `/verdicts/log?tail=N`  
  NDJSON export from disk log, bounded by a hard cap
- `/verdicts.csv?limit=N`  
  CSV export, bounded by a hard cap
- `/mempool`  
  best effort proxy to template-manager mempool endpoint

Terminal note:
- When calling URLs with `?tail=` or `?limit=` in zsh, quote the URL to avoid wildcard expansion.

---

## 7. TCP protocol
ReserveGrid OS uses a line delimited JSON protocol over TCP.

### 7.1 TemplatePropose
Typical fields:
- `version`
- `id`
- `block_height`
- `prev_hash`
- `coinbase_value`
- `tx_count`
- `total_fees`
- optional fields as you extend the protocol

### 7.2 TemplateVerdict
Typical fields:
- `version`
- `id`
- `accepted`
- `reason_code` (stable machine readable string when rejected)
- `reason_detail` (optional operator detail)
- `policy_context` (optional structured context)

---

## 8. Verdict reasons

Veldra returns one primary `reason_code` per rejected template. `reason_code` is the stable contract (snake_case). UI labels and internal enum names may change without notice.

Examples:
- `protocol_version_mismatch`
- `prev_hash_len_mismatch`
- `invalid_prev_hash`
- `empty_template_rejected`
- `coinbase_value_zero_rejected`
- `total_fees_below_minimum`
- `tx_count_exceeded`
- `avg_fee_below_minimum`

Priority behavior:
- One primary reason is emitted for fast triage
- `policy_context` carries relevant thresholds and computed values (e.g., `fee_tier`, `min_avg_fee_used`, `min_total_fees_used`, `reject_coinbase_zero`, `unknown_mempool_as_high`)

---

## 9. Troubleshooting

### 9.1 bitcoind RPC auth failures
If you see auth failures, confirm:
- `-rpcuser=veldra`
- `-rpcpassword=very_secure_password`
- `-rpcport=18443`

### 9.2 avoid_reuse type error
If you see: JSON value of type number is not of expected type bool

A command is passing `avoid_reuse` as `0` or `1`.  
Fix: pass `true` or `false`, or omit the argument.

### 9.3 Fees appear as 0 in regtest
Common causes:
- mempool is empty
- tx creation did not land transactions in mempool
- blocks mined too aggressively, clearing mempool before templates were fetched

Regtest requires deliberate mempool maintenance to exercise fee policy.

---

## 10. Security and operational notes
- Regtest credentials in scripts are for local demos only
- Do not expose the HTTP dashboard publicly without auth and TLS
- Verdict logs are operational telemetry and may leak policy structure
- Production deployments should add:
  - TLS termination
  - auth on admin endpoints and exports
  - log retention and rotation
  - structured metrics export

---

## License
VELDRA SOURCE AVAILABLE LICENSE (see `LICENSE`)

---

## Maintainer
Veldra, Inc.
Jarron Deng  
jarrondeng@veldra.org