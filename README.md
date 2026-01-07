# Veldra — ReserveGrid OS 

**ReserveGrid OS** is Veldra’s policy driven verification layer for Bitcoin mining pools. It inspects candidate block templates against an operator defined policy and returns an **ACCEPT** or **REJECT** verdict with a machine readable reason, plus an operator facing dashboard for observability.

This repo is a **beta prototype** intended to be legible, testable, and easy for a pool operator to evaluate. It is built to be swapped into a pool pipeline with minimal ceremony.

---

## Demo and repo links
- **Repo:** `<https://github.com/LeavesJ/veldra>`
- **Demo (dashboard video):** `<https://youtu.be/lDIIl7Oe73Y>`
- **Contact:** `<jarrondeng@gmail.com>`

---

## What ReserveGrid OS does
- Evaluates incoming block templates against a configurable `policy.toml`
- Returns a verdict over a simple TCP JSON protocol (TemplatePropose -> TemplateVerdict)
- Records verdicts to disk as NDJSON for audit and debugging
- Exposes an operator dashboard with:
  - throughput and accept rate
  - fee tier behavior driven by mempool conditions
  - aggregates by reject reason and tier
  - current active policy view
  - policy wizard UI (generate and optionally apply a policy)

---

## What ReserveGrid OS does not do
- It does not mine blocks
- It does not replace a pool’s payout system
- It does not force pool policy on chain
- It is not a consensus change
- It is not a custody product

ReserveGrid OS is an ops layer control surface. Pools remain in control.

---

## Services
ReserveGrid OS consists of two primary services plus shared protocol types.

1. **pool-verifier**
   - TCP server: receives templates and returns verdicts
   - HTTP server: dashboard, stats, policy endpoints, log export
   - Holds the active policy in memory and can be updated at runtime

2. **template-manager**
   - Fetches templates from a backend (regtest `bitcoind` in this prototype)
   - Sends templates to `pool-verifier` over TCP
   - Exposes a small HTTP endpoint for mempool stats used for tier selection

3. **rg_protocol**
   - Shared message structs and protocol versioning

---

## Repository layout
Typical layout in this repo:

- `services/pool-verifier/`
  - `src/main.rs` (HTTP dashboard, TCP server, log export)
  - `src/policy.rs` (PolicyConfig, VerdictReason, validation logic)
  - `src/state.rs` (shared app state, policy holder, load and update)
  - `data/` (verdict log output)
- `services/template-manager/`
  - bitcoind backend prototype and mempool endpoint
- `config/`
  - `beta-policy.toml` (example policy file used in regtest)
- `scripts/`
  - `dev-regtest.sh` (start the full stack)
  - `dev-traffic.sh` (optional traffic generator, if present)
  - `clear-verdicts.sh` (optional log cleanup)

---

## Architecture overview
High level flow:

~~~text
(bitcoind or stratum bridge)
          |
          v
   template-manager
   (fetch templates)
          |
          |  TCP JSON: TemplatePropose
          v
     pool-verifier  -------->  HTTP dashboard (/)
     (evaluate)              HTTP API (/stats, /policy, /verdicts, exports)
          |
          |  TCP JSON: TemplateVerdict
          v
 (template-manager accepts or rejects template upstream)
~~~

Where this sits in a real pool:
- Between the pool’s template source (bitcoind, stratum bridge, custom builder) and the pool’s job distribution system
- Or as a sidecar that must approve templates before the pool publishes jobs to miners

---

## Quickstart
### 1. Prerequisites
- Rust toolchain (stable)
- `bitcoind` and `bitcoin-cli` installed locally
- macOS or Linux recommended for the scripts

### 2. Build
From repo root:

~~~bash
cargo build
~~~

Or build individual services:

~~~bash
cd services/pool-verifier && cargo build
cd services/template-manager && cargo build
~~~

---

## 3. Run the regtest demo
### 3.1 One command start
From the repository root:

~~~bash
./scripts/dev-regtest.sh
~~~

This script is expected to:
1. Start `bitcoind` in regtest mode
2. Ensure a regtest wallet exists
3. Build `pool-verifier` and `template-manager`
4. Start `pool-verifier`:
   - HTTP on `127.0.0.1:8080`
   - TCP on `127.0.0.1:5001`
5. Start `template-manager` on `127.0.0.1:8081`
6. Generate a repeating pattern of low fee and high fee batches (optional, depending on your script version)

### 3.2 Open the dashboard
Open:

~~~text
http://127.0.0.1:8080
~~~

You should see:
- throughput increasing
- recent templates updating
- aggregates changing as accepts and rejects happen

### 3.3 Start the full regtest stack
If you want to run services manually instead of the script:

1) Start bitcoind regtest:

~~~bash
bitcoind -regtest \
  -server=1 \
  -rpcuser=veldra \
  -rpcpassword=very_secure_password \
  -rpcport=18443 \
  -fallbackfee=0.0001 \
  -maxmempool=300 \
~~~

2) Start `template-manager`:

~~~bash
cd services/template-manager
export VELDRA_MANAGER_HTTP_ADDR="127.0.0.1:8081"
export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"
export VELDRA_MANAGER_CONFIG="./manager.toml"
cargo run
~~~

3) Start `pool-verifier`:

~~~bash
cd services/pool-verifier
mkdir -p data

export VELDRA_HTTP_ADDR="127.0.0.1:8080"
export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"
export VELDRA_MEMPOOL_URL="http://127.0.0.1:8081/mempool"
export VELDRA_DASH_MODE="regtest-bitcoind"
export VELDRA_POLICY_FILE="../../config/beta-policy.toml"

cargo run
~~~

4) Confirm endpoints:

~~~bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/meta
curl -s http://127.0.0.1:8080/policy
curl -s http://127.0.0.1:8080/stats
~~~

---

## 4. Policy management
### 4.1 Policy file
ReserveGrid OS reads an initial policy from:

- `VELDRA_POLICY_FILE` (path to `policy.toml`)

The verifier validates the policy on startup. If validation fails, it refuses to run.

### 4.2 Dynamic fee tiers
The verifier can choose an effective minimum average fee floor based on mempool conditions:
- It fetches mempool tx count from `VELDRA_MEMPOOL_URL` (template-manager endpoint)
- It selects `low`, `mid`, or `high` tier based on configured thresholds
- It applies the tier specific `min_avg_fee_*` floor

### 4.3 Policy wizard
The dashboard includes a **Policy wizard**:
- It displays the current policy
- It lets you modify thresholds and fee floors
- It generates a TOML block
- Optionally, it can POST the generated TOML to the verifier to apply live (if enabled in your build)

Important behavior:
- The wizard should not reset your inputs every refresh
- The dashboard “Current policy” view should reflect the actual active policy in the verifier

If the wizard applies policy live, it should:
1. Parse TOML into `PolicyConfig`
2. Validate it
3. Swap it into shared app state
4. Cause subsequent template verdicts to use the new policy

---

## 5. Policy schema
Your actual `PolicyConfig` is the source of truth. This is the intended shape.

Example `config/beta-policy.toml`:

~~~toml
[policy]
protocol_version = 1
required_prevhash_len = 64

# Fee floors are in sats per tx in this prototype (avg fee per tx)
min_avg_fee_lo  = 1
min_avg_fee_mid = 2000
min_avg_fee_hi  = 5000

# Tier selection driven by mempool tx count
low_mempool_tx  = 0
high_mempool_tx = 50

# Optional constraints
min_total_fees = 0
max_tx_count   = 10000

# Optional safety controls (if enabled in your policy.rs)
reject_empty_templates = true
max_weight_ratio = 0.999
~~~

Notes:
- The “avg fee” is currently computed as `total_fees / tx_count` (sats per tx)
- If `tx_count == 0`, avg fee is treated as 0 by default, unless you choose to hard reject empty templates

---

## 6. HTTP API (pool-verifier)
Base: `http://127.0.0.1:8080`

- `/` and `/ui`
  - HTML dashboard
- `/health`
  - liveness check
- `/stats`
  - counts and last verdict summary
- `/verdicts`
  - JSON list of recent verdicts in memory
- `/verdicts/log`
  - NDJSON export from disk log
- `/verdicts.csv`
  - CSV export of current in memory log window
- `/policy`
  - current policy as JSON (the active policy)
- `/mempool`
  - proxy to template-manager mempool endpoint (best effort)
- `/meta`
  - dashboard mode label, useful for demos
- `/wizard`
  - optional GET and POST endpoints for wizard integration, depending on your build

---

## 7. TCP protocol (template-manager to pool-verifier)
The verifier speaks a simple line delimited JSON protocol.

### 7.1 TemplatePropose (request)
Fields typically include:
- `version`
- `id`
- `block_height`
- `prevhash`
- `tx_count`
- `total_fees`
- any other fields you choose to include later (weight, sigops, txids)

### 7.2 TemplateVerdict (response)
- `version`
- `id`
- `accepted` (bool)
- `reason` (optional string)

---

## 8. Verdict reasons
ReserveGrid OS already supports multiple reasons (your `VerdictReason` enum). You only see a subset if your evaluation logic only checks one thing.

Common reasons you can emit:
- `UnsupportedVersion`
- `PrevHashWrongLen`
- `CoinbaseZero`
- `TotalFeesTooLow`
- `TooManyTransactions`
- `AverageFeeTooLow`
- and more as you add constraints

### Which reason shows if multiple checks fail?
ReserveGrid OS returns **one** reason per verdict in the current prototype. The reason is whichever check your code chooses to evaluate first.

If you want multiple reasons:
- Option A: return a list of reasons in the verdict
- Option B: keep one primary reason (fast path) and log secondary reasons in debug data
- Option C: define a priority ordering (safety first, then economics)

Pools typically want a single primary reason for fast operational triage, with optional secondary detail.

---

## 9. Dashboard interpretation notes
### 9.1 Ratio column
The “ratio” shown in the Recent templates table is:

~~~text
ratio = avg_fee_sats_per_tx / min_avg_fee_used
~~~

Why it can look repetitive:
- If your traffic generator produces two stable fee regimes, you will see the same avg fee values and ratios repeating.
- If `avg_fee_sats_per_tx` is 0, ratio is 0.
- If `min_avg_fee_used` is 0, the ratio needs a safe guard (avoid divide by zero). Many builds show 0.00 or treat ratio as 0 in that case.

If you want more varied ratios, your traffic generator must vary fee rates and tx counts more.

### 9.2 Why you saw total_fees = 0
In regtest, templates can show `total_fees = 0` when:
- the mempool is empty and the candidate template has only coinbase
- your tx generation did not actually land spendable transactions in mempool
- your script mined blocks too aggressively, clearing the mempool before templates were fetched
- your tx creation commands failed silently

When fees are 0, fee based policies become a blunt instrument. That is expected in synthetic regtest unless you deliberately maintain a mempool backlog.

---

## 10. Troubleshooting
### 10.1 bitcoind RPC auth failures
If you see:
- “Authorization failed”
- “Incorrect rpcuser or rpcpassword”

Confirm your script matches your bitcoind args:
- `-rpcuser=veldra`
- `-rpcpassword=very_secure_password`
- `-rpcport=18443`

Also confirm your wrapper script `dev-bitcoin-cli.sh` uses the same values.

### 10.2 Wrong type passed: avoid_reuse
If you see:
- “JSON value of type number is not of expected type bool” for `avoid_reuse`

That means a command is passing `avoid_reuse` as `0` or `1` instead of `true` or `false`.

Fix: pass `true` or `false`, or remove the arg and use the default.

### 10.3 Wizard TOML parse error: missing protocol_version
If the wizard generates TOML that fails parsing, ensure it includes required fields.
If `PolicyConfig` requires `protocol_version`, then the wizard output must include it.

Fix: include:

~~~toml
[policy]
protocol_version = 1
~~~

### 10.4 Dashboard shows old policy after wizard apply
This means the verifier is not actually swapping the policy used by:
- the TCP evaluation path
- the `/policy` endpoint

Fix: the TCP evaluation should read from a shared policy holder (Arc RwLock) instead of cloning a static `PolicyConfig` at startup.

---

## 11. Pool integration notes
### Minimal integration contract
A pool integrating ReserveGrid OS needs to:
1. Produce or access candidate templates
2. Send `TemplatePropose` to `pool-verifier`
3. Receive `TemplateVerdict`
4. If accepted, continue normal job publication
5. If rejected, request a new template or adjust template builder policy

### What pools can customize
Pools can implement their own policy constraints by:
- extending `PolicyConfig`
- extending `VerdictReason`
- extending the validation logic that produces the verdict

The dashboard will display whatever `reason` string is returned in the verdict.

### Future direction for pool defined reasons
For maximum flexibility without forking:
- define a plugin interface (dynamic library, wasm, or policy DSL)
- allow policies to define custom reason codes and messages
- keep the dashboard generic: it renders reason strings and aggregates by key

---

## 12. Security and operational notes
- The regtest credentials in scripts are for local demos only
- Do not expose the HTTP dashboard publicly without auth
- Treat verdict logs as operational telemetry, they can leak policy structure
- Production deployments should include:
  - TLS termination
  - auth on admin endpoints (wizard apply, log download)
  - bounded memory and log retention policies
  - structured logs and metrics export (Prometheus or similar)

---

## 13. Roadmap (high signal)
- Stronger policy validation with actionable errors
- Cleaner policy wizard UX and policy export workflow
- Stratum v2 integration path for real pool pipelines
- Richer template fields: weight, sigops, ancestor stats, package feerate
- Multi reason verdict option with priority ordering
- Operator runbook hardening: “no questions asked” install and demo flow

---

## License
`<License: MIT (see LICENSE)>`

---

## Maintainer
Veldra, ReserveGrid OS
`<Jarron Deng>`  
`<jarrondeng@gmail.com>`  

