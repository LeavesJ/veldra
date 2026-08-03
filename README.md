## ReserveGrid OS

A [Veldra, Inc.](https://veldra.org) product.

**ReserveGrid OS** is a policy driven verification, mining gateway, and observability stack for Bitcoin mining pools. It sits between the template source and miners, inspecting candidate block templates against operator defined policy and routing Stratum V2 work to connected workers. Operators get a full dashboard with live metrics, structured logs, and Prometheus instrumentation out of the box.

Built in Rust. Ships as a native macOS/Linux desktop app (`rg-desktop`) with embedded dashboard, or as a `docker compose up` server stack for headless deployment.

**Current version:** v2.0.0-rc1

**v2.0 highlights (release candidate):** Independent consensus re-derivation against raw block bytes (Phase 1) plus mempool ground truth via direct bitcoind RPC (Phase 2) ship above the v1.1.0 policy + gateway + observability baseline. Production validation soak in progress; final v2.0.0 ships once the soak completes cleanly. See the [v2.0.0-rc1 release notes](https://github.com/LeavesJ/ReserveGrid-OS/releases/tag/v2.0.0-rc1) for the full list.

---

## Links

- **Website:** https://veldra.org
- **Contact:** jarrondeng@veldra.org

---

## What ReserveGrid OS does

- Evaluates candidate block templates against a configurable `policy.toml`
- Returns accept/reject verdicts with stable machine readable reason codes and policy context
- Runs a full Stratum V2 gateway (Noise NX encrypted) with standard and extended mining channels
- Adjusts per channel difficulty dynamically via variable difficulty (vardiff)
- Tracks per channel hashrate with a sliding window estimator
- Degrades automatically from inline to observe mode when the verifier is unreachable, then recovers on heartbeat
- Enforces consensus safety checks: weight ratio, template age, sigops budget, coinbase sigops
- Supports dynamic fee tiers driven by mempool conditions
- Provides an operator dashboard with live service health, verdicts, miners, policy editor, and settings
- Ships Prometheus metrics on all core services
- Includes a complete auth system: registration, email verification, admin approval, forgot/reset password
- Exposes health and readiness probes on every service

## What ReserveGrid OS does not do

- It does not mine blocks
- It does not replace a pool payout system
- It does not force policy on chain
- It is not a consensus change

ReserveGrid OS is an ops layer control surface. Pools remain in control.

---

## Architecture

ReserveGrid OS supports three deployment modes for progressive rollout, plus a developer mode for internal use:

**Shadow** evaluates templates in parallel without affecting mining. The feed stack (rg-demo-feed or rg-feed-server, rg-feed-adapter) replays or proxies real pool traffic so the verifier can score templates without any operational risk. The desktop app gates access until shadow feed services are confirmed healthy, preventing silent degradation to inline mode.

**Observe** connects to a live bitcoind but does not enforce policy. The gateway distributes jobs to miners regardless of the verdict. Operators see what the verifier would reject without blocking any work.

**Inline** enforces policy. The gateway only distributes jobs that the verifier accepts. Rejected templates are held until a passing template arrives or a configurable stale hold timer expires. A dual prevhash buffer holds two pending templates simultaneously during block transitions, with a 50ms verdict window so miners never stall on a prevhash switch. If the verifier becomes unreachable, the gateway automatically degrades to observe behavior (templates flow without enforcement) and recovers when a heartbeat acknowledgment confirms the verifier is back.

**Dev** is a client-side override activated by the developer passkey (compile-time feature). It unlocks all dashboard features regardless of which backend stack is running. A purple DEV badge in the top bar distinguishes it from production modes.

```
  Inline / Observe mode:

  bitcoind (regtest or mainnet)
        |
        v
  template-manager          pool-verifier
  (fetch templates) ------> (evaluate policy)
        |                         |
        v                         v
  sv2-gateway               rg-desktop (native app)
  (SV2 Noise NX,             ├─ rg-dashboard (operator UI)
   dual prevhash buffer)     └─ IPC · auto-update · license
        |
        v
  miners (SV2)

  Shadow mode (non-invasive evaluation):

  rg-demo-feed or rg-feed-server
        |  (WebSocket GBT stream)
        v
  rg-feed-adapter
  (WS -> JSON-RPC bridge)
        |
        v
  template-manager -------> pool-verifier -------> rg-desktop
```

The backend services run in Docker Compose. The `rg-desktop` native app (built with Tauri) wraps the dashboard, manages licensing, and includes an in-app auto-updater. For headless server deployments, `rg-dashboard` can run standalone in Docker without the desktop shell. Prometheus scrapes metrics from pool-verifier, template-manager, and sv2-gateway.

---

## Services

### pool-verifier
TCP server that receives `TemplatePropose` messages and returns `TemplateVerdict`. Evaluates templates against the active policy. Serves the HTTP API for stats, verdicts, policy, and exports. Built in TLS termination and API key auth.

### template-manager
Fetches block templates from bitcoind (`getblocktemplate`) or a Stratum bridge and forwards them to the verifier. Exposes mempool stats for the verifier fee tier logic. Supports runtime settings updates.

### sv2-gateway
Stratum V2 mining gateway with Noise NX encryption. Accepts miner connections on standard and extended mining channels, distributes `NewMiningJob` and `NewExtendedMiningJob` messages, and validates submitted shares (including variable length extranonce for extended channels). Variable difficulty adjusts each channel's target based on observed share rate. Tracks per channel state including a sliding window hashrate estimator. Automatic inline to observe degradation when the verifier heartbeat is lost. Exposes channel snapshots via HTTP for the miners page.

### rg-desktop
Native desktop application (macOS/Linux) built with Tauri. Wraps rg-dashboard in a native window with IPC commands for license management, system tray integration, and in-app auto-updates (signed, with Tauri updater). The desktop app is the primary distribution format for operators. For headless or Docker deployments, rg-dashboard runs standalone.

### rg-dashboard
Operator dashboard and API proxy. Vite/React frontend with live polling. Pages: overview, verdicts, templates, policy editor, miners, and settings. Proxies all API calls to the appropriate backend service. Includes the full auth gate (login, register, verify, forgot password, reset password). Embedded inside rg-desktop for native deployments.

### rg-auth
Authentication service. Argon2id password hashing, session tokens, email verification, admin approval workflow, forgot/reset password. Sends email via any STARTTLS SMTP provider. Falls back to stdout in dev mode when SMTP is not configured.

### rg-protocol
Shared protocol structs and versioning. `TemplatePropose` and `TemplateVerdict` message types. Canonical `VerdictReason` enum and reason code string mappings.

### reservegrid-common
Shared utilities: reason code enums, redacted secret types, per-IP rate limiter, common configuration helpers.

### rg-demo-feed
Synthetic GBT (getblocktemplate) source for shadow mode testing. Generates realistic block template streams over WebSocket without requiring a real bitcoind. Ships multiple scenarios (normal, empty, fee sweep, reorg, stale).

### rg-feed-adapter
WebSocket to JSON-RPC bridge. Connects to rg-demo-feed or rg-feed-server over WebSocket, receives GBT frames, and serves them as `getblocktemplate` JSON-RPC responses to template-manager. Includes reconnection with exponential backoff and a health endpoint.

### rg-feed-server
Authenticated WebSocket relay for real pool template data. Accepts connections from rg-feed-adapter instances, authenticates via bearer token, and broadcasts live GBT frames received from an upstream bitcoind or pool relay.

### rg-load-test
Performance testing harness for the verifier. Spawns concurrent connections, submits templates at configurable rates, and reports latency percentiles. Used to validate CL-01 (sub-100ms verdict latency) and CL-02 (zero drops under load).

### test-miner
Regtest validation tool. Connects to sv2-gateway over Noise NX, opens a standard mining channel, submits shares with random nonces, then exits. Includes a configurable `--job-timeout-secs` (default 60) to prevent hangs. Activated via `docker compose --profile test up`.

---

## Repository layout

```
services/
  pool-verifier/       TCP verifier, HTTP API, policy evaluation
  template-manager/    template fetching, mempool stats
  sv2-gateway/         Stratum V2 gateway, share validation, hashrate
  rg-desktop/          native desktop app (Tauri), license, auto-update
  rg-dashboard/        operator UI (Vite + React), API proxy
  rg-auth/             authentication, email, sessions
  rg-demo-feed/        synthetic GBT source for shadow testing
  rg-feed-adapter/     WebSocket to JSON-RPC bridge
  rg-feed-server/      authenticated WebSocket relay for live feeds
  rg-load-test/        verifier performance testing harness
  rg-protocol/         shared message types, reason codes
  reservegrid-common/  shared utilities
  reservegrid-gateway/ gateway shared library
  sv2-bridge/          Stratum V2 bridge (legacy)
  test-miner/          regtest share submission tool
config/                policy TOML files
dev/                   docker-compose overrides and dev TOML configs
deploy/                production deployment profiles
scripts/               dev, regtest, and CI helper scripts
docs/                  architecture and protocol contract docs
supply-chain/          cargo-vet audit configuration
```

---

## Quickstart

### Option A: Desktop app (recommended for evaluation)

Download the latest `.dmg` (macOS) or `.AppImage` (Linux) from the GitHub releases page. The desktop app bundles the dashboard, license management, system tray, and in-app auto-updates. It connects to backend services running in Docker.

### Option B: Docker only (headless / server deployment)

#### Prerequisites

- Docker and Docker Compose
- A `.env` file at repo root (copy from `.env.example`)

#### Setup

1. Copy the environment template:

       cp .env.example .env

2. Fill in the required values in `.env`:

       VELDRA_BITCOIND_RPC_PASS=<any-password-for-regtest>

   For email delivery (optional, emails print to stdout without this):

       VELDRA_AUTH_SMTP_HOST=smtp.example.com
       VELDRA_AUTH_SMTP_PORT=587
       VELDRA_AUTH_SMTP_USER=you@yourdomain.com
       VELDRA_AUTH_SMTP_PASS=<your-email-password>
       VELDRA_AUTH_SMTP_FROM=you@yourdomain.com
       VELDRA_AUTH_ADMIN_EMAIL=you@yourdomain.com

3. Start the stack:

       docker compose up --build

4. Bootstrap bitcoind (first run only, in a separate terminal):

       docker compose exec bitcoind bitcoin-cli -regtest \
         -rpcuser=reservegrid -rpcpassword=<your-rpc-pass> \
         createwallet "default"

       docker compose exec bitcoind bitcoin-cli -regtest \
         -rpcuser=reservegrid -rpcpassword=<your-rpc-pass> \
         -generate 1

5. Open the dashboard at `http://localhost:8084` (Docker) or via the desktop app

### Port map

| Service          | Port  | Purpose                          |
|------------------|-------|----------------------------------|
| rg-dashboard     | 8084  | Operator UI                      |
| sv2-gateway      | 3333  | Stratum V2 (miners connect here) |
| sv2-gateway      | 8080  | Gateway HTTP API and metrics     |
| pool-verifier    | 8081  | Verifier HTTP API                |
| pool-verifier    | 9090  | Verifier TCP (internal)          |
| template-manager | 8082  | Template HTTP API                |
| rg-auth          | 3030  | Auth HTTP API                    |
| bitcoind         | 18443 | Bitcoin RPC (regtest)            |
| prometheus       | 9091  | Metrics UI (monitoring profile)  |

### Run the test miner

    docker compose --profile test up test-miner

Connects to sv2-gateway, opens a channel, submits 5 shares at 2 second intervals, then exits. Shares and hashrate appear on the miners page.

### Enable Prometheus monitoring

    docker compose --profile monitoring up prometheus

Scrapes metrics from pool-verifier, template-manager, and sv2-gateway.

---

## Policy

### Policy file

The verifier reads policy from `VELDRA_POLICY_FILE` (TOML) at startup. The dashboard policy editor can apply changes at runtime.

### Dynamic fee tiers

The verifier fetches mempool tx count from template-manager and selects a fee tier based on configurable thresholds. When the mempool endpoint is unreachable, a conservative tier is used based on the `unknown_mempool_as_high` setting.

### Example policy

```toml
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
reject_coinbase_zero = true
unknown_mempool_as_high = true

max_weight_ratio = 0.999
max_template_age_secs = 30
max_sigops_cost = 80000
max_coinbase_sigops = 20000
```

---

## Verdict reason codes

Every rejected template carries a stable `reason_code` (snake_case). These are the canonical contract; UI labels may change.

Source of truth: `rg-protocol` and `reservegrid-common` reason enums.

Verdict reason codes (policy): `protocol_version_mismatch`, `invalid_prev_hash`, `prev_hash_len_mismatch`, `coinbase_value_zero_rejected`, `empty_template_rejected`, `tx_count_exceeded`, `total_fees_below_minimum`, `avg_fee_below_minimum`, `weight_ratio_exceeded`, `template_too_old`, `sigops_budget_exceeded`, `coinbase_sigops_exceeded`, `policy_load_error`, `mempool_backend_unavailable`, `internal_error`.

Gateway share codes: `share_difficulty_below_target`, `share_replay_detected`, `share_rate_limited`, `ntime_out_of_range`, `share_invalid_job_id`, `share_invalid_nonce`, `version_bit_violation`, `share_forward_failed`, `share_upstream_rejected`, `share_dropped_queue_full`, `process_crash_recovery`.

Connection and protocol codes: `noise_handshake_failed`, `noise_handshake_timeout`, `unsupported_protocol_version`, `frame_decode_error`, `frame_too_large`, `connection_rate_limited`, `peer_quota_exceeded`, `channel_open_rejected`, `channel_limit_exceeded`, `extended_channel_unsupported`, `miner_unauthorized`, `shutdown_drain`.

The full canonical list lives in `reservegrid-common/src/reason.rs` (GatewayReason enum) and `rg-protocol` (VerdictReason enum).

---

## Environment variables

All secrets and credentials are loaded from environment variables. See `.env.example` for the complete list with documentation.

Key groups:

- **`VELDRA_BITCOIND_RPC_*`** — Bitcoin Core RPC credentials
- **`VELDRA_AUTH_SMTP_*`** — SMTP email configuration for rg-auth
- **`VELDRA_API_SECRET`** — API key for protected endpoints
- **`VELDRA_TLS_*`** — TLS certificate and key paths
- **`VELDRA_NOISE_*`** — Noise NX key and cert paths for sv2-gateway
- **`VELDRA_LOG_*`** — Log format and filter level

No secrets should appear in TOML config files, docker-compose.yml, or source code. The `.env` file is gitignored.

---

## Security notes

- All credentials come from `.env` or a secrets manager, never from config files
- Passwords are hashed with argon2id
- Session tokens are cryptographically random, expire after 7 days
- Password reset tokens expire after 1 hour
- Rate limiting on auth endpoints (3 to 10 requests per minute per IP, scalable via `VELDRA_AUTH_RATE_LIMIT_MULTIPLIER`)
- Forgot password endpoint does not reveal whether an email is registered
- SV2 connections use Noise NX encryption
- API key auth on protected verifier endpoints with automatic localhost bypass
- Built in TLS termination (file based or self signed dev mode)
- Desktop app auto-updater uses signed releases with a pinned public key
- Per-IP connection limits on all WebSocket services (rg-feed-server, rg-demo-feed, sv2-gateway)
- Non-loopback bind blocked by default; requires explicit `VELDRA_ALLOW_NON_LOOPBACK=1` override

---

## Troubleshooting

### Fresh regtest: "failed to parse template response"

Expected on first boot before any blocks exist. Fix:

    docker compose exec bitcoind bitcoin-cli -regtest \
      -rpcuser=reservegrid -rpcpassword=<your-rpc-pass> \
      createwallet "default"

    docker compose exec bitcoind bitcoin-cli -regtest \
      -rpcuser=reservegrid -rpcpassword=<your-rpc-pass> \
      -generate 1

### Emails not sending

If SMTP env vars are not set, rg-auth falls back to printing emails to stdout with `[email-stub]` prefix. Check container logs:

    docker compose logs rg-auth

### Readiness probe returns 503

The pool-verifier `/ready` endpoint returns 503 when policy failed to load or no mempool fetch succeeded in the last 30 seconds. Verify `VELDRA_POLICY_FILE` points to valid TOML and template-manager is healthy.

### Fees appear as 0 in regtest

Mempool is empty or blocks are mined too aggressively. Regtest requires deliberate mempool maintenance to exercise fee policy.

---

## License

RESERVEGRID OS SOURCE AVAILABLE LICENSE (see `LICENSE`)

---

## Maintainer

Veldra, Inc.
Jarron Deng — jarrondeng@veldra.org
