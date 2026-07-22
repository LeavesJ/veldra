# ReserveGrid OS — Deployment Runbook

Production deployment guide for pool operators. Covers all three deployment
modes (shadow, observe, inline), security configuration, monitoring, backup,
upgrade procedures, and troubleshooting.

Version: 1.1.0
Last updated: 2026-04-12

---

## Prerequisites

**Hardware (inline mode, mainnet):**

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 100 GB SSD (bitcoind pruned) | 1 TB NVMe (full node) |
| Network | 100 Mbps symmetric | 1 Gbps symmetric |

Shadow and observe modes require approximately half the above resources because
they do not run bitcoind or sv2-gateway locally.

**Software:**

- Docker Engine 24+ with Compose v2
- A Linux host (Ubuntu 22.04 LTS or Debian 12 recommended)
- `curl` and `jq` for health verification
- Git (to clone the repository)

**Network access:**

| Direction | Port | Protocol | Purpose |
|---|---|---|---|
| Inbound | 3333 | TCP (Noise NX) | Miners connect to sv2-gateway |
| Inbound | 8084 | HTTP/HTTPS | Operator dashboard |
| Outbound | 8332/18443 | HTTP | bitcoind JSON-RPC (inline mode) |
| Outbound | 443 | HTTPS | SMTP relay for auth emails |
| Internal | 8080-8082, 9090, 3030 | HTTP/TCP | Inter-service communication |

Firewall rules should expose only ports 3333 and 8084 to the internet. All
other ports are internal only.

---

## Mode Selection

Choose the deployment mode that matches your trust posture. All modes use the
same binaries. The mode is selected by a single config key and the compose file
you start.

**Shadow** (free trial, zero risk). Synthetic template feed from Veldra
infrastructure. No connection to your bitcoind. No miners. Demonstrates the
verification surface with curated edge cases. Use this to evaluate the product
before committing any infrastructure. The desktop app gates access until the
shadow feed services (`rg-demo-feed`, `rg-feed-adapter`) are confirmed healthy.

```
docker compose -f docker-compose.shadow.yml up --build
```

**Observe** (paid evaluation, read-only). Live mainnet template data from a
Veldra-hosted reference feed. Requires a signed license key from veldra.org
with tier `observe_paid` or `inline_licensed`. Verdicts are logged but not
enforced. Use this to see how your real template traffic looks under policy,
without any production risk.

```
docker compose -f docker-compose.observe.yml up --build
```

**Inline** (production, full enforcement). Your own bitcoind, your own miners,
active policy enforcement on every template. Templates that fail policy are
rejected before reaching miners. This is the production mode.

```
docker compose up --build
```

**Dev** (local development only). Activated by the developer passkey, which is
a compile-time feature (`--features dev-passkey`). Unlocks all dashboard
features regardless of backend mode. Not a backend deployment mode. Build with:

```
VELDRA_DEV_PASSKEY_HASH="<sha256 hex>" scripts/desktop-build.sh dev
```

The rest of this runbook focuses on inline mode. Shadow and observe mode
follow the same structure with fewer services and no enforcement. Differences
are noted where they apply.

---

## Step 1: Clone and Configure Environment

```bash
git clone https://github.com/veldra/reservegrid-os.git
cd reservegrid-os
cp deploy/env.prod.example .env
```

Open `.env` and fill every `TODO_SET_*` field. The system will fail at startup
if required values are missing.

**Required fields:**

| Variable | Description | Example |
|---|---|---|
| `VELDRA_BITCOIND_RPC_USER` | bitcoind RPC username | `mypool` |
| `VELDRA_BITCOIND_RPC_PASS` | bitcoind RPC password | (generate a strong random string) |
| `VELDRA_API_SECRET` | API authentication key, min 32 hex bytes | (see Step 2) |
| `VELDRA_AUTH_SMTP_HOST` | SMTP server for verification emails | `smtp.mailgun.org` |
| `VELDRA_AUTH_SMTP_USER` | SMTP username | `postmaster@mg.yourpool.com` |
| `VELDRA_AUTH_SMTP_PASS` | SMTP password | (from SMTP provider) |
| `VELDRA_AUTH_ALLOWED_ORIGIN` | Frontend URL for CORS | `https://dashboard.yourpool.com` |
| `VELDRA_AUTH_SITE_URL` | Base URL for email links | `https://dashboard.yourpool.com` |
| `VELDRA_AUTH_URL` | Auth service public URL | `https://auth.yourpool.com` |
| `VELDRA_LICENSE_SIGNING_KEY` | Ed25519 seed for license key signing (rg-auth only) | Base64url 32-byte seed |
| `VELDRA_LICENSE_PUBKEY` | Ed25519 pubkey for license verification (rg-feed-server) | Base64 32-byte pubkey |

**Optional but recommended:**

| Variable | Default | Notes |
|---|---|---|
| `VELDRA_GRAFANA_ADMIN_PASSWORD` | `reservegrid` | Change for production |
| `VELDRA_AUTH_RATE_GLOBAL_CEILING` | (disabled) | Set if DDoS is a concern |
| `VELDRA_AUTH_SESSION_TTL_HOURS` | `168` (7 days) | Reduce for higher security |
| `VELDRA_VERDICT_LOG_MAX_ENTRIES` | `1000` | Cap in-memory verdict log size |
| `VELDRA_MEMPOOL_TIMEOUT_MS` | `900` | Mempool HTTP client timeout |

---

## Step 2: Generate Cryptographic Material

**API secret:**

```bash
openssl rand -hex 32
```

Paste the output into `VELDRA_API_SECRET` in `.env`.

**Noise keypair (one per gateway instance):**

```bash
# Build the gateway binary first (or use a released image)
docker compose build sv2-gateway

# Generate the keypair
docker compose run --rm sv2-gateway reservegrid keygen --noise > keys/noise.key
```

If you do not have the `reservegrid keygen` command available yet, generate a
32-byte Ed25519 keypair using your preferred tool and place the private key file
at the path referenced by `noise_keypair_path` in your gateway config.

Set file permissions:

```bash
chmod 0400 keys/noise.key
```

Record the derived x-only public key. You will need it in Step 3.

**mTLS certificates (if verifier runs on a separate host):**

Generate a CA, server certificate for pool-verifier, and client certificate for
sv2-gateway. Use your organization's PKI or a tool like `cfssl`:

```bash
# Example with cfssl (adjust for your CA setup)
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem verifier-csr.json | cfssljson -bare verifier
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem gateway-csr.json | cfssljson -bare gateway-client
```

Place the certificates in a `tls/` directory and reference them in the gateway
and verifier configuration. See `deploy/gateway-prod.toml` for the `[verifier]`
TLS fields.

If both services run on the same host (single-machine deployment), mTLS is not
required and the loopback verifier address is accepted without TLS.

---

## Step 3: Configure Services

Copy the production config templates and customize them:

```bash
mkdir -p config/keys
cp deploy/gateway-prod.toml config/gateway.toml
cp deploy/policy-prod.toml config/policy.toml
cp keys/noise.key config/keys/noise.key
```

**Gateway config (`config/gateway.toml`):**

Fill in the TODO fields:

1. `authority_pubkey`: paste the x-only public key from Step 2
2. `gateway_instance_id`: a unique string per gateway instance (e.g., `prod-gw-us-east-01`)
3. `template_url`: your template-manager URL (default `http://template-manager:8082` if same compose stack)
4. Verify `wal_path` points to a persistent volume mount

**Tunable gateway keys (defaults shown, all optional):**

| Key | Default | What it does |
|---|---|---|
| `extranonce_prefix_len` | `4` | Bytes of extranonce reserved by the gateway for per-channel prefix allocation. Downstream miners get `16 - extranonce_prefix_len` bytes for their own extranonce2 search space. |
| `extended_channels_enabled` | `true` | Accept `OpenExtendedMiningChannel` requests. Disable to force every client onto standard channels. |
| `vardiff_enabled` | `false` | Per-connection target difficulty retargeting based on observed share rate. Off by default so operators opt in after baselining share volume. |
| `vardiff_target_shares_per_min` | `20.0` | Target share submission rate per channel once vardiff is enabled. |
| `vardiff_retarget_interval_secs` | `90` | How often vardiff evaluates share rate and adjusts target. |
| `vardiff_min_difficulty` | `1` | Floor for retargeting. Prevents vardiff from collapsing into single-share-per-block territory on small miners. |
| `vardiff_max_difficulty` | `u64::MAX` | Ceiling for retargeting. Only set if the pool imposes a policy limit. |
| `vardiff_max_adjustment_factor` | `4.0` | Maximum single-step multiplier up or down per retarget. Dampens oscillation under bursty share rates. |
| `auto_degrade` | `true` | When the verifier stops serving verdicts, either by heartbeat loss or by verdict starvation while proposals are outstanding, for longer than `auto_degrade_after_ms`, the gateway flips readiness to degraded and keeps distributing jobs without enforcement. See "Degradation Behavior" further down. |
| `auto_degrade_after_ms` | `10000` | Threshold for both degrade signals (heartbeat loss and verdict starvation). Must be at least `verifier.heartbeat_interval_ms` or the gateway will refuse to start. |

These keys are TOML-only at v1.1.0. There are no `VELDRA_` env overrides yet. If you need per-instance overrides, use separate TOML files per instance, as shown in the multi-gateway section of this runbook.

**Policy config (`config/policy.toml`):**

The production policy enables all enforcement by default. Review each field
and adjust thresholds to match your pool's requirements:

| Field | Default | What it does |
|---|---|---|
| `min_total_fees` | 1000 sats | Minimum total fees to accept a template |
| `max_weight_ratio` | 0.999 | Maximum block weight ratio before rejection |
| `max_template_age_ms` | 5000 | Templates older than 5s are rejected as stale |
| `reject_empty_templates` | true | Reject templates with zero transactions |
| `reject_coinbase_zero` | true | Reject templates with zero coinbase value |

Start with the defaults. Tune after observing verdict patterns in the
dashboard.

**Phase 2 mempool ground truth (`[policy.mempool]`, ADR-003):**

The v2.0 Invariant Shield Class M check runs only when
`[policy.mempool] enforce = true` and the verifier can reach a
bitcoind JSON-RPC endpoint. With `enforce = false` (the shipped
default) the shield runs Phase 1 only and these keys are ignored.

| Field | Default | What it does |
|---|---|---|
| `enforce` | `false` | Master enable for the Class M check. Flip to `true` once `rpc_url` / `rpc_user` / `rpc_pass` are wired. |
| `tolerance_pct` | `4.0` | Percentage of template txs that may be unknown to the verifier's mempool view before rejection. ADR-003 D-18.2. |
| `poll_interval_secs` | `10` | `getrawmempool` poll cadence. |
| `max_stale_secs` | `60` | Fail-stale window. After this many seconds without a successful refresh, the view enters `Degraded` and the Class M check is skipped. |
| `per_tx_detail` | `false` | When `true`, emit one verdict record per missing tx with the txid in the detail string. When `false`, emit one aggregate record with up to 10 representative txids and the total unknown count. |
| `rpc_url` | `""` | Bitcoind JSON-RPC endpoint (e.g. `http://bitcoind:8332`). Required when `enforce = true`. |
| `rpc_user` | `""` | Bitcoind RPC basic-auth user. Required when `enforce = true`. |
| `rpc_pass` | `""` | Bitcoind RPC basic-auth password. Required when `enforce = true`. The pool-verifier reads `VELDRA_BITCOIND_RPC_PASS` first and falls back to this field only if the env var is unset, so production deployments should keep the password out of `policy.toml` on disk and inject via env. |

The pool-verifier consumes the same `VELDRA_BITCOIND_RPC_USER` and
`VELDRA_BITCOIND_RPC_PASS` env vars that template-manager already
uses, so a single secret pair covers both services when they share
a bitcoind. Operators running a separate bitcoind for the verifier
should set distinct creds in `policy.toml` and override
`VELDRA_BITCOIND_RPC_PASS` on the pool-verifier service block only.

Phase 2 surfaces four metrics when `enforce = true`:
`verifier_mempool_view_age_seconds`, `verifier_mempool_view_size`,
`verifier_phase2_checks_total{result}`, and
`verifier_phase2_degraded_total`. Dashboards alert past
`max_stale_secs` on the age gauge and on sustained
`phase2_degraded_total` increments.

---

## Step 4: Prepare Docker Compose for Production

The development `docker-compose.yml` mounts `./dev/` for config. Production
deployments should mount `./config/` (or bake configs into the image).

Create a production override file or modify volume mounts:

```yaml
# docker-compose.prod.yml (override)
services:
  sv2-gateway:
    volumes:
      - ./config:/config:ro
      - ./data:/data:rw
    environment:
      VELDRA_ALLOW_REMOTE_VERIFIER: "0"

  pool-verifier:
    volumes:
      - ./config:/config:ro

  template-manager:
    volumes:
      - ./config:/config:ro

  grafana:
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${VELDRA_GRAFANA_ADMIN_PASSWORD}
      GF_AUTH_ANONYMOUS_ENABLED: "false"
```

Use the override:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```

**Persistent volumes:**

Ensure the `./data` directory exists and is writable by the container user. This
directory stores:

- `share_wal.ndjson` (gateway WAL for crash-durable share delivery)
- `auth.db` (rg-auth SQLite database)

Back up `./data` regularly. See the Backup section below.

---

## Step 5: Bootstrap Bitcoin Core

If using inline mode with a fresh bitcoind, you need a wallet for block
template generation.

For **regtest** (testing):

```bash
docker compose exec bitcoind bitcoin-cli -regtest \
  -rpcuser=$VELDRA_BITCOIND_RPC_USER \
  -rpcpassword=$VELDRA_BITCOIND_RPC_PASS \
  createwallet "default"

docker compose exec bitcoind bitcoin-cli -regtest \
  -rpcuser=$VELDRA_BITCOIND_RPC_USER \
  -rpcpassword=$VELDRA_BITCOIND_RPC_PASS \
  -generate 101
```

For **mainnet**: your bitcoind should already be synced and have a wallet loaded.
Template-manager will begin polling `getblocktemplate` immediately on startup.
Verify bitcoind is reachable:

```bash
curl -s --user "$VELDRA_BITCOIND_RPC_USER:$VELDRA_BITCOIND_RPC_PASS" \
  --data-binary '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
  -H 'content-type: text/plain;' \
  http://localhost:8332/ | jq .result.blocks
```

---

## Step 6: Start the Stack

**Important:** Grafana (port 3000) and Prometheus (port 9091) are on the
`monitoring` Docker Compose profile. A plain `docker compose up` will not
start them. You must pass `--profile monitoring` to include the observability
stack.

```bash
# Inline mode with monitoring (production)
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --profile monitoring up --build -d

# Development (no prod overlay, with monitoring)
docker compose --profile monitoring up --build -d

# Development (core services only, no monitoring)
docker compose up --build -d
```

Watch the logs during first startup:

```bash
docker compose logs -f --tail=50
```

What to look for in a healthy startup sequence:

1. `bitcoind` reports `getblockchaininfo` success in healthcheck
2. `pool-verifier` logs `listening on 0.0.0.0:9090` and `http server on 0.0.0.0:8081`
3. `template-manager` logs first template received from bitcoind
4. `sv2-gateway` logs `listening for miners on 0.0.0.0:3333`
5. `rg-dashboard` logs `rg-dashboard listening` on the configured address (default `127.0.0.1:8084`; compose overrides to `0.0.0.0:8084` via `dev/dashboard.toml`)
6. `prometheus` begins scraping (check `http://localhost:9091/targets`) — requires `--profile monitoring`
7. `grafana` loads the provisioned dashboard (check `http://localhost:3000`) — requires `--profile monitoring`

---

## Step 7: Verify Health

Run health checks against every service:

```bash
# Core services
curl -sf http://localhost:8081/health | jq .         # pool-verifier
curl -sf http://localhost:8082/health               # template-manager
curl -sf http://localhost:8080/healthz | jq .        # sv2-gateway
curl -sf http://localhost:3030/auth/health           # rg-auth
curl -sf http://localhost:8084/healthz               # rg-dashboard

# Aggregated health (dashboard probes all backends)
curl -sf http://localhost:8084/api/health | jq .

# Verify template flow is active
curl -sf http://localhost:8082/latest | jq .block_height

# Verify policy is loaded
curl -sf http://localhost:8081/policy | jq .

# Verify gateway is accepting connections
curl -sf http://localhost:8080/healthz | jq .status
```

All endpoints should return 200. If any service reports unhealthy, check its
logs with `docker compose logs <service-name>`.

**Monitoring endpoints:**

| URL | What it shows |
|---|---|
| `http://localhost:8084` | Operator dashboard (embedded React SPA) |
| `http://localhost:3000` | Grafana dashboards (12 panels across 3 rows) |
| `http://localhost:9091` | Prometheus UI (raw metrics and targets) |

---

## Step 8: Connect Miners

Miners connect to the sv2-gateway on port 3333 using the Stratum V2 protocol
with Noise NX encryption.

**Miner configuration requirements:**

| Parameter | Value |
|---|---|
| Pool address | `your-server:3333` |
| Protocol | Stratum V2 |
| Authority public key | The x-only pubkey from Step 2 |
| Worker name | Operator-defined (e.g., `farm-rack01-unit05`) |

The gateway performs a Noise NX handshake on connection. Miners that fail
the handshake (wrong authority key, timeout, protocol mismatch) are
disconnected. Successful connections appear in the gateway health endpoint:

```bash
curl -sf http://localhost:8080/healthz | jq .connections
```

Channel activity appears in the dashboard and Grafana "Gateway Overview" row.

---

## Monitoring

### Prometheus Metrics

Three scrape targets are configured by default:

| Target | Port | Key metrics |
|---|---|---|
| sv2-gateway | 8080 | `svtwo_shares_total`, `svtwo_connections_active`, `svtwo_channels_active`, `svtwo_verdicts_total`, `svtwo_share_forward_total` |
| pool-verifier | 8081 | `verifier_verdicts_total`, `verifier_templates_evaluated_total`, `verifier_policy_reloads_total` |
| template-manager | 8082 | (template pipeline health) |

All rejection metrics are keyed by `reason_code` label. This is the canonical
join key across the entire observability stack (see EX-006).

### Grafana Dashboard

The pre-built dashboard (`reservegrid-os.json`) is auto-provisioned on Grafana
startup. It contains 12 panels across 3 collapsible rows:

**Gateway Overview:** Active Connections, Active Channels, Total Connections,
Templates Received.

**Share Traffic:** Share Rate (accepted vs rejected timeseries), Rejections by
Reason Code (stacked bars), Share Forward Rate (upstream relay), Gateway
Verdicts Rate.

**Template Verification:** Verifier Verdict Rate, Verifier Rejections by Reason
Code (stacked bars), Templates Evaluated Rate, Policy Reloads (point markers).

Default credentials: admin / (value of `VELDRA_GRAFANA_ADMIN_PASSWORD`). Change
this immediately in production. Disable anonymous access by setting
`GF_AUTH_ANONYMOUS_ENABLED=false`.

### Alerting

Grafana alerting is not pre-configured. Recommended alert rules to add:

| Condition | Severity | Query |
|---|---|---|
| No templates received in 60s | Critical | `rate(svtwo_templates_received_total[2m]) == 0` |
| Rejection rate > 10% sustained 5m | Warning | `rate(verifier_verdicts_total{verdict="rejected"}[5m]) / rate(verifier_verdicts_total[5m]) > 0.1` |
| Active connections drop to 0 | Critical | `svtwo_connections_active == 0` |
| WAL pending entries > 500 | Warning | (custom metric, if exposed) |
| WAL write failure | Critical | `increase(gateway_share_events{reason_code="wal_write_failure"}[1m]) > 0` |
| Gateway health probe stale | Critical | Prometheus target down for > 30s |

---

## Backup and Recovery

### What to Back Up

| Data | Location | Frequency | Method |
|---|---|---|---|
| Auth database | `./data/auth.db` | Continuous or hourly | Litestream to R2/S3, or `sqlite3 .backup` |
| Share WAL | `./data/share_wal.ndjson` | Hourly | File copy (append-only, safe to copy while running) |
| Noise keypair | `./config/keys/noise.key` | On creation and rotation | Secrets manager |
| Policy config | `./config/policy.toml` | On change | Version control |
| Gateway config | `./config/gateway.toml` | On change | Version control |
| Environment file | `./.env` | On change | Secrets manager (never version control) |

### Litestream for Auth Database

rg-auth uses SQLite. For continuous replication to Cloudflare R2:

```yaml
# litestream.yml (mounted into rg-auth container)
dbs:
  - path: /data/auth.db
    replicas:
      - type: s3
        bucket: your-bucket
        path: rg-auth/
        endpoint: https://<account-id>.r2.cloudflarestorage.com
        access-key-id: ${R2_ACCESS_KEY_ID}
        secret-access-key: ${R2_SECRET_ACCESS_KEY}
```

The rg-auth Dockerfile includes Litestream. Configure the replica in the
entrypoint or as an environment variable.

### Recovery from Crash

The gateway WAL provides crash-durable share delivery. On restart:

1. Gateway reads `share_wal.ndjson`
2. Orphaned pending entries (accepted shares without a forward result) receive
   synthetic `share_forward_result` events with `process_crash_recovery`
   reason_code
3. Normal operation resumes

No manual intervention required. The WAL auto-compacts after
`wal_compaction_threshold` completions (default 1000).

### WAL Write Failure Drains the Gateway

As of v1.1.0 (R-152), any failure to append or fsync a WAL record is fatal. The
gateway logs a structured error with `reason_code = "wal_write_failure"` and
`op = "mark_pending"` or `op = "mark_completed"`, transitions the readiness
probe to draining, broadcasts shutdown over the watch channel, and exits the
main loop. Every active SV2 connection observes the shutdown signal and emits
`DisconnectEvent` with `reason_code = "shutdown_drain"`, so the disconnect
counter will jump by the current connection count on the way out. The pool
stops accepting new shares immediately.

This is the intended behaviour. A silent WAL error leaves accepted shares with
no recovery record and permanently breaks the 1:1 accepted-to-forward-result
join invariant, which costs miners payout credit. Halting and forcing operators
to intervene is safer than silently losing shares.

**Operator playbook when this alert fires:**

1. Check free space on the WAL volume with `df -h` on the path from
   `wal_path`. ENOSPC is by far the most common cause.
2. Check filesystem health (`dmesg | tail`, `journalctl -k | tail`). Read only
   remounts from EIO events also surface as WAL write failures.
3. Confirm the mount is still writable by running `touch $(dirname
   $wal_path)/.probe` as the gateway user.
4. Restart the gateway only after the underlying disk or mount issue is
   resolved. The WAL recovery path on startup replays orphaned pending entries
   as `process_crash_recovery` events, so no shares are lost as long as the WAL
   file itself survived.

**Migration shim:** operators running on known flaky storage (overprovisioned
PVs, misbehaving NFS) can temporarily opt back into the pre-R-152 behaviour by
setting `VELDRA_WAL_WRITE_FAILURE_MODE=accept_silent`. In that mode the gateway
logs the error and continues, matching v1.0.x behaviour. This flag exists for a
single release transition and is scheduled for removal in v1.2.0. Any
environment still relying on it at that point will silently violate the join
invariant and is expected to have fixed its storage layer before then.

---

## Breaking Changes in v1.1.0

### HMAC gateway signature now covers body hash (S-8)

The `gateway_signature_hex` field in `ShareSubmission` is now computed as
`HMAC-SHA256(secret, event_id || SHA256(canonical_body))` where `canonical_body`
is the JSON serialization of the submission with `gateway_signature_hex` set to
the empty string. Previously the signature covered only `event_id`.

Any upstream service that verifies the HMAC signature must be updated before
deploying sv2-gateway v1.1.0. The verification procedure is:

1. Copy the received `gateway_signature_hex` value.
2. Set `gateway_signature_hex` to `""` in the received JSON object.
3. Serialize the object to JSON (canonical form, no extra whitespace).
4. Compute `body_hash = SHA256(canonical_json)`.
5. Decode `event_id_hex` from the object to 32 bytes.
6. Verify `HMAC-SHA256(secret, event_id || body_hash)` matches the copied signature.

Deploying sv2-gateway v1.1.0 against an upstream verifier that uses the old
signature scheme will cause all signature checks to fail.

### Tier rename: observe_free to shadow (S-1)

The `observe_free` tier string is renamed to `shadow` across the entire stack.
A SQLite migration (`v4`) updates existing rows. Any external tooling that
matches on the `observe_free` tier string must be updated to use `shadow`.

## Desktop Signing Key Custody

Two independent cryptographic systems govern the desktop app. Do not confuse them.

| System | Purpose | Where it lives | Rotation procedure |
|---|---|---|---|
| License signing (Ed25519) | Validates `veldra_lic_*` keys entered by operators | Private: `~/.veldra/license-signing.key` + backup. Pubkey list baked into desktop at build time via `VELDRA_LICENSE_PUBKEY` (supports comma-separated list, see ADR-001). | Issue new pubkey, ship desktop release with both old and new pubkey embedded, drop old after one release cycle. |
| Tauri updater signing (rsign) | Signs the auto-update tarball so installed desktops verify authenticity before applying an update | Private: `~/.tauri/reservegrid-updater.key` (password protected) + backup. Pubkey embedded in `services/rg-desktop/tauri.conf.json`. | See `docs/runbooks/tauri-updater-key-rotation.md`. |

Both private keys must exist in at least two durable locations at all times. GitHub Actions secrets are write-only and do not count as a durable copy. Required storage:

1. Primary: local file under `~/.tauri/` or `~/.veldra/` on the operator's machine.
2. Backup: password manager (1Password recommended) or encrypted offline storage.
3. Deployment: GitHub Actions secrets (convenience, not a backup).

Minimum password manager entries for Veldra:

- Veldra Tauri updater signing key (private key contents + password + generation date)
- Veldra license signing key (private key contents + generation date)
- Fly.io API token
- GitHub PAT (if used outside browser session)
- SMTP credentials for rg-auth

Without 1Password or equivalent, a single laptop loss forces emergency key rotation on all systems. With it, recovery is minutes.

Local desktop builds use the wrapper script:

```
scripts/desktop-build.sh dev      # fast, no signing, no updater bundle
scripts/desktop-build.sh release  # full signed release
```

Release mode requires `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` in env. Dev mode requires nothing.

## Upgrade Procedure

### Minor Version Upgrades (1.0.x to 1.0.y)

1. Pull the latest release tag
2. Review the changelog for breaking config changes (there should be none in patch releases)
3. Rebuild images: `docker compose build`
4. Rolling restart: `docker compose up -d --no-deps <service-name>` one service at a time
5. Verify health after each service restart

**Restart order for zero-downtime upgrades:**

1. `pool-verifier` (stateless, fast restart)
2. `template-manager` (stateless)
3. `rg-auth` (SQLite, brief write pause during restart)
4. `rg-dashboard` (stateless)
5. `sv2-gateway` (last, because miners will reconnect)

Restarting sv2-gateway causes all connected miners to disconnect and
reconnect. Schedule this during a low-activity window. Miners that support
automatic reconnection will recover within seconds.

### Major Version Upgrades (1.x to 2.0)

Major versions may include schema changes, new config keys, or reason code
additions. Follow the release notes precisely. Back up all data and config
before upgrading.

---

## Noise Keypair Rotation

Two rotation methods are supported simultaneously:

**SIGHUP (recommended for bare-metal):**

1. Generate a new keypair and write it to the same `noise_keypair_path`
2. Send SIGHUP to the gateway process: `kill -HUP $(pidof sv2-gateway)` or `docker kill -s HUP <container>`
3. Gateway logs confirmation of reload
4. Existing connections continue uninterrupted
5. New connections use the new keypair

**File poll (recommended for containers):**

1. Set `noise_keypair_poll_interval_secs = 300` in gateway config
2. Overwrite the key file at `noise_keypair_path` with the new keypair
3. Gateway detects the file modification time change within the poll interval
4. Same behavior as SIGHUP: existing connections unaffected, new connections use new key

**After rotation:** update the `authority_pubkey` in your miner configuration
to match the new derived public key. Miners that connect with the old key will
fail the Noise handshake and be rejected.

---

## Troubleshooting

### Templates Not Flowing

**Symptom:** `curl http://localhost:8082/latest` returns 404 or stale data.

**Causes:**
1. bitcoind not synced or wallet not loaded
2. template-manager cannot reach bitcoind RPC
3. bitcoind mempool empty (regtest: generate transactions first)

**Fix:** Check template-manager logs for RPC errors. Verify bitcoind is
responding to `getblocktemplate`.

### All Templates Rejected

**Symptom:** Dashboard shows 100% rejection rate.

**Causes:**
1. Policy too strict for current traffic (e.g., `min_total_fees` set higher than
   actual mempool fee totals)
2. `enforce_template_age = true` with clock skew between gateway and bitcoind
3. Stale `authority_pubkey` in gateway config after key rotation

**Fix:** Check the `reason_code` breakdown in Grafana "Rejections by Reason
Code" panel. The reason code tells you exactly which policy rule is firing.
Adjust the corresponding policy threshold in `config/policy.toml`.

### Miners Cannot Connect

**Symptom:** Miners report connection refused or handshake failure.

**Causes:**
1. Port 3333 not exposed or firewalled
2. Wrong `authority_pubkey` in miner config
3. Noise handshake timeout (default 5s, increase `noise_handshake_timeout_ms` for
   high-latency miners)
4. `max_connections_per_ip` exceeded (default 50 in production)

**Fix:** Check gateway logs for handshake errors. Verify the authority pubkey
matches between gateway config and miner config.

### Gateway WAL Growing Unbounded

**Symptom:** `share_wal.ndjson` file size exceeds expectations.

**Causes:**
1. Share forwarding failing (upstream unreachable), preventing completion events
2. Compaction threshold too high

**Fix:** Check `share_upstream` connectivity. Verify `wal_compaction_threshold`
is set (default 1000). The WAL compacts automatically after the threshold is
reached.

### Auth Emails Not Sending

**Symptom:** Users register but never receive verification emails.

**Causes:**
1. SMTP credentials incorrect or missing in `.env`
2. SMTP provider blocking sends (check spam/bounce logs)
3. `VELDRA_AUTH_SMTP_HOST` empty (dev mode: emails print to stdout)

**Fix:** Check rg-auth logs for SMTP errors. In development, emails are
printed to container stdout when SMTP is not configured.

### Grafana Shows No Data

**Symptom:** Dashboard panels show "No data."

**Causes:**
1. Prometheus not scraping targets (check `http://localhost:9091/targets`)
2. Services not exposing metrics on expected ports
3. Datasource not configured (should auto-provision)

**Fix:** Verify all three Prometheus targets are UP in the targets page.
If a target is down, check that the service is running and its metrics port
is accessible within the Docker network.

---

## Security Checklist

Run through this checklist before exposing any service to the internet.

- [ ] All `TODO_SET_*` fields in `.env` are filled with real values
- [ ] No default credentials remain (`reservegrid`, `admin@localhost`, etc.)
- [ ] `VELDRA_LOG_FORMAT=json` (structured logs for production)
- [ ] `VELDRA_ALLOW_INSECURE_VERIFIER=0` (unless single-host deployment)
- [ ] `VELDRA_ALLOW_DROP_OLD_INLINE=0`
- [ ] `VELDRA_ALLOW_REMOTE_VERIFIER=0` (unless verifier is on a separate host with mTLS)
- [ ] Noise keypair is unique to this gateway instance
- [ ] Noise key file permissions are 0400
- [ ] `dev/keys/noise.key` is NOT used outside regtest
- [ ] Grafana anonymous access is disabled (`GF_AUTH_ANONYMOUS_ENABLED=false`)
- [ ] Grafana admin password is changed from the default
- [ ] Firewall exposes only ports 3333 (miners) and 8084 (dashboard) externally
- [ ] All internal service ports (8080, 8081, 8082, 9090, 3030) are not reachable from the internet
- [ ] `VELDRA_AUTH_ALLOWED_ORIGIN` is set to the actual frontend URL, not `*`
- [ ] SMTP is configured for email verification (not printing to stdout)
- [ ] Persistent volume for `./data` is backed up
- [ ] WAL is enabled (`wal_path` points to a persistent volume)

---

## Port Reference

| Port | Service | Protocol | Exposure |
|---|---|---|---|
| 3333 | sv2-gateway | TCP (Noise NX) | Public (miners) |
| 8084 | rg-dashboard | HTTP | Public (operators), put behind HTTPS reverse proxy |
| 8080 | sv2-gateway health/metrics | HTTP | Internal only |
| 8081 | pool-verifier HTTP API | HTTP | Internal only |
| 8082 | template-manager HTTP API | HTTP | Internal only |
| 9090 | pool-verifier TCP (NDJSON) | TCP | Internal only (mTLS for remote) |
| 3030 | rg-auth | HTTP | Internal only (proxied through dashboard) |
| 3000 | Grafana | HTTP | Internal only (or behind auth proxy) |
| 9091 | Prometheus | HTTP | Internal only |
| 18443 | bitcoind RPC (regtest) | HTTP | Internal only |
| 8332 | bitcoind RPC (mainnet) | HTTP | Internal only |

---

## Multi-Gateway Deployment (Active/Standby)

A single sv2-gateway instance can serve thousands of miners but represents a
single point of failure. For production pools that require high availability,
deploy two or more gateway instances behind a TCP load balancer in an
active/standby configuration.

### Architecture Overview

```
                ┌──────────────┐
  Miners ──────>│  TCP Load    │
                │  Balancer    │
                │  (HAProxy /  │
                │   AWS NLB)   │
                └──┬───────┬───┘
                   │       │
            ┌──────▼──┐ ┌──▼──────┐
            │ GW-A    │ │ GW-B    │
            │ (active)│ │(standby)│
            └────┬────┘ └────┬────┘
                 │           │
          ┌──────▼───────────▼──────┐
          │  Shared Backend:        │
          │  pool-verifier          │
          │  template-manager       │
          │  rg-auth                │
          └─────────────────────────┘
```

Each gateway instance runs its own SV2 listener, Noise handshake, and
connection handler stack. All gateway instances connect to the same
pool-verifier, template-manager, and rg-auth backend.

The load balancer routes new miner connections to the active gateway. If the
active gateway fails its health check, the load balancer redirects new
connections to the standby. Existing connections on the failed gateway are lost
and miners reconnect through the load balancer to the surviving instance.

SV2 is a long-lived TCP protocol. Miners hold open connections for hours or
days. The load balancer must operate at L4 (TCP) with connection-level
affinity, not request-level HTTP routing.

### What Is Shared and What Is Per-Instance

| Component | Scope | Notes |
|---|---|---|
| Noise keypair | Per instance | Each gateway generates its own keypair. All instances must use the same `authority_pubkey` so miners configure one authority key. |
| Job ID allocator | Per instance | Each gateway allocates job IDs from its own monotonic counter. The `gateway_instance_id` config field disambiguates share origins in the WAL and upstream relay. |
| Channel state | Per instance | Channel allocation, extranonce assignment, and vardiff state are local to each gateway process. There is no cross-instance channel coordination. |
| WAL | Per instance | Each gateway writes its own `share_wal.ndjson` on its local persistent volume. |
| Readiness state | Per instance | Each gateway reports its own `/readyz` status independently. |
| pool-verifier | Shared | One verifier serves all gateway instances. The verifier accepts multiple TCP streams concurrently. |
| template-manager | Shared | One template source. All gateways poll the same HTTP endpoint. |
| Policy | Shared | Policy is loaded from the verifier, which serves the same policy to all gateways. |
| rg-auth / rg-feed-server | Shared | Auth and feed services are gateway-independent. |

### Load Balancer Configuration

The load balancer must satisfy four requirements:

1. **TCP mode (L4).** SV2 uses a Noise NX encrypted TCP stream. The load
   balancer cannot inspect or modify the payload. Configure as a raw TCP
   passthrough.

2. **Health check against `/readyz`.** Poll each gateway's management HTTP
   endpoint at `health_addr` (default `127.0.0.1:8080`). The `/readyz`
   endpoint returns 200 when the gateway is fully operational or degraded
   (miners can still connect), and 503 when draining or not yet ready.

3. **Connection draining on failure.** When a gateway's health check fails,
   the load balancer should stop routing new connections to that instance but
   allow the TCP drain timeout to expire before forcibly closing existing
   connections. This gives miners time to detect the disconnect and reconnect
   through the load balancer.

4. **Sticky connections (no rebalancing).** SV2 connections are stateful.
   Once a miner is connected to a gateway, that connection must stay on the
   same backend for its entire lifetime. The load balancer routes only new
   connections.

#### HAProxy Example

```
frontend sv2_frontend
    bind *:3333
    mode tcp
    default_backend sv2_gateways

backend sv2_gateways
    mode tcp
    balance leastconn

    # Health check against management API (not the SV2 port).
    # Each gateway must expose health_addr on a routable interface.
    option httpchk GET /readyz
    http-check expect status 200

    # Drain timeout: allow 30s for miners to notice and reconnect.
    timeout server 30s

    server gw-a 10.0.1.10:3333 check port 8080 inter 3s fall 3 rise 2
    server gw-b 10.0.1.11:3333 check port 8080 inter 3s fall 3 rise 2 backup
```

The `backup` keyword on `gw-b` makes it a standby server. HAProxy sends
traffic to `gw-b` only when `gw-a` is marked down. Remove `backup` for
active/active distribution across both gateways.

#### AWS Network Load Balancer

Create a TCP target group on port 3333. Register both gateway instances.
Configure health checks:

| Setting | Value |
|---|---|
| Protocol | HTTP |
| Port | 8080 |
| Path | `/readyz` |
| Healthy threshold | 2 |
| Unhealthy threshold | 3 |
| Interval | 10s |

Set the deregistration delay (drain timeout) to 30 seconds. NLB handles
connection-level stickiness by default for TCP targets.

### Gateway Instance Configuration

Each gateway instance requires a unique `gateway_instance_id` and its own
Noise keypair, but must share the same `authority_pubkey`.

**Instance A (`config/gateway-a.toml`):**

```toml
[gateway]
listen_addr = "0.0.0.0:3333"
health_addr = "0.0.0.0:8080"
noise_keypair_path = "/config/keys/noise-a.key"
authority_pubkey = "SHARED_AUTHORITY_PUBKEY_HEX"
gateway_instance_id = "prod-gw-a"

auto_degrade = true
auto_degrade_after_ms = 10000

[verifier]
verifier_addr = "pool-verifier:9090"
```

**Instance B (`config/gateway-b.toml`):**

```toml
[gateway]
listen_addr = "0.0.0.0:3333"
health_addr = "0.0.0.0:8080"
noise_keypair_path = "/config/keys/noise-b.key"
authority_pubkey = "SHARED_AUTHORITY_PUBKEY_HEX"
gateway_instance_id = "prod-gw-b"

auto_degrade = true
auto_degrade_after_ms = 10000

[verifier]
verifier_addr = "pool-verifier:9090"
```

Both instances point to the same verifier. The `gateway_instance_id` appears
in share WAL entries and upstream relay payloads so downstream systems can
attribute shares to the originating gateway.

The `health_addr` must bind to a routable interface (`0.0.0.0` or a specific
internal IP) so the load balancer can reach it. In single-machine deployments
the default `127.0.0.1:8080` is fine because nothing polls the health endpoint
externally.

### Connection Draining and Failover Timing

When a gateway receives SIGTERM (from the orchestrator, rolling restart, or
manual stop):

1. The gateway sets `readiness.draining = true`.
2. `/readyz` immediately returns 503 with `reason_code: "shutdown_drain"`.
3. The load balancer detects the 503 within its health check interval (e.g.,
   3s for HAProxy, 10s for NLB).
4. The load balancer stops routing new connections to the draining gateway.
5. The gateway broadcasts a shutdown signal to all connection handlers.
6. Each handler exits with `HandlerExit::Shutdown`, closing its miner
   connection cleanly.
7. Miners detect the disconnect and reconnect through the load balancer,
   which routes them to the surviving gateway.

**Total failover time** from gateway stop to miners reconnected:

| Component | Time |
|---|---|
| Gateway sets draining flag | Instant |
| LB detects unhealthy (3s interval, 3 failures) | 9s (HAProxy) |
| Miner detects disconnect | 0s (TCP RST or FIN) |
| Miner reconnects + Noise handshake | 1-3s |
| Channel reopen + first job | < 1s |
| **Total (worst case)** | **~13s** |

During this window miners may submit stale shares that arrive after the
gateway has stopped accepting them. These shares are lost. The window is short
enough that the economic impact is negligible for pools with standard block
intervals.

### Degradation Behavior in Multi-Gateway

When `auto_degrade = true`, each gateway independently monitors its verifier
and enters degraded mode when either signal crosses `auto_degrade_after_ms`:
heartbeat loss (dead link), or verdict starvation while proposals are
outstanding (live link whose verdict service went mute; PB-15/PB-17).
Heartbeat-loss degrades recover on the next heartbeat ack; starvation
degrades recover only when a verdict arrives, so a heartbeating-but-mute
verifier cannot flap the mode. A degraded gateway still returns 200 from `/readyz`
(with `"status": "degraded"` and `"degraded": true` in the JSON body) because
miners should stay connected.

If the load balancer needs to distinguish healthy from degraded and prefer
healthy gateways for new connections, parse the JSON body of the `/readyz`
response:

```
# HAProxy agent-check alternative: use an external script that
# returns "up" or "drain" based on the degraded field.
```

For most deployments this distinction is unnecessary. A degraded gateway is
still serving miners correctly (templates flow without enforcement). Prefer
keeping miners on the degraded gateway rather than forcing a reconnect storm
to the healthy one.

### Monitoring Multi-Gateway Deployments

Each gateway instance exposes its own Prometheus metrics on `health_addr`. Add
both instances as scrape targets:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: sv2-gateway
    static_configs:
      - targets:
          - "10.0.1.10:8080"
          - "10.0.1.11:8080"
        labels:
          cluster: "prod"
```

All metrics include the `gateway_instance_id` label. Grafana dashboards can
filter or aggregate by instance. Key metrics to compare across instances:

| Metric | What to look for |
|---|---|
| `svtwo_connections_active` | Even distribution in active/active, all on one instance in active/standby |
| `svtwo_mode_transitions_total` | Degradation events should correlate across instances (same verifier) |
| `svtwo_vardiff_retarget_up_total` | Per-instance retarget rates indicate hashrate distribution |
| `svtwo_shares_total` | Share volume should track connection distribution |

### Limitations of Active/Standby (v1.1.0)

v1.1.0 supports active/standby with independent gateway instances. It does
not support:

1. **Shared job ID allocation.** Each gateway allocates job IDs independently.
   If both are active simultaneously (active/active), the upstream share
   processor must handle duplicate job IDs disambiguated by
   `gateway_instance_id`.

2. **Share deduplication across instances.** Each gateway deduplicates shares
   within its own process. Two active gateways cannot detect a miner
   submitting the same share to both.

3. **Channel state migration.** When a miner reconnects to a different
   gateway, it must reopen channels from scratch. There is no state transfer
   between gateway instances.

These limitations are acceptable for active/standby where only one gateway
serves miners at a time. Active/active with shared state is scoped for v1.2+
(see EX-053 item D-9).

---

## Support

For deployment assistance, contact support@veldra.org.

For security issues, contact security@veldra.org. Do not open public issues
for security vulnerabilities.
