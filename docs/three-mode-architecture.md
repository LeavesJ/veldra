# Three Mode Architecture Spec

**Status:** Implemented
**Version:** v1.1.0
**Date:** 2026-04-14 (v2.0 Invariant Shield section added 2026-04-29 per ADR-002 Phase 1 #4b)

## Overview

ReserveGrid OS operates in three deployment modes. Each mode represents a distinct trust level, data source, and feature surface. The same binary stack powers all three modes. A single config key (`mode = "shadow" | "observe" | "inline"`) selects the active mode at startup.

## Mode Summary

```
Shadow  → free,  demo feed,       limited dashboard,  no enforcement
Observe → paid,  reference feed,  full dashboard,     log-only verdicts
Inline  → prod,  operator bitcoind, full dashboard,   active enforcement
```

## Data Flow Per Mode

### Shadow

```
rg-demo-feed (Veldra-hosted, public)
      │  WebSocket (unauthenticated)
      ▼
rg-feed-adapter (operator-side)
      │  bitcoind JSON-RPC impersonation
      ▼
template-manager
      │  TCP TemplatePropose
      ▼
pool-verifier (observe-only verdicts)
      │
      ▼
rg-dashboard (limited features)
```

### Observe

```
rg-feed-server (Veldra-hosted, authenticated)
      │  WebSocket (license key auth)
      ▼
rg-feed-adapter (operator-side)
      │  bitcoind JSON-RPC impersonation
      ▼
template-manager
      │  TCP TemplatePropose
      ▼
pool-verifier (observe-only verdicts)
      │
      ▼
rg-dashboard (full features)
```

### Inline

```
operator bitcoind (operator-owned)
      │  bitcoind JSON-RPC (native)
      ▼
template-manager
      │  TCP TemplatePropose
      ▼
pool-verifier (enforcing verdicts)
      │
      ▼
sv2-gateway ←→ miners
      │
      ▼
rg-dashboard (full features)
```

## v2.0 Invariant Shield (ADR-002)

The pool-verifier carries a re-derivation pass that runs after policy
checks but before verdict emission. The shield deserializes the raw
block bytes the gateway shipped with the template, re-derives the
consensus quantities the gateway declared, and rejects on disagreement
with a canonical `v2_invariant_*` reason code.

### Where the shield sits

Inside the pool-verifier process, between template ingress and
verdict emission:

```
template ingress
      │
      ▼
basic validity (version, prev_hash)
      │
      ▼
template constraints (tx count, fees, weight ratio)
      │
      ▼
safety constraints (template age, sigops budget)
      │
      ▼
v2.0 Invariant Shield   ◄── ADR-002 Phase 1 #4b
      │
      ▼
verdict emission (Accepted | Rejected{reason_code, detail})
```

Earlier policy verdicts short-circuit before the shield runs, so the
shield never overrides a prior rejection. When `raw_block_hex` is
absent on the wire the shield is skipped silently and the verifier
increments `verifier_shield_skipped_total` to make Phase 1 rollout
coverage observable.

### Outcome ladder

The shield emits one of three outcomes per template:

- **Skipped**: the template omitted `raw_block_hex`. The verifier did
  not run any re-derivation. Counted via `verifier_shield_skipped_total`.
- **Agreed**: every wired invariant matched its declared value. The
  template proceeds to verdict emission with whatever the prior policy
  layers decided.
- **Rejected**: at least one invariant disagreed. First violation wins;
  the verdict carries the matching `v2_invariant_*` reason code and a
  human-readable detail string.

### Wired invariants (20 of 20)

Phase 1 #4b wired eleven of the eighteen checks: ten invariants split
into Tier 1 (critical) and Tier 2 (high), plus the decode-failed
structural fault path. Phase 1.5 wired the remaining seven Tier 3
belt-and-suspenders checks, completing the ADR-002 check set.

PB-20 then added a nineteenth, `v2_invariant_coinbase_prevout_not_null`,
widening the ratified table rather than completing it (ADR-002
Amendment 1). It asserts `txdata[0]` really is a coinbase, which is the
precondition every `skip(1)` "non-coinbase" derivation had assumed
without checking.

PB-21 added a twentieth, `v2_invariant_coinbase_value_exceeds_max`
(ADR-002 Amendment 2). It bounds coinbase value by Bitcoin MoneyRange,
per output and on the total. Nothing in the workspace bounded it
before, and the coinbase output values come straight off the attacker
controlled `raw_block_hex`.

**Tier 1 (CRITICAL, direct attack vectors against pool revenue or
consensus rejection)**

| Reason code | What it catches |
| --- | --- |
| `v2_invariant_coinbase_value_mismatch` | Declared coinbase output sum disagrees with re-derived sum from the raw block. Revenue theft. |
| `v2_invariant_coinbase_height_mismatch` | Declared `block_height` disagrees with the BIP-34 height encoded in the coinbase script. Causes consensus rejection. |
| `v2_invariant_merkle_root_mismatch` | Header `merkle_root` disagrees with the merkle root computed over the body. Broken block, miners waste hashpower. |
| `v2_invariant_witness_commitment_mismatch` | Coinbase OP_RETURN witness commitment disagrees with the BIP-141 commitment computed over witness root and reserved value. Segwit miners reject the block. |
| `v2_invariant_tx_count_mismatch` | Declared `tx_count` disagrees with the actual count in the body. Consistency floor that catches gross tampering early. |

**Tier 2 (HIGH, resource exhaustion vectors and operational-correctness gaps)**

| Reason code | What it catches |
| --- | --- |
| `v2_invariant_template_weight_mismatch` | Declared `template_weight` disagrees with re-derived block weight. |
| `v2_invariant_sigops_mismatch` | Declared `total_sigops` disagrees with re-derived legacy sigop count. |
| `v2_invariant_coinbase_sigops_mismatch` | Declared `coinbase_sigops` disagrees with re-derived count restricted to the coinbase tx. |
| `v2_invariant_witness_commitment_missing` | Block has segwit transactions but the coinbase has no BIP-141 commitment in any OP_RETURN output. |
| `v2_invariant_coinbase_bip34_missing` | Coinbase script does not begin with a valid BIP-34 height push. |

Plus structural fault paths: `v2_invariant_decode_failed` on bad hex
or unparseable bytes, and the `Skipped` path noted above.

**Tier 3 (belt-and-suspenders, standalone consensus ceilings; wired
in Phase 1.5)**

These run after the Tier 1+2 checks, in ADR-002 table order, and need
no declared field: each one reads only the parsed block.

```
v2_invariant_coinbase_script_length     coinbase scriptSig 2..=100 bytes (bad-cb-length)
v2_invariant_coinbase_output_count      coinbase has at least one output
v2_invariant_weight_exceeds_max         total weight <= 4_000_000 WU
v2_invariant_sigops_exceed_max          legacy sigops x4 <= 80_000 sigop cost
v2_invariant_coinbase_value_exceeds_max coinbase output values and total <= MAX_MONEY
v2_invariant_nontcb_null_prevout        non-coinbase txs do not have null prevouts
v2_invariant_coinbase_prevout_not_null  txdata[0] IS a coinbase: one input, null prevout
v2_invariant_header_version_low         header.version >= 4 (BIP-65 floor)
v2_invariant_duplicate_tx               no duplicate txid in the block body
```

### Mode interaction

The shield runs in all three modes. The verdict it produces is
treated according to the mode:

- **Shadow**: shield rejections appear in `template_verdict` events
  and on the dashboard, but no template flow is gated. The mode
  exists to surface coverage gaps and false positives before they
  matter.
- **Observe**: same as Shadow. Shield rejections are observed,
  not enforced.
- **Inline**: shield rejections gate the template. A rejected
  template never reaches `sv2-gateway`, miners never receive jobs
  derived from the rejected template.

### Threat model boundary

The shield catches two attacker classes:

1. **Internal raw_block tampering.** The raw block bytes contain a
   header, a coinbase, and a body that must be internally consistent.
   If header.merkle_root disagrees with the body merkle, or the
   coinbase OP_RETURN witness commitment disagrees with the
   wtxid-tree commitment, the shield rejects.
2. **TemplatePropose vs raw_block mismatches.** The gateway sends
   declared values (coinbase_value, tx_count, block_height, etc.)
   alongside the raw block. If the declared values disagree with what
   re-derivation from the bytes shows, the shield rejects.

The shield does NOT catch one attacker class:

3. **Consistent template-manager tampering.** A malicious or
   compromised template-manager can produce a TemplatePropose where
   both the declared values and the raw_block bytes are tampered in
   a way that keeps internal consistency. The shield sees agreement
   on every wired invariant and emits Agreed. ADR-002 explicitly
   names this gap. Phase 2 closes it by cross-verifying against an
   independent mempool ground truth (rg-feed-server's bitcoind RPC),
   so that the shield can detect when the template's claimed
   transaction set differs from what the network mempool actually
   contains.

### Phase 2 Class M check (ADR-003, shipped 2026-04-30)

The verifier owns its own `mempool_view` populated by a tokio task
that polls `getrawmempool` against an operator bitcoind every
`[policy.mempool] poll_interval_secs` seconds (default 10). The
view carries a `MempoolState` of `Fresh`, `Stale`, or `Degraded`,
gated by `max_stale_secs` (default 60) per the fail-stale state
machine in ADR-003 D3. When `[policy.mempool] enforce = true`,
`check_invariant_shield_with_mempool` runs after the Class S and
Class D chain, comparing the template's non-coinbase txids
(`rg_consensus::template_txids`) against the snapshot. Templates
whose unknown-tx ratio exceeds `tolerance_pct` (default 4.0) emit
`v2_invariant_mempool_tolerance_exceeded` with up to 10
representative unknown txids in the verdict detail string. When the
view is `Degraded`, the Class M check is skipped and the template
falls through to Phase 1 behavior, recorded as a
`verifier_phase2_degraded_total` increment so dashboards can alert
on extended bitcoind RPC outages. Per-tx detail mode is enabled by
`[policy.mempool] per_tx_detail = true` (default `false`); when
set, the rejection detail string carries every unknown txid in the
canonical `sample=[…]` field rather than the bounded sample of up
to 10 representative txids. Wire format stays 1:1, dashboards keep
parsing the same `sample=` field. Per-tx detail mode is intended
for forensics and v3.x selfish-mining detection downstream; default
deployments leave it off to keep verdict log line lengths
predictable.

### Metrics

- `verifier_shield_skipped_total` (counter): incremented once per
  template where the shield ran but `raw_block_hex` was absent.
  Drives the Phase 1 rollout coverage dashboard. As gateways are
  upgraded to ship raw block bytes, this counter trends to zero.
- `verifier_verdicts_total{reason_code, accepted}` (existing counter
  vector): every shield rejection appears here keyed off the canonical
  `v2_invariant_*` reason code. Dashboards can filter to the
  `v2_invariant_` prefix to surface shield-specific rejection rates
  separately from policy rejections.
- `verifier_mempool_view_age_seconds` (gauge): seconds since the
  most recent successful `getrawmempool` refresh. Alerts past
  `max_stale_secs` indicate the view is fail-stale.
- `verifier_mempool_view_size` (gauge): current snapshot size.
  Sanity check that the polling task is feeding the view.
- `verifier_phase2_checks_total{result}` (counter vector): result
  in `agreed`, `rejected`, `skipped`, `stale`. Dashboards key Phase
  2 acceptance rate off this label.
- `verifier_phase2_degraded_total` (counter): increments on every
  verdict served while the view is `Degraded`. Operator alert
  threshold for bitcoind RPC outage longer than `max_stale_secs`.

## New Services

### rg-demo-feed

Lightweight Veldra-hosted service that streams synthetic but realistic Bitcoin template data over WebSocket. Purpose is to give shadow users a compelling first impression of what ReserveGrid flags.

**Hosting:** Veldra infrastructure (demo.veldra.org or feed-demo.veldra.org)
**Auth:** None. Public endpoint.
**Protocol:** WebSocket, NDJSON frames.

**What it streams:**

Every frame is one of two types, matching the two bitcoind RPCs that template-manager calls:

```json
{"type": "blocktemplate", "data": { ... GBT-shaped response ... }}
{"type": "mempoolinfo", "data": { ... getmempoolinfo-shaped response ... }}
```

**Data characteristics:**
- Synthetic transactions with realistic fee distributions
- Curated edge cases that trigger policy detections:
  - Fee anomalies (total fees below minimum, average fee below tier thresholds)
  - Sigops budget warnings (templates near the sigops limit)
  - Weight ratio violations (templates exceeding configured weight ratio)
  - Stale template scenarios (high template age)
  - Empty template injection (zero transaction templates)
  - Zero coinbase templates
- Block height increments at realistic intervals (roughly every 10 minutes)
- Prev hash changes on each new block
- Deterministic seed option for reproducible demos

**Implementation:** Rust binary using tokio + tungstenite. Single binary, stateless. Reads a scenario manifest (TOML) that defines the sequence of templates and edge cases. Can also run in "live loop" mode cycling through scenarios indefinitely.

**Workspace crate:** `services/rg-demo-feed/`

### rg-feed-server

Veldra-hosted service that streams real mainnet Bitcoin data over WebSocket. This is the paid observe-mode data source.

**Hosting:** Veldra infrastructure (feed.veldra.org)
**Auth:** License key validated on WebSocket handshake.
**Protocol:** WebSocket, NDJSON frames. Same frame format as rg-demo-feed.

**What it streams:**
- Live `getblocktemplate` responses from a Veldra-operated mainnet bitcoind
- Live `getmempoolinfo` snapshots
- Data is IDENTICAL to what the operator's own bitcoind would produce

**Auth flow:**
1. Operator registers at veldra.org, gets approved, receives a signed license key (format: `veldra_lic_<base64url_payload>.<base64url_signature>`)
2. Operator sets `VELDRA_FEED_LICENSE_KEY` in their local config (same key used for OS tier gating)
3. rg-feed-adapter connects to feed.veldra.org and sends key in the WebSocket handshake header (`Authorization: Bearer <key>`)
4. rg-feed-server validates key by verifying the Ed25519 signature and checking that the embedded tier is >= `observe_paid`
5. On success, streaming begins. On failure, connection closes with reason.

**Backend data source:** A dedicated mainnet bitcoind node operated by Veldra. Polls `getblocktemplate` and `getmempoolinfo` at configurable interval (default: 2 seconds) and fans out to all connected WebSocket clients.

**Rate limiting:** Per-key connection limit (1 concurrent connection per license key). Prevents key sharing.

**Workspace crate:** `services/rg-feed-server/`

### rg-feed-adapter

Operator-side binary that translates WebSocket feed data into bitcoind JSON-RPC responses. Runs locally alongside template-manager and masquerades as a bitcoind node.

**Purpose:** template-manager already knows how to poll bitcoind via JSON-RPC. The adapter speaks that same interface so template-manager requires zero code changes regardless of data source.

**Interface:**
- Listens on a local HTTP port (default: 127.0.0.1:18444)
- Responds to JSON-RPC method `getblocktemplate` with the latest template from the feed
- Responds to JSON-RPC method `getmempoolinfo` with the latest mempool snapshot from the feed
- All other RPC methods return a clean error

**Configuration:**

```toml
[adapter]
listen = "127.0.0.1:18444"
feed_url = "wss://demo.veldra.org/ws"   # shadow
# feed_url = "wss://feed.veldra.org/ws" # observe
license_key = ""                         # empty for shadow, required for observe
```

Env var overrides:
- `VELDRA_FEED_URL` → feed_url
- `VELDRA_FEED_LICENSE_KEY` → license_key
- `VELDRA_ADAPTER_LISTEN` → listen

**Behavior:**
- Connects to the feed WebSocket on startup
- Buffers the latest `blocktemplate` and `mempoolinfo` frames in memory
- When template-manager polls `getblocktemplate`, adapter returns the buffered template
- When template-manager polls `getmempoolinfo`, adapter returns the buffered mempool snapshot
- Reconnects automatically on WebSocket disconnect (exponential backoff, max 30s)
- Health endpoint at `/health` returns `{"status":"ok","feed_connected":true,"last_template_age_ms":1234}`

**Auth handling:**
- If `license_key` is non-empty, sends it in the WebSocket handshake `Authorization` header
- If empty, connects without auth (shadow mode demo feed)

**Workspace crate:** `services/rg-feed-adapter/`

## Mode Configuration

### Config Shape

The mode is set in the service config files. Each service reads a `mode` field from its TOML config or from the `VELDRA_MODE` env var.

```toml
# Top-level mode selector. Affects all services.
mode = "shadow"  # or "observe" or "inline"
```

**Env var:** `VELDRA_MODE=shadow|observe|inline`

### What Mode Controls

| Behavior | Shadow | Observe | Inline | Dev |
|---|---|---|---|---|
| Data source | rg-demo-feed (public) | rg-feed-server (authenticated) | operator bitcoind | any (stack-dependent) |
| template-manager target | rg-feed-adapter | rg-feed-adapter | bitcoind directly | any |
| Verifier enforcement | observe-only | observe-only | enforcing | stack-dependent |
| Gateway active | no | no | yes | stack-dependent |
| Dashboard policy editing | disabled | enabled | enabled | enabled |
| Dashboard settings mutation | disabled | enabled | enabled | enabled |
| Dashboard CSV export | disabled | enabled | enabled | enabled |
| Dashboard dry-run preview | disabled | enabled | enabled | enabled |
| Verdict persistence (WAL) | in-memory only | disk WAL | disk WAL | stack-dependent |
| License key required | no | yes | no (own infra) | dev passkey |
| Miner connections accepted | no | no | yes | stack-dependent |

**Dev mode** is not a backend deployment mode. It is a client-side override activated by the developer passkey (compile-time `--features dev-passkey`). The backend services still run in whichever mode the compose stack configures. Dev mode unlocks all dashboard UI features regardless of the backend mode, and displays a purple DEV badge in the top bar.

### Dashboard Feature Gating

The dashboard reads `VELDRA_MODE` at startup and applies feature gates in the frontend. When the license tier is `dev` (developer passkey), the frontend overrides the deploy mode to `dev` and unlocks all features.

**Shadow (limited):**
- Overview: full (read-only KPIs, acceptance rate, recent verdicts)
- Verdicts: view-only (no CSV export, no search)
- Templates: view-only (current template inspection)
- Miners: hidden (no miners in shadow/observe)
- Policy: view-only (shows current policy, no edit, no dry-run)
- Settings: all read-only
- LicenseGate requires `rg-feed-adapter` healthy before granting access

**Observe (full except miners):**
- Overview: full
- Verdicts: full (CSV export, search, filters)
- Templates: full
- Miners: hidden (no miners in observe)
- Policy: full (edit, apply, dry-run preview)
- Settings: editable sections enabled
- Note: Miners page hidden because observe mode has no gateway/miners

**Inline (full):**
- All features enabled
- Miners page visible (connected workers, hashrate, shares)

**Dev (all unlocked, developer passkey only):**
- All features enabled regardless of backend mode
- Miners page visible (may show no data if gateway is not running)
- Purple badge in top bar
- Not a backend mode; overrides frontend gating only

### Verifier Mode Behavior

pool-verifier already has a `dash_mode` concept. This maps to:

| VELDRA_MODE | Verifier behavior |
|---|---|
| shadow | Log verdicts, do not forward to gateway, in-memory only |
| observe | Log verdicts, persist to WAL, do not forward to gateway |
| inline | Log verdicts, persist to WAL, forward accept/reject to gateway |

### Gateway Behavior

| VELDRA_MODE | Gateway behavior |
|---|---|
| shadow | Does not start |
| observe | Does not start |
| inline | Full operation: accepts miners, broadcasts jobs, processes shares |

## Operator Journey

### Shadow (zero to first verdict in under 5 minutes)

1. Download ReserveGrid OS binary bundle from veldra.org
2. Run `rg-feed-adapter` (defaults to demo feed, no config needed)
3. Run `template-manager` pointed at the adapter (`rpc_url = "http://127.0.0.1:18444"`)
4. Run `pool-verifier` with `mode = "shadow"`
5. Run `rg-dashboard` with `mode = "shadow"`
6. Open browser to localhost:8084
7. See synthetic templates flowing, verdicts appearing, policy detections highlighted

No bitcoind. No account. No license key. No miners.

### Observe (evaluate with real mainnet data)

1. Register at veldra.org, get admin approval, receive signed license key via email (or retrieve from /license/)
2. Configure rg-feed-adapter: `feed_url = "wss://feed.veldra.org/ws"`, `license_key = "veldra_lic_..."`
3. Set `mode = "observe"` in all service configs
4. Start the stack (same binaries as shadow)
5. See real mainnet templates, real verdicts, real policy behavior
6. Edit policy, run dry-runs, tune thresholds against live data
7. Export verdict history for analysis

### Inline (production enforcement)

1. Stop rg-feed-adapter (no longer needed)
2. Point template-manager at operator's own bitcoind: `rpc_url = "http://bitcoind:8332"`
3. Set `mode = "inline"` in all service configs
4. Start the full stack including sv2-gateway
5. Connect miners to the gateway
6. ReserveGrid now enforces policy on live templates with real hashrate

## Feed Protocol Spec

### Wire Format

Both rg-demo-feed and rg-feed-server use the same wire format:

- Transport: WebSocket (wss://)
- Framing: One NDJSON line per WebSocket text message
- Each message has a `type` field and a `data` field

### Message Types

**`blocktemplate`** — mirrors bitcoind `getblocktemplate` response shape:

```json
{
  "type": "blocktemplate",
  "ts": 1741500000,
  "data": {
    "version": 536870912,
    "previousblockhash": "000000000000000000023a...",
    "transactions": [
      {
        "data": "02000000...",
        "txid": "abc123...",
        "hash": "def456...",
        "fee": 15000,
        "sigops": 4,
        "weight": 1200
      }
    ],
    "coinbaseaux": {"flags": ""},
    "coinbasevalue": 312500000,
    "coinbasetxn": {
      "data": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff",
      "sigops": 1
    },
    "target": "000000000000000000047...",
    "mintime": 1741499900,
    "curtime": 1741500000,
    "bits": "17034219",
    "height": 890001,
    "default_witness_commitment": "6a24aa21a9ed...",
    "sizelimit": 1000000,
    "sigoplimit": 80000,
    "weightlimit": 4000000,
    "rules": ["segwit"],
    "capabilities": ["proposal"],
    "vbavailable": {},
    "vbrequired": 0,
    "longpollid": "000000000000000000023a...1741500000",
    "mutable": ["time", "transactions", "prevblock"],
    "noncerange": "00000000ffffffff"
  }
}
```

**`mempoolinfo`** — mirrors bitcoind `getmempoolinfo` response shape:

```json
{
  "type": "mempoolinfo",
  "ts": 1741500000,
  "data": {
    "loaded": true,
    "size": 45231,
    "bytes": 28419832,
    "usage": 112847392,
    "total_fee": 2.45,
    "maxmempool": 300000000,
    "mempoolminfee": 0.00001000,
    "minrelaytxfee": 0.00001000
  }
}
```

**`heartbeat`** — keep-alive, sent every 30 seconds:

```json
{
  "type": "heartbeat",
  "ts": 1741500000
}
```

### Handshake

1. Client connects to WebSocket endpoint
2. If authenticated feed: client sends `Authorization: Bearer <license_key>` in HTTP upgrade headers
3. Server validates (or skips validation for demo feed)
4. Server sends initial `blocktemplate` and `mempoolinfo` immediately
5. Subsequent messages sent as new data arrives

### Error Codes

Connection close reasons (WebSocket close codes):

| Code | Reason |
|---|---|
| 4001 | invalid_license_key |
| 4002 | license_expired |
| 4003 | concurrent_connection_limit |
| 4004 | feed_unavailable |

## Workspace Layout

```
services/
  rg-demo-feed/          # synthetic demo data server
    Cargo.toml
    Dockerfile
    src/
      main.rs
      scenarios.rs        # scenario functions (normal, low_fees, high_sigops, etc.)
    scenarios/            # reserved for future TOML scenario manifests (currently empty)

  rg-feed-server/        # mainnet reference feed server
    Cargo.toml
    Dockerfile
    src/
      main.rs

  rg-feed-adapter/       # local WebSocket-to-RPC adapter
    Cargo.toml
    Dockerfile
    src/
      main.rs
    config/
      shadow.toml         # pre-configured for demo feed
      observe.toml        # pre-configured for reference feed

  template-manager/      # polls bitcoind (or adapter) via JSON-RPC
  pool-verifier/         # reads VELDRA_MODE for enforcement behavior
  sv2-gateway/           # skips startup when mode != inline
  rg-dashboard/          # React SPA with auth, feature gating based on VELDRA_MODE
  rg-auth/               # user auth, license key model, admin approval
  rg-protocol/           # shared protocol types
```

## Implementation Order

All items below are complete as of 2026-03-10.

1. **rg-feed-adapter** — DONE. Shadow and observe both work with the existing stack. template-manager needs zero changes.
2. **rg-demo-feed** — DONE. Synthetic data with six curated edge case scenarios coded in `scenarios.rs`.
3. **Mode gating in pool-verifier and sv2-gateway** — DONE. Enforcement behavior per mode.
4. **Dashboard feature gating** — DONE. React SPA reads VELDRA_MODE, gates UI accordingly. Auth flow with registration, email verification, and admin approval.
5. **rg-feed-server** — DONE. Wraps a real mainnet bitcoind for observe mode.
6. **License key model in rg-auth** — DONE. Key generation produces signed `veldra_lic_<base64url_payload>.<base64url_sig>` format (EX-046, EX-047). Ed25519 signing key loaded from `VELDRA_LICENSE_SIGNING_KEY` Fly secret. Validation endpoint verifies signature, expiry, and revocation status. Old `veldra_<hex>` format retired.

## Version Targets

All work in this spec is v1.0.0 scope. The three mode architecture, feed services, mode gating, and dashboard feature gates are pre-release design that must land before the initial publish.

- **v1.0.0:** rg-feed-adapter, rg-demo-feed, rg-feed-server, mode gating across all services, dashboard feature gates. Shadow, observe, and inline all functional.
- **v1.0.1:** Security hardening (111 findings across 14 services, done), unified signed license key format (EX-046/047/048, rg-auth done, rg-feed-server done), desktop key persistence (done), website license page copy-to-clipboard (done), auth.veldra.org deployment (done).
- **v1.0.2:** Config.rs unsafe lint fix, dev passkey bypass (SHA-256 hashed, debug-only), in-app auto-updater (Tauri updater + Settings card + tray menu), stale-diff bug fix across all 4 dashboard save handlers, version bumps, website content refresh.
- **v1.1.0:** Automatic mode degradation (inline→observe on verifier unreachable), extended channels + vardiff (PB-6), full per-IP rate limiter module, gateway Phase 1, policy model economic improvements. Shadow readiness gate (LicenseGate blocks access when shadow feed services absent). Dev deploy mode (purple badge, all features unlocked via dev passkey tier). Multi-pubkey license validation (ADR-001). `feed_adapter_url` dashboard health probe.

## Risks and Edge Cases

1. **Feed adapter latency.** The adapter adds one hop between the feed and template-manager. If the adapter buffers stale data, template-manager will evaluate old templates. Mitigation: adapter health endpoint exposes `last_template_age_ms`. template-manager's stale template detection already handles this.

2. **Demo feed realism.** If the synthetic data is too clean, operators will not see value. If it's too noisy, it will look fake. Mitigation: curate scenarios based on real mainnet anomalies observed during testing. Version the scenario manifests.

3. **Feed server as single point of failure for observe.** If feed.veldra.org goes down, observe-mode operators lose data. Mitigation: adapter reconnects automatically. Dashboard shows "feed disconnected" state. Operators already understand this is an evaluation mode, not production.

4. **License key leaking.** An operator could share their key. Mitigation: one concurrent connection per key. Server-side connection tracking.

5. **Mode drift.** If services disagree on mode (e.g. verifier thinks inline, gateway thinks observe), behavior is undefined. Mitigation: all services read `VELDRA_MODE` from the same env var. Dashboard health page shows mode per service.
