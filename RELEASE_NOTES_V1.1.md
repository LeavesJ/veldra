# ReserveGrid OS v1.1.0 — Yield

Production readiness release. Extended mining channels and variable difficulty make the gateway compatible with real ASIC firmware for the first time. Automatic mode degradation keeps miners working when the verifier goes down. Eight security and operability improvements harden the authentication and share relay stack. Two breaking changes require coordinated upgrades.

## Extended channels and variable difficulty

The SV2 gateway now accepts extended mining channels (`OpenExtendedMiningChannel` 0x13, `SubmitSharesExtended` 0x1b). Most production ASIC firmware and mining proxies (Braiins OS, firmware-side SRI) require extended channels to connect. Prior to this release those miners were rejected at handshake with `ExtendedChannelUnsupported`.

Extended channels give the miner a larger extranonce space and let it construct its own coinbase. The gateway negotiates `extranonce_size` at channel open, enforcing a minimum of 2 miner-controlled bytes. `NewExtendedMiningJob` delivers the full merkle path and coinbase prefix/suffix instead of a precomputed merkle root. The miner computes its own merkle root from these components.

Variable difficulty adjusts the channel target based on observed share submission rate. The default target is 6 shares per minute with a 120 second retarget interval. Each retarget is capped at 4x adjustment to prevent oscillation. Initial difficulty is seeded from the miner's `nominal_hash_rate` reported at channel open rather than starting at the config floor. Vardiff applies identically to standard and extended channels via the existing `SetTarget` message.

Config fields: `extended_channels_enabled` (default true), `vardiff_enabled` (default true), `vardiff_target_shares_per_min`, `vardiff_retarget_interval_secs`, `vardiff_min_difficulty`, `vardiff_max_difficulty`, `vardiff_max_adjustment_factor`. Prometheus metric: `svtwo_vardiff_retargets_total{direction}`.

## Automatic inline-to-observe degradation

When the verifier heartbeat is lost, the gateway suspends verdict enforcement and flushes all pending templates to miners without blocking. Recovery requires a full `HeartbeatAck` round trip, not just TCP reconnect. The health probe returns `"status":"degraded"` during the window. A config validation warning fires at startup if `auto_degrade_after_ms` is set below the verifier heartbeat interval, which would cause permanent degradation.

Config fields: `auto_degrade` (default true), `auto_degrade_after_ms` (default 10000). Prometheus counter: `svtwo_mode_transitions_total{direction}`.

## Mode transition NDJSON events

Every degradation entry and recovery emits a structured NDJSON event with timestamp, direction, and the count of jobs that flowed without enforcement during the degraded window.

## Legacy auth fallback removal

The static key list in rg-feed-server and the DB-only `validate_key` path in rg-auth are removed. All key validation now requires Ed25519 signature verification. This eliminates the dual code path where one branch could bypass signature checks.

## Multi-gateway deployment documentation

Active/standby gateway deployment guide covering TCP load balancer configuration, health check endpoints, connection draining behavior, and failover timing.

## Tier rename

`observe_free` is renamed to `shadow` across the entire stack. SQLite migration v4 updates existing rows. All Rust constants, TypeScript types, and signed key payloads use the new string. External tooling that matches on the old tier name must be updated before deploying.

## WebSocket auth at handshake

rg-feed-server rejects unauthenticated connections at the tungstenite handshake callback instead of after the first frame. This eliminates a class of resource exhaustion where unauthenticated clients hold open WebSocket connections indefinitely.

## Rate limiter extraction

The per-IP rate limiter from rg-auth is extracted into `reservegrid-common` and wired into the sv2-gateway and rg-feed-server management endpoints. All three services now share one implementation with consistent configuration.

## HMAC secret rotation

SIGHUP triggers a re-read of the share upstream HMAC secret from disk. The secret is held in an `Arc<RwLock<Vec<u8>>>` and swapped atomically. No restart required for secret rotation.

## Management HTTP graceful drain

The health and management HTTP server now participates in the coordinated shutdown sequence via the existing `shutdown_rx` watch channel and `axum::serve(...).with_graceful_shutdown()`.

## License key generation

Production Ed25519 keypair generated and verified. `VELDRA_LICENSE_SIGNING_KEY` set on Fly.io for rg-auth. `VELDRA_LICENSE_PUBKEY` available for rg-feed-server and rg-desktop builds.

## Devtools gating

Tauri devtools are gated behind `cfg(feature = "devtools")` which auto-enables only in debug builds. The `build.rs` reads the Cargo `PROFILE` env var rather than `cfg!(debug_assertions)` (which always evaluates as debug inside build scripts). Release builds strip devtools entirely.

## HMAC body hash

The `gateway_signature_hex` field in `ShareSubmission` now covers `HMAC-SHA256(secret, event_id || SHA256(canonical_body))` where `canonical_body` is the JSON serialization with `gateway_signature_hex` set to the empty string. Previously the signature covered only `event_id`. This prevents replay attacks with modified request bodies.

## Infrastructure

Fly.io deployment scaffolding for rg-feed-server (`fly.toml`, app `rg-feed-server-veldra`). Actual deployment is gated on provisioning a bitcoind RPC endpoint that supports `getblocktemplate`, deferred until first observe customer confirms.

## Breaking changes

Two changes require coordinated upgrades. See the deployment runbook for detailed procedures.

1. **HMAC body hash.** Upstream services that verify `gateway_signature_hex` must be updated to reconstruct the body hash before signature verification. Deploying sv2-gateway v1.1.0 against the old verification scheme causes all signature checks to fail.

2. **Tier rename.** The `observe_free` tier string is replaced by `shadow` across the entire stack. External tooling matching on `observe_free` must be updated.

## Known limitations

- rg-feed-server deployment pending a bitcoind RPC provider (deferred until first observe customer)
- Rate limiter state remains in-process only (shared state via Redis deferred to v1.2)
- Sustained multi-hour load testing and two-host network latency benchmarks have not been performed

## Upgrade from v1.0.2

1. Update upstream share verifiers to use the new HMAC body hash signature scheme before deploying the gateway (see deployment runbook)
2. Update any external tooling that references the `observe_free` tier to use `shadow`
3. Review new extended channel and vardiff config fields in gateway TOML
4. Rebuild and deploy: `docker compose build && docker compose up -d`
5. Verify health: `curl -s http://localhost:8081/readyz | jq .`

See [CHANGELOG.md](https://github.com/LeavesJ/ReserveGrid-OS/blob/main/CHANGELOG.md) for the complete list of changes.
