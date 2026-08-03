# Deployment Profiles

Production configuration templates. Copy and customize before deploying.

## Files

| File | Purpose |
|---|---|
| `gateway-prod.toml` | SV2 gateway config with hardened defaults (per-IP cap, fail-closed upstream, WAL, no regtest target) |
| `policy-prod.toml` | Policy with all enforcement flags enabled (stale rejection, weight ratio, empty templates, coinbase zero) |
| `env.prod.example` | Environment template with no default credentials and structured JSON logging |

## Usage

1. Copy `env.prod.example` to `.env` and fill every `TODO_SET_*` field.
2. Generate a fresh Noise keypair: `reservegrid keygen --noise > /path/to/noise.key`
3. Set `authority_pubkey` in `gateway-prod.toml` to the derived x-only public key.
4. Mount the config files into your containers (replace `dev/` volume mounts with `deploy/`).
5. For multi-instance deployments, generate a unique keypair per gateway instance.

## Profile Comparison

| Setting | dev/ | deploy/ (prod) |
|---|---|---|
| `upstream_failure_policy` | `fail_open` | `fail_closed` |
| `max_connections_per_ip` | 0 (unlimited) | 50 |
| `ntime_elapsed_slack_seconds` | 30 (regtest) | 10 (mainnet) |
| `channel_target_hex` | all-FF (every hash passes) | omitted (real difficulty) |
| `wal_path` | disabled | `/data/share_wal.ndjson` |
| `noise_keypair_poll_interval_secs` | 0 (disabled) | 300 (5 min check) |
| `enforce_template_age` | false | true (5s stale) |
| `enforce_weight_ratio` | false | true |
| `reject_empty_templates` | false | true |
| `reject_coinbase_zero` | false | true |
| `VELDRA_LOG_FORMAT` | pretty | json |
| `VELDRA_AUTH_TRUST_PROXY` | 0 | 1 |
| `VELDRA_VERIFIER_MAX_CONNECTIONS` | 256 in `docker-compose.yml` (benchmark stack) | 32 (shipped default) |
| `VELDRA_VERIFIER_MAX_CONNECTIONS_PER_IP` | 256 in `docker-compose.yml` (100 conns from one host) | 8 (shipped default) |
| `VELDRA_VERIFIER_IDLE_TIMEOUT_SECS` | 60 (shipped default) | 60 (shipped default) |
