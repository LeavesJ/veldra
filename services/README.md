# Veldra ReserveGrid OS (Prototype)

• This repo contains a prototype of the Veldra ReserveGrid OS for Bitcoin mining pools.

• The system is three services:

1. **pool-verifier**  
   Evaluates block templates against a policy and returns accept or reject.

2. **template-manager**  
   Pulls templates from a backend (bitcoind or Stratum bridge), sends them to the verifier, and exposes HTTP views of templates and mempool.

3. **sv2-bridge**  
   A fake Stratum style bridge that streams synthetic `TemplatePropose` messages for testing.

• Everything runs on regtest and is wired through simple TCP plus HTTP.

-----------------------------------------------------------------------------

## 1. Concept

### 1.1 What the verifier actually does

• The verifier receives `TemplatePropose` messages:

- `block_height` 
- `prev_hash`
- `coinbase_value`
- `tx_count`
- `total_fees`

• It then:

1. Fetches current mempool load from `template-manager` `/mempool` (if configured). 

2. Chooses a fee tier based on mempool `tx_count`:

    - `tx_count` <= `low_mempool_tx` → **Low** tier  
    - `low_mempool_tx` < `tx_count` < `high_mempool_tx` → **Mid** tier  
    - `tx_count` >= `high_mempool_tx` → **High** tier  
    - If mempool hint is missing, it falls back to a default tier (currently treated as mid in tests).

3. Maps tier to a required minimum average fee per transaction:

    - Low tier → `min_avg_fee_lo`  
    - Mid tier → `min_avg_fee_mid`  
    - High tier → `min_avg_fee_hi`

4. Computes the template average fee:

    `avg_fee` = `total_fees` / `tx_count`          (0 if tx_count == 0)

5. Accepts the template if: 

    `avg_fee` >= `min_avg_fee_used`
    &
    other basic constraints such as `max_tx_count` are satisfied.

6. Logs each decision as LoggedVerdict which includes:

    - `id`
    - `height`
    - `total_fees`
    - `accepted`
    - `reason` (text form of the enum)
    - `min_avg_fee_used`
    - `fee_tier` (low, mid, high)
    - `timestamp`

    These logs are summarized at `/stats`.

### 1.2 PolicyConfig Overview

• `PolicyConfig` lives in `services/pool-verifier/src/policy.rs`.

• Important fields: 

- `protocol_version`
- `min_total_fees`
- `max_tx_count`

• Dynamic fee field: 

- `low_mempool_tx`
- `high_mempool_tx`

• Fee floors (sats per transaction):

- `min_avg_fee_lo`
- `min_avg_fee_mid`
- `min_avg_fee_hi` 

• Core helper in policy: 

    fn effective_min_avg_fee_dynamic(
        &self,
        mempool_tx_count: Option<u64>,
    ) -> (u64, FeeTier);

• `Feetier` is an enum with variants like **Low**, **Mid**, **High**.

• There are unit tests in `policy.rs` that verify:

- Low, mid, high tiers are selected correctly based on `tx_count`
- The `None` mempool case falls back to a consistent default
- `validate()` rejects invalid configurations such as `low_mempool_tx >= high_mempool_tx`

-----------------------------------------------------------------------------

## 2. Binaries and environment variables

### 2.1 pool-verifier

• Cargo package: pool-verifier

• Binaries:

- `pool-verifier`
- `init-policy` (wizard that creates policy.toml)

• Environment variables:

- `VELDRA_VERIFIER_ADDR`

    TCP listen address for templates.
    Default: `127.0.0.1:5001`.

- `VELDRA_HTTP_ADDR`

    HTTP listen address for health and stats.
    Default: `127.0.0.1:8080`.

- `VELDRA_POLICY_PATH`

    Path to the policy file.
    Default: `policy.toml`.

- `VELDRA_MEMPOOL_URL`

    URL of the template-manager `/mempool` endpoint.
    Example: `http://127.0.0.1:8081/mempool`.

• HTTP endpoints:

- `GET /health` → `"ok"`
- `GET /verdicts` → list of recent `LoggedVerdict`
- `GET /stats` → summary object similar to:

    {
        "total": 7,
        "accepted": 6,
        "rejected": 1,
        "by_reason": { "Ok": 6, "AverageFeeTooLow { ... }": 1 },
        "by_tier": { "low": 4, "mid": 3 },
        "last": {
            "id": 7,
            "height": 104,
            "total_fees": 1000,
            "accepted": true,
            "reason": null,
            "timestamp": 1764873827,
            "min_avg_fee_used": 1000,
            "fee_tier": "mid"
        }
    }

• Hardening: if mempool HTTP fails, `fetch_mempool_tx_count` logs an error and returns `None`. The verifier still answers templates and does not crash.

### 2.2 template-manager

• Cargo package: `template-manager`

• Binary: `template-manager`   

• Environment variables:

- `VELDRA_MANAGER_CONFIG`

    Manager configuration file path. 
    Example: `services/template-manager/manager.toml`.

- `VELDRA_MANAGER_HTTP_ADDR`

    HTTP listen address for `/health`, `/mempool`, `/templates`.
    Example: `127.0.0.1:8081`.

- `VELDRA_VERIFIER_ADDR`

    Address of the pool-verifier TCP endpoint.
    Example: `127.0.0.1:5001`.

• Config file for bitcoind backend, for example `services/template-manager/manager.toml`:

    backend = "bitcoind"
    rpc_url  = "http://127.0.0.1:18443"
    rpc_user = "veldra"
    rpc_pass = "very_secure_password"
    poll_interval_secs = 5

• Config file for Stratum bridge backend, for example `services/template-manager/manager_stratum.toml`:

    backend = "stratum"
    stratum_addr = "127.0.0.1:3333"
    stratum_auth = ""
    poll_interval_secs = 2

• HTTP endpoints:

- `GET /health` → `"ok"`
- `GET /templates` → recent `LoggedTemplate` entries from the active backend
- `GET /mempool` → last `MempoolStats` snapshot, for example:

    {
        "loaded_from": "bitcoind",
        "tx_count": 1234,
        "bytes": 456789,
        "usage": 123456,
        "max": 300000000,
        "min_relay_fee": 1000,
        "timestamp": 1764873827
    }

• Hardening:

- If connection to verifier fails, manager logs:

    `[manager] failed to connect to verifier ...` and keeps running.

- If `send_and_receive` fails, manager logs

    `[manager] error sending template id=...` and keeps running.

- If `get_mempool_info fails`, manager logs

    `[manager] get_mempool_info error: ...` and keeps running.

### 2.3 sv2-bridge

• Cargo package: `sv2-bridge`

• Binary: `sv2-bridge`

• Environment variables:

- `VELDRA_BRIDGE_ADDR`

    Listen address. 
    Default: `127.0.0.1:3333`.

- `VELDRA_BRIDGE_INTERVAL_SECS`

    Seconds between templates. 
    Default: 5.

- `VELDRA_BRIDGE_START_HEIGHT`

    Synthetic starting block height.
    Default: 500.

- `VELDRA_BRIDGE_TX_COUNT`

    Fixed `tx_count` per template. 
    Default: 5.

- `VELDRA_BRIDGE_TOTAL_FEES`

    Fixed `total_fees` per template in sats. 
    Default: 100.

• Behavior:

- Listens on `VELDRA_BRIDGE_ADDR`.

- For each client connection, streams synthetic `TemplatePropose` JSON lines with incrementing id and `block_height`.

- This allows testing the verifier path without bitcoind.

-----------------------------------------------------------------------------

## 3. Quickstart: regtest with bitcoind backend

• This is the typical end to end path using real `bitcoind`.

### 3.1 Start regtest bitcoind

• Terminal A: 

    bitcoind \
      -regtest \
      -daemon \
      -server=1 \
      -rpcuser=veldra \
      -rpcpassword=very_secure_password \
      -rpcport=18443

• Load or create wallet: 

    bitcoin-cli -regtest -rpcuser=veldra -rpcpassword=very_secure_password -rpcport=18443 loadwallet veldra_wallet 2>/dev/null || \
    bitcoin-cli -regtest -rpcuser=veldra -rpcpassword=very_secure_password -rpcport=18443 createwallet veldra_wallet

• Sanity check: 

    bitcoin-cli -regtest -rpcuser=veldra -rpcpassword=very_secure_password -rpcport=18443 getblockchaininfo

### 3.2 Generate policy with wizard 

• From the repo root: 

    cargo run -p pool-verifier --bin init-policy

• Example answers for development: 

- Minimum total fees in sats: 0
- Maximum number of transactions: 10000
- Low mempool upper bound: 50
- High mempool lower bound: 500
- Low tier min average fee: 0
- Mid tier min average fee: 1000
- High tier min average fee: 5000

• The wizard writes `policy.toml` in the repo root.

### 3.3 Start pool-verifier

• Terminal B: 

    export VELDRA_HTTP_ADDR="127.0.0.1:8080"
    export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"
    export VELDRA_POLICY_PATH="policy.toml"
    export VELDRA_MEMPOOL_URL="http://127.0.0.1:8081/mempool"
    cargo run -p pool-verifier --bin pool-verifier

• Health: 

    curl -s http://127.0.0.1:8080/health
    curl -s http://127.0.0.1:8080/stats | jq

• Initially `total` should be `0`.

### 3.4 Start template-manager 

• Ensure `services/template-manager/manager.toml` is set to the bitcoind config shown above.

• Terminal C: 

    export VELDRA_MANAGER_CONFIG="services/template-manager/manager.toml"
    export VELDRA_MANAGER_HTTP_ADDR="127.0.0.1:8081"
    export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"
    cargo run -p template-manager

• Health: 

    curl -s http://127.0.0.1:8081/health
    curl -s http://127.0.0.1:8081/mempool | jq

### 3.5 Generate activity

• In any terminal: 

    ADDR=$(bitcoin-cli -regtest -rpcuser=veldra -rpcpassword=very_secure_password -rpcport=18443 getnewaddress)
    bitcoin-cli -regtest -rpcuser=veldra -rpcpassword=very_secure_password -rpcport=18443 generatetoaddress 1 "$ADDR"

• Then: 

    curl -s http://127.0.0.1:8080/stats | jq

• Expected: 

- `total` = 1
- `accepted` = 1
- `by_tier` includes `"low": 1`
- `last.min_avg_fee_used` = 0
- `last.fee_tier` = `"low"`

• You can send many transactions to push mempool size across `low_mempool_tx` and `high_mempool_tx` and watch `last.fee_tier` jump between low, mid, and high.

-----------------------------------------------------------------------------

## 4. Quickstart: Stratum bridge backend

• This path uses `sv2-bridge` instead of bitcoind templates.

### 4.1 Manager config for bridge

• Create `services/template-manager/manager_stratum.toml`:

    backend = "stratum"
    stratum_addr = "127.0.0.1:3333"
    stratum_auth = ""
    poll_interval_secs = 2

### 4.2 Start bridge

• Terminal C:

    export VELDRA_BRIDGE_ADDR="127.0.0.1:3333"
    export VELDRA_BRIDGE_INTERVAL_SECS=2
    export VELDRA_BRIDGE_START_HEIGHT=600
    export VELDRA_BRIDGE_TX_COUNT=5
    export VELDRA_BRIDGE_TOTAL_FEES=1000
    cargo run -p sv2-bridge

• The bridge should log that it is listening and printing lines like:

    [time] sent template id=1 height=600 total_fees=1000 tx_count=5

### 4.3 Start template-manager

• Another terminal:

    export VELDRA_MANAGER_CONFIG="services/template-manager/manager_stratum.toml"
    export VELDRA_MANAGER_HTTP_ADDR="127.0.0.1:8081"
    export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"
    cargo run -p template-manager

• You should see logs such as:

- `Template manager backend=stratum ...`
- `Connected to Stratum V2 bridge at 127.0.0.1:3333`
- `New template from backend=stratum id=... height=...`

• Verifier stats: 

    curl -s http://127.0.0.1:8080/stats | jq

• `total` will increase and `by_tier` plus `last` will show how the policy reacts to the synthetic templates.

-----------------------------------------------------------------------------

## 5. Tests

• To run the policy unit tests: 

    cargo test -p pool-verifier

• These tests currently cover:

- Tier selection for low, mid, and high mempool ranges
- Behavior when mempool hint is `None`
- Rejection of invalid policy configurations by `validate()`

• This protects the core fee policy behavior while you keep iterating on the rest of the system.