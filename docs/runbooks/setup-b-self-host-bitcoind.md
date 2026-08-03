# Runbook: Setup B Self-Hosted Mainnet bitcoind

**Audience:** Veldra operator standing up Setup B for the v2.0 launch-gate soak (currently solo founder).
**Goal:** Run an operator-controlled mainnet bitcoind, then point the verifier's Class M mempool poll and the template feed at it, so the launch-gate soak in `docs/runbooks/phase2-shadow-soak.md` runs against real mainnet data.
**Frequency:** One time to establish Setup B. Re-run only if the node is rebuilt or moved.
**Blast radius if botched:** A thin, laggy, or misconfigured mempool inflates `v2_invariant_mempool_tx_unknown` and tolerance-exceeded events, which contaminates the launch-gate false-positive measurement and can make Phase 2 look unsafe when the code is fine. Get the node fully synced and well-peered before T+0.

## Why self-host rather than a free hosted RPC

Class M compares each template's txids against the verifier's mempool view, so the node the verifier polls must be the same well-connected node the templates were built from. A free shared endpoint often restricts `getrawmempool`, and its mempool is less connected, so legitimate template txs read as unknown and drive false positives. Setup B wants one node you control that both builds templates and serves the mempool. Revisit a paid hosted RPC only after the gate, and only one that confirms `getrawmempool`.

A pruned node serves both `getrawmempool` and `getblocktemplate` fully (pruning drops old blocks, not the mempool or the chain tip), so disk stays around 15 GB rather than the ~700 GB of an archival node.

---

## Part 1: Provision the server

1. Rent a Linux VPS or dedicated server. Minimum 4 vCPU, 8 GB RAM, 100 GB SSD, Ubuntu 24.04 LTS. Any provider works (Hetzner, OVH, DigitalOcean, or a spare box). 100 GB is generous for a pruned node; the chainstate plus 550 MB of blocks lands near 15 GB.
2. SSH in, update, install tools, and create a dedicated system user:
   ```sh
   sudo apt-get update && sudo apt-get install -y gnupg wget jq python3 git
   sudo adduser --system --group --home /var/lib/bitcoind bitcoind
   ```

## Part 2: Install and verify Bitcoin Core

Check the current stable on the download page (`https://bitcoincore.org/en/download`). This runbook pins `31.0`; bump `BTC_VER` if a newer stable is listed. Older releases stay downloadable, so the commands work as written.

```sh
export BTC_VER=31.0
cd /tmp
wget https://bitcoincore.org/bin/bitcoin-core-${BTC_VER}/bitcoin-${BTC_VER}-x86_64-linux-gnu.tar.gz
wget https://bitcoincore.org/bin/bitcoin-core-${BTC_VER}/SHA256SUMS
wget https://bitcoincore.org/bin/bitcoin-core-${BTC_VER}/SHA256SUMS.asc
```

Check the binary hash:
```sh
sha256sum --ignore-missing --check SHA256SUMS
# expect: bitcoin-31.0-x86_64-linux-gnu.tar.gz: OK
```

Verify the release signatures. Import the Bitcoin Core builder keys, then verify the signed checksum file. Trust comes from many independent builders signing the same hashes:
```sh
git clone https://github.com/bitcoin-core/guix.sigs
gpg --import guix.sigs/builder-keys/*.gpg
gpg --verify SHA256SUMS.asc SHA256SUMS
# expect a block of "Good signature from ..." lines and no "BAD signature"
```

Install the binaries:
```sh
tar -xzf bitcoin-${BTC_VER}-x86_64-linux-gnu.tar.gz
sudo install -m 0755 bitcoin-${BTC_VER}/bin/bitcoind /usr/local/bin/
sudo install -m 0755 bitcoin-${BTC_VER}/bin/bitcoin-cli /usr/local/bin/
bitcoind --version | head -1
```

## Part 3: Configure bitcoind

1. Generate an `rpcauth` line. It stores only a salted hash in the config; the plaintext password stays in your secret store and is what the verifier uses later:
   ```sh
   wget https://raw.githubusercontent.com/bitcoin/bitcoin/v${BTC_VER}/share/rpcauth/rpcauth.py
   python3 rpcauth.py veldra
   # prints:  rpcauth=veldra:<salt>$<hash>
   #          Your password: <PLAINTEXT>     <-- save this; it becomes VELDRA_BITCOIND_RPC_PASS
   ```
2. Write `/var/lib/bitcoind/bitcoin.conf` (paste the `rpcauth` line from above):
   ```ini
   server=1
   prune=550
   txindex=0
   blocksonly=0
   persistmempool=1
   maxconnections=64
   rpcauth=veldra:<salt>$<hash>
   rpcbind=127.0.0.1
   rpcallowip=127.0.0.1
   rpcport=8332
   ```
   `blocksonly=0` is mandatory. With it on, the node keeps no loose-transaction mempool and Class M flags every template tx as unknown, which is the single most damaging misconfiguration for this soak. `txindex=0` is correct because Class M needs only `getrawmempool` and `getblocktemplate`.
   ```sh
   sudo chown -R bitcoind:bitcoind /var/lib/bitcoind
   sudo chmod 600 /var/lib/bitcoind/bitcoin.conf
   ```

Bind only to loopback. Per the hostile-network posture, never expose bitcoind RPC to the public internet. If the Veldra stack runs on a different host, reach the node over a private network or an SSH tunnel and add that host to `rpcallowip`, not a public bind.

## Part 4: Run bitcoind as a service

Write `/etc/systemd/system/bitcoind.service`:
```ini
[Unit]
Description=Bitcoin daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/bitcoind -datadir=/var/lib/bitcoind -conf=/var/lib/bitcoind/bitcoin.conf
User=bitcoind
Group=bitcoind
Type=simple
Restart=on-failure
TimeoutStopSec=600

[Install]
WantedBy=multi-user.target
```
Enable and start it:
```sh
sudo systemctl daemon-reload
sudo systemctl enable --now bitcoind
sudo journalctl -u bitcoind -f      # watch startup, Ctrl-C to detach
```

## Part 5: Wait for initial block download

```sh
sudo -u bitcoind bitcoin-cli -datadir=/var/lib/bitcoind getblockchaininfo \
  | jq '{blocks, headers, verificationprogress, pruned, size_on_disk}'
```
Re-run periodically. The node is synced when `verificationprogress` is at or above `0.9999` and `blocks` equals `headers`. Expect 1 to 3 days, bounded by CPU for signature validation. Disk stays near 15 GB the whole time because pruning runs during sync.

## Part 6: Confirm the node is soak-ready

1. Mempool is populated, which proves peer relay and that `blocksonly=0` took effect:
   ```sh
   sudo -u bitcoind bitcoin-cli -datadir=/var/lib/bitcoind getmempoolinfo | jq '{size, bytes}'
   ```
   Expect a few thousand transactions on mainnet. A size of `0` after full sync means no peers or `blocksonly=1`; fix before continuing.
2. `getrawmempool` over JSON-RPC with the RPC credentials, the exact call the verifier makes (and the soak runbook T-1 step 2):
   ```sh
   curl --user "veldra:<PLAINTEXT>" \
     -d '{"jsonrpc":"1.0","id":"setupb","method":"getrawmempool","params":[false]}' \
     -H 'content-type: application/json' http://127.0.0.1:8332/ | jq '.result | length'
   ```
   Expect a non-zero integer within a few hundred ms.
3. Peer count is healthy. More peers means a fuller, more representative mempool and fewer spurious unknowns:
   ```sh
   sudo -u bitcoind bitcoin-cli -datadir=/var/lib/bitcoind getconnectioncount
   ```
   Expect 8 or more; aim higher for mempool fidelity.

## Part 7: Wire the Veldra stack to the node

The launch-gate pipeline is bitcoind to template-manager to pool-verifier. template-manager's bitcoind backend polls `getblocktemplate` from the real node directly, and the verifier polls `getrawmempool` directly, so both views come from one node. The synthetic feed chain (rg-demo-feed, rg-feed-adapter) and the licensed feed product (rg-feed-server, rg-auth) are not part of this pipeline. `docker-compose.setup-b.yml` codifies it: host networking so the containers can reach the loopback-only bitcoind, every service bound to 127.0.0.1, and credentials supplied through the environment.

1. **Verifier mempool source.** In `deploy/policy-prod.toml [policy.mempool]`, fill the placeholders added in this repo. This is mandatory, not advisory: with `enforce = true` the verifier refuses to start on a placeholder, an empty value, a non-`http(s)` `rpc_url`, or an empty resolved password, and prints the offending key. A verifier that starts is a verifier whose Class M check is actually wired.
   ```toml
   rpc_url  = "http://<NODE_HOST>:8332"
   rpc_user = "veldra"
   rpc_pass = ""           # leave empty; supplied by env below
   ```
   In the verifier environment:
   ```sh
   export VELDRA_BITCOIND_RPC_PASS="<PLAINTEXT>"
   export VELDRA_POLICY_FILE=/path/to/deploy/policy-prod.toml
   export VELDRA_MODE=observe
   ```
   Do not point `[policy.mempool] rpc_url` at rg-feed-adapter. The adapter derives a synthetic mempool from the template and always agrees, which is exactly the Setup A behavior Setup B must move past.
2. **Template source.** template-manager polls the same node directly via `deploy/manager-setup-b.toml` (`rpc_url = "http://127.0.0.1:8332"`). Its credentials fall back to `VELDRA_BITCOIND_RPC_USER` and `VELDRA_BITCOIND_RPC_PASS` from the environment, so no secret lives in the file.
3. **Deploy and start.** Install Docker on the node (`sudo apt-get install -y docker.io docker-compose-v2 && sudo usermod -aG docker ubuntu`, then log out and back in). From the workstation, copy the repo: `rsync -av --exclude target --exclude node_modules --exclude .git --exclude 'Veldra Site' --exclude data --exclude '.env*' ~/Veldra/ veldra-node:~/veldra/`. On the node in `~/veldra`: fill the two `deploy/policy-prod.toml` placeholders (`rpc_url` to `http://127.0.0.1:8332`, `rpc_user` to `veldra`), create `.env.setup-b` from `deploy/env.setup-b.example` and paste the RPC password, then `docker compose -f docker-compose.setup-b.yml --env-file .env.setup-b up -d --build`.

## Part 8: Observe, then shadow, then soak

1. Start the stack with the verifier in `VELDRA_MODE=observe`. Observe is read-only and lighter than shadow. Confirm clean wiring on the verifier `/metrics` (`:8081`):
   - the log line `Phase 2 mempool view polling task started`,
   - `verifier_phase2_degraded_total` settles at `0` after the first successful poll,
   - `verifier_mempool_view_size` tracks `getmempoolinfo .size`,
   - `verifier_phase2_checks_total{result="agreed"}` climbs as templates flow,
   - `verifier_mempool_empty_responses` holds at `0`. Anything above zero means `getrawmempool` succeeded and came back empty, so the view was refused rather than served: the node is on the wrong chain or has not finished loading `mempool.dat`. Left unfixed the view never primes, `verifier_phase2_checks_total{result="unprimed"}` climbs instead of `agreed`, and the soak measures nothing.
2. Promote the verifier to `VELDRA_MODE=shadow`.
3. Run the one-week soak in `docs/runbooks/phase2-shadow-soak.md` from its Pre-Soak Setup step. The acceptance bar is `FP_total == 0` at `tolerance_pct = 4.0`.

## Acceptance for this runbook

- `getblockchaininfo` shows a fully synced chain.
- `getrawmempool` returns the node's real mempool over JSON-RPC with the verifier's credentials.
- Observe mode shows the view primed, `verifier_phase2_degraded_total` at `0`, and checks flowing as agreed.

Once those hold, Setup B is established and the launch-gate soak can start.

## Cross-References

- `docs/runbooks/phase2-shadow-soak.md` for the one-week soak procedure and the FP measurement.
- `deploy/policy-prod.toml [policy.mempool]` for the verifier-side production Phase 2 config.
- BIZLOG 2026-05-02 for the staged-validation discipline and the Setup A/B/C taxonomy.
- ADR-003 for the Class M design and the `tolerance_pct` rationale.
