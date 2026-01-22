#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BITCOIN_CLI="${BITCOIN_CLI:-${ROOT_DIR}/scripts/dev-bitcoin-cli.sh}"

echo "[dev-traffic] ROOT_DIR    = ${ROOT_DIR}"
echo "[dev-traffic] BITCOIN_CLI = ${BITCOIN_CLI}"

# Tuning knobs
SLEEP_SECS="${SLEEP_SECS:-3}"
RUNS="${RUNS:-0}"                 # 0 = infinite
MAX_BURSTS="${MAX_BURSTS:-3}"     # bursts per cycle
MAX_TXS="${MAX_TXS:-15}"          # txs per burst
AMT="${AMT:-0.001}"               # BTC per tx
FEE_MIN="${FEE_MIN:-1}"           # sat/vB
FEE_MAX="${FEE_MAX:-50}"          # sat/vB
MINE_MAX="${MINE_MAX:-3}"         # blocks to mine occasionally (0..MINE_MAX)
WALLET_NAME="${WALLET_NAME:-veldra_wallet}"

btc() { "${BITCOIN_CLI}" "$@"; }

cleanup() {
  echo "[dev-traffic] exit"
}
trap cleanup INT TERM EXIT

require_wallet() {
  # loadwallet is idempotent; if it fails, try createwallet
  btc loadwallet "${WALLET_NAME}" >/dev/null 2>&1 || \
    btc -named createwallet wallet_name="${WALLET_NAME}" >/dev/null
}

require_spendable() {
  # Require spendable balance, otherwise fail with a deterministic message.
  # dev-regtest mines 110 blocks already; this should pass in normal workflow.
  local bal
  bal="$(btc getbalance)"
  if ! awk -v b="${bal}" 'BEGIN{ exit !(b > 1.0) }'; then
    echo "[dev-traffic] ERROR: insufficient spendable balance (${bal}). Run ./scripts/dev-regtest.sh first."
    exit 1
  fi
}

# One mining address reused
MINING_ADDR="$(btc getnewaddress mining bech32)"

echo "[dev-traffic] mining address = ${MINING_ADDR}"

require_wallet
require_spendable

cycle=0
while true; do
  cycle=$((cycle + 1))
  if [[ "${RUNS}" != "0" ]] && [[ "${cycle}" -gt "${RUNS}" ]]; then
    echo "[dev-traffic] completed RUNS=${RUNS}"
    exit 0
  fi

  bursts=$((RANDOM % MAX_BURSTS + 1))
  echo "[dev-traffic] cycle=${cycle} bursts=${bursts}"

  for _ in $(seq 1 "${bursts}"); do
    txs=$((RANDOM % MAX_TXS + 1))

    for _ in $(seq 1 "${txs}"); do
      addr="$(btc getnewaddress demo bech32)"
      fee_rate_int=$((RANDOM % (FEE_MAX - FEE_MIN + 1) + FEE_MIN))
      fee_rate="$(printf "%d.000" "${fee_rate_int}")"

      # Explicit -named avoids Core positional drift.
      btc -named sendtoaddress \
        address="${addr}" \
        amount="${AMT}" \
        fee_rate="${fee_rate}" \
        avoid_reuse=false \
        >/dev/null
    done
  done

  # Occasionally mine 0..MINE_MAX blocks to clear mempool partially
  blocks=$((RANDOM % (MINE_MAX + 1)))
  if [[ "${blocks}" -gt 0 ]]; then
    btc -named generatetoaddress nblocks="${blocks}" address="${MINING_ADDR}" >/dev/null
    echo "[dev-traffic] mined ${blocks} blocks"
  fi

  sleep "${SLEEP_SECS}"
done
