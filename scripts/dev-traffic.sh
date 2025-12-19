#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Use same wrapper as dev-regtest.sh
BTC_CLI="${ROOT_DIR}/scripts/dev-bitcoin-cli.sh"
BITCOIN_CLI="${BITCOIN_CLI:-$BTC_CLI}"


echo "[dev-traffic] ROOT_DIR  = $ROOT_DIR"
echo "[dev-traffic] BITCOIN_CLI = $BITCOIN_CLI"

# One mining address we keep reusing
MINING_ADDR="$($BITCOIN_CLI getnewaddress mining bech32)"

while true; do
  # random number of "bursts" per cycle
  bursts=$((RANDOM % 3 + 1))

  for _ in $(seq 1 "$bursts"); do
    # each burst has a random number of txs
    txs=$((RANDOM % 15 + 1))

    for _ in $(seq 1 "$txs"); do
      addr="$($BITCOIN_CLI getnewaddress demo bech32)"
      amt="0.001"

      # random fee rate in sat/vB (keeps avg fees moving)
      fee_rate=$((RANDOM % 50 + 1))

      # sendtoaddress "addr" amount "" "" subtractfeefromamount replaceable conf_target "estimate_mode" fee_rate
      $BITCOIN_CLI sendtoaddress "$addr" "$amt" "" "" false true 1 "conservative" >/dev/null
    done
  done

  # occasionally mine 0–3 blocks to clear some of the mempool
  blocks=$((RANDOM % 4))
  if [ "$blocks" -gt 0 ]; then
    $BITCOIN_CLI generatetoaddress "$blocks" "$MINING_ADDR" >/dev/null
  fi

  # pause a bit so the verifier can chew through templates
  sleep 3
done
