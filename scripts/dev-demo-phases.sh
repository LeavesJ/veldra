#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BTC_CLI="${ROOT_DIR}/scripts/dev-bitcoin-cli.sh"

UI_WAIT_SECS="${UI_WAIT_SECS:-3}"

btc_cli() {
  "${BTC_CLI}" "$@"
}

wait_ui() {
  sleep "${UI_WAIT_SECS}"
}

mine1() {
  local addr
  addr="$(btc_cli getnewaddress)"
  btc_cli generatetoaddress 1 "$addr" >/dev/null
}

send_batch() {
  local count="$1"
  local fee_rate_req="$2"   # sat/vB
  local amount="${3:-0.2}"

  # Ensure we never go below node's min relay fee. Your node is rejecting < 1 sat/vB.
  # Keep this simple: clamp to >= 1.0 sat/vB.
  local fee_rate
  fee_rate="$(awk -v r="$fee_rate_req" 'BEGIN{ if (r < 1.0) printf("%.3f", 1.0); else printf("%.3f", r) }')"

  echo "[demo-phases] send_batch count=${count} amount=${amount} fee_rate=${fee_rate} sat/vB (req ${fee_rate_req})"

  for _ in $(seq 1 "${count}"); do
    local to
    to="$(btc_cli getnewaddress)"
    btc_cli -named sendtoaddress address="$to" amount="$amount" fee_rate="$fee_rate" avoid_reuse=false >/dev/null
  done
}

echo "[demo-phases] starting demo loop..."

while true; do
  echo "[demo-phases] baseline: empty mempool (expect EmptyTemplate reject)"
  wait_ui
  mine1
  wait_ui

  echo "[demo-phases] low tier load + low fee (expect fee-based reject)"
  send_batch 3 1.0 0.2
  wait_ui
  mine1
  wait_ui

  echo "[demo-phases] low tier load + high fee (expect Ok)"
  send_batch 3 25.0 0.2
  wait_ui
  mine1
  wait_ui

  echo "[demo-phases] mid/high tier load + mixed fees (expect tier flip + mixed accepts/rejects)"
  send_batch 10 1.0 0.2
  send_batch 10 25.0 0.2
  wait_ui
  mine1
  wait_ui

  echo "[demo-phases] txcount stress (expect TxCountTooHigh)"
  send_batch 15 25.0 0.2
  wait_ui
  mine1
  wait_ui
  
done
