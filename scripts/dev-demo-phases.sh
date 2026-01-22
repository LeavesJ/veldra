#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BTC_CLI="${ROOT_DIR}/scripts/dev-bitcoin-cli.sh"

UI_WAIT_SECS="${UI_WAIT_SECS:-2}"
RUNS="${RUNS:-0}" # 0 = infinite, else run N cycles

VERIFIER_HTTP_ADDR="${VERIFIER_HTTP_ADDR:-127.0.0.1:8080}"
MANAGER_HTTP_ADDR="${MANAGER_HTTP_ADDR:-127.0.0.1:8081}"

AMOUNT="${AMOUNT:-0.05}"
LOW_FEE="${LOW_FEE:-1.0}"     # sat/vB
HIGH_FEE="${HIGH_FEE:-25.0}"  # sat/vB

LOW_COUNT="${LOW_COUNT:-12}"
MID_COUNT="${MID_COUNT:-30}"
STRESS_COUNT="${STRESS_COUNT:-120}"

HOLD_SECS="${HOLD_SECS:-6}"

# Mine between sub batches to avoid too many unconfirmed ancestors.
# Critical rule: never mine after the final sub batch, so the mempool is nonzero at phase end.
MINE_EVERY_SENDS="${MINE_EVERY_SENDS:-20}"

UTXO_WARMUP_COUNT="${UTXO_WARMUP_COUNT:-40}" # confirmed UTXOs to avoid change chains
UTXO_WARMUP_AMOUNT="${UTXO_WARMUP_AMOUNT:-0.12}"

btc_cli() { "${BTC_CLI}" "$@"; }
wait_ui() { sleep "${UI_WAIT_SECS}"; }

require_http_ok() {
  local url="$1"
  for _ in {1..40}; do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  echo "[demo-phases] ERROR: endpoint not ready: ${url}"
  exit 1
}

require_stack_ready() {
  require_http_ok "http://${VERIFIER_HTTP_ADDR}/health"
  require_http_ok "http://${MANAGER_HTTP_ADDR}/health"
}

mempool_size() {
  # Do not silently mask failures as 0 if bitcoind is unreachable or output is empty.
  local raw
  raw="$(btc_cli getmempoolinfo 2>/dev/null || true)"
  if [[ -z "${raw}" ]]; then
    echo 0
    return
  fi

  python3 - <<'PY' <<<"${raw}" 2>/dev/null || echo 0
import sys, json
j = json.load(sys.stdin)
print(j.get("size", 0))
PY
}

wait_mempool_ge() {
  local want="$1"
  local tries="${2:-80}"
  for _ in $(seq 1 "${tries}"); do
    local cur
    cur="$(mempool_size)"
    if [[ "${cur}" -ge "${want}" ]]; then return 0; fi
    sleep 0.25
  done
  echo "[demo-phases] ERROR: mempool did not reach >= ${want} tx (last=$(mempool_size))"
  return 1
}

mine_n() {
  local n="$1"
  local addr
  addr="$(btc_cli getnewaddress)"
  btc_cli -named generatetoaddress nblocks="$n" address="$addr" >/dev/null
}

balance() { btc_cli getbalance; }

require_spendable() {
  local bal
  bal="$(balance)"
  if ! awk -v b="$bal" 'BEGIN{ exit !(b > 1.0) }'; then
    echo "[demo-phases] ERROR: insufficient spendable balance (${bal}). Run dev-regtest.sh first."
    exit 1
  fi
}

phase() {
  local name="$1"
  echo
  echo "============================================================"
  echo "[demo-phases] PHASE: ${name}"
  echo "============================================================"
}

hold_for_templates() {
  local label="$1"
  echo "[demo-phases] hold ${HOLD_SECS}s (${label}) mempool_size=$(mempool_size)"
  sleep "${HOLD_SECS}"
}

send_one() {
  local fee_rate_req="$1"
  local amount="$2"

  local fee_rate
  fee_rate="$(awk -v r="$fee_rate_req" 'BEGIN{ if (r < 1.0) printf("%.3f", 1.0); else printf("%.3f", r) }')"

  local to
  to="$(btc_cli getnewaddress)"
  btc_cli -named sendtoaddress address="$to" amount="$amount" fee_rate="$fee_rate" avoid_reuse=false >/dev/null
}

send_batch_mine_cadence() {
  local count="$1"
  local fee_rate="$2"
  local amount="$3"

  local cadence="${MINE_EVERY_SENDS}"
  if [[ "${cadence}" -le 0 ]]; then cadence=0; fi

  echo "[demo-phases] send_batch count=${count} amount=${amount} fee_rate=${fee_rate} sat/vB (mine every ${cadence}, never after last chunk)"

  # No cadence means: just send all, leave mempool nonzero.
  if [[ "${cadence}" -eq 0 ]] || [[ "${count}" -le "${cadence}" ]]; then
    for _ in $(seq 1 "${count}"); do
      send_one "${fee_rate}" "${amount}"
    done
    return 0
  fi

  # Chunked sending: mine after each full chunk except the final chunk.
  local sent=0
  while [[ "${sent}" -lt "${count}" ]]; do
    local remaining=$((count - sent))
    local chunk="${cadence}"
    if [[ "${remaining}" -lt "${chunk}" ]]; then
      chunk="${remaining}"
    fi

    for _ in $(seq 1 "${chunk}"); do
      send_one "${fee_rate}" "${amount}"
    done
    sent=$((sent + chunk))

    # Mine only between chunks, never after the final chunk.
    if [[ "${sent}" -lt "${count}" ]]; then
      mine_n 1
      wait_ui
    fi
  done
}

utxo_warmup() {
  phase "warmup: create many confirmed UTXOs (prevents ancestor-chain failures)"
  local per_batch=10
  local made=0
  while [[ "${made}" -lt "${UTXO_WARMUP_COUNT}" ]]; do
    local batch=$((UTXO_WARMUP_COUNT - made))
    if [[ "${batch}" -gt "${per_batch}" ]]; then batch="${per_batch}"; fi

    echo "[demo-phases] warmup batch=${batch} amount=${UTXO_WARMUP_AMOUNT} fee_rate=${HIGH_FEE}"
    for _ in $(seq 1 "${batch}"); do
      send_one "${HIGH_FEE}" "${UTXO_WARMUP_AMOUNT}"
    done
    mine_n 1
    wait_ui
    made=$((made + batch))
  done
  echo "[demo-phases] warmup complete"
}

echo "[demo-phases] starting demo loop..."
require_stack_ready
require_spendable

utxo_warmup

i=0
while true; do
  i=$((i+1))
  if [[ "${RUNS}" != "0" ]] && [[ "${i}" -gt "${RUNS}" ]]; then
    echo "[demo-phases] completed RUNS=${RUNS}"
    exit 0
  fi

  phase "A: empty-template rejection showcase (mine once, then hold)"
  mine_n 1
  hold_for_templates "empty-template window"
  wait_ui

  phase "B: low-fee only (forces fee-based rejects because no high-fee tx exist)"
  send_batch_mine_cadence "${LOW_COUNT}" "${LOW_FEE}" "${AMOUNT}"
  wait_mempool_ge 1
  hold_for_templates "low-fee-only window"
  mine_n 1
  wait_ui

  phase "C: high-fee only (expect Ok)"
  send_batch_mine_cadence "${LOW_COUNT}" "${HIGH_FEE}" "${AMOUNT}"
  wait_mempool_ge 1
  hold_for_templates "high-fee-only window"
  mine_n 1
  wait_ui

  phase "D: tier flip (build mempool, then hold; mixed strategy depends on your policy)"
  send_batch_mine_cadence "${MID_COUNT}" "${LOW_FEE}" "${AMOUNT}"
  send_batch_mine_cadence "$((MID_COUNT / 3))" "${HIGH_FEE}" "${AMOUNT}"
  wait_mempool_ge 10
  hold_for_templates "tier-flip window"
  mine_n 1
  wait_ui

  phase "E: txcount stress (aim to trigger TxCountExceeded if max_tx_count is low)"
  send_batch_mine_cadence "${STRESS_COUNT}" "${HIGH_FEE}" "${AMOUNT}"
  wait_mempool_ge 10
  hold_for_templates "stress window"
  mine_n 1
  wait_ui
done
