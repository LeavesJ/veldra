#!/usr/bin/env bash
# phase2-spot-check.sh
#
# Captures the four ADR-003 Phase 2 metric counters from the
# verifier's /metrics endpoint, computes deltas against the baseline
# JSON written by phase2-baseline.sh, and lists every Class M
# tolerance-exceeded rejection from the verdict log so the operator
# can cross-reference each candidate false positive against the
# pool's block-found feed.
#
# Run at T+0 (immediately after phase2-baseline.sh on the start
# day), T+1, T+3, T+5, and T+7 per
# docs/runbooks/phase2-shadow-soak.md.
#
# Usage:
#   scripts/phase2-spot-check.sh [--metrics-url URL] [--baseline PATH]
#                                [--verdict-log PATH] [--max-rejections N]
#
# Defaults:
#   --metrics-url     http://127.0.0.1:8081/metrics
#   --baseline        ./data/phase2-baseline.json
#   --verdict-log     ./data/verdicts.log
#   --max-rejections  50  (per call; bump if a window has more)
#
# Output is human readable; pipe to a log for the DEVLOG entry.
# Exit code 0 on success, 1 on stale baseline or unreachable metrics,
# 2 on bad arg, 3 on missing dependency.

set -euo pipefail

METRICS_URL="${VELDRA_PHASE2_METRICS_URL:-http://127.0.0.1:8081/metrics}"
BASELINE_PATH="${VELDRA_PHASE2_BASELINE_PATH:-./data/phase2-baseline.json}"
VERDICT_LOG="${VELDRA_VERDICT_LOG:-./data/verdicts.log}"
MAX_REJECTIONS=50

while [[ $# -gt 0 ]]; do
  case "$1" in
    --metrics-url)    METRICS_URL="$2"; shift 2 ;;
    --baseline)       BASELINE_PATH="$2"; shift 2 ;;
    --verdict-log)    VERDICT_LOG="$2"; shift 2 ;;
    --max-rejections) MAX_REJECTIONS="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# //; s/^#//'
      exit 0
      ;;
    *)
      echo "phase2-spot-check.sh: unknown arg '$1'" >&2
      exit 2
      ;;
  esac
done

for tool in curl jq awk; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "phase2-spot-check.sh: $tool is required but not on PATH" >&2
    exit 3
  fi
done

if [[ ! -f "$BASELINE_PATH" ]]; then
  echo "phase2-spot-check.sh: baseline not found at $BASELINE_PATH" >&2
  echo "  run scripts/phase2-baseline.sh first (T-1 day step)" >&2
  exit 1
fi

# Re-fetch /metrics. Same parser as phase2-baseline.sh; kept inline
# so the spot-check script stays self-contained and runnable from
# any deploy location without sourcing a shared lib.
METRICS_TEXT="$(curl --silent --show-error --fail --max-time 10 "$METRICS_URL")"

parse_counter_with_label() {
  parse_counter_by_label_key result "$1" "$2"
}

# PB-40's verifier_phase2_second_chance_total keys on `outcome`, not
# `result`, so the label name is a parameter rather than baked in.
parse_counter_by_label_key() {
  local key="$1"
  local name="$2"
  local label="$3"
  echo "$METRICS_TEXT" \
    | awk -v name="$name" -v key="$key" -v label="$label" '
        $0 ~ /^#/ { next }
        index($0, name "{" key "=\"" label "\"}") == 1 ||
        index($0, name "_total{" key "=\"" label "\"}") == 1 {
          print $NF; exit
        }
      '
}
parse_counter() {
  local name="$1"
  echo "$METRICS_TEXT" \
    | awk -v name="$name" '
        $0 ~ /^#/ { next }
        index($0, name " ") == 1 || index($0, name "_total ") == 1 {
          print $NF; exit
        }
      '
}

CUR_AGREED="$(parse_counter_with_label verifier_phase2_checks_total agreed)"
CUR_REJECTED="$(parse_counter_with_label verifier_phase2_checks_total rejected)"
CUR_SKIPPED="$(parse_counter_with_label verifier_phase2_checks_total skipped)"
CUR_STALE="$(parse_counter_with_label verifier_phase2_checks_total stale)"
CUR_RECOVERED="$(parse_counter_with_label verifier_phase2_checks_total recovered)"
CUR_SC_WITHDRAWN="$(parse_counter_by_label_key outcome verifier_phase2_second_chance_total withdrawn)"
CUR_SC_UPHELD="$(parse_counter_by_label_key outcome verifier_phase2_second_chance_total upheld)"
CUR_SC_FAILED="$(parse_counter_by_label_key outcome verifier_phase2_second_chance_total lookup_failed)"
CUR_DEGRADED="$(parse_counter verifier_phase2_degraded_total)"
CUR_VIEW_AGE="$(parse_counter verifier_mempool_view_age_seconds)"
CUR_VIEW_SIZE="$(parse_counter verifier_mempool_view_size)"

CUR_AGREED="${CUR_AGREED:-0}"
CUR_REJECTED="${CUR_REJECTED:-0}"
CUR_SKIPPED="${CUR_SKIPPED:-0}"
CUR_STALE="${CUR_STALE:-0}"
CUR_RECOVERED="${CUR_RECOVERED:-0}"
CUR_SC_WITHDRAWN="${CUR_SC_WITHDRAWN:-0}"
CUR_SC_UPHELD="${CUR_SC_UPHELD:-0}"
CUR_SC_FAILED="${CUR_SC_FAILED:-0}"
CUR_DEGRADED="${CUR_DEGRADED:-0}"
CUR_VIEW_AGE="${CUR_VIEW_AGE:-0}"
CUR_VIEW_SIZE="${CUR_VIEW_SIZE:-0}"

BASE_AGREED="$(jq -r '.counters.verifier_phase2_checks_total_agreed' "$BASELINE_PATH")"
BASE_REJECTED="$(jq -r '.counters.verifier_phase2_checks_total_rejected' "$BASELINE_PATH")"
BASE_SKIPPED="$(jq -r '.counters.verifier_phase2_checks_total_skipped' "$BASELINE_PATH")"
BASE_STALE="$(jq -r '.counters.verifier_phase2_checks_total_stale' "$BASELINE_PATH")"
BASE_DEGRADED="$(jq -r '.counters.verifier_phase2_degraded_total' "$BASELINE_PATH")"
# `// 0` so a baseline captured before PB-40 still parses: those files
# have no recovered or second-chance keys, and jq would yield "null"
# into the arithmetic below.
BASE_RECOVERED="$(jq -r '.counters.verifier_phase2_checks_total_recovered // 0' "$BASELINE_PATH")"
BASE_SC_WITHDRAWN="$(jq -r '.counters.verifier_phase2_second_chance_total_withdrawn // 0' "$BASELINE_PATH")"
BASE_SC_UPHELD="$(jq -r '.counters.verifier_phase2_second_chance_total_upheld // 0' "$BASELINE_PATH")"
BASE_SC_FAILED="$(jq -r '.counters.verifier_phase2_second_chance_total_lookup_failed // 0' "$BASELINE_PATH")"
BASE_AT="$(jq -r '.captured_at' "$BASELINE_PATH")"

DELTA_AGREED=$((CUR_AGREED - BASE_AGREED))
DELTA_REJECTED=$((CUR_REJECTED - BASE_REJECTED))
DELTA_SKIPPED=$((CUR_SKIPPED - BASE_SKIPPED))
DELTA_STALE=$((CUR_STALE - BASE_STALE))
DELTA_DEGRADED=$((CUR_DEGRADED - BASE_DEGRADED))
DELTA_RECOVERED=$((CUR_RECOVERED - BASE_RECOVERED))
DELTA_SC_WITHDRAWN=$((CUR_SC_WITHDRAWN - BASE_SC_WITHDRAWN))
DELTA_SC_UPHELD=$((CUR_SC_UPHELD - BASE_SC_UPHELD))
DELTA_SC_FAILED=$((CUR_SC_FAILED - BASE_SC_FAILED))
TOTAL_CLASSM=$((DELTA_AGREED + DELTA_REJECTED + DELTA_RECOVERED + DELTA_SKIPPED + DELTA_STALE))

NOW="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "═══ ADR-003 Phase 2 #6 spot check at $NOW ═══"
echo "  baseline captured_at: $BASE_AT"
echo "  metrics_url:          $METRICS_URL"
echo
echo "Class M check counters (delta since baseline):"
printf "  agreed    %10d  (current %d)\n" "$DELTA_AGREED"   "$CUR_AGREED"
printf "  rejected  %10d  (current %d)\n" "$DELTA_REJECTED" "$CUR_REJECTED"
printf "  skipped   %10d  (current %d)\n" "$DELTA_SKIPPED"  "$CUR_SKIPPED"
printf "  stale     %10d  (current %d)\n" "$DELTA_STALE"    "$CUR_STALE"
printf "  recovered %10d  (current %d)\n" "$DELTA_RECOVERED" "$CUR_RECOVERED"
printf "  total     %10d\n"               "$TOTAL_CLASSM"
echo
echo "PB-40 second-chance lookups (delta since baseline):"
printf "  withdrawn     %10d  false positives caught in the act, no rejection emitted\n" "$DELTA_SC_WITHDRAWN"
printf "  upheld        %10d  adjudicated rejections, the only detection candidates\n"   "$DELTA_SC_UPHELD"
printf "  lookup_failed %10d  UNADJUDICATED, evidence in neither direction\n"            "$DELTA_SC_FAILED"
echo
printf "  degraded  %10d  (current %d)\n" "$DELTA_DEGRADED" "$CUR_DEGRADED"
printf "  view_age  %10ss\n"              "$CUR_VIEW_AGE"
printf "  view_size %10s\n"               "$CUR_VIEW_SIZE"

if (( DELTA_DEGRADED > 0 )); then
  echo
  echo "WARNING: verifier_phase2_degraded_total grew by $DELTA_DEGRADED since baseline."
  echo "  bitcoind RPC was unavailable for at least one window during the soak."
  echo "  per the runbook, sustained degraded windows invalidate the soak; investigate"
  echo "  the bitcoind side and consider restarting the soak from T+0."
fi

if (( DELTA_SC_FAILED > 0 )); then
  echo
  echo "WARNING: $DELTA_SC_FAILED Class M rejection(s) could not be adjudicated because"
  echo "  bitcoind was unreachable at rejection time. These are evidence in NEITHER"
  echo "  direction and must not be scored as passes. Check the verdict records'"
  echo "  mempool_adjudication.lookup_error, fix the cause, and re-run the window."
fi

if (( DELTA_REJECTED == 0 )); then
  echo
  echo "Zero Class M rejections in the window so far. PASS condition holds."
  if (( DELTA_SC_WITHDRAWN > 0 )); then
    echo "  ($DELTA_SC_WITHDRAWN stale-view false positive(s) were withdrawn before"
    echo "   becoming rejections. Expected and healthy: that is PB-40 working.)"
  fi
  exit 0
fi

echo
echo "═══ Candidate false positives (last $MAX_REJECTIONS Class M rejections) ═══"
echo
echo "Each row is a Class M rejection with the bitcoind answer captured AT rejection"
echo "time (PB-40). Read the sc_* fields; do NOT re-query these txids with bitcoin-cli."
echo "The mempool tail churns within minutes, so a later query reports transactions"
echo "absent whether or not they were ever real, and the review then scores every"
echo "rejection a true positive. That is the wrong answer, confidently."
echo
echo "  sc=upheld        => bitcoind knew none of them AND the block walk completed:"
echo "                      genuine detection candidate. Corroborate against the pool"
echo "                      block-found feed at this height."
echo "  sc=lookup_failed => the lookup could not be completed: UNADJUDICATED, count"
echo "                      separately, never as a detection. sc_error_kind says which:"
echo "                      rpc_error / deadline / mempool_loading / empty_mempool /"
echo "                      block_walk_incomplete / mempool_probe_incomplete."
echo "  sc missing       => verdict predates PB-40; it cannot be adjudicated at all."
echo "  sc_walk_shortfall non-null => the mined case was not fully ruled out; sc_mined"
echo "                      is a FLOOR, not a count. Check sc_blocks_scanned against"
echo "                      (sc_tip_height - height + 1), the number of blocks owed."
echo

if [[ ! -f "$VERDICT_LOG" ]]; then
  # Non-zero on purpose. Rejections are climbing and the durable record
  # that is supposed to adjudicate them does not exist, so this run
  # produced NO evidence. Exiting 0 here would let a soak with zero
  # adjudicable records read as a clean spot check, which is the exact
  # false-pass shape PB-40 exists to prevent. The usual cause is
  # VELDRA_MODE=shadow, which does not persist verdicts at all
  # (DeployMode::persist_verdicts is Observe|Inline), or a verdict log
  # the verifier's uid cannot write.
  echo
  echo "ERROR: $DELTA_REJECTED Class M rejection(s) in this window and NO verdict log at"
  echo "  $VERDICT_LOG. This spot check produced no adjudicable evidence."
  echo "  Check VELDRA_MODE (shadow does NOT persist verdicts; use observe) and that the"
  echo "  log path is writable by the verifier's uid. The verifier logs"
  echo "  'verdict durability write FAILED' on every failed append."
  exit 1
fi

jq -c \
  --arg n "$MAX_REJECTIONS" \
  'select(.reason_code == "v2_invariant_mempool_tolerance_exceeded")
   | {
       ts:        (.timestamp // .ts // null),
       id:        .id,
       height:    (.block_height // .height // null),
       sc:        (.mempool_adjudication.outcome // "missing"),
       sc_unknown_before: (.mempool_adjudication.unknown_before // null),
       sc_in_mempool:     (.mempool_adjudication.in_mempool // null),
       sc_mined:          (.mempool_adjudication.mined // null),
       sc_still_absent:   (.mempool_adjudication.still_absent // null),
       sc_blocks_scanned: (.mempool_adjudication.blocks_scanned // null),
       sc_tip_height:     (.mempool_adjudication.tip_height // null),
       sc_walk_shortfall: (.mempool_adjudication.block_walk_shortfall // null),
       sc_error:          (.mempool_adjudication.lookup_error // null),
       sc_error_kind:     (.mempool_adjudication.lookup_error_kind // null),
       detail:    .reason_detail
     }' \
  "$VERDICT_LOG" \
  | tail -n "$MAX_REJECTIONS" \
  | nl -ba
