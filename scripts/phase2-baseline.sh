#!/usr/bin/env bash
# phase2-baseline.sh
#
# Captures the four ADR-003 Phase 2 metric counters from the
# verifier's /metrics endpoint and writes them to a JSON baseline
# file. Run at T-1 day per docs/runbooks/phase2-shadow-soak.md
# Pre-Soak Setup item 3, before the soak window begins.
#
# Usage:
#   scripts/phase2-baseline.sh [--metrics-url URL] [--out PATH]
#
# Defaults:
#   --metrics-url http://127.0.0.1:8081/metrics  (verifier default HTTP)
#   --out         ./data/phase2-baseline.json
#
# The baseline file gets consumed by phase2-spot-check.sh on every
# subsequent soak check (T+0, T+1, T+3, T+5, T+7) to compute counter
# deltas. Do not delete the baseline file mid-soak; doing so resets
# the soak math.

set -euo pipefail

METRICS_URL="${VELDRA_PHASE2_METRICS_URL:-http://127.0.0.1:8081/metrics}"
OUT_PATH="${VELDRA_PHASE2_BASELINE_PATH:-./data/phase2-baseline.json}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --metrics-url) METRICS_URL="$2"; shift 2 ;;
    --out)         OUT_PATH="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# //; s/^#//'
      exit 0
      ;;
    *)
      echo "phase2-baseline.sh: unknown arg '$1'" >&2
      exit 2
      ;;
  esac
done

if ! command -v curl >/dev/null 2>&1; then
  echo "phase2-baseline.sh: curl is required but not on PATH" >&2
  exit 3
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "phase2-baseline.sh: jq is required but not on PATH" >&2
  exit 3
fi

mkdir -p "$(dirname "$OUT_PATH")"

# Fetch /metrics once. Fail fast if the endpoint is unreachable so
# the operator knows to fix verifier connectivity before T+0 rather
# than discovering it mid-soak.
METRICS_TEXT="$(curl --silent --show-error --fail --max-time 10 "$METRICS_URL")"

# Parse the four Phase 2 counters out of the OpenMetrics text.
#
# Note on metric naming: the prometheus-client crate auto-appends
# `_total` to counter exports per OpenMetrics convention. The verifier
# registration code drops the redundant `_total` from counter names
# (PB-12 fix), so counters export the single-suffix canonical names:
#   verifier_phase2_checks_total{result="agreed"} 12345
#   verifier_phase2_degraded_total 3
# Gauges are unaffected:
#   verifier_mempool_view_age_seconds 7
#   verifier_mempool_view_size 4823
# The parsers below retain dual single/double suffix tolerance so they
# keep working against both post-fix and any older pre-fix verifier.
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

AGREED="$(parse_counter_with_label verifier_phase2_checks_total agreed)"
REJECTED="$(parse_counter_with_label verifier_phase2_checks_total rejected)"
SKIPPED="$(parse_counter_with_label verifier_phase2_checks_total skipped)"
STALE="$(parse_counter_with_label verifier_phase2_checks_total stale)"
# PB-40: a first-pass tolerance breach that bitcoind overturned. It is
# a Class M check that ran, so it belongs in the soak denominator, and
# it emitted no rejection, so it never belongs in FP_total.
RECOVERED="$(parse_counter_with_label verifier_phase2_checks_total recovered)"
SC_WITHDRAWN="$(parse_counter_by_label_key outcome verifier_phase2_second_chance_total withdrawn)"
SC_UPHELD="$(parse_counter_by_label_key outcome verifier_phase2_second_chance_total upheld)"
SC_FAILED="$(parse_counter_by_label_key outcome verifier_phase2_second_chance_total lookup_failed)"
DEGRADED="$(parse_counter verifier_phase2_degraded_total)"
VIEW_AGE="$(parse_counter verifier_mempool_view_age_seconds)"
VIEW_SIZE="$(parse_counter verifier_mempool_view_size)"

# Default any missing label-counter to 0 (the verifier omits unseen
# label combinations from the export until the first observation).
AGREED="${AGREED:-0}"
REJECTED="${REJECTED:-0}"
SKIPPED="${SKIPPED:-0}"
STALE="${STALE:-0}"
RECOVERED="${RECOVERED:-0}"
SC_WITHDRAWN="${SC_WITHDRAWN:-0}"
SC_UPHELD="${SC_UPHELD:-0}"
SC_FAILED="${SC_FAILED:-0}"
DEGRADED="${DEGRADED:-0}"
VIEW_AGE="${VIEW_AGE:-0}"
VIEW_SIZE="${VIEW_SIZE:-0}"

CAPTURED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

jq -n \
  --arg captured_at "$CAPTURED_AT" \
  --arg metrics_url "$METRICS_URL" \
  --argjson agreed   "$AGREED" \
  --argjson rejected "$REJECTED" \
  --argjson skipped  "$SKIPPED" \
  --argjson stale    "$STALE" \
  --argjson recovered "$RECOVERED" \
  --argjson sc_withdrawn "$SC_WITHDRAWN" \
  --argjson sc_upheld "$SC_UPHELD" \
  --argjson sc_failed "$SC_FAILED" \
  --argjson degraded "$DEGRADED" \
  --argjson view_age "$VIEW_AGE" \
  --argjson view_size "$VIEW_SIZE" \
  '{
    captured_at: $captured_at,
    metrics_url: $metrics_url,
    note: "ADR-003 Phase 2 #6 baseline. Consumed by phase2-spot-check.sh.",
    counters: {
      verifier_phase2_checks_total_agreed:   $agreed,
      verifier_phase2_checks_total_rejected: $rejected,
      verifier_phase2_checks_total_skipped:  $skipped,
      verifier_phase2_checks_total_stale:    $stale,
      verifier_phase2_checks_total_recovered: $recovered,
      verifier_phase2_second_chance_total_withdrawn:    $sc_withdrawn,
      verifier_phase2_second_chance_total_upheld:       $sc_upheld,
      verifier_phase2_second_chance_total_lookup_failed: $sc_failed,
      verifier_phase2_degraded_total:        $degraded
    },
    gauges: {
      verifier_mempool_view_age_seconds: $view_age,
      verifier_mempool_view_size:        $view_size
    }
  }' > "$OUT_PATH"

echo "phase2-baseline: wrote $OUT_PATH at $CAPTURED_AT"
echo "  agreed=$AGREED  rejected=$REJECTED  recovered=$RECOVERED  skipped=$SKIPPED  stale=$STALE"
echo "  second_chance: withdrawn=$SC_WITHDRAWN  upheld=$SC_UPHELD  lookup_failed=$SC_FAILED"
echo "  degraded=$DEGRADED  view_age=${VIEW_AGE}s  view_size=$VIEW_SIZE"
