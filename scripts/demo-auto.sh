#!/usr/bin/env bash
# Veldra demo runner (macOS-friendly, regtest-friendly)
# - boots pool-verifier + template-manager
# - waits on /health (NOT /mempool, so it won't hang if backend is down)
# - ensures config/policy.toml exists by copying OPEN_POLICY_PATH into $ROOT/config/policy.toml
# - applies an OPEN policy via /policy/apply_toml
# - writes logs into artifacts/demo_<timestamp>/

set -euo pipefail

# -------------------- paths --------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TS="$(date +'%Y%m%d_%H%M%S')"
ART_DIR="${ART_DIR:-artifacts/demo_${TS}}"
mkdir -p "$ART_DIR"

# -------------------- endpoints / env --------------------
VERIFIER_HTTP="${VERIFIER_HTTP:-127.0.0.1:8080}"
MANAGER_HTTP="${MANAGER_HTTP:-127.0.0.1:8081}"

# template-manager -> verifier TCP
export VELDRA_VERIFIER_ADDR="${VELDRA_VERIFIER_ADDR:-127.0.0.1:5001}"

# manager config path (MUST exist)
export VELDRA_MANAGER_CONFIG="${VELDRA_MANAGER_CONFIG:-$ROOT/manager.toml}"

# open policy file to apply via API (MUST exist)
OPEN_POLICY_PATH="${OPEN_POLICY_PATH:-$ROOT/config/demo-open-policy.toml}"

# crate manifests (override if you don’t have a workspace root Cargo.toml)
VERIFIER_MANIFEST="${VERIFIER_MANIFEST:-$ROOT/services/pool-verifier/Cargo.toml}"
MANAGER_MANIFEST="${MANAGER_MANIFEST:-$ROOT/services/template-manager/Cargo.toml}"

export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export RUST_LOG="${RUST_LOG:-info}"

# -------------------- logging --------------------
VERIFIER_LOG="$ART_DIR/pool-verifier.log"
MANAGER_LOG="$ART_DIR/template-manager.log"

# -------------------- helpers --------------------
die() { echo "[demo] ERROR: $*" >&2; exit 1; }

wait_http_ok_or_die() {
  local url="$1"
  local label="$2"
  local pid="$3"
  local log="$4"
  local tries="${5:-160}"

  echo -n "[demo] wait $label "
  for _ in $(seq 1 "$tries"); do
    # if process died, fail fast with logs
    if ! kill -0 "$pid" 2>/dev/null; then
      echo
      echo "[demo] ERROR: $label process exited (pid=$pid)"
      echo "[demo] ---- last 120 lines of log: $log ----"
      tail -n 120 "$log" || true
      exit 1
    fi

    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "ok"
      return 0
    fi
    echo -n "."
    sleep 0.25
  done

  echo
  echo "[demo] ERROR: timed out waiting for $label at $url"
  echo "[demo] ---- last 120 lines of log: $log ----"
  tail -n 120 "$log" || true
  exit 1
}

post_toml_or_die() {
  local url="$1"
  local toml_path="$2"

  [[ -f "$toml_path" ]] || die "TOML file not found: $toml_path"

  # macOS curl: no --fail-with-body. Use -f and dump body on failure.
  local body_file="$ART_DIR/post_body.txt"
  local code
  code="$(curl -sS -o "$body_file" -w "%{http_code}" -f \
    -H "Content-Type: text/plain" \
    --data-binary "@$toml_path" \
    "$url" || true)"

  if [[ "$code" != "200" && "$code" != "204" ]]; then
    echo "[demo] ERROR: POST failed (status=$code) url=$url" >&2
    echo "[demo] response body:" >&2
    cat "$body_file" >&2 || true
    exit 1
  fi
}

cargo_run_verifier() {
  # pool-verifier crate has multiple bins: pick the right one
  if grep -q 'default-run' "$VERIFIER_MANIFEST" 2>/dev/null; then
    cargo run --manifest-path "$VERIFIER_MANIFEST"
  else
    cargo run --manifest-path "$VERIFIER_MANIFEST" --bin pool-verifier
  fi
}

cargo_run_manager() {
  if grep -q 'default-run' "$MANAGER_MANIFEST" 2>/dev/null; then
    cargo run --manifest-path "$MANAGER_MANIFEST"
  else
    cargo run --manifest-path "$MANAGER_MANIFEST" --bin template-manager
  fi
}

cleanup() {
  echo "[demo] stopping services"
  [[ -n "${MANAGER_PID:-}" ]] && kill "$MANAGER_PID" 2>/dev/null || true
  [[ -n "${VERIFIER_PID:-}" ]] && kill "$VERIFIER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# -------------------- banner --------------------
echo "[demo] root: $ROOT"
echo "[demo] artifacts: $ART_DIR"
echo "[demo] verifier: http://$VERIFIER_HTTP"
echo "[demo] template-manager: http://$MANAGER_HTTP"
echo "[demo] VELDRA_VERIFIER_ADDR: $VELDRA_VERIFIER_ADDR"
echo "[demo] VELDRA_MANAGER_CONFIG: $VELDRA_MANAGER_CONFIG"
echo "[demo] OPEN_POLICY_PATH: $OPEN_POLICY_PATH"

# -------------------- validate inputs --------------------
[[ -f "$VELDRA_MANAGER_CONFIG" ]] || die "manager config file not found: $VELDRA_MANAGER_CONFIG"
[[ -f "$OPEN_POLICY_PATH" ]] || die "open policy file not found: $OPEN_POLICY_PATH"
[[ -f "$VERIFIER_MANIFEST" ]] || die "verifier manifest not found: $VERIFIER_MANIFEST"
[[ -f "$MANAGER_MANIFEST" ]] || die "manager manifest not found: $MANAGER_MANIFEST"

# -------------------- ensure config/policy.toml exists --------------------
# This fixes: "Using policy file: config/policy.toml ... No such file or directory"
mkdir -p "$ROOT/config"
cp -f "$OPEN_POLICY_PATH" "$ROOT/config/policy.toml"

# -------------------- boot services --------------------
echo "[demo] boot pool-verifier..."
(cargo_run_verifier) >"$VERIFIER_LOG" 2>&1 &
VERIFIER_PID=$!

wait_http_ok_or_die "http://$VERIFIER_HTTP/health" "verifier /health" "$VERIFIER_PID" "$VERIFIER_LOG"

echo "[demo] boot template-manager..."
(cargo_run_manager) >"$MANAGER_LOG" 2>&1 &
MANAGER_PID=$!

wait_http_ok_or_die "http://$MANAGER_HTTP/health" "template-manager /health" "$MANAGER_PID" "$MANAGER_LOG"

# -------------------- apply OPEN policy via API --------------------
echo "[demo] apply OPEN policy (TOML)"
post_toml_or_die "http://$VERIFIER_HTTP/policy/apply_toml" "$OPEN_POLICY_PATH"
echo "[demo] policy applied"

echo
echo "[demo] dashboard: http://$VERIFIER_HTTP/"
echo "[demo] logs:"
echo "  $VERIFIER_LOG"
echo "  $MANAGER_LOG"
echo
echo "[demo] running. Ctrl+C to stop."
while true; do sleep 1; done
