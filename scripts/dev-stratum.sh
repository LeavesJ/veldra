#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[dev-stratum] ROOT_DIR = $ROOT_DIR"

VERIFIER_PID=""
BRIDGE_PID=""
MANAGER_PID=""

cleanup() {
  echo "[dev-stratum] cleanup: stopping services..."

  # kill template-manager
  if [[ -n "$MANAGER_PID" ]]; then
    if kill -0 "$MANAGER_PID" 2>/dev/null; then
      echo "[dev-stratum] TERM template-manager (pid $MANAGER_PID)..."
      kill "$MANAGER_PID" 2>/dev/null || true
    fi
  fi

  # kill sv2-bridge
  if [[ -n "$BRIDGE_PID" ]]; then
    if kill -0 "$BRIDGE_PID" 2>/dev/null; then
      echo "[dev-stratum] TERM sv2-bridge (pid $BRIDGE_PID)..."
      kill "$BRIDGE_PID" 2>/dev/null || true
    fi
  fi

  # kill pool-verifier
  if [[ -n "$VERIFIER_PID" ]]; then
    if kill -0 "$VERIFIER_PID" 2>/dev/null; then
      echo "[dev-stratum] TERM pool-verifier (pid $VERIFIER_PID)..."
      kill "$VERIFIER_PID" 2>/dev/null || true
    fi
  fi

  # small grace period
  sleep 1

  # force kill if anything survived
  for pid in "$MANAGER_PID" "$BRIDGE_PID" "$VERIFIER_PID"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      echo "[dev-stratum] KILL pid ${pid}..."
      kill -9 "${pid}" 2>/dev/null || true
    fi
  done
}

trap cleanup INT TERM EXIT

########################################
# 0. Build binaries once
########################################

echo "[dev-stratum] building pool-verifier..."
(cd "$ROOT_DIR/services/pool-verifier" && cargo build --bin pool-verifier)

echo "[dev-stratum] building sv2-bridge..."
(cd "$ROOT_DIR/services/sv2-bridge" && cargo build)

echo "[dev-stratum] building template-manager..."
(cd "$ROOT_DIR/services/template-manager" && cargo build)

########################################
# 1. Start pool-verifier (binary)
########################################

echo "[dev-stratum] starting pool-verifier..."
(
  cd "$ROOT_DIR/services/pool-verifier"

  export VELDRA_HTTP_ADDR="127.0.0.1:8080"
  export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"
  export VELDRA_POLICY_PATH="$ROOT_DIR/services/pool-verifier/policy.toml"
  # no mempool URL in pure Stratum mode
  export VELDRA_DASH_MODE="stratum-synthetic"
  exec ./target/debug/pool-verifier
) &
VERIFIER_PID=$!
echo "[dev-stratum] pool-verifier pid = $VERIFIER_PID"

########################################
# 2. Start sv2-bridge (binary)
########################################

echo "[dev-stratum] starting sv2-bridge..."
(
  cd "$ROOT_DIR/services/sv2-bridge"

  export VELDRA_BRIDGE_ADDR="127.0.0.1:3333"
  export VELDRA_BRIDGE_INTERVAL_SECS=3
  export VELDRA_BRIDGE_START_HEIGHT=500
  export VELDRA_BRIDGE_TX_COUNT=5
  export VELDRA_BRIDGE_TOTAL_FEES=100

  exec ./target/debug/sv2-bridge
) &
BRIDGE_PID=$!
echo "[dev-stratum] sv2-bridge pid = $BRIDGE_PID"

########################################
# 3. Start template-manager in stratum mode (binary)
########################################

echo "[dev-stratum] starting template-manager (stratum backend)..."
(
  cd "$ROOT_DIR/services/template-manager"

  export VELDRA_MANAGER_CONFIG="$ROOT_DIR/services/template-manager/manager_stratum.toml"
  export VELDRA_MANAGER_HTTP_ADDR="127.0.0.1:8081"
  export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"

  exec ./target/debug/template-manager
) &
MANAGER_PID=$!
echo "[dev-stratum] template-manager pid = $MANAGER_PID"

echo "[dev-stratum] HTTP: verifier 127.0.0.1:8080, manager 127.0.0.1:8081"
echo "[dev-stratum] Stratum bridge on 127.0.0.1:3333"

wait
