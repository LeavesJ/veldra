#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[dev-stratum] ROOT_DIR = ${ROOT_DIR}"

# Addresses (allow overrides)
VERIFIER_HTTP_ADDR="${VERIFIER_HTTP_ADDR:-127.0.0.1:8080}"
VERIFIER_TCP_ADDR="${VERIFIER_TCP_ADDR:-127.0.0.1:5001}"
MANAGER_HTTP_ADDR="${MANAGER_HTTP_ADDR:-127.0.0.1:8081}"
BRIDGE_ADDR="${BRIDGE_ADDR:-127.0.0.1:3333}"

# Pick exactly one policy file
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/config/policy.toml}"

VERIFIER_PID=""
BRIDGE_PID=""
MANAGER_PID=""

assert_port_free() {
  local port="$1"
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "[dev-stratum] ERROR: port ${port} already in use"
    exit 1
  fi
}

wait_tcp() {
  local host="$1"
  local port="$2"
  for _ in {1..40}; do
    if nc -z "${host}" "${port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  echo "[dev-stratum] ERROR: ${host}:${port} did not become ready"
  exit 1
}

cleanup() {
  echo "[dev-stratum] cleanup: stopping services..."

  if [[ -n "${MANAGER_PID}" ]] && kill -0 "${MANAGER_PID}" 2>/dev/null; then
    echo "[dev-stratum] TERM template-manager (pid ${MANAGER_PID})..."
    kill "${MANAGER_PID}" 2>/dev/null || true
  fi

  if [[ -n "${BRIDGE_PID}" ]] && kill -0 "${BRIDGE_PID}" 2>/dev/null; then
    echo "[dev-stratum] TERM sv2-bridge (pid ${BRIDGE_PID})..."
    kill "${BRIDGE_PID}" 2>/dev/null || true
  fi

  if [[ -n "${VERIFIER_PID}" ]] && kill -0 "${VERIFIER_PID}" 2>/dev/null; then
    echo "[dev-stratum] TERM pool-verifier (pid ${VERIFIER_PID})..."
    kill "${VERIFIER_PID}" 2>/dev/null || true
  fi

  sleep 0.75

  for pid in "${MANAGER_PID}" "${BRIDGE_PID}" "${VERIFIER_PID}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      echo "[dev-stratum] KILL pid ${pid}..."
      kill -9 "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup INT TERM EXIT

########################################
# 0) fail fast on port conflicts
########################################
assert_port_free "${VERIFIER_HTTP_ADDR##*:}"
assert_port_free "${MANAGER_HTTP_ADDR##*:}"
assert_port_free "${VERIFIER_TCP_ADDR##*:}"
assert_port_free "${BRIDGE_ADDR##*:}"

########################################
# 1) build binaries
########################################
echo "[dev-stratum] building pool-verifier..."
(
  cd "${ROOT_DIR}/services/pool-verifier"
  cargo build --bin pool-verifier
)

echo "[dev-stratum] building sv2-bridge..."
(
  cd "${ROOT_DIR}/services/sv2-bridge"
  cargo build
)

echo "[dev-stratum] building template-manager..."
(
  cd "${ROOT_DIR}/services/template-manager"
  cargo build --bin template-manager
)

########################################
# 2) start pool-verifier
########################################
echo "[dev-stratum] starting pool-verifier..."
(
  cd "${ROOT_DIR}/services/pool-verifier"
  mkdir -p data

  export VELDRA_HTTP_ADDR="${VERIFIER_HTTP_ADDR}"
  export VELDRA_VERIFIER_ADDR="${VERIFIER_TCP_ADDR}"

  # v0.2.0 scripts should set a single authoritative policy file
  export VELDRA_POLICY_FILE="${POLICY_FILE}"

  # Stratum synthetic mode: explicitly disable mempool dependency
  export VELDRA_MEMPOOL_URL=""
  export VELDRA_DASH_MODE="stratum-synthetic"

  exec ./target/debug/pool-verifier
) &
VERIFIER_PID=$!
echo "[dev-stratum] pool-verifier pid = ${VERIFIER_PID}"

echo "[dev-stratum] waiting for verifier TCP..."
wait_tcp "${VERIFIER_TCP_ADDR%:*}" "${VERIFIER_TCP_ADDR##*:}"

########################################
# 3) start sv2-bridge
########################################
echo "[dev-stratum] starting sv2-bridge..."
(
  cd "${ROOT_DIR}/services/sv2-bridge"

  export VELDRA_BRIDGE_ADDR="${BRIDGE_ADDR}"
  export VELDRA_BRIDGE_INTERVAL_SECS="${VELDRA_BRIDGE_INTERVAL_SECS:-3}"
  export VELDRA_BRIDGE_START_HEIGHT="${VELDRA_BRIDGE_START_HEIGHT:-500}"
  export VELDRA_BRIDGE_TX_COUNT="${VELDRA_BRIDGE_TX_COUNT:-5}"
  export VELDRA_BRIDGE_TOTAL_FEES="${VELDRA_BRIDGE_TOTAL_FEES:-100}"

  exec ./target/debug/sv2-bridge
) &
BRIDGE_PID=$!
echo "[dev-stratum] sv2-bridge pid = ${BRIDGE_PID}"

echo "[dev-stratum] waiting for bridge port..."
wait_tcp "${BRIDGE_ADDR%:*}" "${BRIDGE_ADDR##*:}"

########################################
# 4) start template-manager in stratum mode
########################################
echo "[dev-stratum] starting template-manager (stratum backend)..."
(
  cd "${ROOT_DIR}/services/template-manager"

  export VELDRA_MANAGER_CONFIG="${ROOT_DIR}/services/template-manager/manager_stratum.toml"
  export VELDRA_MANAGER_HTTP_ADDR="${MANAGER_HTTP_ADDR}"
  export VELDRA_VERIFIER_ADDR="${VERIFIER_TCP_ADDR}"

  exec ./target/debug/template-manager
) &
MANAGER_PID=$!
echo "[dev-stratum] template-manager pid = ${MANAGER_PID}"

echo "[dev-stratum] HTTP: verifier http://${VERIFIER_HTTP_ADDR}, manager http://${MANAGER_HTTP_ADDR}"
echo "[dev-stratum] Stratum bridge on ${BRIDGE_ADDR}"

wait
