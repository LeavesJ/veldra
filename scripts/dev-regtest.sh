#!/usr/bin/env bash
set -euo pipefail

########################################################################
# dev-regtest.sh
# Clean regtest boot for ReserveGrid OS demo:
#   - bitcoind on regtest (dedicated datadir; no stale processes)
#   - pool-verifier (HTTP 8080, TCP 5001)
#   - template-manager (HTTP 8081, bitcoind backend)
#
# This script does NOT generate ongoing traffic.
# Use scripts/dev-demo-phases.sh for demo traffic.
########################################################################

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[dev-regtest] ROOT_DIR = ${ROOT_DIR}"

# Dedicated, fresh regtest datadir per run
REGTEST_DIR="${ROOT_DIR}/.tmp/regtest-demo"
mkdir -p "${ROOT_DIR}/.tmp"

RPC_USER="veldra"
RPC_PASS="very_secure_password"
RPC_PORT="18443"
P2P_PORT="18444"

BITCOIND_PID=""
VERIFIER_PID=""
MANAGER_PID=""

btc_cli() {
  bitcoin-cli -regtest -datadir="${REGTEST_DIR}" -rpcuser="${RPC_USER}" -rpcpassword="${RPC_PASS}" -rpcport="${RPC_PORT}" "$@"
}

cleanup() {
  echo "[dev-regtest] cleanup: stopping services..."

  if [[ -n "${MANAGER_PID}" ]] && kill -0 "${MANAGER_PID}" 2>/dev/null; then
    echo "[dev-regtest] TERM template-manager (pid ${MANAGER_PID})..."
    kill "${MANAGER_PID}" 2>/dev/null || true
  fi

  if [[ -n "${VERIFIER_PID}" ]] && kill -0 "${VERIFIER_PID}" 2>/dev/null; then
    echo "[dev-regtest] TERM pool-verifier (pid ${VERIFIER_PID})..."
    kill "${VERIFIER_PID}" 2>/dev/null || true
  fi

  # graceful stop if RPC is reachable
  btc_cli stop >/dev/null 2>&1 || true

  # best-effort kill if still alive
  if [[ -n "${BITCOIND_PID}" ]] && kill -0 "${BITCOIND_PID}" 2>/dev/null; then
    echo "[dev-regtest] KILL bitcoind (pid ${BITCOIND_PID})..."
    kill "${BITCOIND_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

########################################
# 1) start bitcoind (fresh)
########################################
echo "[dev-regtest] starting bitcoind (regtest) in ${REGTEST_DIR}..."
rm -rf "${REGTEST_DIR}"
mkdir -p "${REGTEST_DIR}"

bitcoind -regtest \
  -datadir="${REGTEST_DIR}" \
  -daemon \
  -server=1 \
  -rpcuser="${RPC_USER}" \
  -rpcpassword="${RPC_PASS}" \
  -rpcport="${RPC_PORT}" \
  -port="${P2P_PORT}" \
  -fallbackfee=0.0001 \
  -maxmempool=300 \
  >/dev/null 2>&1

sleep 2
BITCOIND_PID="$(pgrep -n bitcoind || true)"
echo "[dev-regtest] bitcoind pid = ${BITCOIND_PID:-unknown}"

echo "[dev-regtest] ensure wallet exists..."
btc_cli loadwallet veldra_wallet >/dev/null 2>&1 || btc_cli createwallet veldra_wallet >/dev/null

########################################
# 2) build
########################################
echo "[dev-regtest] building pool-verifier..."
(
  cd "${ROOT_DIR}/services/pool-verifier"
  cargo build --bin pool-verifier
)

echo "[dev-regtest] building template-manager..."
(
  cd "${ROOT_DIR}/services/template-manager"
  cargo build --bin template-manager
)

########################################
# 3) start pool-verifier
########################################
echo "[dev-regtest] starting pool-verifier..."
(
  cd "${ROOT_DIR}/services/pool-verifier"
  mkdir -p data

  export VELDRA_HTTP_ADDR="127.0.0.1:8080"
  export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"

  # keep both for compatibility with your code
  export VELDRA_POLICY_PATH="${ROOT_DIR}/services/pool-verifier/policy.toml"
  export VELDRA_POLICY_FILE="${ROOT_DIR}/config/beta-policy.toml"
  export VELDRA_POLICY_FILE="${ROOT_DIR}/config/demo-showcase-policy.toml"

  export VELDRA_MEMPOOL_URL="http://127.0.0.1:8081/mempool"
  export VELDRA_DASH_MODE="regtest"

  exec ./target/debug/pool-verifier
) &
VERIFIER_PID=$!
echo "[dev-regtest] pool-verifier pid = ${VERIFIER_PID}"

echo "[dev-regtest] waiting for verifier TCP..."
for _ in {1..40}; do
  if nc -z 127.0.0.1 5001 2>/dev/null; then
    break
  fi
  sleep 0.25
done

########################################
# 4) start template-manager
########################################
echo "[dev-regtest] starting template-manager (bitcoind backend)..."
(
  cd "${ROOT_DIR}/services/template-manager"

  export VELDRA_MANAGER_CONFIG="${ROOT_DIR}/services/template-manager/manager.toml"
  export VELDRA_MANAGER_HTTP_ADDR="127.0.0.1:8081"
  export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"

  exec ./target/debug/template-manager
) &
MANAGER_PID=$!
echo "[dev-regtest] template-manager pid = ${MANAGER_PID}"

echo "[dev-regtest] HTTP: verifier 127.0.0.1:8080, manager 127.0.0.1:8081"

########################################
# 5) initial funding (so demo scripts can spend)
########################################
echo "[dev-regtest] funding wallet..."
ADDR="$(btc_cli getnewaddress)"
btc_cli generatetoaddress 110 "$ADDR" >/dev/null
echo "[dev-regtest] funded. coinbase addr = ${ADDR}"

echo "[dev-regtest] stack is up. Now run: ./scripts/dev-demo-phases.sh"
wait
