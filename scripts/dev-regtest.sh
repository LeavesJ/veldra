#!/usr/bin/env bash
set -euo pipefail

########################################################################
# dev-regtest.sh
# Spin up:
#   - bitcoind on regtest
#   - pool-verifier (HTTP 8080, TCP 5001)
#   - template-manager (HTTP 8081, bitcoind backend)
########################################################################

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BITCOIN_PID=""
VERIFIER_PID=""
MANAGER_PID=""

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

  if [[ -n "${BITCOIN_PID}" ]] && kill -0 "${BITCOIN_PID}" 2>/dev/null; then
    echo "[dev-regtest] stopping bitcoind..."
    bitcoin-cli -regtest -rpcuser=veldra -rpcpassword=very_secure_password -rpcport=18443 stop \
      >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "[dev-regtest] ROOT_DIR = ${ROOT_DIR}"

########################################
# 1. start bitcoind on regtest
########################################
echo "[dev-regtest] starting bitcoind (regtest)..."
bitcoind -regtest \
  -daemon \
  -server=1 \
  -rpcuser=veldra \
  -rpcpassword=very_secure_password \
  -rpcport=18443 \
  -fallbackfee=0.0001 \
  -maxmempool=300 \
  >/dev/null 2>&1 || true

sleep 2

# best-effort PID grab (not critical, only used for nicer cleanup)
BITCOIN_PID="$(pgrep -n bitcoind || true)"

echo "[dev-regtest] ensure wallet exists..."
bitcoin-cli -regtest -rpcuser=veldra -rpcpassword=very_secure_password -rpcport=18443 \
  loadwallet veldra_wallet 2>/dev/null || \
bitcoin-cli -regtest -rpcuser=veldra -rpcpassword=very_secure_password -rpcport=18443 \
  createwallet veldra_wallet >/dev/null

########################################
# 2. build binaries
########################################
echo "[dev-regtest] building pool-verifier..."
(
  cd "${ROOT_DIR}/services/pool-verifier"
  cargo build --bin pool-verifier
)

echo "[dev-regtest] building template-manager..."
(
  cd "${ROOT_DIR}/services/template-manager"
  cargo build
)

########################################
# 3. start pool-verifier
########################################
echo "[dev-regtest] starting pool-verifier..."
(
  cd "${ROOT_DIR}/services/pool-verifier"

  export VELDRA_HTTP_ADDR="127.0.0.1:8080"
  export VELDRA_VERIFIER_ADDR="127.0.0.1:5001"
  export VELDRA_POLICY_PATH="${ROOT_DIR}/services/pool-verifier/policy.toml"
  export VELDRA_MEMPOOL_URL="http://127.0.0.1:8081/mempool"
  export VELDRA_DASH_MODE="regtest-bitcoind"

  exec ./target/debug/pool-verifier
) &
VERIFIER_PID=$!
echo "[dev-regtest] pool-verifier pid = ${VERIFIER_PID}"

echo "[dev-regtest] waiting for verifier TCP..."
for i in {1..10}; do
  if nc -z 127.0.0.1 5001 2>/dev/null; then
    break
  fi
  sleep 0.3
done

########################################
# 4. start template-manager (bitcoind)
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

echo "[dev-regtest] services running. Ctrl+C to stop."

########################################
# 5. block until Ctrl+C
########################################
wait
