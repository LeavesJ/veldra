#!/usr/bin/env bash
set -euo pipefail

########################################################################
# dev-regtest.sh
# Clean regtest boot for Veldra demo:
#   - bitcoind on regtest (dedicated datadir; no stale processes)
#   - pool-verifier (HTTP 8080, TCP 5001)
#   - template-manager (HTTP 8081, bitcoind backend)
#
# This script does NOT generate ongoing traffic.
# Use scripts/dev-demo-phases.sh for demo traffic.
########################################################################

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[dev-regtest] ROOT_DIR = ${ROOT_DIR}"

# Workspace build output (Cargo workspace puts binaries under ROOT_DIR/target/)
POOL_VERIFIER_BIN="${ROOT_DIR}/target/debug/pool-verifier"
TEMPLATE_MANAGER_BIN="${ROOT_DIR}/target/debug/template-manager"

# Dedicated regtest datadir (constant path for the demo stack)
REGTEST_DIR="${ROOT_DIR}/.tmp/regtest-demo"
TMP_DIR="${ROOT_DIR}/.tmp"
mkdir -p "${TMP_DIR}"

# Configurable via env override
RPC_USER="${RPC_USER:-veldra}"
RPC_PASS="${RPC_PASS:-very_secure_password}"
RPC_PORT="${RPC_PORT:-18443}"
P2P_PORT="${P2P_PORT:-18444}"

VERIFIER_HTTP_ADDR="${VERIFIER_HTTP_ADDR:-127.0.0.1:8080}"
MANAGER_HTTP_ADDR="${MANAGER_HTTP_ADDR:-127.0.0.1:8081}"
VERIFIER_TCP_ADDR="${VERIFIER_TCP_ADDR:-127.0.0.1:5001}"

# Pick exactly one policy file for the demo run
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/config/demo-showcase-policy.toml}"

# Wallet name used for funding/demo spends
WALLET_NAME="${WALLET_NAME:-veldra_wallet}"

BITCOIND_PID=""
VERIFIER_PID=""
MANAGER_PID=""

btc_cli() {
  bitcoin-cli -regtest -datadir="${REGTEST_DIR}" \
    -rpcuser="${RPC_USER}" -rpcpassword="${RPC_PASS}" -rpcport="${RPC_PORT}" \
    "$@"
}

pgrep_bitcoind_for_datadir() {
  pgrep -f "bitcoind.*-datadir=${REGTEST_DIR}" || true
}

wait_for_rpc() {
  # Wait up to ~10s for RPC
  for _ in {1..40}; do
    if btc_cli getblockchaininfo >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

assert_port_free() {
  local port="$1"
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "[dev-regtest] ERROR: port ${port} already in use"
    exit 1
  fi
}

assert_bin() {
  local path="$1"
  local name="$2"
  if [[ ! -f "${path}" ]]; then
    echo "[dev-regtest] ERROR: missing ${name} binary at ${path}"
    echo "[dev-regtest] Hint: run cargo build (workspace) succeeded but binary not found."
    exit 1
  fi
  if [[ ! -x "${path}" ]]; then
    echo "[dev-regtest] ERROR: ${name} binary not executable at ${path}"
    exit 1
  fi
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

  # Graceful stop if RPC is reachable
  btc_cli stop >/dev/null 2>&1 || true

  # Kill only bitcoind processes that are explicitly using our datadir
  local pids
  pids="$(pgrep_bitcoind_for_datadir)"
  if [[ -n "${pids}" ]]; then
    echo "[dev-regtest] TERM bitcoind (pids ${pids})..."
    kill ${pids} 2>/dev/null || true
    sleep 0.5
    pids="$(pgrep_bitcoind_for_datadir)"
    if [[ -n "${pids}" ]]; then
      echo "[dev-regtest] KILL bitcoind (pids ${pids})..."
      kill -9 ${pids} 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT

########################################
# 0) fail fast on port conflicts
########################################
assert_port_free "${RPC_PORT}"
assert_port_free "${P2P_PORT}"
assert_port_free "${VERIFIER_TCP_ADDR##*:}"
assert_port_free "${VERIFIER_HTTP_ADDR##*:}"
assert_port_free "${MANAGER_HTTP_ADDR##*:}"

########################################
# 1) pre-clean any stale bitcoind for this datadir
########################################
stale_pids="$(pgrep_bitcoind_for_datadir)"
if [[ -n "${stale_pids}" ]]; then
  echo "[dev-regtest] found stale bitcoind using ${REGTEST_DIR}: ${stale_pids}"
  # Try graceful stop; if it fails, cleanup trap will kill by datadir match
  btc_cli stop >/dev/null 2>&1 || true
  kill ${stale_pids} 2>/dev/null || true
  sleep 0.5
fi

########################################
# 2) start bitcoind (fresh)
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

# Record PID only for informational purposes; killing uses datadir match
BITCOIND_PID="$(pgrep_bitcoind_for_datadir | head -n 1 || true)"
echo "[dev-regtest] bitcoind pid = ${BITCOIND_PID:-unknown}"

echo "[dev-regtest] waiting for bitcoind RPC..."
if ! wait_for_rpc; then
  echo "[dev-regtest] ERROR: bitcoind RPC did not become ready"
  exit 1
fi

echo "[dev-regtest] ensure wallet exists..."
btc_cli loadwallet "${WALLET_NAME}" >/dev/null 2>&1 || \
  btc_cli -named createwallet wallet_name="${WALLET_NAME}" >/dev/null

########################################
# 3) build (workspace outputs binaries to ROOT_DIR/target/debug)
########################################
echo "[dev-regtest] building pool-verifier..."
(
  cd "${ROOT_DIR}"
  cargo build -p pool-verifier --bin pool-verifier
)

echo "[dev-regtest] building template-manager..."
(
  cd "${ROOT_DIR}"
  cargo build -p template-manager --bin template-manager
)

# Verify binaries exist where the script will run them
assert_bin "${POOL_VERIFIER_BIN}" "pool-verifier"
assert_bin "${TEMPLATE_MANAGER_BIN}" "template-manager"

########################################
# 4) start pool-verifier
########################################
echo "[dev-regtest] starting pool-verifier..."
(
  cd "${ROOT_DIR}/services/pool-verifier"
  mkdir -p data

  export VELDRA_HTTP_ADDR="${VERIFIER_HTTP_ADDR}"
  export VELDRA_VERIFIER_ADDR="${VERIFIER_TCP_ADDR}"

  # Set exactly one authoritative policy location for the demo run
  export VELDRA_POLICY_FILE="${POLICY_FILE}"

  # Pool verifier mempool proxy points at template-manager HTTP
  export VELDRA_MEMPOOL_URL="http://${MANAGER_HTTP_ADDR}/mempool"
  export VELDRA_DASH_MODE="regtest"

  exec "${POOL_VERIFIER_BIN}"
) &
VERIFIER_PID=$!
echo "[dev-regtest] pool-verifier pid = ${VERIFIER_PID}"

echo "[dev-regtest] waiting for verifier TCP..."
for _ in {1..40}; do
  if nc -z "${VERIFIER_TCP_ADDR%:*}" "${VERIFIER_TCP_ADDR##*:}" 2>/dev/null; then
    break
  fi
  sleep 0.25
done

########################################
# 5) start template-manager
########################################
echo "[dev-regtest] starting template-manager (bitcoind backend)..."
(
  cd "${ROOT_DIR}/services/template-manager"

  export VELDRA_MANAGER_CONFIG="${ROOT_DIR}/services/template-manager/manager.toml"
  export VELDRA_MANAGER_HTTP_ADDR="${MANAGER_HTTP_ADDR}"
  export VELDRA_VERIFIER_ADDR="${VERIFIER_TCP_ADDR}"

  exec "${TEMPLATE_MANAGER_BIN}"
) &
MANAGER_PID=$!
echo "[dev-regtest] template-manager pid = ${MANAGER_PID}"

echo "[dev-regtest] HTTP: verifier http://${VERIFIER_HTTP_ADDR}, manager http://${MANAGER_HTTP_ADDR}"

########################################
# 6) initial funding (so demo scripts can spend)
########################################
echo "[dev-regtest] funding wallet..."
ADDR="$(btc_cli getnewaddress)"
btc_cli -named generatetoaddress nblocks=110 address="${ADDR}" >/dev/null
echo "[dev-regtest] funded. coinbase addr = ${ADDR}"

echo "[dev-regtest] stack is up. Now run: ./scripts/dev-demo-phases.sh"
wait
