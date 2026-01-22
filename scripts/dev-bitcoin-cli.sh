#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Must match dev-regtest.sh defaults, but allow env overrides.
REGTEST_DIR="${REGTEST_DIR:-${ROOT_DIR}/.tmp/regtest-demo}"

RPC_USER="${RPC_USER:-veldra}"
RPC_PASS="${RPC_PASS:-very_secure_password}"
RPC_PORT="${RPC_PORT:-18443}"

exec bitcoin-cli -regtest \
  -datadir="${REGTEST_DIR}" \
  -rpcuser="${RPC_USER}" \
  -rpcpassword="${RPC_PASS}" \
  -rpcport="${RPC_PORT}" \
  "$@"
