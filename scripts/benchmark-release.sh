#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# benchmark-release.sh — Release build latency benchmark for CL-01
#
# Runs rg-load-test against pool-verifier in Docker Compose (release build).
# Produces numbers for: avg, p99, max latency across multiple scenarios.
#
# Prerequisites:
#   docker compose up -d   (stack must be healthy)
#   cargo build --release -p rg-load-test
#
# Scenario 6 opens 100 concurrent connections, which is far above what a
# production pool ever holds, and it opens all of them from one host.
# docker-compose.yml therefore sets VELDRA_VERIFIER_MAX_CONNECTIONS=256
# (PB-26) and VELDRA_VERIFIER_MAX_CONNECTIONS_PER_IP=256 (PB-27) for
# this stack. Pointing this script at a stack running the shipped
# defaults of 32 and 8 will show refused connections and a rising
# verifier_connections_refused_total or
# verifier_connections_refused_per_ip_total; the per-IP counter is the
# one that tells you the global cap is not what is binding.
#
# Usage:
#   ./scripts/benchmark-release.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BINARY="${RG_LOAD_TEST:-target/release/rg-load-test}"
TARGET="${VELDRA_LOAD_TARGET:-127.0.0.1:9090}"

if [[ ! -x "$BINARY" ]]; then
  echo "Building rg-load-test in release mode..."
  cargo build --release -p rg-load-test
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ReserveGrid OS — CL-01 Release Build Benchmark"
echo "  Target: ${TARGET}"
echo "  Binary: ${BINARY}"
echo "  Date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "════════════════════════════════════════════════════════════════"
echo ""

run_scenario() {
  local label="$1"
  local scenario="$2"
  local conns="${3:-10}"
  local rate="${4:-100}"
  local dur="${5:-30}"

  echo "── ${label} (conn=${conns} rate=${rate} dur=${dur}s) ──"
  "$BINARY" \
    --target "$TARGET" \
    --concurrency "$conns" \
    --rate "$rate" \
    --duration "$dur" \
    --scenario "$scenario" \
    --envelope 2>&1 | grep -E "Summary|completed|reject"
  echo ""
}

# Scenario 1: Baseline valid (10 conn, 100 TPS, 30s)
run_scenario "Baseline valid" valid 10 100 30

# Scenario 2: Stress valid (50 conn, 1000 TPS, 30s)
run_scenario "Stress valid" valid 50 1000 30

# Scenario 3: 100% rejection (bad prevhash, 10 conn, 100 TPS, 15s)
run_scenario "100% rejection (prevhash)" reject-prevhash 10 100 15

# Scenario 4: 100% rejection (stale, 10 conn, 100 TPS, 15s)
run_scenario "100% rejection (stale)" stale 10 100 15

# Scenario 5: Mixed 30% rejection (10 conn, 100 TPS, 15s)
run_scenario "Mixed 30% rejection" mixed 10 100 15

# Scenario 6: High concurrency burst (100 conn, 2000 TPS, 15s)
run_scenario "High concurrency burst" valid 100 2000 15

echo "════════════════════════════════════════════════════════════════"
echo "  Benchmark complete. Copy the numbers above into TESTLOG.md"
echo "  under CL-01 as a 'Release build' evidence row."
echo "════════════════════════════════════════════════════════════════"
