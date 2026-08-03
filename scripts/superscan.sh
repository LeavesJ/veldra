#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# superscan.sh — Local pre-push gate that mirrors every CI job plus
# additional checks CI cannot perform.
#
# Run before every push. Exit 0 means CI will pass (barring Docker or
# integration-only issues). Any failure prints the gate name and stops.
#
# Usage:
#   ./scripts/superscan.sh             # full scan (CI mirror)
#   ./scripts/superscan.sh --quick     # skip audit/deny/vet (faster)
#   ./scripts/superscan.sh --deep      # CI mirror + static category gates
#   ./scripts/superscan.sh --deep-only # static category gates only (no cargo;
#                                      # runs in any sandbox with the repo)
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILURES=()
QUICK=false
START_TIME=$(date +%s)

DEEP=false
DEEP_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=true ;;
    --deep) DEEP=true ;;
    --deep-only) DEEP=true; DEEP_ONLY=true ;;
  esac
done

gate() {
  local name="$1"
  shift
  printf "${CYAN}[SCAN]${NC} %-50s" "$name"
  if "$@" > /tmp/superscan_out.txt 2>&1; then
    if grep -q "WARN" /tmp/superscan_out.txt 2>/dev/null; then
      printf "${YELLOW}PASS*${NC}\n"
      grep "WARN\|:" /tmp/superscan_out.txt | head -8 | sed 's/^/  > /'
    else
      printf "${GREEN}PASS${NC}\n"
    fi
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf "${RED}FAIL${NC}\n"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("$name")
    # Show last 20 lines of output for diagnosis.
    tail -20 /tmp/superscan_out.txt 2>/dev/null | sed 's/^/  > /'
  fi
}

skip() {
  local name="$1"
  printf "${CYAN}[SCAN]${NC} %-50s${YELLOW}SKIP${NC}\n" "$name"
  SKIP_COUNT=$((SKIP_COUNT + 1))
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ReserveGrid OS — superscan (local CI mirror)"
echo "════════════════════════════════════════════════════════════════"
echo ""

if ! $DEEP_ONLY; then

# ── 1. Format ──────────────────────────────────────────────────────
gate "cargo fmt --all --check" \
  cargo fmt --all --check

# ── 2. Build ───────────────────────────────────────────────────────
gate "cargo build --workspace" \
  cargo build --workspace

# ── 3. Clippy ──────────────────────────────────────────────────────
# Uses --all-targets so test binaries are linted too (catches
# explicit_iter_loop, expect_used, etc. that only appear in test code).
gate "cargo clippy --workspace --all-targets -D warnings" \
  cargo clippy --workspace --all-targets -- -D warnings

# ── 4. Tests ───────────────────────────────────────────────────────
gate "cargo test --workspace" \
  cargo test --workspace

# ── 5. Frontend build ──────────────────────────────────────────────
if [ -f services/rg-dashboard/frontend/package.json ]; then
  if has_cmd npx; then
    gate "frontend: npm ci" \
      bash -c "cd services/rg-dashboard/frontend && npm ci --silent"
    gate "frontend: tsc -b" \
      bash -c "cd services/rg-dashboard/frontend && npx tsc -b"
    gate "frontend: vite build" \
      bash -c "cd services/rg-dashboard/frontend && npx vite build"
  else
    skip "frontend (node/npx not found)"
  fi
else
  skip "frontend (package.json not found)"
fi

# ── 6. Advisory scan ──────────────────────────────────────────────
if $QUICK; then
  skip "cargo audit (--quick)"
else
  if has_cmd cargo-audit; then
    # Ignore list mirrors .github/workflows/ci.yml (R-122). Scope note:
    # this audits the FULL workspace lockfile including rg-desktop's
    # tauri tree, which CI seds out; the extra strictness is deliberate
    # (it caught RUSTSEC-2026-0104/0141 that CI's stale advisory cache
    # missed on 2026-06-11).
    gate "cargo audit" cargo audit --ignore RUSTSEC-2026-0173
  else
    skip "cargo audit (not installed)"
  fi
fi

# ── 7. License and ban check ──────────────────────────────────────
if $QUICK; then
  skip "cargo deny (--quick)"
else
  if has_cmd cargo-deny; then
    gate "cargo deny check licenses" cargo deny check licenses
    gate "cargo deny check bans" cargo deny check bans
    gate "cargo deny check sources" cargo deny check sources
    gate "cargo deny check advisories" cargo deny check advisories
  else
    skip "cargo deny (not installed)"
  fi
fi

# ── 8. Supply chain vet ───────────────────────────────────────────
if $QUICK; then
  skip "cargo vet (--quick)"
else
  if has_cmd cargo-vet; then
    gate "cargo vet" cargo vet
  else
    skip "cargo vet (not installed)"
  fi
fi

# ── 9. Secrets scan ──────────────────────────────────────────────
if has_cmd gitleaks; then
  gate "gitleaks detect" \
    gitleaks detect --source . --no-banner
else
  skip "gitleaks (not installed)"
fi

# ── 10. Gitignore shadow check ────────────────────────────────────
# Catches R-40/R-55: broad patterns hiding source files.
gate "gitignore: no source files shadowed" \
  bash -c '
    SHADOWED=$(git ls-files --ignored --exclude-standard 2>/dev/null || true)
    if [ -n "$SHADOWED" ]; then
      echo "ERROR: tracked files are gitignored:"
      echo "$SHADOWED"
      exit 1
    fi
  '

# ── 11. No TODO(v1.0.0) markers left ─────────────────────────────
gate "no TODO(v1.0.0) markers" \
  bash -c '
    HITS=$(grep -rn "TODO(v1\.0\.0)" services/ scripts/ --include="*.rs" --include="*.sh" --include="*.toml" 2>/dev/null | grep -v "superscan\.sh" || true)
    if [ -n "$HITS" ]; then
      echo "ERROR: unresolved TODO(v1.0.0) markers:"
      echo "$HITS"
      exit 1
    fi
  '

# ── 12. reason_code canonicality ──────────────────────────────────
# Catches drift between string literals and the canonical enum.
gate "reason_code: no raw string literals outside enum" \
  bash -c '
    # Look for hard-coded reason_code strings that bypass the enum.
    # Allowlist: test files, docs, TOML configs, the enum definition itself.
    HITS=$(grep -rn "reason_code.*=.*\"" services/ \
      --include="*.rs" \
      | grep -v "as_str()" \
      | grep -v "#\[serde" \
      | grep -v "///" \
      | grep -v "#\[cfg(test)\]" \
      | grep -v "mod tests" \
      | grep -v "assert" \
      | grep -v "unwrap_or" \
      | grep -v "\.into()" \
      | grep -v "ok" \
      | grep -v "unknown" \
      | grep -v "reason_code: None" \
      | grep -v "reason_code: Some(reason" \
      | grep -v "reason_code: Some(code" \
      | grep -v "reason_code: eval" \
      | grep -v "VerdictLabels" \
      || true)
    if [ -n "$HITS" ]; then
      echo "WARNING: possible hard-coded reason_code strings (verify these use the canonical enum):"
      echo "$HITS"
      # Warning only, not a hard fail. Manual review required.
    fi
  '

# ── 13. No .env or secrets committed ─────────────────────────────
gate "no secrets in staged files" \
  bash -c '
    BAD=$(git diff --cached --name-only 2>/dev/null | grep -E "^\.env$|credentials|\.pem$|\.key$" || true)
    if [ -n "$BAD" ]; then
      echo "ERROR: secret files staged for commit:"
      echo "$BAD"
      exit 1
    fi
  '

# ── 14. Cargo.lock in sync ────────────────────────────────────────
# Non-mutating sync check: --locked fails iff the committed lockfile does
# not satisfy the manifests, and touches nothing. The previous
# generate-lockfile approach REWROTE Cargo.lock in place and failed
# whenever upstream published any newer compatible version, which is
# drift availability, not desync (bit on 2026-06-11: mass-bumped the
# working lockfile and left Cargo.lock.bak.old cruft).
gate "Cargo.lock in sync (cargo metadata --locked)" \
  bash -c 'cargo metadata --locked --format-version 1 > /dev/null'

# ── 15. No large binary blobs staged ─────────────────────────────
gate "no large files (>5MB) staged" \
  bash -c '
    LARGE=$(git diff --cached --name-only 2>/dev/null | while read -r f; do
      if [ -f "$f" ]; then
        SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
        if [ "$SIZE" -gt 5242880 ]; then
          echo "  $f ($(( SIZE / 1048576 ))MB)"
        fi
      fi
    done)
    if [ -n "$LARGE" ]; then
      echo "ERROR: files over 5MB staged:"
      echo "$LARGE"
      exit 1
    fi
  '

fi  # end !DEEP_ONLY

# ═══════════════════════════════════════════════════════════════════
# DEEP SECTION (--deep / --deep-only). Static category gates from the
# 2026-06-11 deep-scan rework. Pure bash and grep, no cargo, no
# network; runs anywhere the repo is checked out. Categories mapped
# from the infra checklist; N/A categories (Kubernetes, AWS, Kafka,
# FTP, ML, LB/proxy, sharding) are recorded in the deep-scan report,
# not here.
# ═══════════════════════════════════════════════════════════════════
if $DEEP; then

# ── D1. Containerization: pinned bases, restart policies ─────────
gate "deep: Dockerfile bases pinned (no :latest)" \
  bash -c '
    HITS=$(grep -rn "^FROM .*:latest" services/*/Dockerfile* Dockerfile* 2>/dev/null || true)
    if [ -n "$HITS" ]; then echo "ERROR: unpinned base images:"; echo "$HITS"; exit 1; fi
  '
gate "deep: compose services carry restart policy (warn)" \
  bash -c '
    for f in docker-compose*.yml; do
      [ -f "$f" ] || continue
      SVCS=$(grep -cE "^  [a-z0-9-]+:" "$f" || true)
      RST=$(grep -c "restart:" "$f" || true)
      if [ "$RST" -lt "$SVCS" ]; then
        echo "WARN: $f has $SVCS services, $RST restart policies"
      fi
    done
    exit 0
  '

# ── D2. Firewall/bind posture: loopback defaults (R-93/R-134) ────
gate "deep: no 0.0.0.0 binds in non-test Rust" \
  bash -c '
    HITS=$(grep -rn "0\.0\.0\.0" services/ --include="*.rs" 2>/dev/null \
      | grep -vE "tests?\.rs|/tests/" \
      | grep -vE ":[0-9]+:\s*//" || true)
    PRUNED=""
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      FILE=$(echo "$line" | cut -d: -f1)
      LNO=$(echo "$line" | cut -d: -f2)
      START=$((LNO > 40 ? LNO - 40 : 1))
      if ! sed -n "${START},${LNO}p" "$FILE" | grep -qE "cfg\(test\)|mod tests|#\[test\]"; then
        PRUNED="$PRUNED$line\n"
      fi
    done <<< "$HITS"
    if [ -n "$PRUNED" ]; then printf "ERROR: non-loopback binds outside tests:\n$PRUNED"; exit 1; fi
  '

# ── D3. WebSockets: size limits on every config (R-157/R-95) ─────
gate "deep: WebSocketConfig sets message+frame limits" \
  bash -c '
    FILES=$(grep -rln "WebSocketConfig" services/ --include="*.rs" 2>/dev/null || true)
    BAD=""
    for f in $FILES; do
      grep -q "max_message_size" "$f" || BAD="$BAD $f(no max_message_size)"
      grep -q "max_frame_size" "$f" || BAD="$BAD $f(no max_frame_size)"
    done
    if [ -n "$BAD" ]; then echo "ERROR: unbounded websocket configs:$BAD"; exit 1; fi
  '

# ── D4. Embedded DB: SQLite opens carry timeout/pragma (warn) ────
gate "deep: SQLite opens near busy_timeout/pragma (warn)" \
  bash -c '
    FILES=$(grep -rln "Connection::open" services/ --include="*.rs" 2>/dev/null || true)
    for f in $FILES; do
      if ! grep -qiE "busy_timeout|pragma" "$f"; then
        echo "WARN: $f opens SQLite without visible busy_timeout/pragma"
      fi
    done
    exit 0
  '

# ── D5. Rate limiting coverage (R-84) (warn) ─────────────────────
gate "deep: HTTP services reference the rate limiter (warn)" \
  bash -c '
    for f in $(grep -rln "axum::serve\|Router::new" services/ --include="*.rs" 2>/dev/null | cut -d/ -f1-2 | sort -u); do
      SVC=$f
      if ! grep -rq "RateLimiter\|rate_limit" "$SVC/src" 2>/dev/null; then
        echo "WARN: $SVC serves HTTP without visible rate limiting"
      fi
    done
    exit 0
  '

# ── D6. Error logging: silent result drops (informational) ──────
gate "deep: let _ = count (informational)" \
  bash -c '
    COUNT=$(grep -rn "let _ =" services/ --include="*.rs" 2>/dev/null | grep -vE "/tests/|tests?\.rs" | wc -l | tr -d " ")
    echo "let _ = occurrences outside test files: $COUNT (April 2026 baseline: 7)"
    exit 0
  '

# ── D7. RPC hygiene: credentials never logged ────────────────────
gate "deep: no RPC password in tracing macros" \
  bash -c '
    # Flag only interpolation of secret-bearing variables into log macros
    # (%var, ?var, var = binds), not prose messages that mention passwords.
    HITS=$(grep -rnE "(error|warn|info|debug|trace)!\(.*([%?](rpc_)?pass(word)?\b|pass(word)?\s*=\s*[%?]|rpc_pass|RPC_PASS|BITCOIND_RPC_PASS)" services/ --include="*.rs" 2>/dev/null \
      | grep -vE "redact|\\*\\*\\*|len\(\)|\"[^\"]*pass[^\"]*\"\s*\)" || true)
    if [ -n "$HITS" ]; then echo "ERROR: possible credential logging:"; echo "$HITS"; exit 1; fi
  '

# ── D8. Caching: mempool state machine integrity ─────────────────
gate "deep: MempoolState carries all four states" \
  bash -c '
    F=services/pool-verifier/src/mempool_view.rs
    for v in Fresh Stale Degraded Unprimed; do
      grep -q "$v" "$F" || { echo "ERROR: MempoolState missing $v"; exit 1; }
    done
  '

# ── D9. CI/CD + config parity: compose env vars wired (R-164) ───
gate "deep: every compose VELDRA_ var is read in code" \
  bash -c '
    # Allowlist: vars consumed by third-party container images, not our code.
    ALLOW="VELDRA_GRAFANA_ADMIN_PASSWORD"
    VARS=$(grep -hoE "VELDRA_[A-Z_]+" docker-compose*.yml 2>/dev/null | sort -u)
    MISSING=""
    for v in $VARS; do
      echo "$ALLOW" | grep -qw "$v" && continue
      grep -rq "$v" services/ --include="*.rs" 2>/dev/null || MISSING="$MISSING $v"
    done
    if [ -n "$MISSING" ]; then echo "ERROR: compose vars never read in code:$MISSING"; exit 1; fi
  '

# ── D10. Git hygiene: private docs never tracked (TP-3) ──────────
gate "deep: no private docs tracked" \
  bash -c '
    HITS=$(git ls-files | grep -iE "pitch|founder|linkedin|meeting|bizlog|execlog|testlog|devlog|lesson|blocker|deep_scan|outreach|handoff|gtm|credibility" || true)
    if [ -n "$HITS" ]; then echo "ERROR: private docs tracked:"; echo "$HITS"; exit 1; fi
  '

# ── D11. Deployments: Fly suspend trap (R-176) (warn) ────────────
gate "deep: fly.toml keeps a machine warm (warn)" \
  bash -c '
    for f in $(find . -maxdepth 3 -name "fly.toml" -not -path "./.git/*" 2>/dev/null); do
      if grep -q "min_machines_running = 0" "$f"; then
        echo "WARN: $f has min_machines_running = 0 (R-176 suspend trap)"
      fi
    done
    exit 0
  '

# ── D12. Canonical counts: reason-code stability (R-13/R-155) ───
gate "deep: reason-code count assertions present" \
  bash -c '
    # Anchored on the line that follows the assert_eq! operand, so a bare
    # "39" anywhere else in the file cannot satisfy the gate (PB-20).
    # Counts last moved with PB-21, v2_invariant_coinbase_value_exceeds_max.
    grep -A1 "VerdictReason::ALL.len()," services/rg-protocol/src/lib.rs | grep -qE "^ *39, *$" \
      || { echo "ERROR: VerdictReason::ALL count assertion is not 39"; exit 1; }
    grep -A1 "GatewayReason::ALL.len()," services/reservegrid-common/src/reason.rs | grep -qE "^ *59, *$" \
      || { echo "ERROR: GatewayReason::ALL count assertion is not 59"; exit 1; }
    grep -A1 "ReasonCode::ALL.len()," services/reservegrid-common/src/reason.rs | grep -qE "^ *97, *$" \
      || { echo "ERROR: ReasonCode::ALL count assertion is not 97"; exit 1; }
    C=$(grep -rhoE "v2_invariant_[a-z0-9_]+" services/rg-protocol/src | sort -u | wc -l | tr -d " ")
    [ "$C" = "24" ] || { echo "ERROR: rg-protocol v2_invariant_* count drifted: $C (expect 24)"; exit 1; }
  '

# ── D13. Observability: metric names single-suffix (R-177) ──────
gate "deep: no _total in register() names" \
  bash -c '
    HITS=$(grep -rEA1 "register\(" services/ --include="*.rs" 2>/dev/null | grep -E "\"[a-z_]+_total\"" || true)
    if [ -n "$HITS" ]; then echo "ERROR: counter registered with _total suffix:"; echo "$HITS"; exit 1; fi
  '

# ── D14. Polling: timeout literals outside config (warn) ────────
gate "deep: hardcoded sleep literals (informational)" \
  bash -c '
    COUNT=$(grep -rnE "sleep\(Duration::from_(secs|millis)\([0-9]+\)" services/ --include="*.rs" 2>/dev/null | grep -vE "/tests/|tests?\.rs|backoff|jitter" | wc -l | tr -d " ")
    echo "hardcoded sleep literals outside tests: $COUNT (R-116: prefer config fields)"
    exit 0
  '

# ── D15. Encryption posture: no key material in tracked tree ────
gate "deep: no key files tracked" \
  bash -c '
    HITS=$(git ls-files | grep -E "\.(pem|der|key|p12)$|id_(rsa|ed25519)" | grep -v "\.keep" || true)
    if [ -n "$HITS" ]; then echo "ERROR: key material tracked:"; echo "$HITS"; exit 1; fi
  '

fi  # end DEEP

# ── Summary ───────────────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "════════════════════════════════════════════════════════════════"
printf "  ${GREEN}PASS: %d${NC}  " "$PASS_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
  printf "${RED}FAIL: %d${NC}  " "$FAIL_COUNT"
else
  printf "FAIL: 0  "
fi
if [ "$SKIP_COUNT" -gt 0 ]; then
  printf "${YELLOW}SKIP: %d${NC}  " "$SKIP_COUNT"
fi
printf "(%ds)\n" "$ELAPSED"
echo "════════════════════════════════════════════════════════════════"

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo ""
  printf "${RED}BLOCKED:${NC} fix these before pushing:\n"
  for f in "${FAILURES[@]}"; do
    echo "  • $f"
  done
  echo ""
  exit 1
fi

echo ""
printf "${GREEN}All gates passed. Safe to push.${NC}\n"
echo ""
