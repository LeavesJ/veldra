#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/services/pool-verifier"

echo "[veldra] clearing data/verdicts.log..."
rm -f data/verdicts.log
echo "[veldra] done. restart dev-regtest to repopulate."
