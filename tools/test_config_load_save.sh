#!/usr/bin/env bash
# S-035 Option 1 seed — Config::load + Config::save file IO round-trip.
# Complements test-config-roundtrip (in-memory JSON round-trip) and
# test-config-defaults (default values pin) — those test the JSON
# layer; this test pins the FILE IO layer.
#
# Covered:
#   - save writes well-formed JSON (parseable)
#   - load reads the saved file back losslessly:
#     domain, listen_port, rpc_localhost_only (S-001 critical),
#     rpc_auth_secret, m_creators + k_block_sigs, bft_enabled,
#     chain_role, sharding_mode, R1 region tags, log_quiet
#   - save→load→save→load idempotent (no entropy across cycles)
#   - load of non-existent file: diagnostic names path or "Cannot open"
#   - load of malformed JSON: clean exception
#   - save creates parent directories (mkdirp behavior)
#
# Uses a temp directory (cleaned up at end) so the test doesn't
# leak filesystem state between runs.
#
# 14 assertions across 6 scenarios.
#
# Run from repo root: bash tools/test_config_load_save.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Config::load + Config::save file IO round-trip ==="
OUT=$($DETERM test-config-load-save 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: config-load-save all assertions"; then
  echo ""
  echo "  PASS: config-load-save unit test"
  exit 0
else
  echo ""
  echo "  FAIL: config-load-save had assertion failures"
  exit 1
fi
