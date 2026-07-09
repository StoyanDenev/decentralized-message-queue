#!/usr/bin/env bash
# B1 chain-storage-v1 (pre-launch register, 2026-07-09): the O(1) RUNTIME
# save path. Chain::save_incremental writes append-only per-block files
# (<chain_path>.blocks/<i>.json) + a tiny atomic manifest instead of
# rewriting the whole chain.json under the save worker's shared_lock (the
# register's global-mutex/throughput offender). The legacy full chain.json
# is written once at graceful stop() so every offline consumer (operator
# tools, determ-light verify-chain-file, chain.json-parsing test scripts)
# keeps working unchanged.
#
# Pins (in-process, `determ test-chain-store`):
#   * store round-trip == legacy round-trip (height/head_hash/state_root/
#     balances identical)
#   * APPEND-ONLY: a second incremental save never rewrites persisted files
#   * S-021 head gate on the manifest (tamper -> reject)
#   * missing block file -> fail-closed reject (never a silent fallback to
#     a possibly-stale legacy file)
#   * legacy save() invalidates the manifest (a legacy-only writer can
#     never leave a stale store that REWINDS the chain on the next load)
#   * the Node's graceful-stop pair (save + save_incremental) leaves both
#     views loading to the identical chain
#
# Run from repo root: bash tools/test_chain_store.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== B1 chain-storage-v1: append-only block store + manifest ==="
OUT=$($DETERM test-chain-store 2>&1)
RC=$?
echo "$OUT"

if [ "$RC" -eq 0 ] && echo "$OUT" | tail -3 | grep -q "PASS: chain-store"; then
  echo ""
  echo "  PASS: chain-store unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-store (exit=$RC or missing PASS marker)"
  exit 1
fi
