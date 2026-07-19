#!/usr/bin/env bash
# minix JSON phase 2, increment 2: determ::djson REAL-SURFACE dual-oracle.
#
# inc.1 (test_determ_json.sh) proved determ::djson byte-parity on hand-crafted
# shapes. This proves it on the daemon's ACTUAL serialization: for each real
# object the daemon emits — Transaction, Block (incl. an abort-carrying block),
# AbortEvent + claim, EquivocationEvent, GenesisAlloc, Chain::serialize_state
# snapshot, RPC params, gossip envelope — take nlohmann's own dump() and assert
# determ::djson parses it and re-dumps to the IDENTICAL bytes. That is the
# byte-exact drop-in evidence the owner-gated nlohmann->determ::djson consumer
# swap needs (MinixTacticalProfile §5). ADDITIVE/test-only — no consumer is
# swapped. In-scope surfaces only (int/string/hex/array/object); node Config
# doubles are out of scope (DetermJsonParitySoundness NC-1).
#
# Run from repo root: bash tools/test_determ_json_surfaces.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== minix JSON phase 2 inc.2 — determ::djson byte-exact on the daemon's real surfaces ==="
OUT=$("$DETERM" test-determ-json-surfaces 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-determ-json-surfaces"; then
  echo "  PASS: determ-json real-surface parity"
  exit 0
else
  echo "  FAIL: determ-json real-surface parity (exit $rc)"
  exit 1
fi
