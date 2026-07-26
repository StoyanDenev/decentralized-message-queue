#!/usr/bin/env bash
# D.5 government random-selection — lowest-hash sortition (src/dapp/d5draw.c),
# ratified D1 (2026-07-26). See docs/proofs/D5-RANDOM-SELECTION-SPEC.md §4/§11.
#
# Dual-oracle gate: the draw was frozen python-first — the dependency-free
# oracle tools/verify_d5_draw.py generated tools/vectors/d5_draw.json. The
# binary recomputes every vector's selected ids byte-for-byte through the
# shipped d5_draw() (plus order-independence, ctx/height binding — the SPEC §11
# ctx-drop mutant flips these — and the fail-closed edges). This wrapper also
# re-runs the python oracle's selftest and re-derives the corpus into a temp
# file, asserting it is byte-identical to the committed vectors (no silent drift).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== D.5 lowest-hash sortition (test-d5-draw) ==="
OUT=$($DETERM test-d5-draw 2>&1)
RC=$?
echo "$OUT"

if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_d5_draw (C assertion failure, rc=$RC)"
  exit 1
fi
if ! echo "$OUT" | tail -3 | grep -q "PASS: d5-draw (lowest-hash sortition) unit test"; then
  echo ""
  echo "  FAIL: test_d5_draw (missing summary marker)"
  exit 1
fi

# Independent python side: selftest + no-drift check on the frozen corpus.
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! "$PY" tools/verify_d5_draw.py --selftest; then
  echo "  FAIL: test_d5_draw (python oracle selftest failed)"
  exit 1
fi
TMP="$(mktemp)"
"$PY" tools/verify_d5_draw.py --out "$TMP" >/dev/null 2>&1
if ! diff -q "$TMP" tools/vectors/d5_draw.json >/dev/null 2>&1; then
  rm -f "$TMP"
  echo "  FAIL: test_d5_draw (committed vectors drifted from the python oracle)"
  exit 1
fi
rm -f "$TMP"

echo ""
echo "  PASS: test_d5_draw"
exit 0
