#!/usr/bin/env bash
# D.5 canonical-binary payload codecs (src/dapp/d5codec.c) — roster/case-open/
# result, DECISION-LOG D2 (no JSON on the wire). See D5-RANDOM-SELECTION-SPEC §3/§7.
#
# Dual-oracle gate: the wire layouts were frozen python-first — the
# dependency-free oracle tools/verify_d5_codec.py generated
# tools/vectors/d5_codec.json (the encoded bytes for known structs). The binary
# decodes every vector to its fields AND re-encodes to the identical bytes
# byte-for-byte (the field-order/endianness mutant flips it), plus strict
# fail-closed edges. This wrapper also re-runs the oracle selftest and asserts
# the committed vectors have not drifted from it (no silent drift).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== D.5 payload codecs (test-d5-codec) ==="
OUT=$($DETERM test-d5-codec 2>&1)
RC=$?
echo "$OUT"

if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_d5_codec (C assertion failure, rc=$RC)"
  exit 1
fi
if ! echo "$OUT" | tail -3 | grep -q "PASS: d5-codec (canonical-binary payloads) unit test"; then
  echo ""
  echo "  FAIL: test_d5_codec (missing summary marker)"
  exit 1
fi

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! "$PY" tools/verify_d5_codec.py --selftest; then
  echo "  FAIL: test_d5_codec (python oracle selftest failed)"
  exit 1
fi
TMP="$(mktemp)"
"$PY" tools/verify_d5_codec.py --out "$TMP" >/dev/null 2>&1
if ! diff -q "$TMP" tools/vectors/d5_codec.json >/dev/null 2>&1; then
  rm -f "$TMP"
  echo "  FAIL: test_d5_codec (committed vectors drifted from the python oracle)"
  exit 1
fi
rm -f "$TMP"

echo ""
echo "  PASS: test_d5_codec"
exit 0
