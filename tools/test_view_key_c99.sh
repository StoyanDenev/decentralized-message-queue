#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.24 — A1 per-epoch view-key derivation
# (determ_view_key_derive, src/crypto/viewkey/viewkey.c), the pre-launch
# register A1 decision (Option C, ratified 2026-07-09).
#
# Dual-oracle gate: the mapping was frozen python-first — an independent
# from-scratch RFC 5869 HKDF (tools/verify_view_key.py, gated on RFC 5869
# Appendix A) generated tools/vectors/view_key.json. The binary recomputes
# every vector byte-for-byte through the shipped C, in TWO halves per vector
# (the pinned info encoding, and the end-to-end derive() output), plus the
# fail-closed edges (empty/over-cap/NULL fields) and determinism. The python
# side re-verifies the same corpus independently: `python tools/verify_view_key.py`
# (no args) and the tools/test_c99_vector_files.sh view_key checker.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 view-key derivation (A1 per-epoch HKDF) ==="
OUT=$($DETERM test-view-key-c99 2>&1)
RC=$?
echo "$OUT"

# FAIL-first detection (cluster-triage lesson): any FAIL line, a non-zero
# exit, or a missing terminal summary marker all fail the wrapper.
if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_view_key_c99 (assertion failure, rc=$RC)"
  exit 1
fi
if echo "$OUT" | tail -3 | grep -q "PASS: view-key (A1 per-epoch derivation) unit test"; then
  echo ""
  echo "  PASS: test_view_key_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_view_key_c99 (missing summary marker)"
  exit 1
fi
