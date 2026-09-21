#!/usr/bin/env bash
# D15 / R-6 (S-060 companion) — ROTATE_IDENTITY_KEY (TxType 18).
#
# Allows honest registered validators to rotate their active Ed25519 identity key
# without touching eligibility (zero activation delay) or deregistering.
#
# Requirements pinned by this gate:
#   1. Incumbent authentication: must be signed by currently active identity key.
#   2. Rejection of malformed payloads (size != 32), non-zero amount, non-empty to,
#      unregistered sender, anon sender, small-order points (D10 / S-072), or non-incumbent sig.
#   3. Immediate invalidation of old key: transactions signed by old key fail;
#      transactions signed by new key succeed.
#   4. Deterministic state leaf "rk:" + domain -> SHA256(new_pubkey).
#   5. Snapshot roundtrip fidelity: JSON and DSN1 canonical binary format.
#
# In-process (no cluster), fast suite.
# Run from repo root: bash tools/test_rotate_identity_key.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== D15 / R-6: ROTATE_IDENTITY_KEY (TxType 18) lifecycle, gates & snapshot fidelity ==="
OUT=$("$DETERM" test-rotate-identity-key 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-rotate-identity-key"; then
  echo "  PASS: test_rotate_identity_key"
  exit 0
else
  echo "  FAIL: test_rotate_identity_key (exit $rc)"
  exit 1
fi
