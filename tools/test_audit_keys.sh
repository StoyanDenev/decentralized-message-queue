#!/usr/bin/env bash
# A2 audit layer (pre-launch register A2, owner 2026-07-09) — the consensus
# increment: ROTATE_AUDIT_KEY (TxType 15, set/rotate/clear the account's
# standing audit view-master pubkey on the "ak:" state leaf) and
# LOG_AUDIT_ACCESS (TxType 16, on-chain disclosure record counted on the
# "al:" leaf). Both additive + state-root-invariant: an audit-free chain
# emits NO ak:/al: leaves (also pinned by the FAST golden state-root corpus
# staying green with A2 compiled in).
#
# The binary test covers: feature-off leaf absence; set/rotate/clear
# lifecycle (leaf appears, updates, is REMOVED); disclosure counting incl.
# the full-history epoch sentinel; fee-only accounting under the A1 supply
# identity; apply-level fail-closed skips for every malformed shape
# (validator is authoritative, apply re-checks); state_proof observability
# of both leaves; JSON-snapshot round-trip of both maps (conditional
# emission asserted both ways).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== A2 audit layer (ROTATE_AUDIT_KEY + LOG_AUDIT_ACCESS) ==="
OUT=$($DETERM test-audit-keys 2>&1)
RC=$?
echo "$OUT"

if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_audit_keys (assertion failure, rc=$RC)"
  exit 1
fi
if echo "$OUT" | tail -3 | grep -q "PASS: test-audit-keys"; then
  echo ""
  echo "  PASS: test_audit_keys"
  exit 0
else
  echo ""
  echo "  FAIL: test_audit_keys (missing summary marker)"
  exit 1
fi
