#!/usr/bin/env bash
# S-035 Option 1 seed — Chain::state_proof verify path across all
# major state namespaces (not just a:-accounts). The existing
# `test-state-proof` unit covers the a:-namespace in depth
# (inclusion, tampering, non-membership, determinism, post-mutation
# re-proof). This test extends to the OTHER per-domain namespaces:
#   - s:  stakes
#   - r:  registrants
#   - b:  abort_records (S-032)
#   - d:  dapp_registry  (v2.18)
#
# Plus cross-namespace properties: distinct value_hashes (no
# accidental collision across namespaces) and cross-namespace proof
# swap is rejected (a:-key with s: value_hash fails merkle_verify).
#
# The light-client trust model requires that a proof anchors to a
# SPECIFIC (key, value_hash) pair under state_root. A malicious
# server giving a proof for namespace A but claiming it's namespace B
# must be detected — that's what cross-namespace swap rejection
# guarantees.
#
# 9 assertions:
#
#   Per-namespace inclusion + verify (5):
#     - state_proof('a:alice'), ('s:alice'), ('r:alice'),
#       ('b:alice'), ('d:alice') each verifies under root
#
#   Cross-namespace independence (2):
#     - 5 distinct value_hashes (no namespace collision)
#     - cross-namespace swap rejected (a:-key with s: value_hash fails)
#
#   Non-existent + determinism (2):
#     - state_proof for nonexistent s: key returns nullopt
#     - 2 proofs for same s: key are byte-identical
#
# Run from repo root: bash tools/test_state_proof_namespaces.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== state_proof across all major state namespaces (a/s/r/b/d) ==="
OUT=$($DETERM test-state-proof-namespaces 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: state-proof-namespaces all assertions"; then
  echo ""
  echo "  PASS: state-proof-namespaces unit test"
  exit 0
else
  echo ""
  echo "  FAIL: state-proof-namespaces had assertion failures"
  exit 1
fi
