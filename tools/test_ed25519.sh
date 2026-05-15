#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for Ed25519 sign/verify.
#
# Ed25519 is the foundation under every signature claim in the
# protocol:
#   - V4 Phase-1 commit signatures (creator_ed_sigs[i])
#   - V8 Phase-2 block-digest signatures (creator_block_sigs[i])
#   - Transaction.sig (every TRANSFER, REGISTER, etc.)
#   - V11 equivocation_events sig_a / sig_b
#   - AbortClaimMsg.ed_sig
#   - ContribMsg.ed_sig, BlockSigMsg.ed_sig
#   - A5 PARAM_CHANGE keyholder signatures
#
# FA1, FA2, FA5, FA6, FA7, FA10 all reduce their cryptographic
# failure probability to Ed25519 EUF-CMA — so any silent regression
# in the wrapper around libssl's EVP_PKEY Ed25519 API would cascade
# across every safety claim. A dedicated unit test catches that
# loudly.
#
# Assertions covered (10 total):
#   1. generate_node_key produces 32-byte pubkey + 32-byte priv_seed
#   2. sign + verify round-trip on a representative message
#   3. Tampered message → verify rejects (EUF-CMA bound)
#   4. Tampered signature → verify rejects
#   5. Wrong public key → verify rejects
#   6. Determinism: same (key, msg) → same sig (RFC 8032 property)
#   7. Empty (zero-byte) message: sign/verify still work
#   8. Distinct keys produce distinct sigs on the same message
#   9. Cross-key verify rejected in both directions
#  10. Long (4 KB) message: streaming sign/verify path works
#
# Run from repo root: bash tools/test_ed25519.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Ed25519 sign/verify primitive ==="
OUT=$($DETERM test-ed25519 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ed25519 all assertions"; then
  echo ""
  echo "  PASS: Ed25519 sign/verify unit test"
  exit 0
else
  echo ""
  echo "  FAIL: ed25519 had assertion failures"
  exit 1
fi
