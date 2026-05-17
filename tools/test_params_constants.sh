#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the protocol-level
# constants in `include/determ/chain/params.hpp`.
#
# These constants are deployment-critical defaults: every chain
# whose genesis doesn't override them uses these values for
# validator economics + REGISTER tx geometry + TRANSFER memo cap +
# E1 NEF zeroth-pool address. A silent change would shift behavior
# across every chain pinning the defaults — operators wouldn't
# see an error, just different limits.
#
# 16 assertions covering:
#
#   Stake-economy defaults (3):
#     - MIN_STAKE = 1000
#     - UNSTAKE_DELAY = 1000 blocks
#     - SUSPENSION_SLASH = 10 (rev.8 disincentive)
#
#   REGISTER payload geometry (6):
#     - REGISTER_PAYLOAD_PUBKEY_SIZE = 32 (Ed25519 pubkey)
#     - REGISTER_REGION_MAX = 32 (rev.9 R1 region tag cap)
#     - REGISTER_PAYLOAD_MIN_SIZE = 32 (legacy pubkey-only path)
#     - REGISTER_PAYLOAD_MAX_SIZE = 65 (pubkey + len byte + region)
#     - REGISTER_PAYLOAD_SIZE legacy alias matches pubkey-only path
#     - Cross-arithmetic: MAX = pubkey + 1 + region_max
#
#   TRANSFER memo cap (1):
#     - TRANSFER_PAYLOAD_MAX = 128 (A4 operator-visible cap)
#
#   E1 NEF zeroth-pool address (4):
#     - ZEROTH_ADDRESS: 66 chars (0x + 64 hex)
#     - starts with 0x prefix
#     - all-zero hex tail (low-order curve25519 point — no usable
#       Ed25519 private key for this pubkey)
#     - passes is_anon_address (wire-format compatible)
#
#   Cross-arithmetic invariants (2):
#     - SUSPENSION_SLASH × 100 == MIN_STAKE (BFT-safety economic
#       accounting: 100 baked aborts zero a minimally-staked
#       validator)
#     - UNSTAKE_DELAY >= 1 block (sane lower bound — instant
#       unstake would defeat the suspension-window invariant)
#
# Run from repo root: bash tools/test_params_constants.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== chain/params.hpp protocol-level constants — operator-facing defaults ==="
OUT=$($DETERM test-params-constants 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: params-constants all assertions"; then
  echo ""
  echo "  PASS: params-constants unit test"
  exit 0
else
  echo ""
  echo "  FAIL: params-constants had assertion failures"
  exit 1
fi
