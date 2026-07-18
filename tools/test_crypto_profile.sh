#!/usr/bin/env bash
# NC-8 profile gating: CryptoProfile promoted from a params.hpp posture label to
# a genesis-pinned CONSENSUS field (block.hpp / genesis.hpp / Chain). It selects
# the profile-dependent encrypted-note wiring (EncryptedNoteDeliveryDesign §5):
# FIPS => enote in the tx payload + recipient key from the view-master;
# MODERN => enote in an `en:` state leaf + a dedicated note key.
#
# Gates (via `determ test-crypto-profile`): MODERN (default) is BYTE-NEUTRAL —
# no `k:crypto_profile` state leaf, no genesis-hash marker, no snapshot key, so
# every pre-field chain is byte-identical; FIPS diverges the state_root AND the
# genesis hash (two operators cannot silently disagree) and round-trips through
# the genesis JSON + the state snapshot.
#
# Run from repo root: bash tools/test_crypto_profile.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== NC-8 crypto-profile genesis pin (MODERN byte-neutral / FIPS diverges) ==="
OUT=$($DETERM test-crypto-profile 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: crypto-profile all assertions"; then
  echo ""
  echo "  PASS: crypto-profile unit test"
  exit 0
else
  echo ""
  echo "  FAIL: crypto-profile had assertion failures"
  exit 1
fi
