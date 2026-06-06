#!/usr/bin/env bash
# v2.10 Phase A / CRYPTO-C99-SPEC §3.2 + RFC 9591 — the libsodium-free C99
# FROST-Ed25519 keygen layer at src/crypto/frost/, built on the C99 Ed25519
# group/scalar primitives (src/crypto/ed25519/ed25519_group.h). Shamir secret
# sharing over the Ed25519 scalar field (mod L) + Lagrange reconstruction; the
# threshold-signing round lands on the same base.
#
# 8 assertions: (1) group homomorphism [a]B+[b]B == [a+b]B and [k]([a]B) == [k*a]B
# (validates point add/mul); (2) a * a^-1 == 1 mod L (scalar inversion); (3) a
# trusted-dealer keygen(t=3,n=5) with share-pubkey + group-key consistency and four
# distinct t-subsets each reconstructing the same secret (the Shamir threshold
# invariant). Additive -- not yet wired into the consensus randomness path.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 FROST-Ed25519 keygen (Shamir/Lagrange over the Ed25519 scalar field) ==="
OUT=$($DETERM test-frost-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: frost-c99 all keygen + reconstruction invariants held"; then
  echo ""
  echo "  PASS: frost-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: frost-c99 had assertion failures"
  exit 1
fi
