#!/usr/bin/env bash
# v2.10 Phase A / CRYPTO-C99-SPEC §3.2 + RFC 9591 — the libsodium-free C99
# FROST-Ed25519 keygen layer at src/crypto/frost/, built on the C99 Ed25519
# group/scalar primitives (src/crypto/ed25519/ed25519_group.h). Shamir secret
# sharing over the Ed25519 scalar field (mod L) + Lagrange reconstruction; the
# threshold-signing round lands on the same base.
#
# 20 assertions across five sections: (1) group homomorphism [a]B+[b]B == [a+b]B
# and [k]([a]B) == [k*a]B (point add/mul); (2) a * a^-1 == 1 mod L (scalar
# inversion); (3) trusted-dealer keygen(t=3,n=5) with share/group-key consistency
# and four distinct t-subsets each reconstructing the same secret (Shamir
# threshold invariant); (4) THRESHOLD SIGNING -- two quorums each produce an
# aggregate that verifies as a plain Ed25519 signature under the group key (C99 +
# OpenSSL) + a malformed-set rejection; (5) DISTRIBUTED KEY GENERATION (Pedersen
# DKG / Feldman VSS, trustless) -- proofs-of-possession verify, every dealt share
# passes the VSS check, the summed commitments/secret are consistent, the long-term
# shares reconstruct the group secret AND sign a valid Ed25519 sig under the DKG
# group key, and tampered PoP/share are rejected. Additive -- not yet wired into
# the consensus randomness path.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 FROST-Ed25519 keygen (Shamir/Lagrange over the Ed25519 scalar field) ==="
OUT=$($DETERM test-frost-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: frost-c99 all keygen + DKG + threshold-signing invariants held"; then
  echo ""
  echo "  PASS: frost-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: frost-c99 had assertion failures"
  exit 1
fi
