#!/usr/bin/env bash
# make_anon_address(Ed25519 pubkey) byte-identity contract — pins the
# derivation surface every anon-address transaction's sender/recipient
# flows through. Existing tests cover adjacent surfaces (test-anon-
# address: parser + normalizer helpers; test-anon-routing: cross-
# shard integration), but neither pins the DERIVATION itself byte-
# for-byte. A regression in the encoding (case drift, length
# truncation, prefix change, byte-order swap) would silently fork
# the chain at the identity layer.
#
# Coverage (~20 assertions across 7 scenarios):
#   (1) Replay determinism: 3 consecutive derivations byte-identical;
#       fresh-rebuilt pubkey produces identical address.
#   (2) Format pin: derived address matches ^0x[a-f0-9]{64}$ across
#       all-zero, all-0xFF, and pseudorandom pubkey probes.
#   (3) Per-byte + per-bit sensitivity: flipping any of the 32 bytes
#       or any of the 256 bits changes the address (no byte/bit is
#       masked off); first-vs-last byte flips both differ from base
#       AND from each other (no positional aliasing).
#   (4) Distinctness over 100 random pubkeys: 100 unique pubkeys
#       produce 100 unique addresses (no encoding collisions; catches
#       truncation or fixed-prefix bugs).
#   (5) Lowercase canonical: emit form has no uppercase A-F;
#       normalize_anon_address is a no-op on the emit form (S-028
#       ingress contract is the exact inverse of emit form).
#   (6) Round-trip contract: parse_anon_pubkey(make_anon_address(pk))
#       == pk across {zero, 0xFF, random} — pins that the derivation
#       is a BIJECTION (lowercase hex of the pubkey), NOT a one-way
#       SHA-256 hash. Loud regression-fence if the encoding is ever
#       swapped for a hash.
#   (7) Cross-platform golden fixtures: pk=0x00*32 →
#       "0x" + "0" * 64; pk[i]=i → "0x000102030405060708090a0b0c0d0e0f
#       101112131415161718191a1b1c1d1e1f" (pins big-endian byte order
#       + lowercase hex + nibble width). Reproducible a priori by
#       anyone reading the test — no external state.
#
# Companion to:
#   - test-anon-address (parser + normalizer helpers — 12 assertions)
#   - test-anon-routing (Chain-layer integration contract)
#   - test-shard-routing-determinism (composes with this test's
#     output via shard_id_for_address(canonical-form))
#
# Run from repo root: bash tools/test_anon_address_derivation.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== anon-address-derivation: make_anon_address byte-identity + golden fixtures ==="
OUT=$($DETERM test-anon-address-derivation 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: anon-address-derivation all assertions"; then
  echo ""
  echo "  PASS: anon-address-derivation unit test"
  exit 0
else
  echo ""
  echo "  FAIL: anon-address-derivation had assertion failures"
  exit 1
fi
