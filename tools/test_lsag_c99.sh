#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.23 — the C99 LSAG linkable ring signature over NIST P-256
# (src/crypto/ringsig/lsag.c), the input-unlinkability increment 1. The Liu-Wei-Wong
# 2004 Linkable Spontaneous Anonymous Group signature — the CryptoNote / early-Monero
# RingCT membership primitive: a signer who knows the private key of ONE of n ring
# public keys proves membership WITHOUT revealing which, and publishes a KEY IMAGE
# I = x*H_p(P_signer) that is DETERMINISTIC in the signing key (the double-spend
# nullifier) yet UNLINKABLE to any particular ring member. H_p is the RFC 9380
# P256_XMD:SHA-256_SSWU_RO_ hash-to-curve. Built on the PUBLIC §3.8c/§3.9b P-256 API
# (no new hardness assumption; soundness rests on P-256 ECDLP + the ROM). Signing is
# deterministic (RFC-6979-style nonces) so the bytes are reproducible.
#
# Assertions: sign→verify accepts; the DUAL-ORACLE byte-freeze (key image + signature
# bytes) vs the INDEPENDENT Python reference tools/verify_lsag.py (own P-256 ladder +
# RFC 9380 hash-to-curve); LINKABILITY (same key → same image = double-spend nullifier;
# different key → different image); and tamper / wrong-message / wrong-image / malformed
# reject. Two independent implementations agreeing on one frozen signature means a
# divergence with both green is our bug, not the vector's.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 LSAG linkable ring signature over NIST P-256 (§3.23) ==="
OUT=$($DETERM test-lsag-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: lsag-c99 unit test"; then
  echo ""
  echo "  PASS: test_lsag_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_lsag_c99 (assertion failure or missing summary marker)"
  exit 1
fi
