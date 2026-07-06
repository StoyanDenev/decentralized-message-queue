#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.23b — the C99 CLSAG concise linkable ring signature over NIST
# P-256 (src/crypto/ringsig/clsag.c), the input-unlinkability increment 2. The Goodell-
# Noether-RandomRun 2019 "Concise Linkable Spontaneous Anonymous Group" signature —
# Monero's current RingCT membership + balance primitive. It generalises the §3.23 LSAG
# to TWO key layers (a spend key P and an amount-commitment offset C - Coffset) signed by
# ONE concise ring (n+1 scalars, NOT 2n): the layers are folded by hash-derived
# aggregation coefficients mu_P/mu_C. I = p*H_p(P_signer) is the deterministic link/
# double-spend nullifier; D = z*H_p(P_signer) is the auxiliary commitment image; proving
# C - Coffset is a pure-G multiple is exactly the RingCT balance statement. Built on the
# PUBLIC §3.8c/§3.9b P-256 API (no new hardness assumption; soundness rests on P-256
# ECDLP + the ROM). Signing is deterministic (RFC-6979-style nonces) so bytes reproduce.
#
# Assertions: sign→verify accepts; the DUAL-ORACLE byte-freeze (key image I, aux image D,
# and signature bytes) vs the INDEPENDENT Python reference tools/verify_clsag.py (own
# P-256 ladder + RFC 9380 hash-to-curve); LINKABILITY (same spend key → same image =
# double-spend nullifier, independent of message/pseudo-out; different key → different
# image); and tamper / wrong-message / wrong-aux-image / wrong-key-image / wrong-pseudo-
# out / malformed reject. Two independent implementations agreeing on one frozen
# signature means a divergence with both green is our bug, not the vector's.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 CLSAG concise linkable ring signature over NIST P-256 (§3.23b) ==="
OUT=$($DETERM test-clsag-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: clsag-c99 unit test"; then
  echo ""
  echo "  PASS: test_clsag_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_clsag_c99 (assertion failure or missing summary marker)"
  exit 1
fi
