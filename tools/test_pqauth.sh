#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.21 — the DPQ1 post-quantum transaction-authentication
# envelope (determ::pqauth). Binds a transaction's canonical signing_bytes to an
# ML-DSA (FIPS 204) signature, optionally HYBRID with Ed25519 so an attacker must
# break BOTH primitives. This is a LIBRARY + TOOLING primitive of the owner-
# authorized PQ signature chain-integration track; the consensus accept-rule that
# admits a DPQ1-authenticated tx is a separate, owner-gated step.
#
# DUAL ORACLE: the C side (`determ test-pqauth`) recomputes the frozen corpus
# tools/vectors/pqauth.json byte-for-byte through the shipped determ::pqauth::sign
# (+ round-trip / determinism / tamper / malformed gates for every scheme); the
# python side (tools/verify_pqauth.py) reproduces the SAME envelope bytes through
# an INDEPENDENT ed25519 (pynacl) + the from-scratch python ML-DSA signer
# (verify_mldsa_keygen / verify_mldsa_sign). Two implementations, one frozen
# corpus — a divergence with both green means OUR code is wrong, not the vectors.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

rc=0
echo "=== DPQ1 PQ tx-auth envelope — C side (determ test-pqauth) ==="
OUT=$($DETERM test-pqauth 2>&1)
echo "$OUT"
if ! echo "$OUT" | tail -2 | grep -q "PASS: pqauth (DPQ1 envelope) unit test"; then
  echo "  FAIL: pqauth C-side assertions"; rc=1
fi

echo ""
echo "=== DPQ1 PQ tx-auth envelope — python oracle (verify_pqauth.py) ==="
if python tools/verify_pqauth.py; then
  :
else
  echo "  FAIL: pqauth python oracle byte-mismatch"; rc=1
fi

echo ""
if [ $rc -eq 0 ]; then
  echo "  PASS: pqauth (DPQ1 envelope) dual-oracle"
else
  echo "  FAIL: pqauth dual-oracle had failures"
fi
exit $rc
