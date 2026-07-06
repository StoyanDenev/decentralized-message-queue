#!/usr/bin/env bash
# §3.21 inc.4 — the PQ-native BEARER address (determ::pq_address) + the
# PQ_TRANSFER consensus accept-rule (determ::chain::verify_pq_transaction). The
# owner-authorized on-chain post-quantum signature step (AnonAddressDerivation-
# Migration Option B, reopened by owner authority 2026-07-04): a PQ_TRANSFER's
# sender is a bearer account whose address IS an ML-DSA (FIPS 204) public key
# with a form-byte prefix, and authenticity is a DPQ1 envelope (determ::pqauth)
# bound to that address. ADDITIVE + state-root-invariant: existing tx types
# serialize byte-identically (the new pq_auth field is emitted only when
# non-empty; signing_bytes is unchanged), so a PQ-free chain's state root is
# untouched — the FAST golden-vector suite is the byte-identity witness.
#
# Assertions: PQ address make/parse/round-trip + disjointness from the 66-char
# Ed25519 anon space + malformed rejection; the accept-rule accepts a valid
# PQ_TRANSFER and fail-closed rejects a tampered amount, a non-PQ type, a non-PQ
# `from`, an empty envelope, an envelope whose ML-DSA key != the address key
# (the quantum-resistance binding), and a hybrid (Ed25519-bearing) envelope; and
# a non-PQ tx serializes with no pq_auth key (byte-identity signal).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

OUT=$($DETERM test-pq-transaction 2>&1)
echo "$OUT"
if echo "$OUT" | tail -2 | grep -q "PASS: pq-transaction"; then
  echo ""
  echo "  PASS: pq-transaction unit test"
  exit 0
else
  echo ""
  echo "  FAIL: pq-transaction had assertion failures"
  exit 1
fi
