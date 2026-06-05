#!/usr/bin/env bash
# In-process unit test for the DETECTION-side equivocation-evidence
# verification predicate (FA6) — the trustless two-sig double-sign proof
# that any party can check with only the equivocator's Ed25519 pubkey.
#
# This is distinct from the apply-side tests
# (tools/test_equivocation_apply.sh + tools/test_equivocation_multi.sh),
# which mutate stake/registry using PRE-VALIDATED events whose two sigs
# are default-constructed because apply never re-verifies. The
# verification gate — src/node/validator.cpp::check_equivocation_events
# — is where the real Ed25519 two-sig proof is checked, and it is what
# an offline auditor or a light client (holding only the pubkey) runs to
# decide slash vs. no-slash. This test rebuilds that exact predicate
# from the public crypto primitives (generate_node_key / sign / verify)
# and pins every accept/reject arm.
#
# An EquivocationEvent is sound iff ALL hold:
#   (a) digest_a != digest_b   (otherwise no contradiction),
#   (b) sig_a    != sig_b      (otherwise one signature, no double-sign),
#   (c) verify(key, digest_a, sig_a) AND verify(key, digest_b, sig_b)
#       both pass under the equivocator's REGISTERED key.
#
# ~12 assertions in ten blocks:
#
#   Accept (1):
#     - genuine double-sign: distinct digests, both sigs verify → ACCEPT
#
#   Reject — structural (2):
#     - equal digests (same message signed twice) → REJECT
#     - equal sigs (sig_a == sig_b, one signature) → REJECT
#
#   Reject — cryptographic (2):
#     - tampered sig_b (forged signature) → REJECT
#     - tampered digest_a (sig no longer binds digest) → REJECT
#
#   Reject — attribution (3):
#     - genuine culprit proof rejected under an innocent key
#       (no mis-attribution of the slash)
#     - sig_a signed by a different key → REJECT under both keys
#
#   Wire round-trip (2):
#     - every proof field survives to_json/from_json
#     - decoded evidence still ACCEPTS under culprit key
#
#   Event-hash binding (2):
#     - hash_equivocation_event binds sig_b + equivocator
#
#   Determinism (1):
#     - the verifier is a pure predicate (same verdict twice)
#
# Network-level slashing integration lives in
# tools/test_equivocation_slashing.sh; this in-process test pins the
# detection-side soundness in <1s.
#
# Run from repo root: bash tools/test_equivocation_evidence.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Equivocation-evidence verification (FA6 two-sig double-sign proof) ==="
OUT=$($DETERM test-equivocation-evidence 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: equivocation-evidence all assertions"; then
  echo ""
  echo "  PASS: equivocation-evidence unit test"
  exit 0
else
  echo ""
  echo "  FAIL: equivocation-evidence had assertion failures"
  exit 1
fi
