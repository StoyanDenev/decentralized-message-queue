#!/usr/bin/env bash
# TYPED abort-claims codec + digest gate (D2-inc3). AbortEvent carries
# std::vector<chain::AbortClaim> — the six consensus-bound fields per claim —
# encoded by the ONE shared canonical binary codec
# (chain::encode_abort_claims / decode_abort_claims, src/chain/block.cpp),
# which is BOTH the hash_abort_event digest preimage (domain DTM-F2-ABORT-v2,
# daemon + light mirror) and, hex-wrapped, the block-container form.
#
# This SUPERSEDES the JSON canonicalization layer it replaced
# (include/determ/chain/abort_canonical.hpp, deleted). The channels that layer
# policed are now STRUCTURALLY impossible rather than stripped: a typed claim
# has no unknown members, no float-encoded ints, no hex case, and contributes
# ZERO JSON nesting — which closes round-13 F-10 at its source. The old wedge
# needed a schema-free claims value whose injected nesting the
# container-relative WIRE-2 ceiling accepted on ingest (BLOCK payload) and
# rejected on serve (CHAIN_RESPONSE payload, two levels deeper); "claims" is
# now ONE hex STRING at every depth. See docs/proofs/S022WireFormatCaps.md F-10.
#
# `determ test-abort-claims-canonical` asserts: (1) CODEC round-trip fidelity
# (all six fields of every claim, sig bytes byte-identical so verification
# outcomes are invariant) + byte-determinism + empty-list round-trip;
# (2) PER-FIELD DIGEST BINDING — each of the six fields, plus claim ORDER and
# COUNT, changes the digest (falsify-on-mutant: drop any field's append from
# encode_abort_claims and its leg goes RED); (3) FAIL-CLOSED decode with
# specific reject strings (truncated count header, truncated claim, truncated
# trailing string, trailing bytes after the last claim); (4) F-10 STRUCTURAL
# CLOSURE — the container claims value is a string, the abort-carrying block is
# accepted at BOTH BLOCK and CHAIN_RESPONSE depths (no wedge band), the block
# round-trips as a byte fixed point with its digest intact, and the pre-D2
# JSON-array claims shape is REJECTED at the parse boundary (both ingress
# callers share the one decode, so the second-ingress hazard is closed by
# construction); (5) the ABORT_EVENT gossip round-trip keeps the typed claims
# and the digest. The whole-suite witness is that every existing abort test
# (test-abort-event-apply, test-abort-cert-validation, the FA abort traces) and
# the cross-binary digest parity guard stay green with this change in.
#
# Run from repo root: bash tools/test_abort_claims_canonical.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== typed abort-claims codec + digest (D2-inc3 binary preimage; F-10 closed structurally) ==="
OUT=$("$DETERM" test-abort-claims-canonical 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-abort-claims-canonical"; then
  echo "  PASS: abort-claims-canonical"
  exit 0
else
  echo "  FAIL: abort-claims-canonical (exit $rc)"
  exit 1
fi
