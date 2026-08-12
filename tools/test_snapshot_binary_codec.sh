#!/usr/bin/env bash
# D2-inc8 — in-process unit test for the canonical binary snapshot container
# (`chain::Chain::encode_state` / `decode_state`, src/chain/chain.cpp).
#
# At-rest snapshots are binary as of inc8: the node's bootstrap read, the
# snapshot_save RPC, and `determ snapshot create/fetch/inspect/diff/stats` all
# go through DSN1. serialize_state / restore_from_snapshot survive as the RPC
# text VIEW and as the still-length-prefixed-JSON SNAPSHOT_RESPONSE wire
# payload until that wire increment lands — at which point it reuses THESE
# bytes. DSN1 is the ONE snapshot layout; a second one would be the exact
# divergence D2 exists to remove.
#
# THE FALSIFIER IS SB-5, GATES PRESERVED. restore_from_snapshot runs three
# post-load checks that make a snapshot self-verifying under the
# weak-subjectivity bootstrap model:
#
#   * the head_hash claim (the snapshot must name the head it actually carries),
#   * the S-033 state_root gate (the loaded state must hash to the commitment
#     the tail header already published), and
#   * the opt-in A1 unitary-balance revalidate the node passes true for, so a
#     supply-inconsistent snapshot fails at LOAD instead of wedging the node on
#     its first post-restore apply.
#
# decode_state must run all three. SB-5 tampers ONE account balance in the
# encoded bytes and fixes nothing else; deleting either gate call on the binary
# path turns that leg green when it must be red. It also pins that the
# state_root gate is UNCONDITIONAL — rejection must not depend on the opt-in A1
# flag — and that a tampered head_hash claim is caught on its own.
#
# Legs:
#   SB-1  equivalence with the JSON pair on an all-namespace fixture: same
#         state_root, head, height, A1 counters, live supply, and container
#         contents as restore_from_snapshot(serialize_state(c)); and the
#         restored root equals the SOURCE chain's, so no field was dropped.
#   SB-2  byte determinism + encode_state(decode_state(x)) == x, and the frame
#         leads with the DSN1 magic followed by version u32 = 1 (the exact
#         leading bytes the SNAPSHOT_RESPONSE wire payload will reuse).
#   SB-3  exactness BOTH directions: every proper prefix rejected; one trailing
#         byte rejected with a 'trailing byte(s)' diagnostic.
#   SB-4  hostile bytes: every single-byte corruption twice over. Decode or
#         throw, never UB; reaching the end of the sweep IS the assertion. No
#         survivor may present a state_root divergent from the head's
#         commitment — the S-033 gate catches every state-covered flip.
#   SB-5  the three gates, as above.
#   SB-6  container rules: bad magic, version != 1, and a count claiming four
#         billion entries rejected by the bound applied BEFORE any allocation.
#   SB-7  the at-rest path: bytes out, bytes in, decoded under the node's
#         A1-revalidate policy.
#
# The fixture deliberately commits a REAL state_root on its tail header (apply,
# learn the root, revert, re-append committing to it). A zero state_root is the
# pre-S-033 skip case, and a fixture that left it zero would silently defang
# SB-4 and half of SB-5.
#
# Run from repo root: bash tools/test_snapshot_binary_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Snapshot binary container (DSN1, D2-inc8) ==="
OUT=$($DETERM test-snapshot-binary-codec 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: snapshot-binary-codec all assertions"; then
  echo ""
  echo "  PASS: snapshot-binary-codec unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-binary-codec had assertion failures"
  exit 1
fi
