#!/usr/bin/env bash
# S-074 — an AbortEvent's identity is CANONICAL (landed 2026-09-15).
#
# The hash folded into the post-abort committee re-selection
# (rand = SHA256(rand || event_hash)) was whatever the ASSEMBLING node put in
# the AbortEvent: no verifier recomputed it, its timestamp was the assembler's
# wall clock, and any in-sync peer holding the K-1 public claims could
# assemble. Whoever assembled therefore chose the re-round committee (a free
# targeting lever, zero seats needed), and two honest survivors assembling the
# same abort in different seconds produced two different events — the C1
# abort-tail fork behind the S-050 livelock class. Now:
#   timestamp  = the parent block's timestamp (chain time, not a clock)
#   event_hash = canonical_abort_event_hash(event, tail predecessor, parent)
#              = SHA256("DTM-ABORT-ID-v1" || 0 || committee_seed || height ||
#                round || node) for the first event at a height, and
#                SHA256("DTM-ABORT-ID-v1" || 1 || prev.event_hash || round || node)
#                when chained — seeded by the committee seed every verifier
#                already holds (the timestamp is NOT an input: the parent
#                committee chooses the block timestamp)
# enforced by the validator (check_abort_certs: test-abort-cert-validation's
# S-074 arms), by the assembler (on_abort_claim) and by the gossip adoption path
# (on_abort_event, which also requires the accused to be in the CURRENT
# committee) — this gate pins the last two, at M=5/K=3 so the post-abort draw
# (3 of 4) is not degenerate and a chosen hash demonstrably seats a different
# committee.
#
# Falsify-on-mutant (executed 2026-09-15, reverted):
#   M1 validator skips the event_hash check     -> the V10 gate's "CHOSEN
#      event_hash REJECTED" + chained arms flip RED.
#   M2 validator skips the timestamp check      -> the V10 gate's timestamp arm RED.
#   M3 adoption path skips the canonical check  -> the adoption arms here RED
#      (the chosen-hash variant becomes resident).
#   M4 assembler uses its wall clock            -> the assembly arm RED (the
#      probe reads the assembled event's timestamp).
#   M5 adoption drops the accused-membership check -> the replay arm RED (and the
#      tail no block can carry becomes resident).
#   M6 helper formula changed (height dropped)   -> the first-event formula arm RED.
#
# In-process (virtual-time single-node harness), so it runs in the FAST suite.
# Run from repo root: bash tools/test_abort_event_canonical.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-074: abort event identity is canonical (adoption + assembly) ==="
OUT=$("$DETERM" test-abort-event-canonical 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-abort-event-canonical"; then
  echo "  PASS: test_abort_event_canonical"
  exit 0
else
  echo "  FAIL: test_abort_event_canonical (exit $rc)"
  exit 1
fi
