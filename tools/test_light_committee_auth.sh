#!/usr/bin/env bash
# LVS committee-metadata binding — the `wf_517af620` adversarial audit found that
# three determ-light "committee metadata" reads trusted a STRIPPED header (bound
# only by a string-compared, never-recomputed block_hash), a false-YES vector:
#   #1 committee-at-height read creators[] -> forged IN_COMMITTEE verdict;
#   #2 verify-state-root read committee_size off the stripped header;
#   #3 watch-head printed a daemon-inflated head_height as sigs_valid=yes.
#
# Fix (all CLIENT-side): read committee metadata only from the COMMITTEE-BOUND full
# block (authenticated_committee recomputes compute_hash == the successor-bound
# block_hash), and bind watch-head's head_height to the served header's own index
# (watch_head_slot_bound).
#
# GATE (FAST, offline; the `selftest-committee-auth` subcommand):
#   authenticated_committee: a genuine body yields its creators; a FORGED creators[]
#     with a copied block_hash is REFUSED (the mutant dropping the recompute-bind
#     accepts a forged committee -> false IN_COMMITTEE / forged committee_size).
#   watch_head_slot_bound: a header at the true head slot binds; a genuine EARLIER
#     signed block relabeled as head_height is refused (the mutant dropping the slot
#     bind prints a fictitious head_height as sigs_valid=yes).
#
# NB: never `echo "$OUT"` raw on success (the subcommand's FAIL: lines on a failing
# run would reach run_all's tail-10 marker scan).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

OUT=$("$DETERM_LIGHT" selftest-committee-auth 2>&1); RC=$?

if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PASS: selftest-committee-auth"; then
  echo "  PASS: test_light_committee_auth"
  exit 0
fi
echo "  FAIL: test_light_committee_auth"
echo "$OUT" | sed 's/^/    /'
exit 1
