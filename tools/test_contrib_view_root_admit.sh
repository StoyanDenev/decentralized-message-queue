#!/usr/bin/env bash
# S-104 (docs/SECURITY.md; found 2026-09-17 while designing O-1 step 3b) — a
# Phase-1 contrib whose revealed view LIST does not hash to its SIGNED view
# root is dropped at ingress.
#
# The defect: `Node::on_contrib` verified the contrib signature over
# `make_contrib_commitment(msg)`, which binds the view ROOTS — and never
# checked that the view LISTS the same message carries hash to those roots.
# `validate_contrib_view_roots` (V21..V25) is exactly that recompute and had
# ZERO production callers. `build_body` copies each member's list into the
# block verbatim, and the verifier's `check_eqabort_reconciliation` recomputes
# `compute_view_root(list)` and rejects the WHOLE block ("F2:
# creator_view_eq_lists[i] does not match committed root"). One committee
# member sending one such contrib per round therefore made every honest
# assembler build the block every honest verifier rejects: no append, the
# S-050 valve re-rounds with the SAME committee (the member is PRESENT, so
# nothing aborts and nobody is excluded), and the height never advanced. A
# cost-free, permanent halt.
#
# Now (node-local; no accept rule, wire format, apply path or digest changes):
# on_contrib calls validate_contrib_view_roots right after the signature check
# and DROPS the message on failure. Drop = do not store, which is what every
# other on_contrib rejection already does: the sender is simply MISSING and the
# existing Phase-1 timeout / abort path handles it. Not a new exclusion lever —
# only a party that can already rewrite or withhold the message in transit can
# make a contrib fail this check, and withholding already makes the member
# missing; an honest member never fails it.
#
# Two layers, in-process:
#   (a) INGRESS — a real Node (M=K=3 genesis, virtual-time loop) driven through
#       on_contrib_for_test / round_probe_for_test: a root-matching contrib is
#       ACCEPTED (control), a mismatched one is DROPPED although its signature
#       verifies, the abort dimension (V23) is dropped by the same predicate,
#       and the round is not wedged (the member's well-formed retransmission
#       completes Phase 1).
#   (b) CONSEQUENCE — a fully-signed K-of-K block assembled by build_body from
#       the same contribs, put through the FULL BlockValidator::validate: the
#       honest block passes, the block carrying the mismatched contrib is
#       rejected with "creator_view_eq_lists ... does not match committed root".
#
# Falsify-on-mutant (executed 2026-09-17, reverted; logs under the audit dir):
#   F1-M1 remove the validate_contrib_view_roots call from on_contrib
#         -> the drop / liveness arms RED (this restores the defect verbatim)
#   F1-M2 check the root but keep the contrib on failure (log and fall through)
#         -> the drop arms RED
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_contrib_view_root_admit.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-104: a contrib whose view list does not match its signed root is dropped at ingress ==="
OUT=$("$DETERM" test-contrib-view-root-admit 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-contrib-view-root-admit all assertions"; then
  echo "  PASS: test_contrib_view_root_admit"
  exit 0
else
  echo "  FAIL: test_contrib_view_root_admit (exit $rc)"
  exit 1
fi
