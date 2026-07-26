#!/usr/bin/env bash
# D.5 inc.5 — determ-light verify-selection (pure core) is the SECURITY SPINE of
# the government random-selection DApp. It re-derives the draw over the eligible
# roster + the verify-rand-authenticated beacon and compares to the PUBLISHED
# result, and NEVER reports a false SELECTED. See D5-RANDOM-SELECTION-SPEC §8/§9.
#
# TWO verifier-side defences the design's adversarial pass surfaced, gated here
# offline over synthetic DECODED streams (the stream COMPLETENESS, §11 3a, is the
# committee-authenticated full-block walk's job — a live property, wired later):
#   3b first-open-wins: a compromised authority that pre-commits SEVERAL
#      case-opens for one case and publishes only a favorable draw is defeated —
#      the canonical case-open is the one at the SMALLEST block height, so a
#      favorable-but-later result mismatches the FIRST re-derivation.
#   3c ordering h_o < draw_height < h_s: the case-open must precede the seed
#      height (anti-grinding); a post-hoc case-open is refused.
#
# GATE (FAST, offline; the `selftest-verify-selection` subcommand):
#   CTRL  a selected member -> SELECTED, a non-selected member -> NOT_SELECTED.
#   NEG   a favorable LATER case-open's result -> UNVERIFIABLE (first-open-wins).
#   NEG'  a post-hoc case-open (h_o == draw_height) -> UNVERIFIABLE (ordering).
# Falsify-on-mutant: (3b) picking the max-height case-open flips ONLY the
# first-open-wins NEG; (3c) relaxing h_o<H to h_o<=H flips ONLY the ordering NEG.
#
# NB: never `echo "$OUT"` raw on success (the subcommand's FAIL: lines on a
# failing run would reach run_all's tail-10 marker scan).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

OUT=$("$DETERM_LIGHT" selftest-verify-selection 2>&1); RC=$?

if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PASS: selftest-verify-selection"; then
  echo "  PASS: test_light_verify_selection"
  exit 0
else
  echo "$OUT"
  echo "  FAIL: test_light_verify_selection"
  exit 1
fi
