#!/usr/bin/env bash
# D.5 inc.4 — determ-light verify-rand must authenticate cumulative_rand[H] (the
# MPDH commit-reveal beacon the government random-selection DApp draws from) via
# the S-042 successor binding, and NEVER report a false committee-authenticated.
#
# THE GAP (named in D5-RANDOM-SELECTION-SPEC §7): a bare cumulative_rand[H]
# header field is a daemon CLAIM. cumulative_rand is NOT in the block digest the
# committee signs directly; it is authenticated only transitively — block_hash[H]
# = SHA256(signing_bytes(block[H])) INCLUDES cumulative_rand[H], and the
# committee-signed SUCCESSOR block[H+1] commits block_hash[H] as its prev_hash
# (the "S-042 successor binding"). A MITM that swaps cumulative_rand[H] changes
# block_hash[H], so the recomputed hash no longer equals the signed successor
# prev_hash. Without that recompute+compare, a light client would echo a forged
# beacon as authenticated.
#
# THE FIX: verify_rand_from_blocks recomputes block_hash[H] from the SERVED
# header and requires it equal block[H+1].prev_hash BEFORE reporting VERIFIED
# (and verifies H+1's committee sigs with the LV-1/LV-2 committee-size floor).
# The fetch was split out of a pure core (block JSONs INJECTED) so the binding
# gate is FAST-offline falsifiable with a synthetic 2-block fixture and NO daemon.
#
# GATE (FAST, offline; the `selftest-verify-rand` subcommand):
#   CTRL  a correct successor prev_hash passes the S-042 binding gate and reaches
#         the committee-sig anchor (fails on the empty committee) — non-vacuity.
#   NEG   a successor whose prev_hash != recomputed block_hash[H] (swapped beacon)
#         is refused AT the binding gate, BEFORE the committee-sig anchor.
#   NEG'  a block[H] whose own index != the requested height is refused at the
#         index-binding gate.
# Falsify-on-mutant (remove the S-042 binding check): the swapped-beacon NEG no
# longer trips the binding gate → it falls through to the committee-sig detail →
# ONLY the NEG assert flips RED; CTRL stays green (clean directional split).
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

OUT=$("$DETERM_LIGHT" selftest-verify-rand 2>&1); RC=$?

if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PASS: selftest-verify-rand"; then
  echo "  PASS: test_light_verify_rand"
  exit 0
else
  echo "$OUT"
  echo "  FAIL: test_light_verify_rand"
  exit 1
fi
