#!/usr/bin/env bash
# LightVerify LTX-HEIGHT-NOT-BOUND — verify-tx-inclusion must bind the returned
# block's OWN index to the REQUESTED height.
#
# THE GAP: verify-tx-inclusion asks the `block` RPC for index==height, verifies
# the returned block's committee sigs (over a digest that binds the block's own
# index), recomputes tx_root, cross-checks the body, and answers membership —
# but it NEVER asserts the returned block's index equals the requested height,
# and it reports the verdict at the REQUESTED height (res.height). It anchors on
# the STATIC genesis committee (build_genesis_committee), so a hostile/MITM
# daemon can return a REAL committee-signed block from a DIFFERENT height B' that
# contains the queried tx: every check passes and the tool prints "INCLUDED at
# height <requested>" while the tx is actually at B' — a relabel that deceives
# the caller about WHICH height the tx was included at. Same "displayed label not
# bound to committee-anchored content" class as LSB-ANCHOR-INDEX / EXP-1.
#
# THE FIX: a structural gate (right after the block parse, BEFORE the committee-
# sig anchor) requiring b.index == height. b.index is the first field of the
# committee-signed block digest, so requiring the match binds the reported height
# to committee-authenticated content. The newline of testability: the fetch was
# split out of a pure core verify_tx_inclusion_from_block(blk_json, ...) with the
# block JSON INJECTED, so the gate is FAST-offline falsifiable with a synthetic
# block and NO daemon; verify_tx_inclusion is a thin RPC wrapper over the core.
#
# GATE (FAST, offline; the determ-light `selftest-tx-inclusion-height` subcommand
# drives the core with a synthetic block):
#   NEG   a block whose own index (500) != the requested height (100) is refused
#         at the index-binding gate, BEFORE the committee-sig anchor.
#   CTRL  a matching block index (100 == 100) passes the gate and reaches the
#         committee-sig anchor (which fails on the empty committee) — proving the
#         gate is live, not a tautology, and robust vs a parse-failure vacuous pass.
# Falsify-on-mutant (neutralize the index gate): ONLY the NEG assert flips (the
# mismatched block is no longer refused → it reaches the sig anchor with a
# non-index diagnostic); CTRL stays green — a clean directional split.
#
# NB: never `echo "$OUT"` raw on success — the subcommand's own FAIL: lines on a
# failing run would otherwise reach run_all's tail-10 marker scan.
#
# Run from repo root: bash tools/test_light_verify_tx_inclusion_height.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

OUT=$("$DETERM_LIGHT" selftest-tx-inclusion-height 2>&1); RC=$?

if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PASS: selftest-tx-inclusion-height"; then
  echo "  PASS: test_light_verify_tx_inclusion_height"
  exit 0
else
  echo "$OUT"
  echo "  FAIL: test_light_verify_tx_inclusion_height"
  exit 1
fi
