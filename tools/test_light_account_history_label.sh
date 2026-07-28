#!/usr/bin/env bash
# LightVerify AH-1b — account-history must LABEL a non-head row's balance/nonce
# unambiguously as HEAD-sourced, never as proven-at-that-row's-height.
#
# THE GAP (tool-correctness false verdict, MED): the daemon's state_proof /
# account RPCs are HEAD-ONLY (no height parameter), so account-history
# Merkle-PROVES (balance, next_nonce) at the head only and then copies the head
# value onto EVERY sampled row. For any non-head sampled height whose balance/
# nonce changed by the head, the row shows the HEAD's value against a non-head
# height — even against an HONEST daemon. AccountHistorySoundness.md AH-1 / §2.3 /
# Gate-3 used to claim per-height (balance,nonce) soundness; that is FALSE for the
# shipped head-only tool. The proof is narrowed to AH-1a (per-height committee-
# signed state_root — TRUE) + AH-1b (balance/nonce head-only, LABELED).
#
# THE FIX (client-side, no wire/consensus change): every row's balance/nonce
# provenance is rendered by the pure balance_source_label(merkle_verified,
# proven_at_height): "head@H" for a non-head row (the head value, NOT proven at
# this row's height) and "merkle@H" for the head row (Merkle-proven at H). Both
# the JSON (`balance_source`) and the human table (balance_src column) carry it,
# so a reader can never mistake a non-head row's balance for balance-at-h.
#
# GATE (FAST, offline; the determ-light selftest-account-history-label subcommand
# drives the pure helper): a non-head row is labeled head@H and NEVER claims a
# Merkle proof (2 NEG + a height-carrying NEG-3); the head row is labeled
# merkle@H (CTRL non-vacuity). Falsify (make the non-head arm return "merkle@…",
# falsely claiming a per-height Merkle proof): the NEG asserts flip RED; CTRL
# stays green.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh
if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi
OUT=$("$DETERM_LIGHT" selftest-account-history-label 2>&1); RC=$?
if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PASS: selftest-account-history-label"; then
  echo "  PASS: test_light_account_history_label"
  exit 0
else
  echo "$OUT"
  echo "  FAIL: test_light_account_history_label"
  exit 1
fi
