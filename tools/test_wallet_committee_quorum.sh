#!/usr/bin/env bash
# WCSV-QUORUM — determ-wallet committee-signature-verify must anchor its quorum
# threshold to the OPERATOR-SUPPLIED committee size, never the number of
# signatures the (untrusted) block carries.
#
# THE GAP (found by direct read, HIGH, CLIENT-fixable): the quorum was
#   required = ceil(2 * present_count / 3)
# where present_count = the count of NON-sentinel signatures in the block. That
# denominator is fully attacker-controllable: pad K-1 creator slots with the
# sentinel-zero (all-zero) signature (counted as abstention, not failure) and
# present_count collapses to 1, so required = ceil(2/3) = 1 and a SINGLE valid
# committee signature "meets quorum" — a 1-of-K downgrade the daemon
# (required_block_sigs over the committee size) always rejects. A false
# "committee quorum met" assurance for a block the chain would never accept.
#
# THE FIX (client-side only; no consensus change): the denominator is the
# operator-supplied committee size (pubkey_of.size()), so required = ceil(2K/3)
# over the committee — the attacker cannot shrink it by padding sentinels (or by
# shrinking creators[]). Still the lean ceil(2/3) check the tool documents.
#
# This wrapper runs the pure in-process falsify gate `selftest-committee-quorum`,
# which mints real Ed25519 sigs for a 3-member committee and drives
# committee-signature-verify end-to-end: 3-of-3 and 2-of-3(+abstention) PASS, and
# the 1-valid + 2-sentinel-padded downgrade FAILs. Falsify-on-mutant: reverting
# the denominator to present_count makes the 1-of-3 padded block PASS -> the NEG
# assertion flips.
#
# FAST + OFFLINE (no cluster; deterministic seeds).
# Run from repo root: bash tools/test_wallet_committee_quorum.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
  echo "  SKIP: determ-wallet binary not found; build with"
  echo "        cmake --build build --config Release --target determ-wallet"
  exit 0
fi

set +e
OUT=$("$DETERM_WALLET" selftest-committee-quorum 2>&1)
RC=$?
set -e
# Show ONLY the selftest's own indented markers. The selftest drives
# committee-signature-verify which prints an UNINDENTED "FAIL: committee-signature
# verification" for the NEG (1-of-3) case it is designed to reject — echoing that
# would trip run_all.sh's `^\s*FAIL:` last-10-lines scan and spuriously fail this
# test (the "don't echo a verifier's FAIL:-output" rule). This grep matches only
# the selftest's own 2-space-indented `  ok:` / `  FAIL:` / `  N pass / M fail`
# lines and the `selftest-committee-quorum` verdict — never the inner tool's
# unindented verdict.
echo "$OUT" | grep -E "^  ok:|^  FAIL:|^  [0-9]+ pass / |selftest-committee-quorum" || true

if [ "$RC" = "0" ] && echo "$OUT" | grep -q "PASS: selftest-committee-quorum"; then
  echo "  PASS: test_wallet_committee_quorum"
  exit 0
else
  echo "  FAIL: test_wallet_committee_quorum (rc=$RC)"
  exit 1
fi
