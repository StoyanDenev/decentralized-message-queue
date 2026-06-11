#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.12 / docs/proofs/TimingProbeDesign.md §5.5 — the ONE
# deterministic, suite-eligible piece of the timing probe: the statistics
# engine's pinned fixture. Both the batch Welch formula and the
# Welford-incremental path must return t = -2.0 and df = 8.0 BIT-EXACTLY on
# the integer-clean fixture (all intermediates are dyadic rationals — no
# rounding ambiguity), plus the t(B,A) == +2.0 antisymmetry pin.
#
# The MEASUREMENT mode (`determ ct-timing-probe <target>`) is a REPORTING
# tool and deliberately NOT in this suite (design §3.1: timing is
# environmental; a pass/fail timing test would flake).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== ct-timing-probe statistics-engine selftest (§5.5 pinned fixture) ==="
OUT=$($DETERM ct-timing-probe --selftest 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_frost_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: ct-timing-probe selftest statistics engine matches the pinned"; then
  echo ""
  echo "  PASS: test_ct_timing_selftest"
  exit 0
else
  echo ""
  echo "  FAIL: test_ct_timing_selftest (statistics engine diverges from the §5.5 fixture)"
  exit 1
fi
