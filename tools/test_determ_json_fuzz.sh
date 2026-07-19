#!/usr/bin/env bash
# minix JSON phase 2, increment 3: determ::djson DETERMINISTIC DIFFERENTIAL FUZZER.
#
# inc.1/inc.2 proved byte-parity on a fixed corpus + the daemon's real surfaces.
# This elevates DetermJsonParitySoundness NC-3 from "corpus-bounded" to
# fuzz-tested: `determ test-determ-json-fuzz` generates thousands of RANDOM
# in-scope JSON values (bounded-depth objects/arrays, u64/i64, bool/null, ASCII
# + UTF-8 + escape-triggering strings) and cross-checks BOTH determ::djson code
# paths against nlohmann per value — BUILD+dump (nlohmann tree -> determ::djson
# builder API -> dump) AND PARSE+dump (parse nlohmann's dump -> re-dump) — each
# asserted byte-identical to nlohmann's dump. Any divergence is a real
# determ::djson bug. Deterministic (splitmix64, fixed seed -> identical inputs
# on MSVC + GCC, CI-stable + reproducible); ONLY in-scope values are generated
# (depth < the parser cap, no doubles), so agreement is the expected result.
#
# PHASE 2 (inc.5) adds the ADVERSARIAL MUTATIONAL half, attacking the OTHER
# swap-safety property (DJP-5): valid seeds are corrupted (substitute / insert /
# delete / duplicate / truncate / transpose) and determ::djson and nlohmann must
# AGREE on accept-vs-reject — a disagreement is a mixed-fleet fork/desync. This
# is the fuzz-scale counterpart of inc.4's hand-written corpus (which is exactly
# how the inc.4 review's overflow-to-non-finite divergence had slipped through).
# Mutations are steered clear of the NC-4 deliberate carve-outs (never inserts
# 0x00; depth stays far under the cap) so any disagreement found is a REAL bug,
# and dump-parity is compared on both-accepted mutants only when the value holds
# no double (the documented NC-1 dtoa gap). A non-vacuity gate asserts the
# mutations actually yield BOTH accepted and rejected inputs.
#
# FAST runs the fast default (3000 iters, <1s); pass a larger `--iters N` for a
# deeper standalone stress run.
#
# Run from repo root: bash tools/test_determ_json_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== minix JSON phase 2 inc.3 — determ::djson differential fuzz vs nlohmann (build + parse paths) ==="
OUT=$("$DETERM" test-determ-json-fuzz 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-determ-json-fuzz"; then
  echo "  PASS: determ-json differential fuzz"
  exit 0
else
  echo "  FAIL: determ-json differential fuzz (exit $rc)"
  exit 1
fi
