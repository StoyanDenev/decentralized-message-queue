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
