#!/usr/bin/env bash
# S-035 Path 3 follow-on: run the full regression suite + summarize.
#
# Iterates every tools/test_*.sh script, captures PASS / FAIL per
# test, and prints a summary table at the end. Exits non-zero if any
# test failed.
#
# Each test is run independently (a failure in one doesn't stop the
# suite) so an operator gets the full failure picture in one run
# rather than having to fix-and-retry one-at-a-time.
#
# Output format:
#
#   === tools/test_NAME.sh ===
#   [test stdout/stderr]
#   ...
#
#   ──────────────────────────────────────────────
#   PASS: N tests
#   FAIL: M tests
#   ──────────────────────────────────────────────
#   Failed tests:
#     - tools/test_FAILED1.sh
#     - tools/test_FAILED2.sh
#
# Per-test outcome detection: the script grep's the last 10 lines of
# each test's output for a "PASS:" or "FAIL:" line. Every existing
# test follows the convention of a final-line PASS / FAIL marker, so
# this is robust to test-specific output noise above it.
#
# Run from repo root: bash tools/run_all.sh
#
# Override hooks (passed through to each test via tools/common.sh):
#   DETERM_BIN=/path/to/determ         # custom chain-daemon binary
#   DETERM_WALLET_BIN=/path/to/wallet  # custom wallet binary
#
# Environment knobs:
#   SKIP_PATTERN='regex'  Skip tests whose path matches this regex
#                         (useful for skipping known-flaky tests on
#                         specific platforms).
#   ONLY_PATTERN='regex'  Only run tests whose path matches.
#   QUIET=1               Suppress per-test stdout; only print
#                         summary at the end.
#   FAST=1                Run ONLY the deterministic in-process tests
#                         (no multi-node clusters, no network). These
#                         are the `determ test-*` subcommand wrappers:
#                         atomic_scope, composable_batch, dapp_register,
#                         dapp_call, s018_json_validation, merkle,
#                         committee_selection. Each runs in <5s with
#                         no flakes. Useful for quick iteration during
#                         development.

set -u
cd "$(dirname "$0")/.."

# Verify binaries are findable before iterating (saves running 49
# tests just to see them all fail on the same missing binary).
source tools/common.sh
echo "Using DETERM=$DETERM"
echo "Using DETERM_WALLET=${DETERM_WALLET:-<none>}"
echo "Using PROJECT_ROOT=$PROJECT_ROOT"
echo

PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=()
START_TIME=$(date +%s)

SKIP_PATTERN="${SKIP_PATTERN:-}"
ONLY_PATTERN="${ONLY_PATTERN:-}"

# FAST=1 short-circuits to the deterministic in-process subset.
# These are wrappers around `determ test-*` subcommands — no network,
# no clusters, <5s each, no flakes. Useful for dev iteration.
if [ "${FAST:-0}" = "1" ]; then
    ONLY_PATTERN='test_(atomic_scope|composable_batch|dapp_register|dapp_call|s018_json_validation|merkle|committee_selection)\.sh$'
    echo "FAST=1 mode: ONLY_PATTERN set to in-process tests only"
    echo
fi

for t in tools/test_*.sh; do
    # Filtering knobs.
    if [ -n "$ONLY_PATTERN" ] && [[ ! "$t" =~ $ONLY_PATTERN ]]; then
        continue
    fi
    if [ -n "$SKIP_PATTERN" ] && [[ "$t" =~ $SKIP_PATTERN ]]; then
        echo "=== SKIP: $t (matched SKIP_PATTERN) ==="
        continue
    fi

    echo "=== $t ==="
    if [ "${QUIET:-0}" = "1" ]; then
        OUT=$(bash "$t" 2>&1)
    else
        OUT=$(bash "$t" 2>&1 | tee /dev/stderr)
    fi

    # Outcome detection: look at the final 10 lines for a clear
    # PASS / FAIL marker. Tests use either:
    #   "  PASS: <description>"  on success
    #   "  FAIL: <description>"  on failure
    # Both with a leading space (the existing test convention).
    LAST=$(echo "$OUT" | tail -10)
    if echo "$LAST" | grep -qE "^\s*PASS:"; then
        PASS_COUNT=$((PASS_COUNT + 1))
    elif echo "$LAST" | grep -qE "^\s*FAIL:"; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$t")
    else
        # Ambiguous outcome — count as failure for safety.
        echo "  (no PASS:/FAIL: marker in final 10 lines — counted as failure)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$t (no marker)")
    fi
    echo
done

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "──────────────────────────────────────────────"
echo "Regression suite summary (${ELAPSED}s)"
echo "──────────────────────────────────────────────"
echo "PASS: $PASS_COUNT tests"
echo "FAIL: $FAIL_COUNT tests"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "──────────────────────────────────────────────"
    echo "Failed tests:"
    for ft in "${FAILED_TESTS[@]}"; do
        echo "  - $ft"
    done
fi

# Exit non-zero if anything failed.
[ "$FAIL_COUNT" -eq 0 ] || exit 1
