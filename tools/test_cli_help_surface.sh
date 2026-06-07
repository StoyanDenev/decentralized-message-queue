#!/usr/bin/env bash
# CLI help-surface drift guard across the THREE Determ binaries
# (determ, determ-wallet, determ-light).
#
# Every operator-facing subcommand listed in a binary's help text is a
# public-API promise. If a refactor accidentally drops a dispatch arm —
# or, more subtly, drops the help LINE while keeping the dispatch arm
# (silent doc-drift) — this test fails loudly. It runs ONLY the help
# command of each binary (no node, no cluster, no RPC) and asserts the
# output CONTAINS a curated set of known-shipped subcommand names.
#
# Help invocations (verified against src/main.cpp, wallet/main.cpp,
# light/main.cpp):
#   - determ         : no-arg prints usage() to STDOUT, exit 0.
#   - determ-wallet  : `help` prints print_usage() to STDERR, exit 0.
#   - determ-light   : `help` prints print_usage() to STDOUT, exit 0.
# Each invocation is captured with 2>&1 so the test is robust to which
# stream a given binary writes help to.
#
# Curated subcommand sets (stable, definitely-shipped — picked from the
# actual help text / main() dispatchers, not docs):
#   determ        : init register start send status committee validators
#                   supply head snapshot
#   determ-wallet : shamir-split shamir-combine shamir-verify
#                   inspect-envelope account-create-batch account-import
#                   keyfile-create keyfile-info
#   determ-light  : verify-headers verify-block-sigs verify-state-proof
#                   fetch-headers fetch-state-proof verify-chain
#                   balance-trustless sign-tx submit-tx
#
# SKIP-with-PASS per binary: a binary that isn't built contributes no
# assertions (and no failures), so this script is a no-op-PASS in a
# minimal env that built only a subset of the three binaries — never a
# hard fail. If NONE of the three are present the script still exits 0
# with an all-skipped summary.
#
# Run from repo root: bash tools/test_cli_help_surface.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

pass_count=0; fail_count=0; skip_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# check_help <invocation-label> <help-output> <subcmd>...
#   Asserts that each <subcmd> appears verbatim in <help-output>. A fixed
#   (non-regex) grep keeps the match literal so a subcommand named, e.g.,
#   "sign-tx" can't be matched by an unrelated regex fragment.
check_help() {
  local label="$1"; shift
  local out="$1"; shift
  local sub
  for sub in "$@"; do
    if printf '%s\n' "$out" | grep -qF -- "$sub"; then
      assert "true" "$label help lists '$sub'"
    else
      assert "false" "$label help MISSING '$sub' (drift / accidental removal)"
    fi
  done
}

# ── determ (node binary) ───────────────────────────────────────────────────────
# No-arg invocation prints usage() to stdout and exits 0.
echo "=== determ help surface ==="
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ]; then
  DETERM_HELP=$("$DETERM" 2>&1)
  check_help "determ" "$DETERM_HELP" \
    "init" "register" "start" "send" "status" \
    "committee" "validators" "supply" "head" "snapshot"
else
  echo "  SKIP: determ binary not found"
  skip_count=$((skip_count + 1))
fi

# ── determ-wallet (key / share tooling) ────────────────────────────────────────
# `help` prints print_usage() to stderr and exits 0.
echo
echo "=== determ-wallet help surface ==="
if [ -n "${DETERM_WALLET:-}" ] && [ -x "$DETERM_WALLET" ]; then
  WALLET_HELP=$("$DETERM_WALLET" help 2>&1)
  check_help "determ-wallet" "$WALLET_HELP" \
    "shamir-split" "shamir-combine" "shamir-verify" \
    "inspect-envelope" "account-create-batch" "account-import" \
    "keyfile-create" "keyfile-info"
else
  echo "  SKIP: determ-wallet binary not found"
  skip_count=$((skip_count + 1))
fi

# ── determ-light (trust-minimized light client) ───────────────────────────────
# `help` prints print_usage() to stdout and exits 0.
echo
echo "=== determ-light help surface ==="
if [ -n "${DETERM_LIGHT:-}" ] && [ -x "$DETERM_LIGHT" ]; then
  LIGHT_HELP=$("$DETERM_LIGHT" help 2>&1)
  check_help "determ-light" "$LIGHT_HELP" \
    "verify-headers" "verify-block-sigs" "verify-state-proof" \
    "fetch-headers" "fetch-state-proof" "verify-chain" \
    "balance-trustless" "sign-tx" "submit-tx"
else
  echo "  SKIP: determ-light binary not found"
  skip_count=$((skip_count + 1))
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail / $skip_count binary(s) skipped"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_cli_help_surface"; exit 0
else
  echo "  FAIL: test_cli_help_surface"; exit 1
fi
