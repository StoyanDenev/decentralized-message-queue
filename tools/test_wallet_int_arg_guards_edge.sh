#!/usr/bin/env bash
# determ-wallet integer-argument GUARD regression test.
#
# CLASS UNDER TEST
# ----------------
# Many determ-wallet subcommands parse integer CLI flags with std::sto*.
# An UNGUARDED parse throws std::invalid_argument out of main on a non-
# numeric value -> std::terminate -> process ABORT (a fail-open crash:
# non-zero non-1 status, RC 127 on this box, no diagnostic). This was a
# systemic class (cmd_shamir_verify --threshold was the first instance found
# + fixed; the remaining ~20 sites were guarded in the same change via the
# typed arg_i32 / arg_u32 / arg_i64 / arg_u64 helpers in wallet/main.cpp).
#
# CONTRACT asserted here (one representative flag per guarded command, and
# one per helper TYPE):
#   (a) a non-integer value -> CLEAN `<cmd>: <flag> must be an integer` on
#       stderr + exit 1 (NOT a crash / abort / 127 / empty-diagnostic).
#   (b) a LARGE valid u64 --fee (near UINT64_MAX) is still ACCEPTED by the
#       parse (arg_u64 keeps stoull's full range — it must NOT be rejected
#       as "must be an integer", which a wrong stoll/stoi narrowing would do).
#
# Pure offline: every probe fails inside the arg-parse loop before any
# network / daemon / keyfile work, so no daemon is needed.
#
# Run from repo root: bash tools/test_wallet_int_arg_guards_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
W="$DETERM_WALLET"

pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }

# guard_rejects "<label>" "<flag>" -- run the given argv, assert exit 1 AND a
# "must be an integer" diagnostic AND that it is NOT a crash (status 127 or a
# >128 signal status). Captures rc BEFORE any pipe so $? is the wallet's own.
guard_rejects() {
    local label="$1"; shift
    local out rc
    out="$("$W" "$@" 2>&1)"; rc=$?
    out="$(printf '%s' "$out" | tr -d '\r')"
    if [ "$rc" -eq 1 ]; then ok "$label: clean exit 1 (not a crash)"
    else bad "$label: expected exit 1, got $rc (crash/abort if 127/>128)"; fi
    if printf '%s' "$out" | grep -q "must be an integer"; then ok "$label: prints 'must be an integer' diagnostic"
    else bad "$label: missing 'must be an integer' diagnostic (got: $out)"; fi
}

echo "=== non-integer values must be rejected cleanly (one per guarded command/type) ==="
guard_rejects "bulk-send --fee (u64)"                 bulk-send --fee abc
guard_rejects "bulk-send --starting-nonce (i64)"      bulk-send --starting-nonce zz
guard_rejects "bulk-stake --fee (u64)"                bulk-stake --fee nope
guard_rejects "shamir-split --threshold (i32)"        shamir-split --threshold qq
guard_rejects "shamir split -t (i32)"                 shamir split --secret deadbeef -t tt -n 5
guard_rejects "envelope encrypt --iters (u32)"        envelope encrypt --iters nn
guard_rejects "opaque-handshake --guardian-id (i32)"  opaque-handshake --guardian-id gg
guard_rejects "tx-history-export --from (i64)"        tx-history-export --from ff
guard_rejects "account-balance-history --checkpoint-every (i64)" account-balance-history --checkpoint-every cc
guard_rejects "create-recovery -t (i32)"              create-recovery -t xx -n 3

echo
echo "=== positive control: a large valid u64 --fee must be ACCEPTED by the parse ==="
# 18000000000000000000 < UINT64_MAX (18446744073709551615). The command will
# still fail later (missing recipients), but NOT with a --fee parse error.
CTRL="$("$W" bulk-send --fee 18000000000000000000 2>&1 | tr -d '\r')"
if printf '%s' "$CTRL" | grep -q -- "--fee must be an integer"; then
    bad "large u64 --fee wrongly rejected as non-integer (range narrowed?)"
else
    ok "large u64 --fee (1.8e19, near UINT64_MAX) accepted by parse (not narrowed)"
fi

echo
echo "=== summary ==="
echo "  $pass pass / $fail fail"
if [ "$fail" -eq 0 ]; then echo "  PASS: determ-wallet integer-arg guards edge"; exit 0
else echo "  FAIL: determ-wallet integer-arg guards edge"; exit 1; fi
