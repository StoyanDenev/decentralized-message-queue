#!/usr/bin/env bash
# determ node (chain daemon) integer-argument GUARD regression test.
#
# CLASS UNDER TEST
# ----------------
# Many `determ` CLI subcommands parse integer arguments (positional
# <amount>/<index> and flags like --fee / --rpc-port / --shard-id) with
# std::sto*. An UNGUARDED parse throws std::invalid_argument out of main
# on a non-numeric value -> std::terminate -> process ABORT (a fail-open
# crash: non-zero non-1 status, RC 127 on this box, no diagnostic). The
# ~28 sites were guarded in one change via the typed arg_i32 / arg_u32 /
# arg_i64 / arg_u64 helpers in src/main.cpp (mirroring the determ-wallet
# fix), plus inline try/catch on the get_rpc_port / size_t / uint8_t
# odd-type sites.
#
# CONTRACT asserted here (one representative probe per guarded command,
# and one per helper TYPE / odd-type):
#   (a) a non-integer value -> CLEAN `<cmd>: <flag> must be an integer` on
#       stderr + exit 1 (NOT a crash / abort / 127 / empty-diagnostic).
#   (b) a LARGE valid u64 amount (near UINT64_MAX) is still ACCEPTED by
#       the parse (arg_u64 keeps stoull's full range — it must NOT be
#       rejected as "must be an integer", which a wrong stoll/stoi
#       narrowing would do). It later fails on no-daemon; that's fine.
#
# Pure offline: every probe fails inside the arg-parse loop before any
# network / daemon / RPC work, so no daemon is needed. (get_rpc_port is
# parsed up front, before the RPC call, so its probe also stays offline.)
#
# Run from repo root: bash tools/test_node_int_arg_guards_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found; build with"
    echo "        cmake --build build --config Release --target determ"
    exit 0
fi
D="$DETERM"

# A 64-hex pseudo-domain for commands that take a recipient before the
# integer arg (e.g. send <to> <amount>). Value is irrelevant — the parse
# of the *next* arg is what we exercise.
HEX64="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }

# guard_rejects "<label>" -- run the given argv, assert exit 1 AND a
# "must be an integer" diagnostic AND that it is NOT a crash (status 127
# or a >128 signal status). Captures rc BEFORE any pipe so $? is the
# node binary's own.
guard_rejects() {
    local label="$1"; shift
    local out rc
    out="$("$D" "$@" 2>&1)"; rc=$?
    out="$(printf '%s' "$out" | tr -d '\r')"
    if [ "$rc" -eq 1 ]; then ok "$label: clean exit 1 (not a crash)"
    else bad "$label: expected exit 1, got $rc (crash/abort if 127/>128)"; fi
    if printf '%s' "$out" | grep -q "must be an integer"; then ok "$label: prints 'must be an integer' diagnostic"
    else bad "$label: missing 'must be an integer' diagnostic (got: $out)"; fi
}

echo "=== non-integer values must be rejected cleanly (one per guarded command/type) ==="
# Positional <amount> / <index> (arg_u64):
guard_rejects "send <amount> (u64 positional)"        send "$HEX64" abc
guard_rejects "stake <amount> (u64 positional)"       stake abc
guard_rejects "unstake <amount> (u64 positional)"     unstake abc
guard_rejects "show-block <index> (u64 positional)"   show-block abc
guard_rejects "block-hash <index> (u64 positional)"   block-hash abc
guard_rejects "send_anon <amount> (u64 positional)"   send_anon "$HEX64" abc deadbeef
# Flag forms (arg_u64):
guard_rejects "stake --fee (u64 flag)"                stake 100 --fee xyz
guard_rejects "headers --from (u64 flag)"             headers --from ff
guard_rejects "pending-params --at-height (u64 flag)" pending-params --at-height qq
# arg_u32 flag:
guard_rejects "chain-summary --last (u32 flag)"       chain-summary --last nn
guard_rejects "headers --count (u32 flag)"            headers --count nn
guard_rejects "submit-merge-event --shard-id (u32)"   submit-merge-event --priv aa --from x --event y --shard-id zz
# arg_i64 flag:
guard_rejects "send_anon --nonce (i64 flag)"          send_anon "$HEX64" 100 deadbeef --nonce gg
# inline-guarded odd-type sites:
guard_rejects "--rpc-port (inline get_rpc_port)"      status --rpc-port pp
guard_rejects "abort-records --top (size_t inline)"   abort-records --top tt
guard_rejects "submit-dapp-register --retention (u8)" submit-dapp-register --priv aa --from x --retention rr
# submit-param-change / submit-dapp-call / genesis-tool fee+u64 paths:
guard_rejects "submit-param-change --fee (u64 flag)"  submit-param-change --priv aa --from x --name p --value-hex 00 --fee ff
guard_rejects "submit-dapp-call --amount (u64 flag)"  submit-dapp-call --priv aa --from x --to y --amount aa
guard_rejects "genesis-tool peer-info --stake (u64)"  genesis-tool peer-info dom --stake ss

echo
echo "=== positive control: a large valid u64 amount must be ACCEPTED by the parse ==="
# 18000000000000000000 < UINT64_MAX (18446744073709551615). The command
# will still fail later (no daemon), but NOT with an <amount> parse error.
CTRL="$("$D" stake 18000000000000000000 2>&1 | tr -d '\r')"
if printf '%s' "$CTRL" | grep -q "must be an integer"; then
    bad "large u64 <amount> wrongly rejected as non-integer (range narrowed?)"
else
    ok "large u64 <amount> (1.8e19, near UINT64_MAX) accepted by parse (not narrowed)"
fi

echo
echo "=== summary ==="
echo "  $pass pass / $fail fail"
if [ "$fail" -eq 0 ]; then echo "  PASS: determ node integer-arg guards edge"; exit 0
else echo "  FAIL: determ node integer-arg guards edge"; exit 1; fi
