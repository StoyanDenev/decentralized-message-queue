#!/usr/bin/env bash
# determ-light persisted-anchor cache (`state` subcommand + `verify-chain
# --persist`). The persistence module (light/persist.{hpp,cpp}) is fully
# OFFLINE-verifiable — no daemon needed — so this whole wrapper is deterministic
# on every host (unlike the cluster-bound tools/test_light_*.sh tests).
#
# Layers:
#   (A) `state --selftest` — the module's own in-binary round-trip + fail-closed
#       reject-path checks (save→load byte-equality, malformed JSON, bad
#       schema_version, short/non-hex fields, missing fields).
#   (B) CLI contract for --show / --clear / mode-flag / unknown-arg / env-override.
#   (C) verify-chain --persist arg parsing (the WRITE itself is daemon-bound and
#       exercised on WSL2/CI; here we pin that the new flags are accepted and that
#       an anchor is only written after a successful verify — never on connect
#       failure).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

pass=0; fail=0
ck() { if [ "$1" = "$2" ]; then echo "  PASS: $3 (exit $1)"; pass=$((pass+1));
       else echo "  FAIL: $3 (got exit $1, want $2)"; fail=$((fail+1)); fi; }

T="$(mktemp -d 2>/dev/null || echo /tmp/determ_state_$$)"; mkdir -p "$T"
trap 'rm -rf "$T" 2>/dev/null' EXIT INT
SP="$T/state.json"
H64a=$(printf 'a%.0s' $(seq 1 64))
H64b=$(printf 'b%.0s' $(seq 1 64))
H64c=$(printf 'c%.0s' $(seq 1 64))

echo "=== (A) in-binary persist-module selftest ==="
OUT=$($DETERM_LIGHT state --selftest 2>&1); rc=$?
echo "$OUT" | sed 's/^/    /'
ck $rc 0 "state --selftest all checks pass"
# The selftest must actually run >=6 checks (guards against a no-op pass).
n=$(echo "$OUT" | grep -c "PASS ")
if [ "$n" -ge 6 ]; then echo "  PASS: selftest ran $n checks (>=6)"; pass=$((pass+1));
else echo "  FAIL: selftest ran only $n checks"; fail=$((fail+1)); fi

echo ""
echo "=== (B) state --show / --clear / mode-flag / env CLI contract ==="

# 1. --show on a missing file is graceful (exit 0, not an error).
$DETERM_LIGHT state --show --state "$SP" >/dev/null 2>&1
ck $? 0 "--show on missing cache is graceful"

# 2. a valid hand-written state shows + validates (exit 0) and echoes a field.
printf '{"schema_version":1,"genesis_hash":"%s","head_height":42,"head_block_hash":"%s","head_state_root":"%s"}\n' \
    "$H64a" "$H64b" "$H64c" > "$SP"
OUT=$($DETERM_LIGHT state --show --state "$SP" 2>&1); rc=$?
if [ "$rc" = "0" ] && echo "$OUT" | grep -q "head_height:        42"; then
    echo "  PASS: --show prints a valid anchor (height 42)"; pass=$((pass+1))
else echo "  FAIL: --show on valid anchor (exit $rc)"; echo "$OUT" | sed 's/^/      /'; fail=$((fail+1)); fi

# 3. --clear removes it (exit 0) and a re-show then reports absence.
$DETERM_LIGHT state --clear --state "$SP" >/dev/null 2>&1
ck $? 0 "--clear removes the cache"
if [ ! -f "$SP" ]; then echo "  PASS: file gone after --clear"; pass=$((pass+1));
else echo "  FAIL: file still present after --clear"; fail=$((fail+1)); fi

# 4. --clear on already-absent is graceful (exit 0).
$DETERM_LIGHT state --clear --state "$SP" >/dev/null 2>&1
ck $? 0 "--clear on absent cache is graceful"

# 5. --show on a corrupt file fails CLOSED (exit 1, not a false 'no anchor').
echo "{ not json" > "$SP"
$DETERM_LIGHT state --show --state "$SP" >/dev/null 2>&1
ck $? 1 "--show on corrupt cache fails closed"

# 6. no mode flag → usage error (exit 1).
$DETERM_LIGHT state --state "$SP" >/dev/null 2>&1
ck $? 1 "missing --show/--clear/--selftest rejected"

# 7. unknown arg → usage error (exit 1).
$DETERM_LIGHT state --show --bogus >/dev/null 2>&1
ck $? 1 "unknown arg rejected"

# 8. DETERM_LIGHT_STATE env override drives the default path. Match on the
#    unique temp-dir leaf (present in both the MSYS and native-Windows path
#    forms — the binary is native, so it prints C:/... while $SP is /tmp/...)
#    and on it NOT being the ~/.determ-light home default.
rm -f "$SP"
LEAF=$(basename "$T")
OUT=$(DETERM_LIGHT_STATE="$SP" $DETERM_LIGHT state --show 2>&1); rc=$?
if [ "$rc" = "0" ] && echo "$OUT" | grep -qF "$LEAF" && ! echo "$OUT" | grep -q ".determ-light"; then
    echo "  PASS: DETERM_LIGHT_STATE overrides the default path"; pass=$((pass+1))
else echo "  FAIL: env override not honored (exit $rc)"; echo "$OUT" | sed 's/^/      /'; fail=$((fail+1)); fi

# 9. state listed in help.
if $DETERM_LIGHT help 2>&1 | grep -q "state (--show"; then
    echo "  PASS: state listed in help"; pass=$((pass+1))
else echo "  FAIL: state not listed in help"; fail=$((fail+1)); fi

echo ""
echo "=== (C2) state --verify-anchor offline genesis re-pin gate (LSP-2) ==="
# Craft a minimal genesis (chain_id + shard params — all load_genesis needs) and
# read its authoritative LOCAL genesis hash off `shard-route --json` (which prints
# compute_genesis_hash). This is fully offline — the LSP-6 resume's genesis gate.
SALT=$(printf '0%.0s' $(seq 1 64))
cat > "$T/gen.json" <<EOF
{
  "chain_id": "light-state-test",
  "initial_shard_count": 1,
  "shard_address_salt": "$SALT"
}
EOF
GH=$($DETERM_LIGHT shard-route --genesis "$T/gen.json" --address alice --json 2>/dev/null \
     | "${PY:-python}" -c "import json,sys;print(json.load(sys.stdin).get('genesis_hash',''))" 2>/dev/null)
if [ -n "$GH" ] && [ ${#GH} -eq 64 ]; then
    # 13. matching anchor → PASS (exit 0)
    printf '{"schema_version":1,"genesis_hash":"%s","head_height":7,"head_block_hash":"%s","head_state_root":""}\n' \
        "$GH" "$H64b" > "$SP"
    $DETERM_LIGHT state --verify-anchor --genesis "$T/gen.json" --state "$SP" >/dev/null 2>&1
    ck $? 0 "--verify-anchor PASS on matching genesis"

    # 14. wrong-chain anchor → MISMATCH (exit 2)
    printf '{"schema_version":1,"genesis_hash":"%s","head_height":7,"head_block_hash":"%s","head_state_root":""}\n' \
        "$H64a" "$H64b" > "$SP"
    $DETERM_LIGHT state --verify-anchor --genesis "$T/gen.json" --state "$SP" >/dev/null 2>&1
    ck $? 2 "--verify-anchor MISMATCH on wrong-chain anchor (exit 2)"
else
    echo "  SKIP: --verify-anchor PASS/MISMATCH (could not derive local genesis hash;"
    echo "        shard-route --json unavailable on this host — usage paths below still run)"
fi

# 15. --verify-anchor without --genesis → usage error (exit 1).
$DETERM_LIGHT state --verify-anchor --state "$SP" >/dev/null 2>&1
ck $? 1 "--verify-anchor without --genesis rejected"

# 16. --verify-anchor with no cached anchor → exit 1 (can't verify nothing).
rm -f "$SP"
$DETERM_LIGHT state --verify-anchor --genesis "$T/gen.json" --state "$SP" >/dev/null 2>&1
ck $? 1 "--verify-anchor on absent cache rejected"

# 17. --verify-anchor listed in help.
if $DETERM_LIGHT help 2>&1 | grep -q -- "--verify-anchor"; then
    echo "  PASS: --verify-anchor listed in help"; pass=$((pass+1))
else echo "  FAIL: --verify-anchor not in help"; fail=$((fail+1)); fi

echo ""
echo "=== (C) verify-chain --persist arg contract (write is daemon-bound) ==="

# 10. --persist + --state are accepted (the error is the missing genesis file /
#     unreachable daemon, NOT an 'unknown arg' parse failure).
OUT=$($DETERM_LIGHT verify-chain --rpc-port 59997 --genesis "$T/nope.json" --persist --state "$T/vc.json" 2>&1)
if echo "$OUT" | grep -qv "unknown arg" && ! echo "$OUT" | grep -q "unknown arg"; then
    echo "  PASS: verify-chain accepts --persist/--state"; pass=$((pass+1))
else echo "  FAIL: verify-chain rejected --persist/--state ($OUT)"; fail=$((fail+1)); fi

# 11. an anchor is NOT written when verify fails (no daemon → connect error).
if [ ! -f "$T/vc.json" ]; then
    echo "  PASS: no anchor written on failed verify (fail-closed persist)"; pass=$((pass+1))
else echo "  FAIL: anchor written despite verify failure"; fail=$((fail+1)); fi

# 12. --persist documented in help.
if $DETERM_LIGHT help 2>&1 | grep -q -- "--persist"; then
    echo "  PASS: --persist listed in help"; pass=$((pass+1))
else echo "  FAIL: --persist not in help"; fail=$((fail+1)); fi

echo ""
echo "=== (D) verify-chain --resume arg contract (LSP-6; suffix verify is daemon-bound) ==="

# The live resume (verify the suffix above a cached anchor, the fallback-to-full
# paths, and the fork-below-anchor hard error) needs a running cluster and is
# exercised on WSL2/CI. Here we pin the deterministic offline arg contract.

# 13. --resume is accepted (the error is the missing genesis / unreachable
#     daemon, NOT an 'unknown arg' parse failure).
OUT=$($DETERM_LIGHT verify-chain --rpc-port 59996 --genesis "$T/nope.json" --resume --state "$T/r.json" 2>&1)
if ! echo "$OUT" | grep -q "unknown arg"; then
    echo "  PASS: verify-chain accepts --resume"; pass=$((pass+1))
else echo "  FAIL: verify-chain rejected --resume ($OUT)"; fail=$((fail+1)); fi

# 14. --resume + --persist accepted together (the steady-state loop).
OUT=$($DETERM_LIGHT verify-chain --rpc-port 59996 --genesis "$T/nope.json" --resume --persist --state "$T/r.json" 2>&1)
if ! echo "$OUT" | grep -q "unknown arg"; then
    echo "  PASS: verify-chain accepts --resume + --persist together"; pass=$((pass+1))
else echo "  FAIL: --resume + --persist rejected together ($OUT)"; fail=$((fail+1)); fi

# 15. --resume documented in help.
if $DETERM_LIGHT help 2>&1 | grep -q -- "--resume"; then
    echo "  PASS: --resume listed in help"; pass=$((pass+1))
else echo "  FAIL: --resume not in help"; fail=$((fail+1)); fi

echo ""
echo "=== Test summary ==="
echo "  $pass pass / $fail fail"
if [ "$fail" -eq 0 ]; then echo "  PASS: test_light_state"; exit 0
else echo "  FAIL: test_light_state"; exit 1; fi
