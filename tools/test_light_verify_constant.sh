#!/usr/bin/env bash
# test_light_verify_constant.sh — the determ-light `verify-constant` trust-
# minimized reader for the `k:` (genesis-pinned constants) namespace — the
# LAST of the 10 committed state namespaces to gain a light reader.
#
# WHAT IT VERIFIES
# ----------------
# verify-constant is CONFIRM-shaped (like verify-merge-state): `k:` has no
# cleartext RPC, so the OPERATOR asserts (name, value) and the reader proves
# the assertion against the committee-attested k: leaf — key-bound
# (proof.key_bytes == "k:"+name, the F-6 closure) and Merkle-bound to the
# committee-signed state_root (committee_bound_state_root, S-042). BOTH
# verdicts are cryptographic: CONFIRMED (exit 0) = the committee attests
# exactly SHA256(u64_be(value)) [or SHA256(salt) for shard_salt]; MISMATCH
# (exit 2) = it attests a different value (sound under A2 — no daemon-asserted
# negative exists here because every k: leaf is unconditionally committed by
# build_state_leaves; a not_found is UNVERIFIABLE exit 3, never a negative).
#
# WHAT RUNS HERE (offline, no cluster) vs CI
# ------------------------------------------
#   * OFFLINE (always): help advertises the command; the canonical-name gate
#     rejects unknown names listing the 12 u64 constants + shard_salt; the
#     value-form gate rejects a u64 constant without --value and shard_salt
#     without --value-hex; bad --wait rejected; no-daemon fails fast with NO
#     verdict (no false CONFIRMED/MISMATCH).
#   * CI/WSL2 (cluster): live CONFIRMED (assert the genesis's real min_stake),
#     live MISMATCH exit 2 (assert min_stake+1), UNVERIFIABLE vs a daemon that
#     cannot serve k:, and the key-bind negative (daemon proving a different
#     constant's leaf → fail-closed). Documented + SKIPPED here, not faked.
#
# Run from repo root: bash tools/test_light_verify_constant.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

pass=0; fail=0; skip=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
no()  { echo "  FAIL: $1"; fail=$((fail+1)); }
skp() { echo "  SKIP: $1"; skip=$((skip+1)); }

# ── 1. help advertises verify-constant ──────────────────────────────────────────
echo "=== 1. help advertises verify-constant ==="
HELP=$($DETERM_LIGHT help 2>&1)
if printf '%s\n' "$HELP" | grep -qE "^[[:space:]]*verify-constant .*--name"; then
    ok "help lists verify-constant with --name"
else no "help should list verify-constant with --name"; fi
if printf '%s\n' "$HELP" | grep -A2 -E "^[[:space:]]*verify-constant" | grep -q -- "--wait"; then
    ok "verify-constant usage shows --wait"
else no "verify-constant usage should show --wait"; fi

# ── 2. canonical-name gate: unknown constant rejected with the full list ─────────
echo
echo "=== 2. unknown constant name rejected (canonical-name gate) ==="
set +e
OUT=$($DETERM_LIGHT verify-constant --rpc-port 7777 --genesis /no/such.json \
        --name not_a_constant --value 1 2>&1)
RC=$?
set -e
printf '    %s\n' "$OUT" | head -1
if [ "$RC" = "1" ] && printf '%s' "$OUT" | grep -q "unknown constant" \
   && printf '%s' "$OUT" | grep -q "min_stake" \
   && printf '%s' "$OUT" | grep -q "shard_salt"; then
    ok "unknown name -> rc=1 with the canonical constant list"
else no "unknown name should be rejected listing the known constants (rc=$RC)"; fi

# ── 3. value-form gates: u64 needs --value; shard_salt needs --value-hex ─────────
echo
echo "=== 3. value-form gates ==="
set +e
OUT=$($DETERM_LIGHT verify-constant --rpc-port 7777 --genesis /no/such.json \
        --name min_stake 2>&1); RC=$?
set -e
if [ "$RC" = "1" ] && printf '%s' "$OUT" | grep -q -- "--value <u64>"; then
    ok "u64 constant without --value -> rc=1 naming --value"
else no "u64 constant without --value should be rejected (rc=$RC)"; fi
set +e
OUT=$($DETERM_LIGHT verify-constant --rpc-port 7777 --genesis /no/such.json \
        --name shard_salt 2>&1); RC=$?
set -e
if [ "$RC" = "1" ] && printf '%s' "$OUT" | grep -q -- "--value-hex"; then
    ok "shard_salt without --value-hex -> rc=1 naming --value-hex"
else no "shard_salt without --value-hex should be rejected (rc=$RC)"; fi

# ── 4. bad --wait rejected; no-daemon fails fast with NO verdict ─────────────────
echo
echo "=== 4. bad --wait + no-daemon fail-fast ==="
set +e
OUT=$($DETERM_LIGHT verify-constant --rpc-port 59999 --genesis /no/such.json \
        --name min_stake --value 1000 --wait abc 2>&1); RC=$?
set -e
if [ "$RC" != "0" ] && printf '%s' "$OUT" | grep -qiE "wait must be a non-negative integer"; then
    ok "--wait abc -> clean rejection (rc=$RC)"
else no "--wait abc should be rejected (rc=$RC)"; fi
set +e
t0=$SECONDS
OUT=$($DETERM_LIGHT verify-constant --rpc-port 59999 \
        --genesis /no/such/genesis.json --name min_stake --value 1000 2>&1)
RC=$?
elapsed=$((SECONDS - t0))
set -e
if [ "$RC" != "0" ] && [ "$elapsed" -lt 10 ] \
   && ! printf '%s' "$OUT" | grep -qE "CONFIRMED|MISMATCH"; then
    ok "no-daemon read fails fast (rc=$RC, ${elapsed}s) with NO verdict emitted"
else no "no-daemon read should fail fast with no verdict (rc=$RC, ${elapsed}s)"; fi

# ── 5. live legs — CI/WSL2 cluster only ─────────────────────────────────────────
echo
echo "=== 5. live CONFIRMED / MISMATCH(exit 2) / UNVERIFIABLE / key-bind (cluster) ==="
skp "live CONFIRMED (genesis min_stake), MISMATCH exit 2 (min_stake+1), k:-refusing daemon -> UNVERIFIABLE exit 3, wrong-leaf key-bind fail-closed — CI/WSL2"

echo
echo "=== Test summary ==="
echo "  $pass pass / $fail fail / $skip skip"
if [ "$fail" = "0" ]; then
    echo "  PASS: test_light_verify_constant (offline contract; live legs are CI legs)"
    exit 0
else
    echo "  FAIL: test_light_verify_constant"
    exit 1
fi
