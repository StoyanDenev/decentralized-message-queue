#!/usr/bin/env bash
# test_light_verify_abort_record.sh — the determ-light `verify-abort-record`
# trust-minimized reader for the `b:` (abort_records) namespace.
#
# WHAT IT VERIFIES
# ----------------
# verify-abort-record is the `b:`-namespace sibling of stake-trustless (`s:`):
# it anchors genesis, committee-verifies the header chain to head, fetches the
# `b:` state-proof for a node <D>, Merkle-verifies it against the COMMITTEE-BOUND
# state_root (committee_bound_state_root, the S-042 successor binding), and
# hash-binds the daemon's `abort_records` cleartext to the proven value_hash
# (= SHA256(u64_be(count) ‖ u64_be(last_block)), matching build_state_leaves).
# RECORDED reports the committee-verified (count, last_block); NOT-RECORDED is a
# daemon-asserted negative (state_proof not_found; negative_footing tagged).
#
# WHAT RUNS HERE (offline, no cluster) vs CI
# ------------------------------------------
#   * OFFLINE (always): help advertises the command + its flags; a missing
#     required flag is a clean usage error (exit 1); a bad --wait is rejected;
#     and with no daemon the read fails fast/clean (no hang, no false verdict).
#   * CI/WSL2 (cluster): the live legs — drive a node to a Phase-1 abort and
#     assert RECORDED with the hash-bound (count, last_block); assert NOT-RECORDED
#     (+ negative_footing=daemon_asserted) for a never-aborted node; assert a
#     tampered abort_records cleartext / swapped state_root → fail-closed. These
#     need a live (and abort-inducing) cluster, documented + SKIPPED here.
#
# Run from repo root: bash tools/test_light_verify_abort_record.sh
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

# ── 1. help advertises verify-abort-record + its flags ──────────────────────────
echo "=== 1. help advertises verify-abort-record ==="
HELP=$($DETERM_LIGHT help 2>&1)
if printf '%s\n' "$HELP" | grep -qE "^[[:space:]]*verify-abort-record .*--domain"; then
    ok "help lists verify-abort-record with --domain"
else no "help should list verify-abort-record with --domain"; fi
if printf '%s\n' "$HELP" | grep -A1 -E "^[[:space:]]*verify-abort-record" | grep -q -- "--wait"; then
    ok "verify-abort-record usage shows --wait"
else no "verify-abort-record usage should show --wait"; fi

# ── 2. a missing required flag is a clean usage error (exit 1) ───────────────────
echo
echo "=== 2. missing --domain -> clean usage error (exit 1) ==="
set +e
OUT=$($DETERM_LIGHT verify-abort-record --rpc-port 7777 --genesis /no/such.json 2>&1)
RC=$?
set -e
printf '    %s\n' "$OUT" | head -1
if [ "$RC" = "1" ] && printf '%s' "$OUT" | grep -q "are required"; then
    ok "missing --domain -> usage error naming the required flags (rc=1)"
else no "missing --domain should be a clean usage error rc=1 (got rc=$RC)"; fi

# ── 3. a bad --wait value is rejected cleanly ───────────────────────────────────
echo
echo "=== 3. bad --wait rejected ==="
set +e
OUT=$($DETERM_LIGHT verify-abort-record --rpc-port 59999 --genesis /no/such.json \
        --domain alice --wait abc 2>&1)
RC=$?
set -e
printf '    %s\n' "$OUT" | head -1
if [ "$RC" != "0" ] && printf '%s' "$OUT" | grep -qiE "wait must be a non-negative integer|--wait"; then
    ok "--wait abc -> clean rejection (rc=$RC, no crash)"
else no "--wait abc should be rejected (rc=$RC)"; fi

# ── 4. with no daemon the read fails fast + clean (no false verdict) ─────────────
echo
echo "=== 4. no daemon -> clean fail (no false RECORDED/NOT-RECORDED) ==="
set +e
t0=$SECONDS
OUT=$($DETERM_LIGHT verify-abort-record --rpc-port 59999 \
        --genesis /no/such/genesis.json --domain alice 2>&1)
RC=$?
elapsed=$((SECONDS - t0))
set -e
printf '    %s\n' "$OUT" | head -1
if [ "$RC" != "0" ] && [ "$elapsed" -lt 10 ] \
   && ! printf '%s' "$OUT" | grep -qE "RECORDED|NOT-RECORDED"; then
    ok "no-daemon read fails fast (rc=$RC, ${elapsed}s) with NO verdict emitted"
else no "no-daemon read should fail fast with no verdict (rc=$RC, ${elapsed}s)"; fi

# ── 5. live legs — CI/WSL2 cluster only ─────────────────────────────────────────
echo
echo "=== 5. live RECORDED / NOT-RECORDED / fail-closed (cluster) ==="
skp "live RECORDED (induce a Phase-1 abort, assert hash-bound count/last_block), NOT-RECORDED (+negative_footing), and tamper fail-closed — CI/WSL2"

echo
echo "=== Test summary ==="
echo "  $pass pass / $fail fail / $skip skip"
if [ "$fail" = "0" ]; then
    echo "  PASS: test_light_verify_abort_record (offline contract; live legs are CI legs)"
    exit 0
else
    echo "  FAIL: test_light_verify_abort_record"
    exit 1
fi
