#!/usr/bin/env bash
# determ-wallet subsidy-schedule CLI test.
#
# Exercises the OFFLINE forward projection of the FLAT / E4 block-subsidy
# emission curve from genesis-pinned parameters. Given a per-block subsidy S,
# an optional E4 finite fund P, an already-accumulated amount A, and a target
# horizon, the command reproduces — with no daemon and no snapshot — the
# chain's per-block subsidy rule (src/chain/chain.cpp::apply_transactions
# ~L1250-1272):
#
#     subsidy_this_block = (pool_initial == 0)
#         ? block_subsidy
#         : min(block_subsidy, pool_initial - accumulated_subsidy)
#
# subsidy-schedule is the FORWARD dual of supply-audit: supply-audit verifies
# a captured snapshot's A1 conservation identity backward; subsidy-schedule
# projects the issuance schedule forward (cumulative subsidy at a horizon, the
# E4 finite-fund drain height, and the resulting total supply).
#
# This test recomputes the EXPECTED values independently in Python and asserts
# the wallet output matches exactly — correctness, not just output shape. No
# cluster, no daemon, no network, no crypto: pure offline integer arithmetic.
#
# E3 LOTTERY note: subsidy_mode==1 keeps the SAME expected issuance schedule
# (expected per-block == FLAT S), so the projection is exact for FLAT and holds
# in expectation for LOTTERY; the tool projects the scheduled emission.
#
# Differentiation vs sibling commands:
#   * supply-audit  — recomputes a captured snapshot's A1 identity BACKWARD
#                     (needs a snapshot file; reports balanced/VIOLATED).
#   * subsidy-schedule — projects the subsidy emission curve FORWARD from
#                     genesis params alone (no snapshot; reports cumulative /
#                     drain height / projected total supply).
#
# Assertions (~30):
#   1.  Global help mentions subsidy-schedule.
#   2.  subsidy-schedule --help exits 0.
#   3.  Unknown CLI arg: exit 1.
#   4.  Missing --block-subsidy: exit 1.
#   5.  Missing --to-height: exit 1.
#   6.  Non-decimal --block-subsidy: exit 1.
#   7.  to-height < from-height: exit 1.
#   8-9.  Perpetual (P==0): cumulative == S*blocks, perpetual flag true.
#   10. Perpetual: drains == false.
#   11-13. Finite fund exact multiple (P = S*n): cumulative caps at P,
#          drain_height correct, final_partial == S.
#   14-16. Finite fund with partial tail (P not a multiple of S): cumulative,
#          drain_height, final_partial == tail.
#   17. Finite fund, horizon SHORTER than drain: cumulative == S*blocks (no cap).
#   18. Finite fund, horizon LONGER than drain: cumulative caps at remaining.
#   19. --from-accumulated reduces the remaining fund (drain sooner).
#   20. Zero subsidy (S=0) with finite fund: cumulative 0, drains false.
#   21. projected_total_supply == genesis_total + cumulative.
#   22. pool_remaining at horizon == P - accumulated (finite).
#   23. perpetual pool_remaining reported as "unlimited".
#   24. overflows_u64 flag set for a huge perpetual projection.
#   25. overflows_u64 false for a small projection.
#   26. --json shape: all required keys present.
#   27. Text-mode cumulative == JSON-mode cumulative.
#   28. Determinism: two invocations give identical JSON.
#   29. drain_height == from_height + drain_in_blocks (finite).
#   30. accumulated_subsidy_at_horizon == from_accumulated + cumulative.
#
# Run from repo root: bash tools/test_wallet_subsidy_schedule.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

field() {  # field <json> <key>
  echo "$1" | $PY -c "import json,sys; print(json.loads(sys.stdin.read()).get('$2',''))"
}

# ── Independent reference computation (Python, mirrors src/ subsidy rule) ────
# Prints: cumulative drains drain_height drain_in_blocks final_partial
#         accum_horizon total_supply overflows_u64
ref() {  # ref <S> <from> <to> <from_accum> <pool> <genesis>
  $PY - "$@" <<'PYEOF'
import sys
S=int(sys.argv[1]); frm=int(sys.argv[2]); to=int(sys.argv[3])
A=int(sys.argv[4]); P=int(sys.argv[5]); G=int(sys.argv[6])
blocks = to - frm
perpetual = (P == 0)
drains=False; drain_h=0; drain_b=0; final_partial=0
if perpetual:
    cumulative = S * blocks
else:
    remaining = P - A if P > A else 0
    if S == 0:
        cumulative = 0
    else:
        full = remaining // S
        tail = remaining % S
        full_in_window = min(full, blocks)
        cumulative = S * full_in_window
        if tail != 0 and blocks > full:
            cumulative += tail
        total_paying = full + (1 if tail != 0 else 0)
        drains = True
        drain_b = total_paying
        drain_h = frm + total_paying
        final_partial = tail if tail != 0 else (S if full != 0 else 0)
accum_h = A + cumulative
total = G + cumulative
U64 = (1 << 64) - 1
ov = (cumulative > U64) or (accum_h > U64) or (total > U64)
print(f"{cumulative} {str(drains).lower()} {drain_h} {drain_b} {final_partial} {accum_h} {total} {str(ov).lower()}")
PYEOF
}

echo "=== 1. Global help mentions subsidy-schedule ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "subsidy-schedule" "help mentions subsidy-schedule"

echo
echo "=== 2. subsidy-schedule --help exits 0 ==="
set +e
"$WALLET" subsidy-schedule --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "subsidy-schedule --help exits 0"

echo
echo "=== 3. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" subsidy-schedule --block-subsidy 10 --to-height 5 --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 4. Missing --block-subsidy: exit 1 ==="
set +e
"$WALLET" subsidy-schedule --to-height 5 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --block-subsidy returns 1"

echo
echo "=== 5. Missing --to-height: exit 1 ==="
set +e
"$WALLET" subsidy-schedule --block-subsidy 10 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --to-height returns 1"

echo
echo "=== 6. Non-decimal --block-subsidy: exit 1 ==="
set +e
"$WALLET" subsidy-schedule --block-subsidy 0xA --to-height 5 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "non-decimal block-subsidy returns 1"

echo
echo "=== 7. to-height < from-height: exit 1 ==="
set +e
"$WALLET" subsidy-schedule --block-subsidy 10 --from-height 8 --to-height 5 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "to < from returns 1"

echo
echo "=== 8-10. Perpetual (P==0): cumulative == S*blocks ==="
read -r R_CUM R_DRN R_DH R_DB R_FP R_AH R_TS R_OV <<<"$(ref 10 0 1000 0 0 0)"
J=$("$WALLET" subsidy-schedule --block-subsidy 10 --to-height 1000 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" cumulative_subsidy_at_horizon)" "$R_CUM" "perpetual cumulative == $R_CUM"
assert_eq "$(field "$J" perpetual)"                     "True"   "perpetual flag true"
assert_eq "$(field "$J" drains)"                        "$R_DRN" "perpetual drains == $R_DRN"

echo
echo "=== 11-13. Finite fund, exact multiple (P = S*n) ==="
# S=100, P=1000 -> 10 full blocks, drain at height 10, final_partial == 100.
read -r R_CUM R_DRN R_DH R_DB R_FP R_AH R_TS R_OV <<<"$(ref 100 0 50 0 1000 0)"
J=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 50 --pool-initial 1000 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" cumulative_subsidy_at_horizon)" "$R_CUM" "exact-mult cumulative caps at $R_CUM"
assert_eq "$(field "$J" drain_height)"                  "$R_DH"  "exact-mult drain_height == $R_DH"
assert_eq "$(field "$J" final_partial_subsidy)"         "$R_FP"  "exact-mult final_partial == $R_FP"

echo
echo "=== 14-16. Finite fund, partial tail (P not a multiple of S) ==="
# S=100, P=1050 -> 10 full + 1 tail(50), drain at height 11, final_partial==50.
read -r R_CUM R_DRN R_DH R_DB R_FP R_AH R_TS R_OV <<<"$(ref 100 0 50 0 1050 0)"
J=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 50 --pool-initial 1050 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" cumulative_subsidy_at_horizon)" "$R_CUM" "tail cumulative == $R_CUM"
assert_eq "$(field "$J" drain_height)"                  "$R_DH"  "tail drain_height == $R_DH"
assert_eq "$(field "$J" final_partial_subsidy)"         "$R_FP"  "tail final_partial == $R_FP (tail)"

echo
echo "=== 17. Finite fund, horizon SHORTER than drain (no cap) ==="
# S=100, P=100000 (drains at 1000), horizon 5 blocks -> cumulative == 500.
read -r R_CUM R_DRN R_DH R_DB R_FP R_AH R_TS R_OV <<<"$(ref 100 0 5 0 100000 0)"
J=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 5 --pool-initial 100000 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" cumulative_subsidy_at_horizon)" "$R_CUM" "short-horizon cumulative == $R_CUM (no cap)"

echo
echo "=== 18. Finite fund, horizon LONGER than drain (caps at remaining) ==="
# S=100, P=550 -> remaining caps cumulative at 550 over a 100-block horizon.
read -r R_CUM R_DRN R_DH R_DB R_FP R_AH R_TS R_OV <<<"$(ref 100 0 100 0 550 0)"
J=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 100 --pool-initial 550 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" cumulative_subsidy_at_horizon)" "$R_CUM" "long-horizon cumulative caps at $R_CUM"

echo
echo "=== 19. --from-accumulated reduces the fund (drains sooner) ==="
# S=100, P=1000, A=400 -> remaining 600 -> 6 full blocks, drain_height 6.
read -r R_CUM R_DRN R_DH R_DB R_FP R_AH R_TS R_OV <<<"$(ref 100 0 50 400 1000 0)"
J=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 50 --from-accumulated 400 --pool-initial 1000 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" cumulative_subsidy_at_horizon)" "$R_CUM" "from-accum cumulative == $R_CUM"
assert_eq "$(field "$J" drain_height)"                  "$R_DH"  "from-accum drain_height == $R_DH"

echo
echo "=== 20. Zero subsidy with finite fund: cumulative 0, drains false ==="
J=$("$WALLET" subsidy-schedule --block-subsidy 0 --to-height 100 --pool-initial 1000 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" cumulative_subsidy_at_horizon)" "0"     "S=0 cumulative == 0"
assert_eq "$(field "$J" drains)"                        "False" "S=0 drains false"

echo
echo "=== 21. projected_total_supply == genesis_total + cumulative ==="
read -r R_CUM R_DRN R_DH R_DB R_FP R_AH R_TS R_OV <<<"$(ref 10 0 100 0 0 5000)"
J=$("$WALLET" subsidy-schedule --block-subsidy 10 --to-height 100 --genesis-total 5000 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" projected_total_supply)" "$R_TS" "projected_total_supply == $R_TS"

echo
echo "=== 22. pool_remaining at horizon (finite) ==="
# S=100, P=2000, horizon 5 -> minted 500 -> remaining 1500.
read -r R_CUM R_DRN R_DH R_DB R_FP R_AH R_TS R_OV <<<"$(ref 100 0 5 0 2000 0)"
J=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 5 --pool-initial 2000 --json 2>&1 | tr -d '\r')
EXP_REM=$((2000 - R_CUM))
assert_eq "$(field "$J" pool_remaining_at_horizon)" "$EXP_REM" "pool_remaining == $EXP_REM"

echo
echo "=== 23. perpetual pool_remaining reported as unlimited ==="
J=$("$WALLET" subsidy-schedule --block-subsidy 10 --to-height 100 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" pool_remaining_at_horizon)" "unlimited" "perpetual pool_remaining == unlimited"

echo
echo "=== 24. overflows_u64 set for a huge perpetual projection ==="
# S = ~1.8e10, blocks = ~1.8e10 -> product ~3.4e20 > 2^64 (~1.8e19).
J=$("$WALLET" subsidy-schedule --block-subsidy 18446744073 --to-height 18446744073 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" overflows_u64)" "True" "huge projection sets overflows_u64"

echo
echo "=== 25. overflows_u64 false for a small projection ==="
J=$("$WALLET" subsidy-schedule --block-subsidy 10 --to-height 1000 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" overflows_u64)" "False" "small projection overflows_u64 false"

echo
echo "=== 26. --json shape: all required keys present ==="
J=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 50 --pool-initial 1050 --genesis-total 1 --json 2>&1 | tr -d '\r')
PARSED_OK=$(echo "$J" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
keys = ('block_subsidy','from_height','to_height','blocks_projected',
        'from_accumulated','pool_initial','perpetual','subsidy_per_block_now',
        'cumulative_subsidy_at_horizon','accumulated_subsidy_at_horizon',
        'pool_remaining_at_horizon','drains','paying_blocks_in_window',
        'genesis_total','projected_total_supply','overflows_u64')
print('yes' if all(k in d for k in keys) else 'no')
" 2>/dev/null || echo "no")
assert_eq "$PARSED_OK" "yes" "--json has all required keys"

echo
echo "=== 27. Text-mode cumulative == JSON-mode cumulative ==="
TEXT_CUM=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 50 --pool-initial 1050 2>&1 \
  | tr -d '\r' | grep '^  cumulative_subsidy:' | awk '{print $2}')
JSON_CUM=$(field "$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 50 --pool-initial 1050 --json 2>&1 | tr -d '\r')" cumulative_subsidy_at_horizon)
assert_eq "$TEXT_CUM" "$JSON_CUM" "text-mode cumulative == JSON-mode cumulative"

echo
echo "=== 28. Determinism: two invocations identical ==="
R1=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 50 --from-accumulated 400 --pool-initial 1050 --genesis-total 9 --json 2>&1 | tr -d '\r')
R2=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 50 --from-accumulated 400 --pool-initial 1050 --genesis-total 9 --json 2>&1 | tr -d '\r')
assert_eq "$R1" "$R2" "two invocations give identical JSON"

echo
echo "=== 29. drain_height == from_height + drain_in_blocks (finite) ==="
J=$("$WALLET" subsidy-schedule --block-subsidy 100 --from-height 7 --to-height 100 --pool-initial 1050 --json 2>&1 | tr -d '\r')
DH=$(field "$J" drain_height)
DB=$(field "$J" drain_in_blocks)
assert_eq "$DH" "$((7 + DB))" "drain_height == from_height + drain_in_blocks"

echo
echo "=== 30. accumulated_subsidy_at_horizon == from_accumulated + cumulative ==="
read -r R_CUM R_DRN R_DH R_DB R_FP R_AH R_TS R_OV <<<"$(ref 100 0 50 400 1050 0)"
J=$("$WALLET" subsidy-schedule --block-subsidy 100 --to-height 50 --from-accumulated 400 --pool-initial 1050 --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" accumulated_subsidy_at_horizon)" "$R_AH" "accumulated_at_horizon == $R_AH"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
