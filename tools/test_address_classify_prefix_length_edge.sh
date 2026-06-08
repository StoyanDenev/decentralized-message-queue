#!/usr/bin/env bash
# determ-wallet address-classify — S-028 PREFIX-CASE + LENGTH-BOUNDARY edge test.
#
# The existing classify tests (test_wallet_address_classify.sh,
# test_address_classify_fuzz.sh) cover canonical/mixed-case anon, domain,
# empty, grossly-short "0xabc", and non-hex-tail. They DO NOT pin two
# subtle S-028 disambiguation boundaries that a case-folding or off-by-one
# regression could silently flip:
#
#   A. PREFIX CASE-SENSITIVITY. is_anon_address (include/determ/types.hpp
#      L117) and the wallet's re-statement (wallet/main.cpp L13583,
#      `s[0] != '0' || s[1] != 'x'`) require a *lowercase* "0x" prefix.
#      An uppercase-X paste "0X"+64hex is therefore NOT an anon attempt:
#      looks_like_anon_attempt (wallet/main.cpp L13606-13608) also keys on
#      lowercase 0x, so the string falls through to the DOMAIN branch and
#      passes through verbatim (canonical == input, submit_tx_ok=true,
#      exit 0). This matches the chain's own "not the unique 0x+64-hex
#      shape => domain" rule. A regression that case-folded the prefix
#      check would either (a) admit "0X..." as anon and fragment a bearer
#      wallet across an "0x"/"0X" key split, or (b) mis-flag it invalid.
#      Pinning kind==domain + verbatim canonical fences both.
#
#   B. LENGTH OFF-BY-ONE around the size()==66 gate. is_anon requires
#      EXACTLY 66 chars (wallet/main.cpp L13582). The existing suite only
#      exercises a grossly-short "0xabc" (5 chars); it never pins the
#      one-over (0x + 65 hex = 67 total) or one-under (0x + 63 hex = 65
#      total) boundary. Both are still 0x-led, so looks_like_anon_attempt
#      is true => both must classify "invalid" (NOT domain) with exit 2.
#      A `<=`/`>=` slip or a `!= 66` -> `< 66` regression would leak the
#      67-char form through as domain or as anon. Pinning kind==invalid +
#      exit 2 at both ±1 boundaries fences the gate on both sides.
#
# Happy-path control: a canonical lowercase "0x"+64hex anon (exit 0,
# kind==anon) and a plain domain (exit 0, kind==domain) — proves the
# command isn't simply rejecting everything.
#
# Pure OFFLINE string work — no SHA-256, no RPC, no daemon, no network,
# no @file. Cluster-free, no temp dir to clean (only a throwaway keyfile
# under a self-made tmp dir for the canonical control address).
#
# Differentiation vs sibling tests:
#   * test_wallet_address_classify.sh — canonical/mixed anon, domain,
#       empty, "0xabc" too-short, non-hex tail, batch/JSON/@file. Does
#       NOT touch uppercase "0X" prefix NOR the exact ±1 length boundary.
#   * test_address_classify_fuzz.sh   — fixed-seed truth-table fuzz;
#       invalid cases use LOWERCASE 0x + truncation(drop 1-10) or non-hex
#       corruption only. Never an uppercase-X prefix; never a one-OVER
#       (67-char) length.
#
# Assertions (8):
#   1. Control: canonical lowercase anon -> kind=anon, exit 0.
#   2. Control: plain domain -> kind=domain, exit 0.
#   3. Uppercase "0X"+64hex -> kind=domain (NOT anon, NOT invalid).
#   4. Uppercase "0X"+64hex -> canonical == input verbatim, exit 0.
#   5. Uppercase "0X"+64hex -> submit_tx_ok=true (domains pass the gate).
#   6. 0x + 65 hex (67 total, one OVER) -> kind=invalid, exit 2.
#   7. 0x + 63 hex (65 total, one UNDER) -> kind=invalid, exit 2.
#   8. Non-0x 66-char string ("ab"+64hex) -> kind=domain (size match but
#      wrong prefix is NOT an anon attempt).
#
# Run from repo root: bash tools/test_address_classify_prefix_length_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_address_classify_prefix_length_edge.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

PY=python
command -v python >/dev/null 2>&1 || PY=python3

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}

# jq-free field extractor (python json over single-result --json output).
field() {  # $1 = json, $2 = key in results[0]
  echo "$1" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['$2'])"
}

# ── Build a real canonical lowercase anon address from the wallet ──────────
# (the command's own account generator is the only ground-truth source —
#  no algorithm re-implementation.)
"$WALLET" account-create-batch --count 1 --out "$TMP/k.json" >/dev/null 2>&1
ADDR=$($PY -c "import json; print(json.load(open('$TMP/k.json'))['accounts'][0]['address'])")
TAIL="${ADDR:2}"                       # 64 lowercase hex chars

# Derived probe strings.
ADDR_UPPER_X="0X$TAIL"                  # uppercase prefix, lowercase tail
ADDR_67="0x${TAIL}f"                    # 0x + 65 hex = 67 total (one OVER)
ADDR_65="0x${TAIL:0:63}"               # 0x + 63 hex = 65 total (one UNDER)
ADDR_NO0X="ab${TAIL}"                  # 66 chars, hex tail, but no 0x prefix

# run_json IDENTIFIER -> populates globals OUT (JSON string) and RC (exit
# code). Defined as a plain block (not a $(...) subshell) so the captured
# exit code is visible to the caller. We write the JSON to a temp file and
# read it back, keeping the wallet's real exit code in RC via PIPESTATUS.
run_json() {  # $1 = identifier
  set +e
  "$WALLET" address-classify --address "$1" --json 2>/dev/null \
    | tr -d '\r' > "$TMP/out.json"
  RC=${PIPESTATUS[0]}
  set -e
  OUT=$(cat "$TMP/out.json")
}

echo "=== 1. Control: canonical lowercase anon -> anon, exit 0 ==="
run_json "$ADDR"
assert_eq "$RC" "0" "control canonical anon exit 0"
assert_eq "$(field "$OUT" kind)" "anon" "control canonical anon kind=anon"

echo
echo "=== 2. Control: plain domain -> domain, exit 0 ==="
run_json "alice.validator"
assert_eq "$RC" "0" "control domain exit 0"
assert_eq "$(field "$OUT" kind)" "domain" "control domain kind=domain"

echo
echo "=== 3-5. Uppercase '0X' prefix -> DOMAIN (case-sensitive prefix gate) ==="
run_json "$ADDR_UPPER_X"
assert_eq "$RC" "0" "0X-prefix exit 0 (classified, not invalid)"
assert_eq "$(field "$OUT" kind)" "domain" "0X-prefix kind=domain (NOT anon, NOT invalid)"
assert_eq "$(field "$OUT" canonical)" "$ADDR_UPPER_X" "0X-prefix canonical == input verbatim (no normalization)"
assert_eq "$(field "$OUT" submit_tx_ok)" "True" "0X-prefix submit_tx_ok=true (domain passes strict gate)"

echo
echo "=== 6. 0x + 65 hex (67 total, one OVER) -> invalid, exit 2 ==="
run_json "$ADDR_67"
assert_eq "$RC" "2" "67-char (one OVER) exit 2"
assert_eq "$(field "$OUT" kind)" "invalid" "67-char (one OVER) kind=invalid"

echo
echo "=== 7. 0x + 63 hex (65 total, one UNDER) -> invalid, exit 2 ==="
run_json "$ADDR_65"
assert_eq "$RC" "2" "65-char (one UNDER) exit 2"
assert_eq "$(field "$OUT" kind)" "invalid" "65-char (one UNDER) kind=invalid"

echo
echo "=== 8. Non-0x 66-char string ('ab'+64hex) -> domain (wrong prefix) ==="
run_json "$ADDR_NO0X"
assert_eq "$RC" "0" "66-char non-0x exit 0"
assert_eq "$(field "$OUT" kind)" "domain" "66-char non-0x kind=domain (size match, wrong prefix => not anon attempt)"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
