#!/usr/bin/env bash
# determ-wallet address-classify CLI test.
#
# Exercises the OFFLINE account-identifier classifier + S-028 canonicalizer:
# given anon bearer addresses ("0x"+64 hex) and/or domain names, report the
# kind (anon|domain|invalid), the S-028 canonical form, whether the input was
# already canonical (the submit_tx anon strict gate), and the derived Ed25519
# pubkey for anon addresses. Pure local string work — no SHA-256, no RPC, no
# daemon (only reads an @file when one is given). Cluster-free.
#
# Differentiation vs sibling commands:
#   * shard-route        — maps an address to its OWNING shard (SHA-256 +
#                          modulo over the genesis salt); does NOT classify
#                          or canonicalize.
#   * sign-anon-tx       — PRODUCES a signed TRANSFER from an anon keyfile;
#                          rejects a non-canonical --to but emits nothing for
#                          a screening-only workflow.
#   * validate-tx        — full composite gate over a SIGNED envelope.
#   * address-classify   — classify + canonicalize one or many bare
#                          identifiers; no keys, no signing, no envelope.
#
# Reproduces is_anon_address / normalize_anon_address (include/determ/
# types.hpp) byte-for-byte: anon = "0x"+64 hex (case-insensitive on input),
# canonical = lowercase tail; a malformed 0x-attempt or empty id is "invalid";
# everything else is a domain.
#
# Assertions (~28):
#   1.  Global help mentions address-classify.
#   2.  address-classify --help exits 0.
#   3.  No identifier supplied: exit 1.
#   4.  Unknown CLI arg: exit 1.
#   5.  --addresses @nonexistent-file: exit 1.
#   6.  Single canonical anon: exit 0, kind=anon, changed=false.
#   7.  Single anon: pubkey_hex equals the address tail.
#   8.  Single anon: submit_tx_ok=true (already canonical).
#   9.  Mixed-case anon: exit 0 (single id, kind anon — valid).
#  10.  Mixed-case anon: canonical is fully lowercase.
#  11.  Mixed-case anon: changed=true.
#  12.  Mixed-case anon: submit_tx_ok=false (strict-reject signal).
#  13.  Mixed-case anon canonical == lowercased input tail.
#  14.  Single domain: exit 0, kind=domain.
#  15.  Single domain: canonical == input (verbatim), submit_tx_ok=true.
#  16.  Single domain: no pubkey_hex field.
#  17.  Malformed 0x (too short): kind=invalid, exit 2.
#  18.  Malformed 0x (non-hex tail): kind=invalid, exit 2.
#  19.  Empty identifier (--address ""): kind=invalid, exit 2.
#  20.  Single id + --json emits parseable JSON with count + results + summary.
#  21.  Multi-id auto-enables JSON (count==3).
#  22.  Multi-id summary tallies anon/domain/invalid correctly.
#  23.  Multi-id summary changed + submit_tx_ok counts.
#  24.  Multi-id results preserve input order.
#  25.  --addresses comma list parses (count==2).
#  26.  --addresses @file parses, skips blank + # lines (count==2).
#  27.  Mixed --address + --addresses combine (count==3).
#  28.  All-valid batch (anon + domain, none invalid): exit 0.
#
# Run from repo root: bash tools/test_wallet_address_classify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_address_classify.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

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

# Generate two fresh anon addresses (canonical lowercase, "0x"+64 hex).
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][1]['address'])")
# Mixed-case spelling of ADDR_A: upper-case the hex tail.
ADDR_A_UPPER="0x$(echo "${ADDR_A:2}" | tr 'a-f' 'A-F')"
TAIL_A="${ADDR_A:2}"

echo "=== 1. Global help mentions address-classify ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "address-classify"; then
  echo "  PASS: help mentions address-classify"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing address-classify"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. address-classify --help exits 0 ==="
set +e
"$WALLET" address-classify --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "address-classify --help exits 0"

echo
echo "=== 3. No identifier supplied: exit 1 ==="
set +e
"$WALLET" address-classify >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "no identifier returns 1"

echo
echo "=== 4. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" address-classify --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 5. --addresses @nonexistent file: exit 1 ==="
set +e
"$WALLET" address-classify --addresses "@$TMP/no_such_file.txt" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "nonexistent @file returns 1"

echo
echo "=== 6-8. Single canonical anon ==="
set +e
OUT_A=$("$WALLET" address-classify --address "$ADDR_A" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "single canonical anon returns 0"
KIND_A=$(echo "$OUT_A" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['kind'])")
assert_eq "$KIND_A" "anon" "single anon: kind=anon"
CHG_A=$(echo "$OUT_A" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['changed'])")
assert_eq "$CHG_A" "False" "single canonical anon: changed=false"
PUB_A=$(echo "$OUT_A" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['pubkey_hex'])")
assert_eq "$PUB_A" "$TAIL_A" "single anon: pubkey_hex equals address tail"
SUB_A=$(echo "$OUT_A" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['submit_tx_ok'])")
assert_eq "$SUB_A" "True" "single canonical anon: submit_tx_ok=true"

echo
echo "=== 9-13. Mixed-case anon ==="
set +e
OUT_U=$("$WALLET" address-classify --address "$ADDR_A_UPPER" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "mixed-case anon returns 0 (valid)"
KIND_U=$(echo "$OUT_U" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['kind'])")
assert_eq "$KIND_U" "anon" "mixed-case: kind=anon"
CANON_U=$(echo "$OUT_U" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['canonical'])")
assert_eq "$CANON_U" "$ADDR_A" "mixed-case: canonical lowercases tail to ADDR_A"
CHG_U=$(echo "$OUT_U" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['changed'])")
assert_eq "$CHG_U" "True" "mixed-case: changed=true"
SUB_U=$(echo "$OUT_U" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['submit_tx_ok'])")
assert_eq "$SUB_U" "False" "mixed-case: submit_tx_ok=false (strict-reject signal)"

echo
echo "=== 14-16. Single domain ==="
set +e
OUT_D=$("$WALLET" address-classify --address "alice.validator" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "single domain returns 0"
KIND_D=$(echo "$OUT_D" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['kind'])")
assert_eq "$KIND_D" "domain" "single domain: kind=domain"
CANON_D=$(echo "$OUT_D" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['canonical'])")
assert_eq "$CANON_D" "alice.validator" "single domain: canonical == input (verbatim)"
HAS_PUB_D=$(echo "$OUT_D" | $PY -c "import json,sys; print('yes' if 'pubkey_hex' in json.loads(sys.stdin.read())['results'][0] else 'no')")
assert_eq "$HAS_PUB_D" "no" "single domain: no pubkey_hex field"

echo
echo "=== 17. Malformed 0x (too short): invalid, exit 2 ==="
set +e
OUT_S=$("$WALLET" address-classify --address "0xabc" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "too-short 0x returns 2"
KIND_S=$(echo "$OUT_S" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['kind'])")
assert_eq "$KIND_S" "invalid" "too-short 0x: kind=invalid"

echo
echo "=== 18. Malformed 0x (non-hex tail): invalid, exit 2 ==="
BAD_HEX="0x${TAIL_A:0:63}z"   # 64-char tail but last char is non-hex
set +e
OUT_NH=$("$WALLET" address-classify --address "$BAD_HEX" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "non-hex tail returns 2"
KIND_NH=$(echo "$OUT_NH" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['kind'])")
assert_eq "$KIND_NH" "invalid" "non-hex tail: kind=invalid"

echo
echo "=== 19. Empty identifier: invalid, exit 2 ==="
set +e
OUT_E=$("$WALLET" address-classify --address "" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "empty identifier returns 2"
KIND_E=$(echo "$OUT_E" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['results'][0]['kind'])")
assert_eq "$KIND_E" "invalid" "empty identifier: kind=invalid"

echo
echo "=== 20. Single id + --json: parseable, has count + results + summary ==="
SHAPE_OK=$(echo "$OUT_A" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
ok = ('count' in d) and ('results' in d) and ('summary' in d)
print('yes' if ok else 'no')
")
assert_eq "$SHAPE_OK" "yes" "--json has count + results + summary"

echo
echo "=== 21-24. Multi-id (auto JSON): order + tallies ==="
set +e
OUT_M=$("$WALLET" address-classify \
  --address "$ADDR_A" --address "bob.v" --address "0xabc" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "multi-id with one invalid returns 2"
CNT_M=$(echo "$OUT_M" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['count'])")
assert_eq "$CNT_M" "3" "multi-id auto-JSON: count==3"
TALLY_OK=$(echo "$OUT_M" | $PY -c "
import json,sys
s = json.loads(sys.stdin.read())['summary']
ok = (s['anon']==1) and (s['domain']==1) and (s['invalid']==1)
print('yes' if ok else 'no')
")
assert_eq "$TALLY_OK" "yes" "multi-id summary: anon=1 domain=1 invalid=1"
COUNT_OK=$(echo "$OUT_M" | $PY -c "
import json,sys
s = json.loads(sys.stdin.read())['summary']
# canonical anon (not changed) + domain are submit_tx_ok; invalid is not.
ok = (s['changed']==0) and (s['submit_tx_ok']==2)
print('yes' if ok else 'no')
")
assert_eq "$COUNT_OK" "yes" "multi-id summary: changed=0 submit_tx_ok=2"
ORDER_OK=$(echo "$OUT_M" | $PY -c "
import json,sys
r = json.loads(sys.stdin.read())['results']
ok = (r[0]['input']=='$ADDR_A') and (r[1]['input']=='bob.v') and (r[2]['input']=='0xabc')
print('yes' if ok else 'no')
")
assert_eq "$ORDER_OK" "yes" "multi-id results preserve input order"

echo
echo "=== 25. --addresses comma list parses (count==2) ==="
set +e
OUT_C=$("$WALLET" address-classify --addresses "$ADDR_A,carol.v" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "comma list (both valid) returns 0"
CNT_C=$(echo "$OUT_C" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['count'])")
assert_eq "$CNT_C" "2" "comma list: count==2"

echo
echo "=== 26. --addresses @file parses, skips blank + # lines (count==2) ==="
printf '%s\n\n# a comment\n%s\n' "$ADDR_A" "$ADDR_B" > "$TMP/list.txt"
set +e
OUT_F=$("$WALLET" address-classify --addresses "@$TMP/list.txt" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "@file (both anon) returns 0"
CNT_F=$(echo "$OUT_F" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['count'])")
assert_eq "$CNT_F" "2" "@file: blank + # lines skipped, count==2"

echo
echo "=== 27. Mixed --address + --addresses combine (count==3) ==="
set +e
OUT_MIX=$("$WALLET" address-classify --address "$ADDR_A" \
  --addresses "dave.v,erin.v" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "mixed --address + --addresses returns 0"
CNT_MIX=$(echo "$OUT_MIX" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['count'])")
assert_eq "$CNT_MIX" "3" "mixed sources: count==3"

echo
echo "=== 28. All-valid batch (anon + domain, none invalid): exit 0 ==="
set +e
"$WALLET" address-classify --address "$ADDR_A" --address "$ADDR_B" \
  --address "frank.v" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "all-valid batch returns 0"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
