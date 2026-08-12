#!/usr/bin/env bash
# determ-wallet verify-equivocation — OFFLINE FA6 equivocation-evidence
# verifier (the EquivocationEvent two-sig proof, EQV-height-bind form).
#
# An EquivocationEvent records that ONE registered Ed25519 key double-signed
# at ONE height — the unambiguous proof the chain slashes the equivocator's
# full stake on. The event carries per-side OPENINGS (index, body_root) of
# two-level digests; each signed digest is DERIVED as
#   SHA256(TAG || index u64 BE || body_root),
#   TAG = "DTM-BLKDIG-v2" (kind 0) / "DTM-CONTRIB-v2" (kind 1).
# This command reproduces src/node/validator.cpp::check_equivocation_events
# byte-for-byte:
#   (1) kind <= 1
#   (2) index_a == index_b == block_index   (the height bind)
#   (3) body_root_a != body_root_b
#   (4) sig_a != sig_b
#   (5) sig_a verifies over the DERIVED digest_a against --pubkey
#   (6) sig_b verifies over the DERIVED digest_b against --pubkey
# PROVEN ⟺ all hold.
#
# Daemon-free AND runtime-crypto-free: the evidence is a FIXED, DETERMINISTIC
# Ed25519 fixture (seed = 0x00..0x1f; body roots = SHA256 of fixed strings;
# sigs over the composed digests) generated once and baked in — reproducible
# on any host, no Python crypto backend needed. The wallet verifies with its
# own linked backend, so a passing PROVEN run is a genuine cross-tool check.
#
# Assertions:
#   1.  Help mentions verify-equivocation + the height-bound condition rule.
#   2.  Happy path: genuine two-sig evidence → PROVEN + exit 0.
#   3.  JSON output is well-formed and carries every expected field.
#   4.  Tamper sig_a (single hex flip) → NOT PROVEN, exit 2, sig_a_valid=false.
#   5.  Wrong --pubkey (a second key) → NOT PROVEN, exit 2 (both sigs fail).
#  5b.  (EQV-height-bind) --index-b 8 with a REAL sig composed at height 8 →
#       NOT PROVEN, exit 2, heights_match=false — the cross-height forged-
#       slash replay is refused offline too.
#   6.  Same body root twice (same signed opening) → NOT PROVEN, exit 2,
#       distinct_body_roots=false (the "signer signed the same thing twice"
#       non-equivocation case the validator explicitly rejects).
#   7.  Identical (root,sig) on both sides → NOT PROVEN, exit 2,
#       distinct_sigs=false.
#   8.  --event with a bare EquivocationEvent JSON → PROVEN + echoes
#       equivocator metadata.
#   9.  --event with a Block JSON (equivocation_events[0]) → PROVEN.
#  10.  --event with --index selecting the second event → PROVEN.
#  11.  --event out-of-range --index → exit 1 (operator error, not auth).
#  12.  Missing --pubkey → exit 1 (key is ALWAYS operator-supplied).
#  13.  --event mutually exclusive with inline evidence args → exit 1.
#  14.  Wrong-length --sig-a (hex) → exit 1 (args), not 2 (auth).
#  15.  Non-hex --body-root-a → exit 1.
#  16.  Missing --event file → exit 1.
#
# Run from repo root: bash tools/test_wallet_verify_equivocation.sh
set -u
# pipefail so `OUT=$(cmd | tr -d '\r'); RC=$?` propagates the wallet's exit
# code (2 / 1) rather than always reporting tr's success.
set -o pipefail
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_verify_equivocation.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  # NOTE: no `grep -q` here — with `set -o pipefail`, -q exits on first match
  # and the (large) echo upstream dies of SIGPIPE, turning a MATCH into exit
  # 141. Plain grep drains its whole input, so the pipeline status is grep's.
  if echo "$1" | grep -- "$2" >/dev/null; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ── Fixed deterministic Ed25519 fixture (seed = 0x00..0x1f) ──────────────────
# PUB_A = the equivocator's key; PUB_B = an unrelated key (seed XOR 0xff) for
# the wrong-key negative. Body roots = SHA256 of fixed strings; every sig is
# over the DERIVED digest SHA256("DTM-BLKDIG-v2" || height u64 BE || root).
PUB_A="03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
PUB_B="bafc71bead3ac5e4b63e9c8216ee71a34aaec65722eedbca728b4e9b3ccce396"
# Height-7 pair (roots = SHA256("light-verify-equivocation-A"/"-B")).
ROOT_A="03d70ec7e6f3721b9c82c77ea10b47186daa14273b823d417323b9a1e73c5d4e"
SIG_A="06ba2eeab0eee85183f54127a4d83901f7f3f8ea5be08ffd12aef5b27a486d21db74f72949eeb7dc161687e079b2ff1c89f3d9b9b974f4224d363f65a0d7c102"
ROOT_B="d3672c9732c2ab1d3e273f5cd639b4177a73b8ad2bb36d0b5f8d8b89b2a681d0"
SIG_B="828bc27427e5c842e86d633cb7c69439bd15ffacf5517cb583d7b26cffc6c7da1bb673a8cefd2c675abd9254118c9777deaf82afb5362d6621efca68e2213208"
# A REAL signature over compose(8, ROOT_B) — genuinely signed at the WRONG
# height, for the height-mismatch leg (5b).
SIG_B_H8="4f84d509419d0e7f7b22cd12659cb09db2931cc896eb43bd5721e1879605726038bf3f65624c933f401d87b486fbfacc2da8499ab01c66fc029300cc50046001"
# Height-9 pair (roots = SHA256("wallet-verify-equivocation-C"/"-D")) for the
# --index leg.
ROOT_C="52ac0d208caf36efa2a4299e7fd2495b5fb2b9869391968c303b73748f7f9953"
SIG_C="2962382d7e2207d12d5096be3d7e06d32a4625ce492db84253a780f6b1971a020356f674e559c47ac620880dc5b851b9050550b8b72ac05080ccf2ae92af1807"
ROOT_D="73d7fee2b1af598e52924b941ebd3dcc69abaf17cc37841c317993f4130e425d"
SIG_D="09b8cb97167b1fb6630fdd4d05c888f692605d8f034bbdc09bb0e0d06a51cd29b934976163745f4b8bedc10b75d71805837d7eea147c0ad1259509e830b2de05"

# verify_inline <root_a> <sig_a> <root_b> <sig_b> [extra args...]
verify_inline() {
  local ra="$1" sa="$2" rb="$3" sb="$4"; shift 4
  "$WALLET" verify-equivocation --pubkey "$PUB_A" \
      --kind 0 --block-index 7 \
      --index-a 7 --body-root-a "$ra" --sig-a "$sa" \
      --index-b 7 --body-root-b "$rb" --sig-b "$sb" "$@" 2>&1 | tr -d '\r'
}

echo "=== 1. Help mentions verify-equivocation + the height-bound rule ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "verify-equivocation"               "help lists verify-equivocation"
assert_contains "$H" "body_root_a!=body_root_b"          "help states the distinct-root condition"
assert_contains "$H" "index_a==index_b==block_index"     "help states the height-bind condition"
assert_contains "$H" "check_equivocation_events"         "help cites the validator gate it mirrors"

echo
echo "=== 2. Happy path: genuine two-sig evidence → PROVEN, exit 0 ==="
OUT=$(verify_inline "$ROOT_A" "$SIG_A" "$ROOT_B" "$SIG_B")
RC=$?
assert_eq "$RC" "0" "genuine evidence exits 0"
assert_contains "$OUT" "^PROVEN" "first line reports PROVEN"

echo
echo "=== 3. JSON output shape ==="
JOUT=$(verify_inline "$ROOT_A" "$SIG_A" "$ROOT_B" "$SIG_B" --json)
RC=$?
assert_eq "$RC" "0" "json mode exits 0 on PROVEN"
$PY - <<PY_EOF
import json, sys
r = json.loads('''$JOUT''')
needed = ['proven','kind_known','heights_match','distinct_body_roots',
          'distinct_sigs','sig_a_valid','sig_b_valid','pubkey_hex','kind',
          'block_index','index_a','body_root_a_hex','index_b',
          'body_root_b_hex','derived_digest_a_hex','derived_digest_b_hex']
for k in needed:
    assert k in r, 'missing key: ' + k
assert r['proven'] is True, 'proven should be True'
assert r['kind_known'] is True
assert r['heights_match'] is True
assert r['distinct_body_roots'] is True
assert r['distinct_sigs'] is True
assert r['sig_a_valid'] is True
assert r['sig_b_valid'] is True
assert r['pubkey_hex'].lower() == '$PUB_A'.lower(), 'pubkey echo mismatch'
print('JSON_OK')
PY_EOF
JSON_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$JSON_OK" "true" "json carries {proven,kind_known,heights_match,distinct_body_roots,distinct_sigs,sig_*_valid,pubkey_hex,kind,block_index,index_*,body_root_*_hex,derived_digest_*_hex}"

echo
echo "=== 4. Tamper sig_a → NOT PROVEN, exit 2, sig_a_valid=false ==="
FIRST=${SIG_A:0:1}
case "$FIRST" in
  0) NEW=1;; 1) NEW=2;; 2) NEW=3;; 3) NEW=4;; 4) NEW=5;; 5) NEW=6;;
  6) NEW=7;; 7) NEW=8;; 8) NEW=9;; 9) NEW=a;; a) NEW=b;; b) NEW=c;;
  c) NEW=d;; d) NEW=e;; e) NEW=f;; f) NEW=0;; *) NEW=1;;
esac
SIG_A_BAD="${NEW}${SIG_A:1}"
JOUT=$(verify_inline "$ROOT_A" "$SIG_A_BAD" "$ROOT_B" "$SIG_B" --json)
RC=$?
assert_eq "$RC" "2" "tampered sig_a exits 2 (auth-style alert)"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']      is False, 'proven must be False'
assert r['sig_a_valid'] is False, 'sig_a_valid must be False'
assert r['sig_b_valid'] is True,  'sig_b should still be valid'
print('TAMP_OK')
PY_EOF
TAMP_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$TAMP_OK" "true" "tampered sig_a: proven=false, sig_a_valid=false, sig_b_valid=true"

echo
echo "=== 5. Wrong --pubkey → NOT PROVEN, exit 2 (both sigs fail) ==="
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_B" \
        --kind 0 --block-index 7 \
        --index-a 7 --body-root-a "$ROOT_A" --sig-a "$SIG_A" \
        --index-b 7 --body-root-b "$ROOT_B" --sig-b "$SIG_B" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "2" "wrong pubkey exits 2"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']      is False
assert r['sig_a_valid'] is False
assert r['sig_b_valid'] is False
print('WPK_OK')
PY_EOF
WPK_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$WPK_OK" "true" "wrong pubkey: both sig_*_valid=false"

echo
echo "=== 5b. Cross-height openings (EQV-height-bind) → NOT PROVEN, exit 2 ==="
# --index-b 8 with a REAL signature composed at height 8: kind valid, roots
# distinct, sigs distinct, BOTH sigs verify against their own derived digests
# — ONLY heights_match refuses it. This is the exact cross-height forged-slash
# replay the daemon gate rejects.
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --kind 0 --block-index 7 \
        --index-a 7 --body-root-a "$ROOT_A" --sig-a "$SIG_A" \
        --index-b 8 --body-root-b "$ROOT_B" --sig-b "$SIG_B_H8" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "2" "cross-height openings exit 2 (auth-style alert)"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']        is False, 'proven must be False'
assert r['heights_match'] is False, 'heights_match must be False'
# Every OTHER condition holds — the height bind is the unique refusal.
assert r['kind_known']          is True
assert r['distinct_body_roots'] is True
assert r['distinct_sigs']       is True
assert r['sig_a_valid']         is True, 'sig_a genuinely verifies at height 7'
assert r['sig_b_valid']         is True, 'sig_b genuinely verifies at height 8'
print('XH_OK')
PY_EOF
XH_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$XH_OK" "true" "cross-height: heights_match=false is the sole failing condition (no forged slash)"

echo
echo "=== 6. Same body root twice (same signed opening) → NOT PROVEN ==="
# Re-presenting the SAME signed opening on both sides is the non-equivocation
# case the validator rejects: distinct_body_roots=false even though the sigs
# verify.
JOUT=$(verify_inline "$ROOT_A" "$SIG_A" "$ROOT_A" "$SIG_A" --json)
RC=$?
assert_eq "$RC" "2" "same body root twice exits 2"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']              is False, 'proven must be False'
assert r['distinct_body_roots'] is False, 'distinct_body_roots must be False'
# Both sigs DO verify — it is the distinctness rule (not the crypto) that
# fails, exactly as validator.cpp::check_equivocation_events distinguishes.
assert r['sig_a_valid']         is True
assert r['sig_b_valid']         is True
print('SAME_OK')
PY_EOF
SAME_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$SAME_OK" "true" "same opening: distinct_body_roots=false (both sigs valid, but no conflict)"

echo
echo "=== 7. Identical (root,sig) both sides → NOT PROVEN, distinct_sigs=false ==="
JOUT=$(verify_inline "$ROOT_A" "$SIG_A" "$ROOT_A" "$SIG_A" --json)
RC=$?
assert_eq "$RC" "2" "identical pair exits 2"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']        is False
assert r['distinct_sigs'] is False, 'distinct_sigs must be False'
print('IDENT_OK')
PY_EOF
IDENT_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$IDENT_OK" "true" "identical pair: distinct_sigs=false"

echo
echo "=== 8. --event with a bare EquivocationEvent JSON → PROVEN + metadata ==="
$PY - <<PY_EOF > "$TMP/event.json"
import json
print(json.dumps({
  "equivocator": "node-evil",
  "block_index": 7,
  "kind": 0,
  "index_a": 7,
  "body_root_a": "$ROOT_A",
  "sig_a":       "$SIG_A",
  "index_b": 7,
  "body_root_b": "$ROOT_B",
  "sig_b":       "$SIG_B",
  "shard_id": 0,
  "beacon_anchor_height": 0
}))
PY_EOF
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/event.json" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--event EquivocationEvent exits 0 (PROVEN)"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven']      is True
assert r['equivocator'] == 'node-evil', 'equivocator metadata echoed'
assert r['block_index'] == 7,           'block_index echoed'
print('EV_OK')
PY_EOF
EV_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$EV_OK" "true" "--event echoes equivocator + block_index from the record"

echo
echo "=== 9. --event with a Block JSON (equivocation_events[0]) → PROVEN ==="
$PY - <<PY_EOF > "$TMP/block.json"
import json
print(json.dumps({
  "index": 7,
  "transactions": [],
  "equivocation_events": [
    {"equivocator":"node-evil","block_index":7,"kind":0,
     "index_a":7,"body_root_a":"$ROOT_A","sig_a":"$SIG_A",
     "index_b":7,"body_root_b":"$ROOT_B","sig_b":"$SIG_B"}
  ]
}))
PY_EOF
OUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/block.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--event Block (events[0]) exits 0"
assert_contains "$OUT" "^PROVEN" "--event Block reports PROVEN"

echo
echo "=== 10. --event --index selecting the second event → PROVEN ==="
$PY - <<PY_EOF > "$TMP/block2.json"
import json
print(json.dumps({
  "index": 9,
  "equivocation_events": [
    {"equivocator":"node-evil","block_index":7,"kind":0,
     "index_a":7,"body_root_a":"$ROOT_A","sig_a":"$SIG_A",
     "index_b":7,"body_root_b":"$ROOT_B","sig_b":"$SIG_B"},
    {"equivocator":"node-evil2","block_index":9,"kind":0,
     "index_a":9,"body_root_a":"$ROOT_C","sig_a":"$SIG_C",
     "index_b":9,"body_root_b":"$ROOT_D","sig_b":"$SIG_D"}
  ]
}))
PY_EOF
JOUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/block2.json" --index 1 --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--index 1 exits 0"
$PY - <<PY_EOF
import json
r = json.loads('''$JOUT''')
assert r['proven'] is True
assert r['block_index'] == 9, 'should reflect events[1] block_index'
print('IDX_OK')
PY_EOF
IDX_OK=$([ $? -eq 0 ] && echo true || echo false)
assert_eq "$IDX_OK" "true" "--index 1 selects the second event (block_index=9)"

echo
echo "=== 11. --event out-of-range --index → exit 1 ==="
"$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/block.json" --index 5 >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "out-of-range --index returns 1 (operator error)"

echo
echo "=== 12. Missing --pubkey → exit 1 ==="
"$WALLET" verify-equivocation \
        --kind 0 --block-index 7 \
        --index-a 7 --body-root-a "$ROOT_A" --sig-a "$SIG_A" \
        --index-b 7 --body-root-b "$ROOT_B" --sig-b "$SIG_B" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "missing --pubkey returns 1 (key is always operator-supplied)"

echo
echo "=== 13. --event mutually exclusive with inline evidence args → exit 1 ==="
"$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/event.json" \
        --body-root-a "$ROOT_A" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "--event + inline evidence returns 1"

echo
echo "=== 14. Wrong-length --sig-a → exit 1 (args, not auth) ==="
"$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --kind 0 --block-index 7 \
        --index-a 7 --body-root-a "$ROOT_A" --sig-a "abcd" \
        --index-b 7 --body-root-b "$ROOT_B" --sig-b "$SIG_B" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "short --sig-a returns 1, not 2"

echo
echo "=== 15. Non-hex --body-root-a → exit 1 ==="
NONHEX=$($PY -c "print('z' * 64)")
"$WALLET" verify-equivocation --pubkey "$PUB_A" \
        --kind 0 --block-index 7 \
        --index-a 7 --body-root-a "$NONHEX" --sig-a "$SIG_A" \
        --index-b 7 --body-root-b "$ROOT_B" --sig-b "$SIG_B" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "1" "non-hex --body-root-a returns 1"

echo
echo "=== 16. Missing --event file → exit 1 ==="
OUT=$("$WALLET" verify-equivocation --pubkey "$PUB_A" --event "$TMP/nope.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "1" "missing --event file returns 1"
assert_contains "$OUT" "cannot open" "missing --event diagnostic mentions cannot open"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet verify-equivocation (offline FA6 two-sig proof verifier, height-bound)"; exit 0
else
    echo "  FAIL: test_wallet_verify_equivocation"; exit 1
fi
