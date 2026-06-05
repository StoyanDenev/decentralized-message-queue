#!/usr/bin/env bash
# determ-light rpc-auth — OFFLINE compute/verify of the S-001 HMAC RPC tag.
#
# Pure offline test (no cluster, no daemon, no genesis). Exercises
# `determ-light rpc-auth`, which re-implements the daemon's v2.16 RPC auth
# tag (src/rpc/rpc.cpp::canonical_for_hmac + hmac_sha256_hex) from scratch.
# The test computes the SAME tag INDEPENDENTLY in Python (hmac + hashlib),
# so a passing run is a genuine cross-implementation conformance check on
# the wire-visible `auth` field: HMAC-SHA256(secret, method + "|" +
# params.dump()) hex-encoded, with the secret hex-decoded to raw key bytes.
#
# Verdict / exit contract:
#   compute → exit 0, tag on stdout.
#   verify (--expect): MATCH → exit 0; MISMATCH → exit 3 (fail-closed).
#   usage / bad-hex / unparseable-params → exit 1.
#
# Assertions:
#   1. compute matches an independent Python HMAC over (method|{}).
#   2. compute with params matches the independent Python HMAC.
#   3. Key-order independence: keys supplied out of order yield the SAME tag
#      (the parse-then-dump canonicalization the server also performs).
#   4. --emit-request prints {method, params, auth} with the matching tag.
#   5. --params-string and --params-stdin give the same tag as --params-file.
#   6. --expect with the correct tag → MATCH, exit 0.
#   7. --expect with a wrong tag → MISMATCH, exit 3 (fail-closed).
#   8. --expect is case-insensitive (uppercase hex still MATCHes).
#   9. A different secret yields a different tag (MAC actually keyed).
#  10. Non-hex --secret → usage error exit 1 (never a silent empty key).
#  11. Missing --method → usage error exit 1.
#  12. Unparseable --params-string → usage error exit 1 (not a bogus tag).
#
# Run from repo root: bash tools/test_light_rpc_auth.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3

TMP="build/test_light_rpc_auth.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

SECRET="00112233445566778899aabbccddeeff"   # 16-byte hex key
OTHER="ffeeddccbbaa99887766554433221100"    # different key, same length

# expect_tag <secret_hex> <method> <params_json>
# Independent reference implementation of the daemon's tag: parse the
# params JSON, dump with nlohmann-compatible sorted keys + compact
# separators, prepend "<method>|", and HMAC-SHA256 under the hex-decoded
# secret. Prints the lowercase hex tag.
expect_tag() {
  "$PY" - "$1" "$2" "$3" <<'EOF'
import sys, json, hmac, hashlib, binascii
secret_hex, method, params_json = sys.argv[1:4]
key = binascii.unhexlify(secret_hex)
params = json.loads(params_json)
# nlohmann json::dump() default: sorted object keys, compact separators.
dumped = json.dumps(params, sort_keys=True, separators=(',', ':'))
msg = (method + "|" + dumped).encode("utf-8")
print(hmac.new(key, msg, hashlib.sha256).hexdigest())
EOF
}

run_auth() {  # run_auth <args...>; sets RC + OUT globals
  set +e
  OUT=$("$DETERM_LIGHT" rpc-auth "$@" 2>&1)
  RC=$?
  set -e
}

echo "=== 1. compute (empty params) matches independent Python HMAC ==="
REF=$(expect_tag "$SECRET" "head" "{}")
run_auth --secret "$SECRET" --method head
if [ "$RC" = "0" ] && [ "$OUT" = "$REF" ]; then
  assert "true" "empty-params tag matches reference ($REF)"
else
  echo "got=$OUT want=$REF rc=$RC"; assert "false" "empty-params tag matches reference"
fi

echo
echo "=== 2. compute (with params) matches independent Python HMAC ==="
echo '{"domain":"alice","count":3}' > "$TMP/p.json"
REF=$(expect_tag "$SECRET" "account" '{"domain":"alice","count":3}')
run_auth --secret "$SECRET" --method account --params-file "$TMP/p.json"
if [ "$RC" = "0" ] && [ "$OUT" = "$REF" ]; then
  assert "true" "params tag matches reference ($REF)"
else
  echo "got=$OUT want=$REF rc=$RC"; assert "false" "params tag matches reference"
fi

echo
echo "=== 3. key-order independence (parse-then-dump canonicalization) ==="
echo '{"count":3,"domain":"alice"}' > "$TMP/p_reordered.json"
run_auth --secret "$SECRET" --method account --params-file "$TMP/p_reordered.json"
if [ "$RC" = "0" ] && [ "$OUT" = "$REF" ]; then
  assert "true" "reordered keys yield the SAME tag"
else
  echo "got=$OUT want=$REF rc=$RC"; assert "false" "reordered keys yield the SAME tag"
fi

echo
echo "=== 4. --emit-request prints {method,params,auth} with matching tag ==="
run_auth --secret "$SECRET" --method account --params-file "$TMP/p.json" --emit-request
EMIT=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s' % (d.get('method'), d.get('auth')))
except Exception: print('ERR')
")
if [ "$EMIT" = "account/$REF" ]; then
  assert "true" "--emit-request carries method + matching auth"
else
  echo "got=$EMIT want=account/$REF"; assert "false" "--emit-request carries method + matching auth"
fi

echo
echo "=== 5. --params-string and --params-stdin equal --params-file ==="
run_auth --secret "$SECRET" --method account --params-string '{"domain":"alice","count":3}'
STR_TAG="$OUT"; STR_RC="$RC"
set +e
STDIN_TAG=$(printf '%s' '{"domain":"alice","count":3}' | "$DETERM_LIGHT" rpc-auth --secret "$SECRET" --method account --params-stdin 2>&1)
STDIN_RC=$?
set -e
if [ "$STR_RC" = "0" ] && [ "$STR_TAG" = "$REF" ] \
   && [ "$STDIN_RC" = "0" ] && [ "$STDIN_TAG" = "$REF" ]; then
  assert "true" "--params-string + --params-stdin both equal --params-file tag"
else
  echo "str=$STR_TAG/$STR_RC stdin=$STDIN_TAG/$STDIN_RC want=$REF"
  assert "false" "--params-string + --params-stdin both equal --params-file tag"
fi

echo
echo "=== 6. --expect with correct tag → MATCH exit 0 ==="
run_auth --secret "$SECRET" --method head --expect "$(expect_tag "$SECRET" head '{}')"
if [ "$RC" = "0" ] && echo "$OUT" | grep -q "MATCH"; then
  assert "true" "correct expect → MATCH exit 0"
else
  echo "$OUT (rc=$RC)"; assert "false" "correct expect → MATCH exit 0"
fi

echo
echo "=== 7. --expect with wrong tag → MISMATCH exit 3 (fail-closed) ==="
run_auth --secret "$SECRET" --method head --expect "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
if [ "$RC" = "3" ] && echo "$OUT" | grep -q "MISMATCH"; then
  assert "true" "wrong expect → MISMATCH exit 3"
else
  echo "$OUT (rc=$RC)"; assert "false" "wrong expect → MISMATCH exit 3"
fi

echo
echo "=== 8. --expect is case-insensitive (uppercase hex still MATCHes) ==="
UPPER=$(expect_tag "$SECRET" head '{}' | tr 'a-f' 'A-F')
run_auth --secret "$SECRET" --method head --expect "$UPPER"
if [ "$RC" = "0" ] && echo "$OUT" | grep -q "MATCH"; then
  assert "true" "uppercase expect → MATCH exit 0"
else
  echo "$OUT (rc=$RC)"; assert "false" "uppercase expect → MATCH exit 0"
fi

echo
echo "=== 9. different secret yields a different tag (MAC is keyed) ==="
run_auth --secret "$OTHER" --method head
OTHER_TAG="$OUT"
if [ "$RC" = "0" ] && [ -n "$OTHER_TAG" ] \
   && [ "$OTHER_TAG" != "$(expect_tag "$SECRET" head '{}')" ] \
   && [ "$OTHER_TAG" = "$(expect_tag "$OTHER" head '{}')" ]; then
  assert "true" "different secret → different (correct) tag"
else
  echo "$OTHER_TAG (rc=$RC)"; assert "false" "different secret → different (correct) tag"
fi

echo
echo "=== 10. non-hex --secret → usage error exit 1 ==="
run_auth --secret "nothex!!" --method head
[ "$RC" = "1" ] && assert "true" "non-hex secret → exit 1" \
                || { echo "$OUT (rc=$RC)"; assert "false" "non-hex secret → exit 1"; }

echo
echo "=== 11. missing --method → usage error exit 1 ==="
run_auth --secret "$SECRET"
[ "$RC" = "1" ] && assert "true" "missing --method → exit 1" \
                || { echo "$OUT (rc=$RC)"; assert "false" "missing --method → exit 1"; }

echo
echo "=== 12. unparseable --params-string → usage error exit 1 ==="
run_auth --secret "$SECRET" --method head --params-string 'not-json'
[ "$RC" = "1" ] && assert "true" "bad params JSON → exit 1 (not a bogus tag)" \
                || { echo "$OUT (rc=$RC)"; assert "false" "bad params JSON → exit 1"; }

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_rpc_auth"; exit 0
else
  echo "  FAIL: test_light_rpc_auth"; exit 1
fi
