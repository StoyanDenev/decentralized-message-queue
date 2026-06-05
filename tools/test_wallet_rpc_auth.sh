#!/usr/bin/env bash
# determ-wallet rpc-auth CLI test.
#
# Verifies the OFFLINE computor + verifier for the S-001 (v2.16) RPC HMAC-auth
# tag — the wallet-side dual of RpcServer::verify_auth / rpc_call's auth wiring
# in src/rpc/rpc.cpp. The command:
#   (a) compute mode (default): derives auth = lowercase-hex(HMAC-SHA-256(
#       hex_decode(secret), method + "|" + params.dump())) and emits a ready-
#       to-send {method,params,auth} request envelope;
#   (b) verify mode (--verify <hex> or --request <file>): recomputes the
#       expected tag and constant-time-compares it to a claimed tag.
# Entirely in-process — no socket, no daemon, no subprocess.
#
# The canonical form MUST match src/rpc/rpc.cpp::canonical_for_hmac byte-for-
# byte: the server parses `params` out of the request then re-dumps it, so the
# nlohmann default object (std::map) sorts keys. We cross-check every tag
# against an INDEPENDENT Python reference that mirrors the same scheme:
#   key       = bytes.fromhex(secret)
#   canonical = method + "|" + json.dumps(params, sort_keys=True,
#                                         separators=(",", ":"))
#   auth      = hmac.new(key, canonical.encode(), sha256).hexdigest()
# json.dumps(sort_keys=True, separators=(",", ":")) reproduces nlohmann's
# compact sorted-key dump() for the JSON object shapes exercised here.
#
# Covers (~30 assertions):
#   1.  --help text exists + documents every flag.
#   2.  Global help dispatcher lists rpc-auth.
#   3.  Missing --secret / --method → exit 1.
#   4.  Bad hex secret / empty secret → exit 1.
#   5.  Mutually-exclusive flag pairs → exit 1.
#   6.  Unknown flag → exit 1.
#   7.  Compute (no params) auth matches the Python reference.
#   8.  Compute (with params) auth matches; hand-ordered keys still canonical.
#   9.  --json compute: strict schema + canonical/request shape.
#  10.  --params-file path equals inline --params.
#  11.  Verify MATCH (--verify) → exit 0.
#  12.  Verify MISMATCH (--verify) → exit 2.
#  13.  Verify via --request file (round-trips compute output) → exit 0.
#  14.  Verify --request with tampered auth → exit 2.
#  15.  --request CLI/file method disagreement → exit 1.
#  16.  Malformed --params / --request JSON → exit 1.
#
# Cluster-free + deterministic. Run from repo root:
#   bash tools/test_wallet_rpc_auth.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
SCRATCH="build/test_wallet_rpc_auth.$$"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

PY=python
command -v python >/dev/null 2>&1 || PY=python3

pass_count=0; fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; fail_count=$((fail_count + 1)); fi
}

# ── Independent Python reference for the S-001 tag. ───────────────────────────
# args: <secret_hex> <method> <params_json>   (params_json="" → no params, {})
ref_auth() {
  $PY - "$@" <<'PYEOF'
import sys, json, hmac, hashlib
secret_hex, method, params_json = sys.argv[1], sys.argv[2], sys.argv[3]
key = bytes.fromhex(secret_hex)
params = json.loads(params_json) if params_json != "" else {}
canonical = method + "|" + json.dumps(params, sort_keys=True, separators=(",", ":"))
print(hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest())
PYEOF
}

SECRET="0011223344556677889900aabbccddeeff00112233445566778899aabbccddee"

# ── 1. --help text ────────────────────────────────────────────────────────────
echo
echo "=== 1. --help text ==="
HELP=$("$WALLET" rpc-auth --help 2>&1 | tr -d '\r')
assert_contains "$HELP" "Usage: determ-wallet rpc-auth" "help shows synopsis"
assert_contains "$HELP" "OFFLINE computor + verifier"   "help describes purpose"
assert_contains "$HELP" "\-\-method <m>"                "help documents --method"
assert_contains "$HELP" "\-\-params <json>"             "help documents --params"
assert_contains "$HELP" "\-\-secret <hex>"              "help documents --secret"
assert_contains "$HELP" "\-\-verify <hex>"              "help documents --verify"
assert_contains "$HELP" "\-\-request <file>"            "help documents --request"
assert_contains "$HELP" "HMAC-SHA-256"                  "help references the HMAC scheme"

# ── 2. Global help dispatcher ─────────────────────────────────────────────────
echo
echo "=== 2. Global help mentions rpc-auth ==="
GLOBAL=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$GLOBAL" "rpc-auth" "global help lists rpc-auth"

# ── 3. Missing required flags → exit 1 ────────────────────────────────────────
echo
echo "=== 3. Missing required flags → exit 1 ==="
set +e
ERR=$("$WALLET" rpc-auth --method head 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "missing --secret exits 1"
assert_contains "$(echo "$ERR" | tr -d '\r')" "secret" "missing --secret mentions secret"
set +e
ERR=$("$WALLET" rpc-auth --secret "$SECRET" 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "missing --method exits 1"

# ── 4. Bad / empty secret → exit 1 ────────────────────────────────────────────
echo
echo "=== 4. Bad / empty secret → exit 1 ==="
set +e
ERR=$("$WALLET" rpc-auth --method head --secret "zz" 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "non-hex secret exits 1"
assert_contains "$(echo "$ERR" | tr -d '\r')" "hex" "non-hex secret diagnostic mentions hex"
set +e
ERR=$("$WALLET" rpc-auth --method head --secret "abc" 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "odd-length secret exits 1"

# ── 5. Mutually-exclusive flags → exit 1 ──────────────────────────────────────
echo
echo "=== 5. Mutually-exclusive flags → exit 1 ==="
set +e
ERR=$("$WALLET" rpc-auth --method head --secret "$SECRET" --params '{}' --params-file x.json 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "--params + --params-file exits 1"
assert_contains "$(echo "$ERR" | tr -d '\r')" "mutually exclusive" "diagnostic mentions mutually exclusive"
set +e
ERR=$("$WALLET" rpc-auth --method head --secret "$SECRET" --verify aa --request r.json 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "--verify + --request exits 1"

# ── 6. Unknown flag → exit 1 ──────────────────────────────────────────────────
echo
echo "=== 6. Unknown flag → exit 1 ==="
set +e
ERR=$("$WALLET" rpc-auth --bogus 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "unknown flag exits 1"
assert_contains "$(echo "$ERR" | tr -d '\r')" "unknown argument" "diagnostic mentions unknown argument"

# ── 7. Compute (no params) matches Python reference ───────────────────────────
echo
echo "=== 7. Compute (no params) auth matches reference ==="
set +e
OUT=$("$WALLET" rpc-auth --method head --secret "$SECRET" --json 2>&1 | tr -d '\r'); RC=$?
set -e
assert_eq "$RC" "0" "compute (no params) exits 0"
WALLET_AUTH=$(echo "$OUT" | $PY -c "import sys,json; print(json.loads(sys.stdin.read())['auth'])")
REF_AUTH=$(ref_auth "$SECRET" "head" "")
assert_eq "$WALLET_AUTH" "$REF_AUTH" "no-params auth equals Python HMAC reference"
assert_contains "$OUT" '"canonical":"head|{}"' "no-params canonical is head|{}"

# ── 8. Compute (with params) matches; hand-ordered keys canonicalize ──────────
echo
echo "=== 8. Compute (params, hand-ordered keys) matches reference ==="
# Keys deliberately out of alphabetical order — the tool must sort them.
PARAMS='{"to":"determ1xyz","amount":100,"from":"determ1abc"}'
set +e
OUT=$("$WALLET" rpc-auth --method submit_tx --secret "$SECRET" --params "$PARAMS" --json 2>&1 | tr -d '\r'); RC=$?
set -e
assert_eq "$RC" "0" "compute (params) exits 0"
WALLET_AUTH=$(echo "$OUT" | $PY -c "import sys,json; print(json.loads(sys.stdin.read())['auth'])")
REF_AUTH=$(ref_auth "$SECRET" "submit_tx" "$PARAMS")
assert_eq "$WALLET_AUTH" "$REF_AUTH" "params auth equals Python HMAC reference (sorted keys)"
# Canonical must show sorted keys (amount before from before to).
assert_contains "$OUT" "submit_tx|{\\\"amount\\\":100,\\\"from\\\":\\\"determ1abc\\\",\\\"to\\\":\\\"determ1xyz\\\"}" \
    "canonical sorts params keys alphabetically"

# ── 9. --json compute schema ──────────────────────────────────────────────────
echo
echo "=== 9. --json compute schema ==="
SCHEMA_OK=$(echo "$OUT" | $PY -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    assert d.get('command') == 'rpc-auth',        'command'
    assert d.get('mode') == 'compute',            'mode==compute'
    assert d.get('method') == 'submit_tx',        'method'
    assert isinstance(d.get('params'), dict),     'params:obj'
    assert isinstance(d.get('secret_bytes'), int),'secret_bytes:int'
    assert d.get('secret_bytes') == 32,           'secret_bytes==32'
    assert isinstance(d.get('canonical'), str),   'canonical:str'
    assert isinstance(d.get('auth'), str),        'auth:str'
    assert len(d.get('auth')) == 64,              'auth 64 hex'
    req = d.get('request')
    assert isinstance(req, dict),                 'request:obj'
    assert req.get('method') == 'submit_tx',      'request.method'
    assert req.get('auth') == d.get('auth'),      'request.auth==auth'
    assert isinstance(req.get('params'), dict),   'request.params:obj'
    print('ok')
except AssertionError as e:
    print('bad:'+str(e))
except Exception as e:
    print('parse:'+str(e))
")
assert_eq "$SCHEMA_OK" "ok" "compute JSON envelope passes strict schema check"

# ── 10. --params-file equals inline --params ──────────────────────────────────
echo
echo "=== 10. --params-file equals inline --params ==="
PFILE="$SCRATCH/params.json"
printf '%s' "$PARAMS" > "$PFILE"
set +e
OUTF=$("$WALLET" rpc-auth --method submit_tx --secret "$SECRET" --params-file "$PFILE" --json 2>&1 | tr -d '\r'); RC=$?
set -e
assert_eq "$RC" "0" "--params-file exits 0"
FILE_AUTH=$(echo "$OUTF" | $PY -c "import sys,json; print(json.loads(sys.stdin.read())['auth'])")
assert_eq "$FILE_AUTH" "$WALLET_AUTH" "--params-file auth equals inline --params auth"

# ── 11. Verify MATCH (--verify) → exit 0 ──────────────────────────────────────
echo
echo "=== 11. Verify MATCH (--verify) → exit 0 ==="
set +e
OUT=$("$WALLET" rpc-auth --method submit_tx --secret "$SECRET" --params "$PARAMS" --verify "$REF_AUTH" --json 2>&1 | tr -d '\r'); RC=$?
set -e
assert_eq "$RC" "0" "matching --verify exits 0"
assert_contains "$OUT" '"valid":true'          "match reports valid=true"
assert_contains "$OUT" '"exit_reason":"match"' "match reports exit_reason=match"
assert_contains "$OUT" '"mode":"verify"'       "verify mode reported"

# ── 12. Verify MISMATCH (--verify) → exit 2 ───────────────────────────────────
echo
echo "=== 12. Verify MISMATCH (--verify) → exit 2 ==="
BAD_AUTH="0000000000000000000000000000000000000000000000000000000000000000"
set +e
OUT=$("$WALLET" rpc-auth --method submit_tx --secret "$SECRET" --params "$PARAMS" --verify "$BAD_AUTH" --json 2>&1); RC=$?
set -e
assert_eq "$RC" "2" "mismatching --verify exits 2"
assert_contains "$(echo "$OUT" | tr -d '\r')" '"valid":false'             "mismatch reports valid=false"
assert_contains "$(echo "$OUT" | tr -d '\r')" '"exit_reason":"mismatch"'  "mismatch reports exit_reason=mismatch"

# ── 13. Verify via --request round-trip → exit 0 ──────────────────────────────
echo
echo "=== 13. Verify via --request (round-trips compute) → exit 0 ==="
REQ="$SCRATCH/req.json"
"$WALLET" rpc-auth --method submit_tx --secret "$SECRET" --params "$PARAMS" --json 2>/dev/null \
    | tr -d '\r' \
    | $PY -c "import sys,json; json.dump(json.loads(sys.stdin.read())['request'], open('$REQ','w'))"
set +e
OUT=$("$WALLET" rpc-auth --secret "$SECRET" --request "$REQ" --json 2>&1 | tr -d '\r'); RC=$?
set -e
assert_eq "$RC" "0" "request round-trip verifies (exit 0)"
assert_contains "$OUT" '"valid":true' "request round-trip reports valid=true"

# ── 14. --request with tampered auth → exit 2 ─────────────────────────────────
echo
echo "=== 14. --request tampered auth → exit 2 ==="
TAMPER_REQ="$SCRATCH/tamper_req.json"
$PY -c "
import json
d = json.load(open('$REQ'))
d['auth'] = '0'*64   # forge the tag
json.dump(d, open('$TAMPER_REQ','w'))
"
set +e
OUT=$("$WALLET" rpc-auth --secret "$SECRET" --request "$TAMPER_REQ" --json 2>&1); RC=$?
set -e
assert_eq "$RC" "2" "tampered request auth exits 2"
assert_contains "$(echo "$OUT" | tr -d '\r')" '"valid":false' "tampered request reports valid=false"

# ── 15. --request CLI/file method disagreement → exit 1 ───────────────────────
echo
echo "=== 15. --request CLI/file method disagreement → exit 1 ==="
set +e
ERR=$("$WALLET" rpc-auth --method WRONG_METHOD --secret "$SECRET" --request "$REQ" 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "method disagreement exits 1"
assert_contains "$(echo "$ERR" | tr -d '\r')" "disagrees" "diagnostic mentions disagreement"

# ── 16. Malformed JSON → exit 1 ───────────────────────────────────────────────
echo
echo "=== 16. Malformed JSON → exit 1 ==="
set +e
ERR=$("$WALLET" rpc-auth --method head --secret "$SECRET" --params 'not{json' 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "malformed --params exits 1"
BADREQ="$SCRATCH/bad_req.json"
echo 'not { valid json' > "$BADREQ"
set +e
ERR=$("$WALLET" rpc-auth --secret "$SECRET" --request "$BADREQ" 2>&1); RC=$?
set -e
assert_eq "$RC" "1" "malformed --request exits 1"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet rpc-auth"; exit 0
else
    echo "  FAIL"; exit 1
fi
