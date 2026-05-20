#!/usr/bin/env bash
# determ-wallet sign-arbitrary + verify-arbitrary CLI test.
#
# Off-chain arbitrary-message signer using a FIXED domain separator
# "DETERM-MSG-v1". Distinct from:
#   * message-sign / message-verify (operator-supplied domain tag +
#     SHA-256 commitment scheme)
#   * tx-sign-verify (chain's canonical Transaction signing_bytes)
#
# Signs an arbitrary text or binary message with an Ed25519 private key
# loaded from an `account-export` style JSON keyfile (single account,
# shape {"address":"0x..","privkey_hex":".."}). The signed bytes are
# the literal byte string `"DETERM-MSG-v1" || msg_bytes` — Ed25519's
# internal hash handles the digest step per RFC 8032.
#
# Assertions:
#   1.  Help mentions sign-arbitrary + verify-arbitrary.
#   2.  Round-trip: sign + verify on a short text inline message.
#   3.  Round-trip: sign + verify on a text file via --msg-file.
#   4.  Round-trip: sign + verify on a binary file (full 0x00..0xFF byte
#       range, NUL-safe).
#   5.  --detached default emits 128-hex sig on stdout.
#   6.  --out <file> writes raw 64-byte binary sig.
#   7.  Bundle mode: sign emits parseable JSON with all five fields.
#   8.  Bundle round-trip: sign --bundle → verify --bundle file → VALID.
#   9.  Bundle --out file: written file is parseable + verifies.
#  10.  Tamper the sig (single-bit flip) → verify INVALID + exit 2.
#  11.  Tamper the msg (1-char change) → verify INVALID + exit 2.
#  12.  Different pubkey → verify INVALID + exit 2.
#  13.  Domain separator pin: a sig from --msg "X" does NOT verify
#       against --msg "DETERM-MSG-v1X". Confirms the separator is part
#       of the signed pre-image, NOT a verifier-side concatenation
#       hint that an attacker could replicate by pasting it on later.
#  14.  Bundle tamper (flip sig_hex) → INVALID + exit 2.
#  15.  Bundle tamper (flip a byte in msg_b64) → INVALID + exit 2.
#  16.  Bundle tamper (change `domain` field to a non-canonical value) →
#       INVALID + exit 2 (binary pins the canonical domain).
#  17.  Determinism: two consecutive signs on same priv+msg yield same sig.
#  18.  verify-arbitrary output is one-line JSON {"status":"ok","result":...}.
#  19.  Wrong --sig-hex length → exit 1 (args), not 2 (auth).
#  20.  Wrong --ed-pub length → exit 1.
#  21.  Missing required arg (no --priv-keyfile) → exit 1.
#  22.  --detached + --bundle together → exit 1 (mutually exclusive).
#  23.  Both --msg and --msg-file together → exit 1.
#  24.  Neither --msg nor --msg-file → exit 1.
#  25.  --bundle with stray --ed-pub → exit 1 (mode confusion).
#
# Run from repo root: bash tools/test_wallet_message_sign_verify.sh
set -u
# pipefail: make `OUT=$(cmd | tr -d '\r'); RC=$?` propagate the exit code
# of the wallet invocation rather than always reporting tr's success
# (which would mask exit 2 / exit 1 from the wallet auth-style failures).
set -o pipefail
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Per-run scratch directory (relative path under build/; see
# test_wallet_message_sign.sh for the rationale re: MSYS path translation).
TMP="build/test_wallet_message_sign_verify.$$"
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
assert_neq() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       both values: $1"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ── Generate fresh keypairs + export single-account keyfiles ───────────────────
# sign-arbitrary expects a `--priv-keyfile` that is a single-account JSON
# (the shape `account-export` would emit). account-create-batch emits a
# *list*-shaped {accounts:[...]} JSON; we extract per-index and rewrite
# into the single-account shape using Python.
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
$PY - <<PY_EOF
import json
keys = json.load(open("$TMP/keys.json"))
for i, a in enumerate(keys["accounts"]):
    with open("$TMP/key_%d.json" % i, "w") as f:
        json.dump({"address": a["address"], "privkey_hex": a["privkey_hex"]}, f)
PY_EOF

ADDR_A=$($PY -c "import json; print(json.load(open('$TMP/key_0.json'))['address'])")
PUB_A="${ADDR_A#0x}"
ADDR_B=$($PY -c "import json; print(json.load(open('$TMP/key_1.json'))['address'])")
PUB_B="${ADDR_B#0x}"

echo "=== 1. Help mentions sign-arbitrary + verify-arbitrary ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "sign-arbitrary"   "help mentions sign-arbitrary"
assert_contains "$H" "verify-arbitrary" "help mentions verify-arbitrary"
assert_contains "$H" "DETERM-MSG-v1"    "help advertises the fixed domain separator"

echo
echo "=== 2. Round-trip on short inline text message ==="
SIG=$("$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "hello determ" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "sign exits 0 on text"
SIG_LEN=$(echo -n "$SIG" | wc -c | tr -d ' ')
assert_eq "$SIG_LEN" "128" "detached sig hex is 128 chars (64-byte Ed25519)"
OUT=$("$WALLET" verify-arbitrary --ed-pub "$PUB_A" --msg "hello determ" --sig-hex "$SIG" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "verify exits 0 on round-trip"
assert_contains "$OUT" "\"result\":\"VALID\"" "verify reports VALID"
assert_contains "$OUT" "\"status\":\"ok\""    "verify reports status ok"

echo
echo "=== 3. Round-trip on text file via --msg-file ==="
printf "First line\nSecond line\nThird line with utf-8 bytes\n" > "$TMP/textmsg.txt"
"$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg-file "$TMP/textmsg.txt" --out "$TMP/textmsg.sig" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "sign --msg-file --out exits 0"
# File should be exactly 64 bytes (raw binary sig).
TEXTSIG_LEN=$(wc -c < "$TMP/textmsg.sig" | tr -d ' ')
assert_eq "$TEXTSIG_LEN" "64" "raw-binary --out file is exactly 64 bytes"
TEXTSIG_HEX=$($PY -c "import sys; print(open('$TMP/textmsg.sig','rb').read().hex())")
OUT=$("$WALLET" verify-arbitrary --ed-pub "$PUB_A" --msg-file "$TMP/textmsg.txt" --sig-hex "$TEXTSIG_HEX" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "verify --msg-file with hex-from-file sig exits 0"
assert_contains "$OUT" "VALID" "verify reports VALID for text file"

echo
echo "=== 4. Round-trip on binary file (full 0x00..0xFF range, NUL-safe) ==="
$PY - "$TMP/binary.bin" <<'PY_EOF'
import sys
with open(sys.argv[1], "wb") as f:
    f.write(bytes(range(256)))
PY_EOF
BINSIG=$("$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg-file "$TMP/binary.bin" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "sign of binary file exits 0"
OUT=$("$WALLET" verify-arbitrary --ed-pub "$PUB_A" --msg-file "$TMP/binary.bin" --sig-hex "$BINSIG" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "verify of binary file exits 0"
assert_contains "$OUT" "VALID" "binary-file round-trip VALID"

echo
echo "=== 5. --detached default emits 128-hex on stdout ==="
DEF_SIG=$("$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "x" 2>&1 | tr -d '\r')
DEF_LEN=$(echo -n "$DEF_SIG" | wc -c | tr -d ' ')
assert_eq "$DEF_LEN" "128" "default output (no flag) is 128-char hex"
# Confirm the explicit --detached produces the same bytes (determinism).
EXP_SIG=$("$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "x" --detached 2>&1 | tr -d '\r')
assert_eq "$EXP_SIG" "$DEF_SIG" "--detached default matches explicit --detached"

echo
echo "=== 6. --out <file> writes raw 64 bytes ==="
"$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "raw bytes test" --out "$TMP/raw.sig" --detached >/dev/null 2>&1
RAWSIG_LEN=$(wc -c < "$TMP/raw.sig" | tr -d ' ')
assert_eq "$RAWSIG_LEN" "64" "--out file is exactly 64 bytes"
RAWSIG_HEX=$($PY -c "print(open('$TMP/raw.sig','rb').read().hex())")
"$WALLET" verify-arbitrary --ed-pub "$PUB_A" --msg "raw bytes test" --sig-hex "$RAWSIG_HEX" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "raw-binary sig round-trips through hex"

echo
echo "=== 7. Bundle mode emits parseable JSON with all five fields ==="
BUNDLE_TEXT=$("$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "bundle test" --bundle 2>&1 | tr -d '\r')
$PY - <<PY_EOF
import json
d = json.loads('''$BUNDLE_TEXT''')
assert "address"    in d and isinstance(d["address"], str)
assert "ed_pub_hex" in d and isinstance(d["ed_pub_hex"], str) and len(d["ed_pub_hex"]) == 64
assert "domain"     in d and d["domain"] == "DETERM-MSG-v1"
assert "msg_b64"    in d and isinstance(d["msg_b64"], str)
assert "sig_hex"    in d and len(d["sig_hex"]) == 128
PY_EOF
assert_eq "$?" "0" "--bundle emits JSON with {address, ed_pub_hex, domain, msg_b64, sig_hex}"

echo
echo "=== 8. Bundle round-trip via file ==="
"$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "bundle file test" --bundle --out "$TMP/bundle.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "--bundle --out writes file"
OUT=$("$WALLET" verify-arbitrary --bundle "$TMP/bundle.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "verify --bundle <file> exits 0"
assert_contains "$OUT" "VALID" "bundle round-trip reports VALID"

echo
echo "=== 9. Bundle on stdout is parseable + verifiable round-trip ==="
echo "$BUNDLE_TEXT" > "$TMP/bundle_from_stdout.json"
OUT=$("$WALLET" verify-arbitrary --bundle "$TMP/bundle_from_stdout.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "stdout-bundle written to file verifies"
assert_contains "$OUT" "VALID" "stdout-bundle round-trip VALID"

echo
echo "=== 10. Tamper signature (single-bit flip) → INVALID + exit 2 ==="
GOOD=$("$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "tamper test" 2>&1 | tr -d '\r')
FIRST=${GOOD:0:1}
case "$FIRST" in
    0) NEW=1;; 1) NEW=2;; 2) NEW=3;; 3) NEW=4;; 4) NEW=5;;
    5) NEW=6;; 6) NEW=7;; 7) NEW=8;; 8) NEW=9;; 9) NEW=a;;
    a) NEW=b;; b) NEW=c;; c) NEW=d;; d) NEW=e;; e) NEW=f;; f) NEW=0;;
    *) NEW=1;;
esac
TAMPERED="${NEW}${GOOD:1}"
set +e
OUT=$("$WALLET" verify-arbitrary --ed-pub "$PUB_A" --msg "tamper test" --sig-hex "$TAMPERED" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "tampered-sig verify exits 2"
assert_contains "$OUT" "INVALID" "tampered-sig reports INVALID"

echo
echo "=== 11. Tamper the message → INVALID + exit 2 ==="
set +e
OUT=$("$WALLET" verify-arbitrary --ed-pub "$PUB_A" --msg "tamper Test" --sig-hex "$GOOD" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "tampered-message verify exits 2"
assert_contains "$OUT" "INVALID" "tampered-message reports INVALID"

echo
echo "=== 12. Different pubkey (key B) → INVALID + exit 2 ==="
set +e
OUT=$("$WALLET" verify-arbitrary --ed-pub "$PUB_B" --msg "tamper test" --sig-hex "$GOOD" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "wrong-pubkey verify exits 2"
assert_contains "$OUT" "INVALID" "wrong-pubkey reports INVALID"

echo
echo "=== 13. Domain-separator pin (sig from --msg 'X' != sig over 'DETERM-MSG-v1X') ==="
# Pin the invariant: signing 'X' under the binary's fixed domain separator
# produces sig_x. If we then verify by claiming the message was actually
# the bytes 'DETERM-MSG-v1X' (i.e., an attacker who tries to fake the
# domain separator being plaintext by prepending it themselves), the
# verifier reconstructs domain_sep || 'DETERM-MSG-v1X' = double-prefixed
# pre-image, which Ed25519 will NOT accept for the sig over the
# single-prefix pre-image. This pins that the domain separator is part
# of the signed bytes, not a verifier-side hint.
SIG_X=$("$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "X" 2>&1 | tr -d '\r')
set +e
OUT=$("$WALLET" verify-arbitrary --ed-pub "$PUB_A" --msg "DETERM-MSG-v1X" --sig-hex "$SIG_X" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "domain-sep pasted into message does NOT validate (exit 2)"
assert_contains "$OUT" "INVALID" "domain-sep pasting reports INVALID"

echo
echo "=== 14. Bundle tamper: flip sig_hex byte → INVALID + exit 2 ==="
$PY - <<PY_EOF > "$TMP/bundle_sigtamp.json"
import json
b = json.load(open("$TMP/bundle.json"))
s = b["sig_hex"]
ch = s[0]
table = "0123456789abcdef"
new = table[(table.index(ch.lower()) + 1) % 16]
b["sig_hex"] = new + s[1:]
print(json.dumps(b))
PY_EOF
set +e
OUT=$("$WALLET" verify-arbitrary --bundle "$TMP/bundle_sigtamp.json" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "bundle with tampered sig_hex exits 2"
assert_contains "$OUT" "INVALID" "bundle-sig-tamper reports INVALID"

echo
echo "=== 15. Bundle tamper: flip a base64 byte in msg_b64 → INVALID + exit 2 ==="
$PY - <<PY_EOF > "$TMP/bundle_msgtamp.json"
import json, base64
b = json.load(open("$TMP/bundle.json"))
raw = base64.b64decode(b["msg_b64"])
# Flip a bit in the first byte of the plaintext (or append a byte if empty).
mod = bytes([raw[0] ^ 0x01]) + raw[1:] if raw else b"\x01"
b["msg_b64"] = base64.b64encode(mod).decode("ascii")
print(json.dumps(b))
PY_EOF
set +e
OUT=$("$WALLET" verify-arbitrary --bundle "$TMP/bundle_msgtamp.json" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "bundle with tampered msg_b64 exits 2"
assert_contains "$OUT" "INVALID" "bundle-msg-tamper reports INVALID"

echo
echo "=== 16. Bundle tamper: domain field swapped → INVALID + exit 2 ==="
$PY - <<PY_EOF > "$TMP/bundle_domtamp.json"
import json
b = json.load(open("$TMP/bundle.json"))
b["domain"] = "DETERM-MSG-v2"
print(json.dumps(b))
PY_EOF
set +e
OUT=$("$WALLET" verify-arbitrary --bundle "$TMP/bundle_domtamp.json" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "bundle with non-canonical domain field exits 2"
assert_contains "$OUT" "INVALID" "bundle-domain-tamper reports INVALID"

echo
echo "=== 17. Determinism: same priv+msg yields same sig (RFC 8032) ==="
S1=$("$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "determ-test" 2>&1 | tr -d '\r')
S2=$("$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "determ-test" 2>&1 | tr -d '\r')
assert_eq "$S1" "$S2" "two back-to-back signs produce identical sigs"

echo
echo "=== 18. verify-arbitrary output shape ==="
OUT=$("$WALLET" verify-arbitrary --ed-pub "$PUB_A" --msg "determ-test" --sig-hex "$S1" 2>&1 | tr -d '\r')
$PY - <<PY_EOF
import json
d = json.loads('''$OUT''')
assert d.get("status") == "ok"
assert d.get("result") in ("VALID","INVALID")
PY_EOF
assert_eq "$?" "0" "verify emits one-line JSON {status:ok,result:VALID|INVALID}"

echo
echo "=== 19. Wrong --sig-hex length → exit 1 (args, not auth) ==="
set +e
"$WALLET" verify-arbitrary --ed-pub "$PUB_A" --msg "x" --sig-hex "abcd" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "short --sig-hex returns 1, not 2"

echo
echo "=== 20. Wrong --ed-pub length → exit 1 ==="
set +e
"$WALLET" verify-arbitrary --ed-pub "deadbeef" --msg "x" --sig-hex "$S1" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "short --ed-pub returns 1"

echo
echo "=== 21. Missing --priv-keyfile on sign → exit 1 ==="
set +e
"$WALLET" sign-arbitrary --msg "x" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --priv-keyfile returns 1"

echo
echo "=== 22. --detached and --bundle mutually exclusive → exit 1 ==="
set +e
"$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "x" --detached --bundle >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--detached + --bundle returns 1"

echo
echo "=== 23. Both --msg and --msg-file on sign → exit 1 ==="
set +e
"$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" --msg "x" --msg-file "$TMP/binary.bin" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--msg + --msg-file together returns 1"

echo
echo "=== 24. Neither --msg nor --msg-file on sign → exit 1 ==="
set +e
"$WALLET" sign-arbitrary --priv-keyfile "$TMP/key_0.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "no message arg returns 1"

echo
echo "=== 25. --bundle with stray --ed-pub → exit 1 (mode confusion) ==="
set +e
"$WALLET" verify-arbitrary --bundle "$TMP/bundle.json" --ed-pub "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--bundle + --ed-pub returns 1"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet sign-arbitrary + verify-arbitrary"; exit 0
else
    echo "  FAIL"; exit 1
fi
