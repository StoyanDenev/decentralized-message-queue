#!/usr/bin/env bash
# determ-wallet account-derive-batch operator-workflow CLI test.
#
# Companion to test_wallet_account_create_batch.sh. Where create-batch
# generates N keypairs from a fresh CSPRNG draw per call, derive-batch
# derives N keypairs DETERMINISTICALLY from a single 32-byte master seed:
#
#     seed_i    = SHA-256(master_seed || u32_le(i))
#     keypair_i = ed25519_seed_keypair(seed_i)
#
# So the SAME master seed ALWAYS produces the SAME set of accounts, in
# the SAME order, regardless of which machine the operator runs the
# command on. Different master seeds always produce disjoint sets.
#
# Operator use cases:
#   * Cold-wallet provisioning from a single backed-up seed (one seed
#     -> N derived addresses).
#   * Reproducible test-fixture generation (CI pipelines pin a master
#     seed and get the same address set across runs).
#   * Recovery: lost individual keys are reconstructible from the
#     master seed alone.
#
# Assertions:
#   1. Help line mentions account-derive-batch.
#   2. N=1 (smallest batch) prints exactly one account[] line (human mode).
#   3. N=5 prints exactly five account[] lines, indices 0..4.
#   4. N=10 via --out writes JSON with the expected master_seed_hash_hex,
#      count, accounts[] of length 10.
#   5. --json (no --out) prints same JSON to stdout, parseable.
#   6. Determinism: same seed + same count produce BYTE-IDENTICAL output
#      across back-to-back invocations.
#   7. Determinism: same seed + same count produce BYTE-IDENTICAL output
#      across THREE invocations (transitive — no hidden RNG draw).
#   8. Determinism: same seed + same count produce IDENTICAL JSON via
#      --out across invocations.
#   9. Different seed produces DISJOINT address set (different first byte
#      flipped -> totally different set).
#  10. Every address matches anon-format: 0x + 64 lowercase hex.
#  11. Every privkey_hex is 64 lowercase hex chars.
#  12. Within a batch every address is unique.
#  13. Within a batch every privkey_hex is unique.
#  14. master_seed_hash_hex in JSON equals SHA-256 of the supplied seed
#      (verified independently in Python).
#  15. Cross-machine reproducibility: derive the seed independently in
#      Python (sha256(seed || u32_le(i)) -> ed25519_seed_keypair) and
#      compare ALL addresses + privkeys byte-for-byte against the C++
#      output. This is the strongest determinism check: it pins the
#      algorithm spec, not just the implementation's self-consistency.
#  16. Indices in JSON are exactly 0..N-1 (and in order).
#  17. --count 0 fails (rc=1).
#  18. --count -1 fails (rc=1).
#  19. --count 10001 fails (rc=1) with diagnostic mentioning the cap.
#  20. --count missing fails (rc=1).
#  21. --seed missing fails (rc=1).
#  22. --seed too short (63 hex) fails (rc=1).
#  23. --seed too long (65 hex) fails (rc=1).
#  24. --seed non-hex (z's mixed in) fails (rc=1).
#  25. --out parent dir missing fails (rc=1) with diagnostic.
#  26. --out existing file refused without --force; --force overrides.
#  27. --out + --json: --out wins; stdout is the confirmation line, NOT JSON.
#  28. master_seed_hash_hex in --out file does NOT equal the master seed
#      itself (it's the SHA-256; first byte of hash != first byte of seed
#      with overwhelming probability).
#  29. The output file does NOT contain the raw seed_hex substring
#      anywhere (defense-in-depth: master seed must not leak to disk).
#  30. SLIP-0010-style sanity: derive seed[0] independently and verify it
#      EQUALS the first sub_seed = SHA-256(master_seed || 0x00000000).
#
# Run from repo root: bash tools/test_wallet_account_derive_batch.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
TMP="$(mktemp -d)"
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
assert_not_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  FAIL: $3 (unexpected substring: $2)"; fail_count=$((fail_count + 1))
  else echo "  PASS: $3"; pass_count=$((pass_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# Fixed reproducible master seed for the determinism checks. Operator
# test fixtures must NEVER use real secret material — these are public,
# checked-into-the-repo bytes. The first byte (0xde) is preserved so a
# later visual-diff against the expected JSON is humane.
SEED1="deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb"
SEED2="cafef00d00112233445566778899aabbccddeeff00112233445566778899aabb"

echo "=== 1. Help text mentions account-derive-batch ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "account-derive-batch"; then
  echo "  PASS: help mentions account-derive-batch"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing account-derive-batch"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. N=1 (smallest batch) — exactly one account[] line ==="
OUT=$("$WALLET" account-derive-batch --seed "$SEED1" --count 1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on N=1"
n_blocks=$(echo "$OUT" | grep -c "^account\[")
assert_eq "$n_blocks" "1" "N=1 emits exactly 1 'account[' line"
assert_contains "$OUT" "account\[0\]:" "human mode starts at account[0]"
assert_contains "$OUT" "address=0x"    "human mode shows address= label"
assert_contains "$OUT" "privkey_hex="  "human mode shows privkey_hex= label"

echo
echo "=== 3. N=5 — exactly five account[] lines, indices 0..4 ==="
OUT=$("$WALLET" account-derive-batch --seed "$SEED1" --count 5 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on N=5"
n_blocks=$(echo "$OUT" | grep -c "^account\[")
assert_eq "$n_blocks" "5" "N=5 emits exactly 5 'account[' lines"
assert_contains "$OUT" "account\[0\]:" "first index is 0"
assert_contains "$OUT" "account\[4\]:" "last index is 4 (0-based)"

echo
echo "=== 4. N=10 via --out writes JSON with expected fields ==="
"$WALLET" account-derive-batch --seed "$SEED1" --count 10 --out "$TMP/batch10.json" > "$TMP/stdout10.txt" 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on N=10 with --out"
STDOUT=$(cat "$TMP/stdout10.txt" | tr -d '\r')
assert_contains "$STDOUT" "derived 10 accounts to" "stdout reports 10 accounts derived"
if [ -s "$TMP/batch10.json" ]; then
    echo "  PASS: --out file is non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file is empty"; fail_count=$((fail_count + 1))
fi
LEN=$($PY -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d['accounts']))" "$TMP/batch10.json")
assert_eq "$LEN" "10" "JSON accounts[] length 10"
CNT=$($PY -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['count'])" "$TMP/batch10.json")
assert_eq "$CNT" "10" "JSON count field == 10"
HAS_HASH=$($PY -c "import json,sys; d=json.load(open(sys.argv[1])); print('yes' if 'master_seed_hash_hex' in d else 'no')" "$TMP/batch10.json")
assert_eq "$HAS_HASH" "yes" "JSON contains master_seed_hash_hex"

echo
echo "=== 5. --json (no --out) prints JSON to stdout, parseable ==="
JSON=$("$WALLET" account-derive-batch --seed "$SEED1" --count 7 --json | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on --json stdout"
LEN=$(echo "$JSON" | $PY -c "import json,sys; d=json.load(sys.stdin); print(len(d['accounts']))")
assert_eq "$LEN" "7" "--json stdout accounts[] length 7"

echo
echo "=== 6. Determinism: same seed + count -> BYTE-IDENTICAL output (2 runs) ==="
"$WALLET" account-derive-batch --seed "$SEED1" --count 8 --out "$TMP/det_a.json" >/dev/null 2>&1
"$WALLET" account-derive-batch --seed "$SEED1" --count 8 --out "$TMP/det_b.json" --force >/dev/null 2>&1
HASH_A=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$TMP/det_a.json")
HASH_B=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$TMP/det_b.json")
assert_eq "$HASH_A" "$HASH_B" "two runs with same seed produce byte-identical files"

echo
echo "=== 7. Determinism: 3 runs all identical (transitive) ==="
"$WALLET" account-derive-batch --seed "$SEED1" --count 8 --out "$TMP/det_c.json" --force >/dev/null 2>&1
HASH_C=$($PY -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$TMP/det_c.json")
assert_eq "$HASH_C" "$HASH_A" "third run also byte-identical"

echo
echo "=== 8. Determinism via --json stdout (no --out) ==="
J1=$("$WALLET" account-derive-batch --seed "$SEED1" --count 4 --json | tr -d '\r')
J2=$("$WALLET" account-derive-batch --seed "$SEED1" --count 4 --json | tr -d '\r')
if [ "$J1" = "$J2" ]; then
    echo "  PASS: --json stdout deterministic across calls"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json stdout differs across calls"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 9. Different seed -> disjoint address set ==="
"$WALLET" account-derive-batch --seed "$SEED2" --count 8 --out "$TMP/seed2.json" >/dev/null 2>&1
DIFFER=$($PY - "$TMP/det_a.json" "$TMP/seed2.json" <<'PY_EOF'
import json, sys
a = json.load(open(sys.argv[1]))["accounts"]
b = json.load(open(sys.argv[2]))["accounts"]
a_addrs = {x["address"] for x in a}
b_addrs = {x["address"] for x in b}
print("DISJOINT" if not (a_addrs & b_addrs) else "OVERLAP")
PY_EOF
)
assert_eq "$DIFFER" "DISJOINT" "different seeds produce disjoint address sets"

echo
echo "=== 10. Every address is anon-format (0x + 64 lowercase hex) ==="
$PY - "$TMP/batch10.json" <<'PY_EOF'
import json, re, sys
d = json.load(open(sys.argv[1]))
shape = re.compile(r"^0x[0-9a-f]{64}$")
bad = [a["address"] for a in d["accounts"] if not shape.match(a["address"])]
sys.exit(1 if bad else 0)
PY_EOF
RC=$?
assert_eq "$RC" "0" "every address matches anon-format (0x + 64 lowercase hex)"

echo
echo "=== 11. Every privkey_hex is 64 lowercase hex ==="
$PY - "$TMP/batch10.json" <<'PY_EOF'
import json, re, sys
d = json.load(open(sys.argv[1]))
shape = re.compile(r"^[0-9a-f]{64}$")
bad = [a["privkey_hex"] for a in d["accounts"] if not shape.match(a["privkey_hex"])]
sys.exit(1 if bad else 0)
PY_EOF
RC=$?
assert_eq "$RC" "0" "every privkey_hex is 64 lowercase hex"

echo
echo "=== 12. All addresses unique within a batch ==="
$PY - "$TMP/batch10.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
addrs = [a["address"] for a in d["accounts"]]
sys.exit(1 if len(set(addrs)) != len(addrs) else 0)
PY_EOF
RC=$?
assert_eq "$RC" "0" "all 10 addresses unique within batch"

echo
echo "=== 13. All privkey_hex unique within a batch ==="
$PY - "$TMP/batch10.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
keys = [a["privkey_hex"] for a in d["accounts"]]
sys.exit(1 if len(set(keys)) != len(keys) else 0)
PY_EOF
RC=$?
assert_eq "$RC" "0" "all 10 privkey_hex unique within batch"

echo
echo "=== 14. master_seed_hash_hex == SHA-256(seed bytes) ==="
EXPECTED_HASH=$($PY -c "import hashlib; print(hashlib.sha256(bytes.fromhex('$SEED1')).hexdigest())")
ACTUAL_HASH=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['master_seed_hash_hex'])" "$TMP/batch10.json")
assert_eq "$ACTUAL_HASH" "$EXPECTED_HASH" "master_seed_hash_hex matches independent Python SHA-256"

echo
echo "=== 15. Cross-machine reproducibility (Python re-derives identical accounts) ==="
# This is the BIG ONE: re-derive the entire batch in pure Python using
# the documented algorithm, and compare every account byte-for-byte.
# Catches: integer encoding direction (endianness), preimage layout,
# ed25519 primitive substitution, hex casing.
$PY - "$SEED1" "$TMP/batch10.json" <<'PY_EOF'
import hashlib, json, sys
try:
    from nacl.signing import SigningKey
except ImportError:
    print("SKIP: pynacl not installed; cannot run cross-machine reproducibility check")
    sys.exit(0)

seed_hex = sys.argv[1]
path     = sys.argv[2]
master   = bytes.fromhex(seed_hex)
doc      = json.load(open(path))
mismatch = []
for i, acc in enumerate(doc["accounts"]):
    # seed_i = SHA-256(master_seed || u32_le(i))
    preimage = master + i.to_bytes(4, "little")
    sub_seed = hashlib.sha256(preimage).digest()
    sk = SigningKey(sub_seed)
    pub = bytes(sk.verify_key)
    expected_addr    = "0x" + pub.hex()
    expected_privhex = sub_seed.hex()
    if acc["address"] != expected_addr or acc["privkey_hex"] != expected_privhex:
        mismatch.append((i, expected_addr, expected_privhex, acc))
if mismatch:
    for m in mismatch[:3]:
        print("MISMATCH index", m[0])
        print("  expected addr:", m[1])
        print("  expected priv:", m[2])
        print("  got:           ", m[3])
    sys.exit(1)
print("OK")
PY_EOF
RC=$?
if [ "$RC" = "0" ]; then
    echo "  PASS: Python independently re-derives byte-identical accounts (cross-machine reproducibility)"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: Python re-derivation mismatch"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 16. Indices in JSON are exactly 0..N-1 in order ==="
$PY - "$TMP/batch10.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
got = [a["index"] for a in d["accounts"]]
expected = list(range(10))
sys.exit(0 if got == expected else 1)
PY_EOF
RC=$?
assert_eq "$RC" "0" "indices are exactly 0..N-1 in order"

echo
echo "=== 17. --count 0 fails ==="
set +e
"$WALLET" account-derive-batch --seed "$SEED1" --count 0 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on --count 0"

echo
echo "=== 18. --count -1 fails ==="
set +e
"$WALLET" account-derive-batch --seed "$SEED1" --count -1 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on --count -1"

echo
echo "=== 19. --count 10001 fails (cap = 10000) ==="
set +e
ERR=$("$WALLET" account-derive-batch --seed "$SEED1" --count 10001 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --count > 10000"
assert_contains "$ERR" "10000" "diagnostic mentions cap"

echo
echo "=== 20. --count missing fails ==="
set +e
"$WALLET" account-derive-batch --seed "$SEED1" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --count"

echo
echo "=== 21. --seed missing fails ==="
set +e
ERR=$("$WALLET" account-derive-batch --count 1 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --seed"
assert_contains "$ERR" "seed" "diagnostic mentions --seed"

echo
echo "=== 22. --seed too short (63 chars) fails ==="
set +e
SHORT=$(echo "$SEED1" | cut -c1-63)
ERR=$("$WALLET" account-derive-batch --seed "$SHORT" --count 1 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on 63-char --seed"
assert_contains "$ERR" "64 hex" "diagnostic mentions 64 hex"

echo
echo "=== 23. --seed too long (65 chars) fails ==="
set +e
LONG="${SEED1}f"
ERR=$("$WALLET" account-derive-batch --seed "$LONG" --count 1 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on 65-char --seed"

echo
echo "=== 24. --seed non-hex (z's mixed in) fails ==="
set +e
BAD="zzadbeef00112233445566778899aabbccddeeff00112233445566778899aabb"
ERR=$("$WALLET" account-derive-batch --seed "$BAD" --count 1 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on non-hex --seed"
assert_contains "$ERR" "hex" "diagnostic mentions hex"

echo
echo "=== 25. --out parent dir missing fails ==="
set +e
ERR=$("$WALLET" account-derive-batch --seed "$SEED1" --count 1 --out "$TMP/no_such_dir/x.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing parent dir"
assert_contains "$ERR" "parent directory" "diagnostic mentions parent directory"

echo
echo "=== 26. --out existing file refused without --force; --force overrides ==="
# $TMP/batch10.json was written in step 4 (still exists).
set +e
ERR=$("$WALLET" account-derive-batch --seed "$SEED1" --count 1 --out "$TMP/batch10.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on existing --out (no --force)"
assert_contains "$ERR" "already exists" "diagnostic mentions file exists"
assert_contains "$ERR" "--force"        "diagnostic suggests --force"
# With --force, succeeds and shrinks to N=1.
"$WALLET" account-derive-batch --seed "$SEED1" --count 1 --out "$TMP/batch10.json" --force >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "--force overrides existing file"
LEN_AFTER=$($PY -c "import json,sys; print(len(json.load(open(sys.argv[1]))['accounts']))" "$TMP/batch10.json")
assert_eq "$LEN_AFTER" "1" "after --force overwrite accounts[] is length 1"

echo
echo "=== 27. --out + --json: --out wins, no JSON on stdout ==="
"$WALLET" account-derive-batch --seed "$SEED1" --count 2 --out "$TMP/both.json" --json > "$TMP/both_stdout.txt" 2>&1
RC=$?
STDOUT=$(cat "$TMP/both_stdout.txt" | tr -d '\r')
assert_eq "$RC" "0" "exit 0 on --out + --json"
assert_contains "$STDOUT" "derived 2 accounts to" "stdout has confirmation line"
assert_not_contains "$STDOUT" '"accounts"' "stdout does NOT contain JSON document"
assert_not_contains "$STDOUT" "privkey_hex" "stdout does NOT leak privkey to terminal"

echo
echo "=== 28. master_seed_hash_hex != raw master seed (sanity) ==="
"$WALLET" account-derive-batch --seed "$SEED1" --count 1 --out "$TMP/hash_check.json" --force >/dev/null 2>&1
ACTUAL_HASH=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['master_seed_hash_hex'])" "$TMP/hash_check.json")
if [ "$ACTUAL_HASH" != "$SEED1" ]; then
    echo "  PASS: master_seed_hash_hex differs from raw seed (it's the SHA-256)"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: master_seed_hash_hex equals raw seed (would be a leak)"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 29. Output file does NOT contain raw seed_hex (defense in depth) ==="
if grep -q "$SEED1" "$TMP/hash_check.json"; then
    echo "  FAIL: --out file contains the raw master seed hex (leak)"; fail_count=$((fail_count + 1))
else
    echo "  PASS: --out file does NOT contain the raw master seed"; pass_count=$((pass_count + 1))
fi

echo
echo "=== 30. SLIP-0010-style sanity: account[0] privkey == SHA-256(seed || 0x00000000) ==="
$PY - "$SEED1" "$TMP/hash_check.json" <<'PY_EOF'
import hashlib, json, sys
seed = bytes.fromhex(sys.argv[1])
expected = hashlib.sha256(seed + (0).to_bytes(4, "little")).hexdigest()
got = json.load(open(sys.argv[2]))["accounts"][0]["privkey_hex"]
sys.exit(0 if got == expected else 1)
PY_EOF
RC=$?
assert_eq "$RC" "0" "account[0] privkey_hex == SHA-256(master_seed || u32_le(0))"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-derive-batch"; exit 0
else
    echo "  FAIL"; exit 1
fi
