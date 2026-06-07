#!/usr/bin/env bash
# `determ-wallet merkle-root` — offline S-033 committed state_root recompute.
#
# merkle-root rebuilds the WHOLE sorted-leaves balanced binary Merkle tree from a
# full leaf set and applies the S-040 leaf-count wrap, byte-for-byte per
# src/crypto/merkle.cpp::merkle_root (the inverse of state-proof-verify, which
# checks ONE leaf's path against a root). The wallet does not link the chain
# library, so the algorithm is reimplemented inline with OpenSSL SHA-256.
#
# This is a FULLY OFFLINE test (no cluster). It cross-checks merkle-root against
# (a) an independent Python reference of the exact algorithm, and (b) the
# wallet's already-validated `state-proof-verify`: a single-leaf tree's root must
# verify VALID through state-proof-verify with an empty proof — so merkle-root
# and the daemon-validated merkle_verify agree end-to-end.
# Soundness: docs/proofs/MerkleRootRecomputeSoundness.md.
#
# Run from repo root: bash tools/test_wallet_merkle_root.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

T=test_wallet_merkle_root
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# Independent Python reference of src/crypto/merkle.cpp::merkle_root + fixtures.
python - "$T" <<'PY'
import hashlib, json, sys
T = sys.argv[1]
def lh(key, vh): return hashlib.sha256(bytes([0]) + len(key).to_bytes(4,'big') + key + vh).digest()
def ih(l, r):    return hashlib.sha256(bytes([1]) + l + r).digest()
def root(leaves):
    if not leaves: return bytes(32)
    s = sorted(leaves, key=lambda x: x[0])
    row = [lh(k, v) for k, v in s]
    while len(row) > 1:
        if len(row) % 2 == 1: row.append(row[-1])
        row = [ih(row[i], row[i+1]) for i in range(0, len(row), 2)]
    return hashlib.sha256(bytes([2]) + len(leaves).to_bytes(4,'big') + row[0]).digest()
vh = bytes(range(32))
# 1, 2, 3, 5 leaves + empty. L3/L5 deliberately UNSORTED on input to test sort.
L1 = [(b"a:alice", vh)]
L3 = [(b"a:bob", vh), (b"a:alice", vh), (b"s:carol", vh)]
L5 = [(b"d:dapp1", vh), (b"a:alice", vh), (b"k:max", vh), (b"a:bob", vh), (b"r:reg", vh)]
def dump(name, leaves):
    open(f"{T}/{name}.json", "w").write(json.dumps([{"key": k.decode(), "value_hash": v.hex()} for k, v in leaves]))
dump("L1", L1); dump("L3", L3); dump("L5", L5)
open(f"{T}/empty.json", "w").write("[]")
# key vs key_hex equivalence: same leaf via key_hex.
open(f"{T}/L1hex.json", "w").write(json.dumps([{"key_hex": b"a:alice".hex(), "value_hash": vh.hex()}]))
exp = {"L1": root(L1).hex(), "L3": root(L3).hex(), "L5": root(L5).hex(), "empty": ("00"*32)}
open(f"{T}/expect.json", "w").write(json.dumps(exp))
PY

EXP_L1=$(python -c "import json;print(json.load(open('$T/expect.json'))['L1'])")
EXP_L3=$(python -c "import json;print(json.load(open('$T/expect.json'))['L3'])")
EXP_L5=$(python -c "import json;print(json.load(open('$T/expect.json'))['L5'])")
EXP_E=$(python -c "import json;print(json.load(open('$T/expect.json'))['empty'])")

mr_root() { "$DETERM_WALLET" merkle-root --leaves "$1" --json 2>/dev/null | python -c "import json,sys;print(json.load(sys.stdin).get('root',''))"; }

echo "=== 1. --help exit 0, no-args + bad-args exit 1 ==="
"$DETERM_WALLET" merkle-root --help >/dev/null 2>&1; assert "$([ $? -eq 0 ] && echo true || echo false)" "--help exit 0"
"$DETERM_WALLET" merkle-root >/dev/null 2>&1;        assert "$([ $? -eq 1 ] && echo true || echo false)" "no-args exit 1"

echo
echo "=== 2. root matches the independent Python reference (1/3/5 leaves + empty) ==="
for pair in "L1 $EXP_L1" "L3 $EXP_L3" "L5 $EXP_L5" "empty $EXP_E"; do
  name=${pair%% *}; exp=${pair##* }; got=$(mr_root "$T/$name.json")
  assert "$([ "$got" = "$exp" ] && echo true || echo false)" "$name root == Python ref ($got)"
done

echo
echo "=== 3. order-independence (merkle-root sorts by key) ==="
# Reverse L3's input order; root must be identical.
python -c "import json;d=json.load(open('$T/L3.json'));json.dump(d[::-1],open('$T/L3rev.json','w'))"
R_FWD=$(mr_root "$T/L3.json"); R_REV=$(mr_root "$T/L3rev.json")
assert "$([ "$R_FWD" = "$R_REV" ] && echo true || echo false)" "shuffled input -> same root"

echo
echo "=== 4. key vs key_hex equivalence ==="
R_KEY=$(mr_root "$T/L1.json"); R_HEX=$(mr_root "$T/L1hex.json")
assert "$([ "$R_KEY" = "$R_HEX" ] && echo true || echo false)" "key (UTF-8) == key_hex (binary) -> same root"

echo
echo "=== 5. --check VALID exit 0 / INVALID exit 2 ==="
"$DETERM_WALLET" merkle-root --leaves "$T/L3.json" --check "$EXP_L3" >/dev/null 2>&1
assert "$([ $? -eq 0 ] && echo true || echo false)" "--check correct root -> exit 0 (VALID)"
"$DETERM_WALLET" merkle-root --leaves "$T/L3.json" --check "$EXP_E" >/dev/null 2>&1
assert "$([ $? -eq 2 ] && echo true || echo false)" "--check wrong root -> exit 2 (INVALID)"

echo
echo "=== 6. tamper sensitivity: altering one value_hash changes the root ==="
python -c "
import json
d=json.load(open('$T/L3.json'))
d[0]['value_hash']='ff'+d[0]['value_hash'][2:]
json.dump(d,open('$T/L3tamper.json','w'))"
R_TAMPER=$(mr_root "$T/L3tamper.json")
assert "$([ "$R_TAMPER" != "$EXP_L3" ] && echo true || echo false)" "one altered value_hash -> different root"

echo
echo "=== 7. cross-command: 1-leaf merkle-root root verifies VALID via state-proof-verify ==="
# A single-leaf tree has an empty proof; state-proof-verify(key,vh,index 0,
# leaf_count 1, proof []) against merkle-root's root must be VALID — so
# merkle-root agrees with the independently-reimplemented, daemon-validated
# merkle_verify (tools/test_wallet_state_proof_verify.sh / committee-signed).
KEYHEX=$(python -c "print(b'a:alice'.hex())")
VHHEX=$(python -c "print(bytes(range(32)).hex())")
cat > "$T/proof.json" <<EOF
{"key_bytes":"$KEYHEX","value_hash":"$VHHEX","target_index":0,"leaf_count":1,"proof":[]}
EOF
SPV=$("$DETERM_WALLET" state-proof-verify --in "$T/proof.json" --root "$EXP_L1" 2>&1)
echo "$SPV" | grep -iq "VALID" && [ $? -eq 0 ] && assert true "merkle-root(1-leaf) root -> state-proof-verify VALID" || assert false "state-proof-verify cross-check VALID"

echo
echo "=== 8. arg validation ==="
echo '[{"value_hash":"zz","key":"x"}]' > "$T/badhex.json"
"$DETERM_WALLET" merkle-root --leaves "$T/badhex.json" >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "invalid value_hash hex -> exit 1"
echo '[{"value_hash":"'"$VHHEX"'","key":"x","key_hex":"6162"}]' > "$T/both.json"
"$DETERM_WALLET" merkle-root --leaves "$T/both.json" >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "both key + key_hex -> exit 1"
echo '[{"value_hash":"'"$VHHEX"'"}]' > "$T/neither.json"
"$DETERM_WALLET" merkle-root --leaves "$T/neither.json" >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "neither key nor key_hex -> exit 1"
echo '[{"value_hash":"abcd","key":"x"}]' > "$T/shortvh.json"
"$DETERM_WALLET" merkle-root --leaves "$T/shortvh.json" >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "non-32-byte value_hash -> exit 1"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_merkle_root"; exit 0
else
  echo "  FAIL: test_wallet_merkle_root"; exit 1
fi
