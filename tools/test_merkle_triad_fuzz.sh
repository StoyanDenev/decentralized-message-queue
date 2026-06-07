#!/usr/bin/env bash
# Merkle triad fuzz / cross-tool consistency — the offline state-tree commands
# (determ-wallet merkle-root / merkle-proof / state-proof-verify) must agree
# with each other AND with an independent reference across MANY random leaf-set
# shapes, not just the hand-picked fixtures in their per-command tests.
#
# Each command reimplements src/crypto/merkle.cpp byte-for-byte inside the
# chain-library-free wallet TCB (see MerkleRootRecomputeSoundness.md MR-1,
# MerkleProofGenSoundness.md MP-1/MP-2). The tree-walk has size-dependent edge
# cases — odd-vs-even rows triggering the duplicate-last rule at different
# levels, the single-leaf empty-proof base case, the S-040 leaf-count wrap — that
# a small fixed fixture set can miss. This fuzz harness exercises leaf counts
# 1..48 with a FIXED seed (reproducible) and asserts, per random set:
#   (A) merkle-root == an independent Python reference of the exact algorithm;
#   (B) merkle-proof(target) round-trips VALID through state-proof-verify against
#       the emitted state_root (every random target position);
#   (C) merkle-proof's emitted state_root == merkle-root's root (cross-tool);
#   (D) tampering one proof sibling flips state-proof-verify to INVALID.
#
# Fully OFFLINE (no cluster). Run from repo root: bash tools/test_merkle_triad_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

T=test_merkle_triad_fuzz
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT
W="$DETERM_WALLET"
ITERS="${FUZZ_ITERS:-48}"

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# Generate ITERS random leaf sets (sizes 1..ITERS) + a manifest of the expected
# root and a random target key per set, using an independent Python reference of
# src/crypto/merkle.cpp::merkle_root with a FIXED seed for reproducibility.
python - "$T" "$ITERS" <<'PY'
import hashlib, json, os, random, sys
T, iters = sys.argv[1], int(sys.argv[2])
random.seed(0xDE7E124)  # fixed -> reproducible (Determ "determ" pun, why not)
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
manifest = []
for it in range(iters):
    n = it + 1  # sizes 1..iters, hitting every parity at every level
    keys = set()
    while len(keys) < n:
        keys.add("k%d:%s" % (it, ''.join(random.choice('0123456789abcdef') for _ in range(random.randint(1,12)))))
    keys = list(keys)
    leaves = [(k.encode(), bytes(random.getrandbits(8) for _ in range(32))) for k in keys]
    # leaf file (random INPUT order — merkle-root/proof must sort internally)
    random.shuffle(leaves)
    json.dump([{"key": k.decode(), "value_hash": v.hex()} for k, v in leaves],
              open(f"{T}/L{it}.json", "w"))
    tgt = random.choice(leaves)[0].decode()
    manifest.append({"it": it, "n": n, "root": root(leaves).hex(), "target": tgt})
json.dump(manifest, open(f"{T}/manifest.json", "w"))
print("generated", iters, "random leaf sets (sizes 1..%d)" % iters)
PY

echo "=== fuzzing $ITERS random leaf sets (sizes 1..$ITERS) across the triad ==="
ROOT_OK=true; RT_OK=true; XCHK_OK=true; TAMPER_OK=true
N=$(python -c "import json;print(len(json.load(open('$T/manifest.json'))))")
i=0
while [ "$i" -lt "$N" ]; do
  exp=$(python -c "import json;print(json.load(open('$T/manifest.json'))[$i]['root'])")
  tgt=$(python -c "import json;print(json.load(open('$T/manifest.json'))[$i]['target'])")
  Lf="$T/L$i.json"

  # (A) merkle-root == Python reference
  got=$("$W" merkle-root --leaves "$Lf" --json 2>/dev/null | python -c "import json,sys;print(json.load(sys.stdin).get('root',''))")
  [ "$got" = "$exp" ] || { ROOT_OK=false; echo "    iter $i (n=$((i+1))): root mismatch got=$got exp=$exp"; }

  # (B)+(C) merkle-proof(target) -> state-proof-verify VALID; root cross-check
  "$W" merkle-proof --leaves "$Lf" --key "$tgt" --json > "$T/p.json" 2>/dev/null || { RT_OK=false; echo "    iter $i: proof-gen failed"; i=$((i+1)); continue; }
  proot=$(python -c "import json;print(json.load(open('$T/p.json'))['state_root'])")
  [ "$proot" = "$exp" ] || { XCHK_OK=false; echo "    iter $i: proof state_root != root"; }
  out=$("$W" state-proof-verify --in "$T/p.json" --root "$proot" 2>&1)
  if ! { echo "$out" | grep -qi "VALID" && ! echo "$out" | grep -qi "INVALID"; }; then
    RT_OK=false; echo "    iter $i (n=$((i+1)), target=$tgt): round-trip NOT VALID"
  fi

  # (D) tamper one sibling -> INVALID (only when the proof is non-empty)
  plen=$(python -c "import json;print(len(json.load(open('$T/p.json'))['proof']))")
  if [ "$plen" -gt 0 ]; then
    python -c "
import json
d=json.load(open('$T/p.json')); s=d['proof'][0]
d['proof'][0]='%02x'%(int(s[:2],16)^0xff)+s[2:]  # XOR -> always a real change
json.dump(d,open('$T/pt.json','w'))"
    "$W" state-proof-verify --in "$T/pt.json" --root "$proot" >/dev/null 2>&1
    [ $? -eq 2 ] || { TAMPER_OK=false; echo "    iter $i: tampered proof not rejected"; }
  fi
  i=$((i+1))
done

assert "$ROOT_OK"   "(A) merkle-root == Python reference for all $N random sets"
assert "$RT_OK"     "(B) merkle-proof -> state-proof-verify VALID for all $N random targets"
assert "$XCHK_OK"   "(C) merkle-proof state_root == merkle-root root for all $N sets"
assert "$TAMPER_OK" "(D) tampered sibling -> state-proof-verify INVALID for all non-trivial sets"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail  (over $N random leaf sets, sizes 1..$N)"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_merkle_triad_fuzz"; exit 0
else
  echo "  FAIL: test_merkle_triad_fuzz"; exit 1
fi
