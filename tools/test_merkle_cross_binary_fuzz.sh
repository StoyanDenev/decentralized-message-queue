#!/usr/bin/env bash
# Cross-BINARY Merkle parity fuzz — determ-wallet (proof GENERATOR) vs
# determ-light (proof VERIFIER) must agree on every random leaf set, with NO
# hand-rolled Merkle reference anywhere in this test.
#
# The two binaries are DIFFERENT implementations of the same S-033 sorted-leaves
# balanced binary Merkle tree (src/crypto/merkle.cpp::merkle_proof on the wallet
# side; light/verify_state_proof.cpp::merkle_verify on the light side). If either
# drifts — leaf domain-separation byte, inner-node order, odd-row duplicate-last
# rule, the S-040 leaf-count wrap, target_index handling — the round-trip breaks.
# This harness makes the OTHER binary the reference, so correctness is judged by
# AGREEMENT BETWEEN TWO INDEPENDENT IMPLEMENTATIONS rather than by a Python copy
# of the algorithm (a re-implementation can itself be wrong — the #1 way a fuzz
# test gives false confidence). It is therefore deliberately disjoint from
# test_merkle_triad_fuzz.sh, which checks the wallet triad against a Python
# reference and never invokes determ-light.
#
# Per random leaf set (fixed seed -> reproducible), sizes 1..N covering empty
# (size 0), single (empty proof), and every odd/even parity at every tree level:
#   (A) ROUND-TRIP: wallet `merkle-proof`(target) -> light `verify-state-proof
#       --state-root <emitted>` is VALID (exit 0) for EVERY leaf as target.
#   (B) ROOT-AGREE: wallet `merkle-root` root == wallet `merkle-proof` state_root
#       AND the light binary accepts that same root — three surfaces, one value.
#   (C) TAMPER(sibling): XOR-flip proof[0] -> light REJECTS (exit 1).
#   (D) TAMPER(value_hash): XOR-flip the leaf value_hash -> light REJECTS.
#   (E) WRONG-ROOT: XOR-flip the --state-root byte -> light REJECTS (exit 1).
#
# Fully OFFLINE — no cluster, no daemon. Both commands are pure local SHA-256.
# Run from repo root: bash tools/test_merkle_cross_binary_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi
W="$DETERM_WALLET"
L="$DETERM_LIGHT"
PY=python
ITERS="${FUZZ_ITERS:-24}"   # >= 20 random leaf sets (sizes 1..ITERS)

T=test_merkle_cross_binary_fuzz
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# ── Generate ITERS random leaf sets (sizes 1..ITERS), random INPUT order so the
#    binaries must sort internally. FIXED seed -> reproducible. NO Merkle math
#    here — this only emits leaf files + picks a random target key per set. The
#    expected root is NEVER computed in this script; the binaries supply it.
$PY - "$T" "$ITERS" <<'PYGEN'
import json, os, random, sys
T, iters = sys.argv[1], int(sys.argv[2])
random.seed(0xC0FFEE42)  # fixed -> reproducible
manifest = []
for it in range(iters):
    n = it + 1  # sizes 1..iters -> every parity at every level (1=single, etc.)
    keys = set()
    while len(keys) < n:
        keys.add("k%d_%s" % (it, ''.join(random.choice('0123456789abcdef')
                                         for _ in range(random.randint(1, 14)))))
    keys = list(keys)
    leaves = [(k, bytes(random.getrandbits(8) for _ in range(32))) for k in keys]
    random.shuffle(leaves)  # random input order; binaries sort internally
    json.dump([{"key": k, "value_hash": v.hex()} for k, v in leaves],
              open(f"{T}/L{it}.json", "w"))
    # ALL leaves are proof targets (every position), so (A) exercises every path
    manifest.append({"it": it, "n": n, "keys": [k for k, _ in leaves]})
json.dump(manifest, open(f"{T}/manifest.json", "w"))
print("generated %d random leaf sets (sizes 1..%d), %d total targets"
      % (iters, iters, sum(len(m["keys"]) for m in manifest)))
PYGEN

echo "=== cross-binary fuzz: wallet GENERATES, light VERIFIES (no algo reference) ==="
N=$($PY -c "import json;print(len(json.load(open('$T/manifest.json'))))")

RT_OK=true        # (A) every wallet-proof round-trips VALID through light
ROOTAGREE_OK=true # (B) wallet merkle-root == wallet proof state_root, light accepts
TAMPER_SIB_OK=true   # (C) sibling tamper rejected by light
TAMPER_VH_OK=true    # (D) value_hash tamper rejected by light
WRONGROOT_OK=true    # (E) flipped --state-root rejected by light
targets_tested=0

i=0
while [ "$i" -lt "$N" ]; do
  Lf="$T/L$i.json"

  # (B) wallet's whole-tree root must equal the proof's emitted state_root.
  wroot=$("$W" merkle-root --leaves "$Lf" --json 2>/dev/null \
            | $PY -c "import json,sys;print(json.load(sys.stdin).get('root',''))")

  # Iterate EVERY key in this set as the proof target. Keys come from a
  # newline-list read with `read -r` and then have any trailing CR stripped
  # (`key=${key%$'\r'}`): on Windows Python `print` emits CRLF, and a trailing
  # \r in the --key value breaks the wallet's exact-match lookup. One Python
  # call per set materializes the key list; the per-target "prep" call below
  # does ALL the JSON mutation in a single process to keep the harness fast.
  $PY -c "import json;print('\n'.join(json.load(open('$T/manifest.json'))[$i]['keys']))" > "$T/keys.txt"
  first_key=1
  while IFS= read -r key; do
    key=${key%$'\r'}
    [ -n "$key" ] || continue
    targets_tested=$((targets_tested + 1))

    # wallet generates the inclusion proof (rpc_state_proof shape + state_root)
    if ! "$W" merkle-proof --leaves "$Lf" --key "$key" --json > "$T/p.json" 2>/dev/null; then
      RT_OK=false; echo "    iter $i key=$key: wallet proof-gen FAILED"; continue
    fi

    # ONE prep subprocess: read p.json, emit "<state_root> <bad_root> <plen>",
    # and write the value_hash-tampered (pv.json) + sibling-tampered (pt.json)
    # variants. XOR-flips guarantee every mutation is a REAL change even when
    # the original first byte is already 0xff. No Merkle math here — pure field
    # surgery on the wallet's own output.
    prep=$($PY -c "
import json
d=json.load(open('$T/p.json'))
root=d['state_root']
bad ='%02x'%(int(root[:2],16)^0xff)+root[2:]
v=d['value_hash']; dv=dict(d); dv['value_hash']='%02x'%(int(v[:2],16)^0xff)+v[2:]
json.dump(dv,open('$T/pv.json','w'))
pl=len(d['proof'])
if pl>0:
    s=d['proof'][0]; dt=dict(d); dt['proof']=list(d['proof'])
    dt['proof'][0]='%02x'%(int(s[:2],16)^0xff)+s[2:]
    json.dump(dt,open('$T/pt.json','w'))
print(root, bad, pl)")
    proot=$(echo "$prep" | awk '{print $1}')
    badroot=$(echo "$prep" | awk '{print $2}')
    plen=$(echo "$prep" | awk '{print $3}')

    # (B) three-surface root agreement (once per set, against the first target)
    if [ "$first_key" = "1" ]; then
      [ "$wroot" = "$proot" ] || { ROOTAGREE_OK=false
        echo "    iter $i (n=$((i+1))): merkle-root($wroot) != proof state_root($proot)"; }
      first_key=0
    fi

    # (A) round-trip VALID: light (a DIFFERENT impl) accepts the wallet's proof
    #     against the wallet's emitted root. exit 0 == VALID.
    if ! "$L" verify-state-proof --in "$T/p.json" --state-root "$proot" >/dev/null 2>&1; then
      RT_OK=false; echo "    iter $i key=$key: cross-binary round-trip NOT VALID"
    fi

    # (E) WRONG-ROOT: XOR-flipped root -> light must REJECT.
    "$L" verify-state-proof --in "$T/p.json" --state-root "$badroot" >/dev/null 2>&1
    [ $? -ne 0 ] || { WRONGROOT_OK=false
      echo "    iter $i key=$key: light ACCEPTED a flipped state_root"; }

    # (D) TAMPER value_hash: XOR-flipped leaf value -> light must REJECT.
    "$L" verify-state-proof --in "$T/pv.json" --state-root "$proot" >/dev/null 2>&1
    [ $? -ne 0 ] || { TAMPER_VH_OK=false
      echo "    iter $i key=$key: light ACCEPTED a flipped value_hash"; }

    # (C) TAMPER sibling: only meaningful when the proof has >=1 sibling
    #     (single-leaf sets emit an empty proof -> nothing to flip; (D)/(E) cover them).
    if [ "$plen" -gt 0 ]; then
      "$L" verify-state-proof --in "$T/pt.json" --state-root "$proot" >/dev/null 2>&1
      [ $? -ne 0 ] || { TAMPER_SIB_OK=false
        echo "    iter $i key=$key: light ACCEPTED a flipped sibling"; }
    fi
  done < "$T/keys.txt"
  i=$((i + 1))
done

echo
assert "$RT_OK"         "(A) wallet proof -> light verify VALID for all $targets_tested targets over $N sets"
assert "$ROOTAGREE_OK"  "(B) wallet merkle-root == proof state_root, light-accepted, all $N sets"
assert "$TAMPER_SIB_OK" "(C) flipped sibling -> light REJECTS (every non-trivial proof)"
assert "$TAMPER_VH_OK"  "(D) flipped value_hash -> light REJECTS (every target)"
assert "$WRONGROOT_OK"  "(E) flipped --state-root -> light REJECTS (every target)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail  ($N random leaf sets, $targets_tested targets, sizes 1..$N)"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_merkle_cross_binary_fuzz"; exit 0
else
  echo "  FAIL: test_merkle_cross_binary_fuzz"; exit 1
fi
