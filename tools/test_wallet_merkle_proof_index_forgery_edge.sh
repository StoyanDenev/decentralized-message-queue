#!/usr/bin/env bash
# `determ-wallet merkle-proof` -> `state-proof-verify` POSITION-BINDING edge.
#
# The offline Merkle triad's inclusion proof binds a leaf to a SPECIFIC sorted
# slot. `state-proof-verify` recomputes the root by walking the proof siblings,
# and at each level it uses target_index's parity (idx % 2) to decide whether the
# running hash is the LEFT or the RIGHT child:
#     current = (idx % 2 == 0) ? inner(current, sib) : inner(sib, current)
# (wallet/main.cpp cmd_state_proof_verify, the `idx % 2 == 0` branch at the
# merkle_verify walk). target_index is therefore consensus-load-bearing: a proof
# generated for sorted slot i MUST NOT verify when its target_index is re-pointed
# to a DIFFERENT in-range slot j != i, even though value_hash, key_bytes, proof[]
# and leaf_count are all left byte-identical. Re-pointing flips one or more
# left/right direction bits in the walk, so the recomputed root diverges and the
# verdict must be INVALID (exit 2). This is the position-binding contract that
# stops a malicious snapshot server from re-using one leaf's proof to assert that
# leaf sits at some OTHER position in the committed state tree.
#
# Why this is NOT already covered (non-duplication):
#   * tools/test_wallet_merkle_proof.sh round-trips every leaf VALID and tampers a
#     SIBLING BYTE (its case 7) — it never mutates target_index.
#   * tools/test_wallet_merkle_root.sh has no proof / target_index surface at all.
#   * tools/test_merkle_proof_tampering.sh covers target_index +/-1 + out-of-range,
#     but on the DAEMON's internally-generated proofs via the C++
#     `test-merkle-proof-tampering` subcommand — not a wallet `merkle-proof`-
#     GENERATED proof round-tripped through the wallet `state-proof-verify`.
#   * tools/test_light_state_proof_leaf_count_forgery_edge.sh is the LIGHT binary
#     and only forges target_index == leaf_count (OUT-of-range), never an in-range
#     wrong slot.
# So the in-range cross-slot target_index forgery on a wallet-generated proof,
# verified through the wallet verifier, is genuinely untested.
#
# FULLY OFFLINE (no cluster). Pure local SHA-256 via the two wallet subcommands.
#
# Run from repo root: bash tools/test_wallet_merkle_proof_index_forgery_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

W="$DETERM_WALLET"
T=test_wallet_merkle_proof_index_forgery_edge
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# 4-leaf set. Sorted by raw key bytes the order is deterministic:
#   index 0 = a:alice, 1 = a:bob, 2 = d:dapp1, 3 = s:carol.
# All four share one value_hash so the proof's ONLY position signal is
# target_index (no value_hash distinction the verifier could lean on).
VH=$(python -c "print(bytes(range(32)).hex())")
python -c "
import json
vh='$VH'
ks=['a:bob','a:alice','s:carol','d:dapp1']   # deliberately unsorted on input
json.dump([{'key':k,'value_hash':vh} for k in ks], open('$T/L4.json','w'))
"

# Generate a genuine proof for KEY, write it to $T/$1.json, and emit its root.
gen() {  # $1 = out-stem  $2 = key
  "$W" merkle-proof --leaves "$T/L4.json" --key "$2" --json > "$T/$1.json" 2>/dev/null
  python -c "import json;print(json.load(open('$T/$1.json'))['state_root'])"
}

# Re-point target_index to NEWIDX, keep everything else byte-identical, then
# verify against ROOT. Echo the state-proof-verify exit code.
forge_verify() {  # $1 = src-stem  $2 = newidx  $3 = root  -> echoes RC
  python -c "
import json
d=json.load(open('$T/$1.json'))
d['target_index']=$2
json.dump(d, open('$T/$1.forge$2.json','w'))
"
  "$W" state-proof-verify --in "$T/$1.forge$2.json" --root "$3" >/dev/null 2>&1
  echo $?
}

echo "=== 0. sanity: sorted indices are as assumed ==="
ALL_IDX_OK=true
for pair in "a:alice 0" "a:bob 1" "d:dapp1 2" "s:carol 3"; do
  k=${pair%% *}; want=${pair##* }
  got=$("$W" merkle-proof --leaves "$T/L4.json" --key "$k" --json 2>/dev/null \
        | python -c "import json,sys;print(json.load(sys.stdin)['target_index'])")
  [ "$got" = "$want" ] || ALL_IDX_OK=false
  echo "    $k -> target_index=$got (want $want)"
done
assert "$ALL_IDX_OK" "sorted target_index assignment matches expectation"

echo
echo "=== 1. CONTROL: genuine proofs verify VALID (exit 0) ==="
R_ALICE=$(gen alice a:alice)   # sorted index 0 (even)
R_BOB=$(gen bob   a:bob)       # sorted index 1 (odd)
"$W" state-proof-verify --in "$T/alice.json" --root "$R_ALICE" >/dev/null 2>&1
assert "$([ $? -eq 0 ] && echo true || echo false)" "genuine a:alice proof -> VALID exit 0"
"$W" state-proof-verify --in "$T/bob.json" --root "$R_BOB" >/dev/null 2>&1
assert "$([ $? -eq 0 ] && echo true || echo false)" "genuine a:bob proof -> VALID exit 0"
# The two genuine proofs are byte-identical in value_hash but MUST differ in
# target_index — proving target_index is the live position discriminator.
TI_A=$(python -c "import json;print(json.load(open('$T/alice.json'))['target_index'])")
TI_B=$(python -c "import json;print(json.load(open('$T/bob.json'))['target_index'])")
VH_A=$(python -c "import json;print(json.load(open('$T/alice.json'))['value_hash'])")
VH_B=$(python -c "import json;print(json.load(open('$T/bob.json'))['value_hash'])")
assert "$([ "$VH_A" = "$VH_B" ] && [ "$TI_A" != "$TI_B" ] && echo true || echo false)" \
       "same value_hash, distinct target_index -> position rides on target_index alone"

echo
echo "=== 2. FORGE: even-index leaf re-pointed to odd slot (0 -> 1) -> INVALID ==="
# Level-0 parity flips even->odd: verifier swaps inner(current,sib) for
# inner(sib,current); the recomputed root diverges -> exit 2.
RC=$(forge_verify alice 1 "$R_ALICE")
assert "$([ "$RC" = "2" ] && echo true || echo false)" "a:alice proof @ target_index=1 -> INVALID exit 2 (got RC=$RC)"

echo
echo "=== 3. FORGE: odd-index leaf re-pointed to even slot (1 -> 0) -> INVALID ==="
RC=$(forge_verify bob 0 "$R_BOB")
assert "$([ "$RC" = "2" ] && echo true || echo false)" "a:bob proof @ target_index=0 -> INVALID exit 2 (got RC=$RC)"

echo
echo "=== 4. FORGE: deep re-point across a higher level (0 -> 3) -> INVALID ==="
# 0 (binary 00) vs 3 (binary 11): BOTH the level-0 and level-1 direction bits
# differ, so two left/right decisions in the walk are wrong at once.
RC=$(forge_verify alice 3 "$R_ALICE")
assert "$([ "$RC" = "2" ] && echo true || echo false)" "a:alice proof @ target_index=3 -> INVALID exit 2 (got RC=$RC)"

echo
echo "=== 5. FORGE: re-point to a slot with matching low bit (0 -> 2) -> INVALID ==="
# 0 (00) and 2 (10) share the level-0 bit but differ at level 1, so the
# low-level direction matches yet the upper level still diverges -> must reject.
# This guards against a verifier that only checks the first sibling's side.
RC=$(forge_verify alice 2 "$R_ALICE")
assert "$([ "$RC" = "2" ] && echo true || echo false)" "a:alice proof @ target_index=2 -> INVALID exit 2 (got RC=$RC)"

echo
echo "=== 6. NEGATIVE-CONTROL: restoring the true target_index re-verifies VALID ==="
# Proves the rejections above are caused by target_index alone, not by some
# unrelated corruption introduced when rewriting the JSON.
python -c "
import json
d=json.load(open('$T/alice.forge2.json'))   # the mutated file from step 5
d['target_index']=0                          # put the true index back
json.dump(d, open('$T/alice.restored.json','w'))
"
"$W" state-proof-verify --in "$T/alice.restored.json" --root "$R_ALICE" >/dev/null 2>&1
assert "$([ $? -eq 0 ] && echo true || echo false)" "restoring true target_index=0 -> VALID exit 0"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_merkle_proof_index_forgery_edge"; exit 0
else
  echo "  FAIL: test_wallet_merkle_proof_index_forgery_edge"; exit 1
fi
