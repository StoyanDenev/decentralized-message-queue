#!/usr/bin/env bash
# `determ-wallet merkle-proof` — offline Merkle inclusion-proof generator.
#
# merkle-proof is the proof GENERATOR completing the offline Merkle triad:
# merkle-root BUILDS the committed state_root, state-proof-verify CONSUMES a
# proof, and merkle-proof GENERATES one. It reproduces src/crypto/merkle.cpp::
# merkle_proof byte-for-byte (the wallet does not link the chain library — TCB
# separation) and emits the exact rpc_state_proof reply shape, so its output
# round-trips directly through state-proof-verify.
#
# This is a FULLY OFFLINE test (no cluster). The load-bearing assertion is the
# ROUND-TRIP: for EVERY leaf in a set, the generated proof must verify VALID via
# state-proof-verify against the emitted state_root — covering every target
# position including the odd-row duplicate-last cases. It also pins consistency
# with merkle-root (same set => same state_root), the single-leaf empty-proof
# case, key vs key_hex, tamper -> INVALID, and key-not-found.
# Soundness: docs/proofs/MerkleProofGenSoundness.md.
#
# Run from repo root: bash tools/test_wallet_merkle_proof.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

T=test_wallet_merkle_proof
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT
W="$DETERM_WALLET"

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# Build leaf sets: L5 (odd -> exercises duplicate-last), L4 (even), L1 (single).
python - "$T" <<'PY'
import json, sys
T = sys.argv[1]
vh = bytes(range(32)).hex()
def dump(name, keys):
    json.dump([{"key": k, "value_hash": vh} for k in keys], open(f"{T}/{name}.json", "w"))
dump("L5", ["a:bob", "a:alice", "s:carol", "d:dapp1", "k:max"])
dump("L4", ["a:bob", "a:alice", "s:carol", "d:dapp1"])
dump("L1", ["a:solo"])
# key_hex fixture: same single leaf addressed by hex key.
json.dump([{"key_hex": b"a:solo".hex(), "value_hash": vh}], open(f"{T}/L1hex.json", "w"))
PY

echo "=== 1. --help exit 0, no-args + missing-key + both-keys exit 1 ==="
"$W" merkle-proof --help >/dev/null 2>&1;                       assert "$([ $? -eq 0 ] && echo true || echo false)" "--help exit 0"
"$W" merkle-proof >/dev/null 2>&1;                              assert "$([ $? -eq 1 ] && echo true || echo false)" "no-args exit 1"
"$W" merkle-proof --leaves "$T/L5.json" >/dev/null 2>&1;        assert "$([ $? -eq 1 ] && echo true || echo false)" "no --key/--key-hex exit 1"
"$W" merkle-proof --leaves "$T/L5.json" --key x --key-hex 6161 >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "both --key and --key-hex exit 1"

# Round-trip helper: generate a proof for KEY in FILE, verify via state-proof-verify.
roundtrip() {  # $1=leaves file  $2=key
  local p="$T/p.json"
  "$W" merkle-proof --leaves "$1" --key "$2" --json > "$p" 2>/dev/null || { echo "GEN_FAIL"; return; }
  local root; root=$(python -c "import json;print(json.load(open('$p'))['state_root'])")
  local out; out=$("$W" state-proof-verify --in "$p" --root "$root" 2>&1)
  if echo "$out" | grep -qi "VALID" && ! echo "$out" | grep -qi "INVALID"; then echo "VALID"; else echo "INVALID"; fi
}

echo
echo "=== 2. ROUND-TRIP: every leaf in L5 (odd, duplicate-last) verifies VALID ==="
ALL_OK=true
for k in a:bob a:alice s:carol d:dapp1 k:max; do
  r=$(roundtrip "$T/L5.json" "$k"); [ "$r" = "VALID" ] || ALL_OK=false
  echo "    $k -> $r"
done
assert "$ALL_OK" "all 5 leaves (L5) round-trip VALID via state-proof-verify"

echo
echo "=== 3. ROUND-TRIP: every leaf in L4 (even) verifies VALID ==="
ALL_OK=true
for k in a:bob a:alice s:carol d:dapp1; do
  r=$(roundtrip "$T/L4.json" "$k"); [ "$r" = "VALID" ] || ALL_OK=false
done
assert "$ALL_OK" "all 4 leaves (L4) round-trip VALID"

echo
echo "=== 4. single leaf: empty proof, round-trips VALID ==="
"$W" merkle-proof --leaves "$T/L1.json" --key "a:solo" --json > "$T/p1.json"
PLEN=$(python -c "import json;print(len(json.load(open('$T/p1.json'))['proof']))")
assert "$([ "$PLEN" = "0" ] && echo true || echo false)" "single-leaf proof is empty (proof_len=0)"
R1=$(roundtrip "$T/L1.json" "a:solo"); assert "$([ "$R1" = "VALID" ] && echo true || echo false)" "single-leaf round-trips VALID"

echo
echo "=== 5. consistency: emitted state_root == merkle-root over the same set ==="
"$W" merkle-proof --leaves "$T/L5.json" --key "a:alice" --json > "$T/p5.json"
SR_PROOF=$(python -c "import json;print(json.load(open('$T/p5.json'))['state_root'])")
SR_ROOT=$("$W" merkle-root --leaves "$T/L5.json" --json | python -c "import json,sys;print(json.load(sys.stdin)['root'])")
assert "$([ "$SR_PROOF" = "$SR_ROOT" ] && echo true || echo false)" "merkle-proof state_root == merkle-root root"

echo
echo "=== 6. key vs key_hex produce the same proof ==="
"$W" merkle-proof --leaves "$T/L1.json"    --key "a:solo"              --json > "$T/pk.json"
"$W" merkle-proof --leaves "$T/L1hex.json" --key-hex "$(python -c 'print(b"a:solo".hex())')" --json > "$T/ph.json"
SAME=$(python -c "import json;print(json.load(open('$T/pk.json'))==json.load(open('$T/ph.json')))")
assert "$([ "$SAME" = "True" ] && echo true || echo false)" "--key and --key-hex yield identical proof object"

echo
echo "=== 7. negative: tampering a sibling -> state-proof-verify INVALID (exit 2) ==="
python -c "
import json
d=json.load(open('$T/p5.json')); d['proof'][0]='ff'+d['proof'][0][2:]
json.dump(d,open('$T/p5tamper.json','w'))"
"$W" state-proof-verify --in "$T/p5tamper.json" --root "$SR_PROOF" >/dev/null 2>&1
assert "$([ $? -eq 2 ] && echo true || echo false)" "tampered sibling -> state-proof-verify INVALID exit 2"

echo
echo "=== 8. target key not in the set -> exit 1 ==="
"$W" merkle-proof --leaves "$T/L5.json" --key "a:nobody" >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "key not present -> exit 1"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_merkle_proof"; exit 0
else
  echo "  FAIL: test_wallet_merkle_proof"; exit 1
fi
