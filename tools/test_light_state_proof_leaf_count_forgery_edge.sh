#!/usr/bin/env bash
# determ-light verify-state-proof — S-040 leaf_count forgery + --state-root
# length-guard edge. FULLY OFFLINE (no cluster, no daemon, no RPC).
#
# WHY THIS EDGE IS UNCOVERED
# --------------------------
# Every existing determ-light verify-state-proof test tampers value_hash,
# a sibling, or the state_root VALUE:
#   - test_light_verify_state_proof.sh / test_verify_state_proof.sh : cluster,
#     value_hash + sibling + wrong-root only.
#   - test_wallet_state_proof_vs_daemon.sh : cluster, wrong-root only.
#   - test_merkle_cross_binary_fuzz.sh : offline, but flips ONLY proof[0],
#     value_hash, and the --state-root byte. Its header NAMES "the S-040
#     leaf-count wrap" as a thing that could drift, yet it never mutates the
#     `leaf_count` FIELD, never an out-of-range `target_index`, and never a
#     wrong-LENGTH `--state-root`.
# So three distinct guards in the light verifier have ZERO file-based
# coverage at the determ-light CLI layer:
#
#   (1) S-040 leaf_count binding. crypto::merkle_verify finishes with
#         merkle_root_wrap(inner_root, leaf_count) == root
#       i.e. the committed root is SHA-256(0x02 || u32_be(leaf_count) ||
#       inner_root). A proof whose proof[]/value_hash/target_index/root are
#       ALL untouched but whose claimed `leaf_count` is bumped up OR down
#       must be REJECTED — otherwise a malicious server could mis-state the
#       tree size to splice a leaf from one tree into another. We tamper
#       leaf_count in BOTH directions while leaving the 2-sibling proof
#       intact, so the ONLY thing that can reject it is the S-040 wrap
#       binding (not a sibling-count mismatch).
#
#   (2) target_index out-of-range. merkle_verify rejects target_index >=
#       leaf_count up front. We set target_index == leaf_count.
#
#   (3) --state-root LENGTH guard. light/verify.cpp checks the CLI flag is
#       exactly 64 hex chars BEFORE any Merkle math, emitting a distinct
#       "--state-root must be 64 hex chars" message (NOT the "FAIL:
#       merkle_verify rejected" path the fuzz's wrong-VALUE root hits).
#       This proves the two rejection layers are separate.
#
# The proof FIXTURE is generated 100% offline by determ-wallet `merkle-proof`
# (the proof GENERATOR that emits the exact rpc_state_proof reply shape), so
# this test needs no cluster and no hand-rolled Merkle oracle — the real
# wallet binary builds a genuine valid proof, the real light binary judges
# every variant. The happy-path control (unmodified proof -> OK, exit 0)
# proves the rejections are caused by the tamper and not by a broken fixture.
#
# Assertions:
#   1. CONTROL: unmodified wallet-generated proof -> determ-light OK, exit 0.
#   2. leaf_count bumped UP (4 -> 5), proof/root untouched -> FAIL, exit 1.
#   3. leaf_count bumped DOWN (4 -> 3), proof/root untouched -> FAIL, exit 1.
#   4. target_index out-of-range (== leaf_count) -> FAIL, exit 1.
#   5. wrong-LENGTH --state-root (32 hex) -> distinct length-guard error,
#      exit 1 (NOT the merkle_verify FAIL path).
#   6. CONTROL still OK after the tampers (fixture undamaged / layers distinct).
#
# SKIP-with-PASS (exit 0) when determ-wallet or determ-light is absent.
#
# Run from repo root: bash tools/test_light_state_proof_leaf_count_forgery_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found (needed as the OFFLINE proof"
    echo "        generator); build with"
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
command -v python >/dev/null 2>&1 || PY=python3

T="build/test_light_state_proof_leaf_count_forgery_edge.$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 0. Build a 4-leaf set + generate a REAL proof offline (no cluster) ==="
# Four distinct keys -> sorted tree of 4 leaves -> the proof for any leaf has
# exactly TWO siblings (one per level). Tampering leaf_count by +/-1 keeps the
# sibling COUNT consistent enough that the ONLY rejector is the S-040 wrap.
$PY -c "
import json
leaves = [
  {'key': 'a:alice', 'value_hash': '11' * 32},
  {'key': 'a:bob',   'value_hash': '22' * 32},
  {'key': 'a:carol', 'value_hash': '33' * 32},
  {'key': 'a:dave',  'value_hash': '44' * 32},
]
json.dump(leaves, open('$T/leaves.json', 'w'))
"
if ! "$W" merkle-proof --leaves "$T/leaves.json" --key "a:alice" --json \
        > "$T/proof.json" 2>"$T/gen.err"; then
    cat "$T/gen.err"
    assert "false" "wallet merkle-proof generated a proof fixture"
    echo "  $pass_count pass / $fail_count fail"
    echo "  FAIL: test_light_state_proof_leaf_count_forgery_edge"; exit 1
fi
# Sanity: the fixture must really be a 4-leaf, 2-sibling proof, else the
# leaf_count +/-1 tampers below wouldn't isolate the S-040 binding.
SHAPE=$($PY -c "
import json
d = json.load(open('$T/proof.json'))
ok = (d.get('leaf_count') == 4 and len(d.get('proof', [])) == 2
      and d.get('target_index') == 0 and len(d.get('state_root','')) == 64)
print('true' if ok else 'false')
")
assert "$SHAPE" "offline fixture is a 4-leaf / 2-sibling proof (leaf_count=4)"

echo
echo "=== 1. CONTROL: unmodified proof -> determ-light OK, exit 0 ==="
set +e
OUT=$("$L" verify-state-proof --in "$T/proof.json" 2>&1); RC=$?
set -e
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
if [ "$RC" = "0" ] && [ "$OK" = "true" ]; then
    assert "true" "control: valid proof verifies OK, exit 0"
else
    echo "$OUT"
    assert "false" "control: valid proof verifies OK, exit 0 (RC=$RC)"
fi

echo
echo "=== 2. S-040: leaf_count 4 -> 5 (proof + root untouched) -> FAIL ==="
# Only the claimed leaf_count changes. The committed root binds leaf_count via
# merkle_root_wrap, so SHA-256(0x02 || u32_be(5) || inner_root) != root.
$PY -c "
import json
d = json.load(open('$T/proof.json'))
d['leaf_count'] = 5
json.dump(d, open('$T/lc_up.json', 'w'))
"
set +e
OUT=$("$L" verify-state-proof --in "$T/lc_up.json" 2>&1); RC=$?
set -e
FAIL=$(echo "$OUT" | grep -q "FAIL: merkle_verify rejected" && echo true || echo false)
if [ "$RC" = "1" ] && [ "$FAIL" = "true" ]; then
    assert "true" "forged leaf_count (up) -> merkle_verify FAIL, exit 1"
else
    echo "$OUT"
    assert "false" "forged leaf_count (up) -> merkle_verify FAIL, exit 1 (RC=$RC)"
fi

echo
echo "=== 3. S-040: leaf_count 4 -> 3 (proof + root untouched) -> FAIL ==="
$PY -c "
import json
d = json.load(open('$T/proof.json'))
d['leaf_count'] = 3
json.dump(d, open('$T/lc_dn.json', 'w'))
"
set +e
OUT=$("$L" verify-state-proof --in "$T/lc_dn.json" 2>&1); RC=$?
set -e
FAIL=$(echo "$OUT" | grep -q "FAIL: merkle_verify rejected" && echo true || echo false)
if [ "$RC" = "1" ] && [ "$FAIL" = "true" ]; then
    assert "true" "forged leaf_count (down) -> merkle_verify FAIL, exit 1"
else
    echo "$OUT"
    assert "false" "forged leaf_count (down) -> merkle_verify FAIL, exit 1 (RC=$RC)"
fi

echo
echo "=== 4. target_index out-of-range (== leaf_count) -> FAIL ==="
# merkle_verify rejects target_index >= leaf_count before walking the proof.
$PY -c "
import json
d = json.load(open('$T/proof.json'))
d['target_index'] = d['leaf_count']   # 4 == leaf_count -> out of range
json.dump(d, open('$T/ti_oor.json', 'w'))
"
set +e
OUT=$("$L" verify-state-proof --in "$T/ti_oor.json" 2>&1); RC=$?
set -e
FAIL=$(echo "$OUT" | grep -q "FAIL: merkle_verify rejected" && echo true || echo false)
if [ "$RC" = "1" ] && [ "$FAIL" = "true" ]; then
    assert "true" "out-of-range target_index -> merkle_verify FAIL, exit 1"
else
    echo "$OUT"
    assert "false" "out-of-range target_index -> merkle_verify FAIL, exit 1 (RC=$RC)"
fi

echo
echo "=== 5. wrong-LENGTH --state-root (32 hex) -> distinct length guard ==="
# This is a DIFFERENT rejection path than a wrong-VALUE 64-hex root: the CLI
# checks the flag length first and emits its own message before any Merkle
# math. Proves the length guard and the merkle FAIL are separate layers.
SHORT_ROOT="abcdef0123456789abcdef0123456789"   # 32 hex chars, not 64
set +e
OUT=$("$L" verify-state-proof --in "$T/proof.json" --state-root "$SHORT_ROOT" 2>&1); RC=$?
set -e
LEN_GUARD=$(echo "$OUT" | grep -q "state-root must be 64 hex chars" && echo true || echo false)
NOT_MERKLE=$(echo "$OUT" | grep -q "merkle_verify rejected" && echo false || echo true)
if [ "$RC" = "1" ] && [ "$LEN_GUARD" = "true" ] && [ "$NOT_MERKLE" = "true" ]; then
    assert "true" "wrong-length --state-root -> length guard (not merkle FAIL), exit 1"
else
    echo "$OUT"
    assert "false" "wrong-length --state-root -> length guard, exit 1 (RC=$RC)"
fi

echo
echo "=== 6. CONTROL re-check: original proof still OK (fixture undamaged) ==="
set +e
OUT=$("$L" verify-state-proof --in "$T/proof.json" 2>&1); RC=$?
set -e
OK=$(echo "$OUT" | head -1 | grep -q "^OK$" && echo true || echo false)
if [ "$RC" = "0" ] && [ "$OK" = "true" ]; then
    assert "true" "control still OK after tampers (layers distinct)"
else
    echo "$OUT"
    assert "false" "control still OK after tampers (RC=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_state_proof_leaf_count_forgery_edge"; exit 0
else
  echo "  FAIL: test_light_state_proof_leaf_count_forgery_edge"; exit 1
fi
