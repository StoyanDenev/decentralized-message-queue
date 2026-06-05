#!/usr/bin/env bash
# determ-wallet block-tx-root CLI test.
#
# Exercises the OFFLINE recompute of the canonical Block.tx_root from a block
# JSON's creator_tx_lists. This is the EXACT accept gate the daemon's
# validator runs (src/node/validator.cpp:165-166):
#
#     Hash expected_root = compute_tx_root(b.creator_tx_lists);
#     if (expected_root != b.tx_root) <reject the block>
#
# tx_root is NOT a per-tx Merkle root and NOT the chained digest over full
# transaction signing_bytes. It is the commitment over the sorted-dedup UNION
# of the per-creator tx_hash lists (src/node/producer.cpp::compute_tx_root):
#
#     u = sorted std::set of every 32-byte tx_hash across all creator lists
#     tx_root = SHA-256( u[0] || u[1] || ... || u[n-1] )   (canonical order)
#
# Properties this test pins:
#   * union:           {A,B} U {B,C}  =>  {A,B,C}
#   * dedup:           identical tx_hashes across creator lists collapse
#   * order-invariant: list order + within-list order do not affect the root
#   * empty union:     no transactions => SHA-256("") = e3b0c4...
#
# This test recomputes the EXPECTED tx_root independently in Python (a sorted
# set of the raw 32-byte hashes, concatenated, SHA-256'd) and asserts the
# wallet output matches it exactly — correctness, not just shape. No cluster,
# no daemon, no network: pure offline derivation.
#
# Differentiation vs sibling commands:
#   * derive-tx-hash             — recompute a single TRANSACTION hash from an
#                                  envelope (SHA-256 of signing_bytes).
#   * committee-signature-verify — verify committee sigs over a daemon-pinned
#                                  block_digest (needs the digest).
#   * block-tx-root              — recompute + (optionally) --check ONE
#                                  consensus rule (the validator's tx_root gate)
#                                  with pure local SHA-256.
#
# Assertions (~20):
#   1.  Global help mentions block-tx-root.
#   2.  block-tx-root --help exits 0.
#   3.  Unknown CLI arg: exit 1.
#   4.  Missing --block-json: exit 1.
#   5.  Non-existent file: exit 1.
#   6.  Not-a-JSON-object input: exit 1.
#   7.  Missing creator_tx_lists: exit 1.
#   8.  creator_tx_lists not an array: exit 1.
#   9.  tx_hash wrong length: exit 1.
#  10.  tx_hash invalid hex: exit 1.
#  11.  Happy path (union of two lists): exit 0.
#  12.  recomputed_tx_root matches independent Python computation.
#  13.  leaf_count == size of deduped union.
#  14.  --json parseable + has recomputed_tx_root + leaf_count keys.
#  15.  Dedup: duplicate tx_hash across lists collapses (leaf_count, root).
#  16.  Order-invariance: permuting lists gives the same root.
#  17.  Empty union (no transactions) => SHA-256("").
#  18.  --check match: exit 0 + match=true.
#  19.  --check mismatch: exit 2 + match=false.
#  20.  Determinism: two invocations give identical recomputed_tx_root.
#
# Run from repo root: bash tools/test_wallet_block_tx_root.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

field() {  # field <json> <key>
  echo "$1" | $PY -c "import json,sys; print(json.loads(sys.stdin.read()).get('$2',''))"
}

# Independent reference: tx_root = SHA-256 over the sorted-dedup union of the
# raw 32-byte tx_hashes across all creator lists. Reads a block JSON file.
ref_tx_root() {  # ref_tx_root <block.json>
  $PY -c "
import json, hashlib, sys
b = json.load(open('$1'))
u = set()
for lst in b['creator_tx_lists']:
    for h in lst:
        u.add(bytes.fromhex(h))
buf = b''.join(sorted(u))
print(hashlib.sha256(buf).hexdigest())
"
}
ref_leaf_count() {  # ref_leaf_count <block.json>
  $PY -c "
import json
b = json.load(open('$1'))
u = set()
for lst in b['creator_tx_lists']:
    for h in lst:
        u.add(h.lower())
print(len(u))
"
}

# Fixed 32-byte tx_hash test vectors (64 hex chars each).
HA="aa$(printf 'a0%.0s' $(seq 1 31))"
HB="bb$(printf 'b0%.0s' $(seq 1 31))"
HC="cc$(printf 'c0%.0s' $(seq 1 31))"

echo "=== 1. Global help mentions block-tx-root ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "block-tx-root" "help mentions block-tx-root"

echo
echo "=== 2. block-tx-root --help exits 0 ==="
set +e
"$WALLET" block-tx-root --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "block-tx-root --help exits 0"

echo
echo "=== 3. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" block-tx-root --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 4. Missing --block-json: exit 1 ==="
set +e
"$WALLET" block-tx-root >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --block-json returns 1"

echo
echo "=== 5. Non-existent file: exit 1 ==="
set +e
"$WALLET" block-tx-root --block-json "$WORK/nope.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "non-existent file returns 1"

echo
echo "=== 6. Not-a-JSON-object input: exit 1 ==="
echo '[1,2,3]' > "$WORK/arr.json"
set +e
"$WALLET" block-tx-root --block-json "$WORK/arr.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "non-object JSON returns 1"

echo
echo "=== 7. Missing creator_tx_lists: exit 1 ==="
echo '{"index":1}' > "$WORK/noctl.json"
set +e
"$WALLET" block-tx-root --block-json "$WORK/noctl.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing creator_tx_lists returns 1"

echo
echo "=== 8. creator_tx_lists not an array: exit 1 ==="
echo '{"creator_tx_lists":42}' > "$WORK/badctl.json"
set +e
"$WALLET" block-tx-root --block-json "$WORK/badctl.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "non-array creator_tx_lists returns 1"

echo
echo "=== 9. tx_hash wrong length: exit 1 ==="
echo '{"creator_tx_lists":[["aabbcc"]]}' > "$WORK/short.json"
set +e
"$WALLET" block-tx-root --block-json "$WORK/short.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "short tx_hash returns 1"

echo
echo "=== 10. tx_hash invalid hex: exit 1 ==="
BADHEX=$($PY -c "print('zz' * 32)")
echo "{\"creator_tx_lists\":[[\"$BADHEX\"]]}" > "$WORK/badhex.json"
set +e
"$WALLET" block-tx-root --block-json "$WORK/badhex.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "non-hex tx_hash returns 1"

echo
echo "=== 11-13. Happy path: union of two lists ==="
# Two creators: [HA,HB] and [HB,HC] => union {HA,HB,HC}, 3 distinct leaves.
cat > "$WORK/block.json" <<EOF
{"index":5,"creator_tx_lists":[["$HA","$HB"],["$HB","$HC"]]}
EOF
set +e
B_JSON=$("$WALLET" block-tx-root --block-json "$WORK/block.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "happy path returns 0"
GOT_ROOT=$(field "$B_JSON" recomputed_tx_root)
GOT_LEAVES=$(field "$B_JSON" leaf_count)
EXP_ROOT=$(ref_tx_root "$WORK/block.json")
EXP_LEAVES=$(ref_leaf_count "$WORK/block.json")
assert_eq "$GOT_ROOT"   "$EXP_ROOT"   "recomputed_tx_root matches Python reference"
assert_eq "$GOT_LEAVES" "$EXP_LEAVES" "leaf_count == deduped union size (3)"

echo
echo "=== 14. --json shape (recomputed_tx_root + leaf_count) ==="
PARSED_OK=$(echo "$B_JSON" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
ok = all(k in d for k in ('recomputed_tx_root','leaf_count'))
print('yes' if ok else 'no')
" 2>/dev/null || echo "no")
assert_eq "$PARSED_OK" "yes" "--json has recomputed_tx_root + leaf_count"

echo
echo "=== 15. Dedup: duplicate tx_hash across lists collapses ==="
# Both creators report the same single hash HA => union {HA}, 1 leaf.
cat > "$WORK/dup.json" <<EOF
{"creator_tx_lists":[["$HA"],["$HA"]]}
EOF
DUP_JSON=$("$WALLET" block-tx-root --block-json "$WORK/dup.json" --json 2>&1 | tr -d '\r')
DUP_LEAVES=$(field "$DUP_JSON" leaf_count)
DUP_ROOT=$(field "$DUP_JSON" recomputed_tx_root)
# Reference: SHA-256 of the single 32-byte hash.
EXP_DUP_ROOT=$($PY -c "import hashlib; print(hashlib.sha256(bytes.fromhex('$HA')).hexdigest())")
assert_eq "$DUP_LEAVES" "1"             "dedup: leaf_count collapses to 1"
assert_eq "$DUP_ROOT"   "$EXP_DUP_ROOT" "dedup: root == SHA-256(single hash)"

echo
echo "=== 16. Order-invariance: permuted lists give same root ==="
# Same union {HA,HB,HC}, different list + within-list ordering.
cat > "$WORK/perm.json" <<EOF
{"creator_tx_lists":[["$HC"],["$HB","$HA"]]}
EOF
PERM_ROOT=$("$WALLET" block-tx-root --block-json "$WORK/perm.json" --json 2>&1 \
  | tr -d '\r' | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['recomputed_tx_root'])")
assert_eq "$PERM_ROOT" "$GOT_ROOT" "order-invariance: permuted union same root"

echo
echo "=== 17. Empty union => SHA-256(\"\") ==="
echo '{"creator_tx_lists":[]}' > "$WORK/empty.json"
EMPTY_JSON=$("$WALLET" block-tx-root --block-json "$WORK/empty.json" --json 2>&1 | tr -d '\r')
EMPTY_ROOT=$(field "$EMPTY_JSON" recomputed_tx_root)
EMPTY_LEAVES=$(field "$EMPTY_JSON" leaf_count)
EXP_EMPTY=$($PY -c "import hashlib; print(hashlib.sha256(b'').hexdigest())")
assert_eq "$EMPTY_ROOT"   "$EXP_EMPTY" "empty union root == SHA-256(\"\")"
assert_eq "$EMPTY_LEAVES" "0"          "empty union leaf_count == 0"

echo
echo "=== 18. --check match: exit 0 + match=true ==="
# Embed the (correct) recomputed root as the block's stored tx_root.
cat > "$WORK/checked.json" <<EOF
{"creator_tx_lists":[["$HA","$HB"],["$HB","$HC"]],"tx_root":"$EXP_ROOT"}
EOF
set +e
CHK_JSON=$("$WALLET" block-tx-root --block-json "$WORK/checked.json" --check --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "--check match returns 0"
CHK_MATCH=$(field "$CHK_JSON" match)
assert_eq "$CHK_MATCH" "True" "--check match reports match=true"

echo
echo "=== 19. --check mismatch: exit 2 + match=false ==="
WRONG="00$(printf '00%.0s' $(seq 1 31))"
cat > "$WORK/wrong.json" <<EOF
{"creator_tx_lists":[["$HA","$HB"],["$HB","$HC"]],"tx_root":"$WRONG"}
EOF
set +e
WR_JSON=$("$WALLET" block-tx-root --block-json "$WORK/wrong.json" --check --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "--check mismatch returns 2"
WR_MATCH=$(field "$WR_JSON" match)
assert_eq "$WR_MATCH" "False" "--check mismatch reports match=false"

echo
echo "=== 20. Determinism (two runs identical) ==="
R1=$("$WALLET" block-tx-root --block-json "$WORK/block.json" --json 2>&1 | tr -d '\r')
R2=$("$WALLET" block-tx-root --block-json "$WORK/block.json" --json 2>&1 | tr -d '\r')
D1=$(field "$R1" recomputed_tx_root)
D2=$(field "$R2" recomputed_tx_root)
assert_eq "$D1" "$D2" "two invocations give identical recomputed_tx_root"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
