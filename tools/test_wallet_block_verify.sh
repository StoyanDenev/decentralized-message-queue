#!/usr/bin/env bash
# `determ-wallet block-verify` — offline one-shot single-block verifier.
#
# block-verify composes three checks over a block JSON into one PASS/FAIL with a
# monitor-friendly exit code, adding no new crypto beyond a structural pass:
#   STRUCTURE — block JSON well-formedness (required Block fields + shapes;
#               creators[] non-empty).
#   TX-ROOT   — recompute compute_tx_root(creator_tx_lists) == stored tx_root
#               (delegates to block-tx-root --check; mirrors the daemon's
#               validator accept gate byte-for-byte).
#   SIGS      — K-of-K / BFT Ed25519 committee-sig verification over the
#               operator-supplied block_digest (delegates to committee-
#               signature-verify). Attempted ONLY when both --committee and
#               --block-digest are given; otherwise SKIP (the wallet cannot
#               recompute the digest — no chain-library link).
#
# This is a FULLY OFFLINE test (no cluster) — every fixture is constructed
# locally. The SIGS-positive crypto path is exercised separately by the
# cluster-bound tools/test_wallet_committee_signature_verify.sh (block-verify
# delegates to the same cmd_committee_signature_verify); here the SIGS path is
# covered via its SKIP branch and its attempted-then-FAIL delegation branch.
# Soundness: docs/proofs/OfflineBlockVerifySoundness.md (BV-1 tx-root byte-
# equivalence, BV-2 conditional-digest sig boundary, BV-3 composite/fail-closed).
#
# Run from repo root: bash tools/test_wallet_block_verify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

T=test_wallet_block_verify
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

EMPTY_ROOT=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# Run block-verify, capturing combined output + exit code into globals.
run() { OUT=$("$DETERM_WALLET" block-verify "$@" 2>&1); RC=$?; }

echo "=== 1. --help exits 0, no-args exits 1 ==="
"$DETERM_WALLET" block-verify --help >/dev/null 2>&1
assert "$([ $? -eq 0 ] && echo true || echo false)" "--help exit 0"
"$DETERM_WALLET" block-verify >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "no-args exit 1 (usage)"
"$DETERM_WALLET" block-verify --block-json - >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "stdin (-) rejected exit 1"

echo
echo "=== 2. valid empty block -> PASS (STRUCTURE+TX-ROOT PASS, SIGS SKIP) ==="
cat > "$T/ok.json" <<EOF
{"index":1,"prev_hash":"$EMPTY_ROOT","timestamp":1700000000,"creators":["node1"],"creator_tx_lists":[[]],"tx_root":"$EMPTY_ROOT","creator_block_sigs":[]}
EOF
run --block-json "$T/ok.json"
assert "$([ $RC -eq 0 ] && echo true || echo false)" "valid empty block exit 0"
echo "$OUT" | grep -q "BLOCK-VERIFY: PASS" && assert true "summary PASS line" || assert false "summary PASS line"
echo "$OUT" | grep -Eq "STRUCTURE PASS"  && assert true "STRUCTURE PASS" || assert false "STRUCTURE PASS"
echo "$OUT" | grep -Eq "TX-ROOT   PASS"  && assert true "TX-ROOT PASS"   || assert false "TX-ROOT PASS"
echo "$OUT" | grep -Eq "SIGS      SKIP"  && assert true "SIGS SKIP (no committee/digest)" || assert false "SIGS SKIP"

echo
echo "=== 3. --json shape (pure JSON, audit=PASS, passed=2 skipped=1) ==="
run --block-json "$T/ok.json" --json
JOK=$(echo "$OUT" | python -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    m={c['check']:c['verdict'] for c in d.get('checks',[])}
    ok=(d.get('audit')=='PASS' and d.get('passed')==2 and d.get('failed')==0
        and d.get('skipped')==1 and m.get('STRUCTURE')=='PASS'
        and m.get('TX-ROOT')=='PASS' and m.get('SIGS')=='SKIP')
    print('true' if ok else 'false')
except Exception: print('false')
")
assert "$JOK" "--json: audit=PASS, counts, per-check verdicts"
assert "$([ $RC -eq 0 ] && echo true || echo false)" "--json exit 0"

echo
echo "=== 4. valid NON-empty block (real tx_root via block-tx-root) -> PASS ==="
cat > "$T/ne_pre.json" <<'EOF'
{"index":2,"prev_hash":"aa","timestamp":1700000001,"creators":["n1","n2"],"creator_tx_lists":[["1111111111111111111111111111111111111111111111111111111111111111","2222222222222222222222222222222222222222222222222222222222222222"],["2222222222222222222222222222222222222222222222222222222222222222","3333333333333333333333333333333333333333333333333333333333333333"]],"tx_root":"PLACEHOLDER","creator_block_sigs":[]}
EOF
REALROOT=$("$DETERM_WALLET" block-tx-root --block-json "$T/ne_pre.json" --json 2>/dev/null | python -c "
import json,sys
try: print(json.loads(sys.stdin.read())['recomputed_tx_root'])
except Exception: print('ERR')
")
sed "s/PLACEHOLDER/$REALROOT/" "$T/ne_pre.json" > "$T/ne.json"
run --block-json "$T/ne.json"
assert "$([ $RC -eq 0 ] && echo true || echo false)" "non-empty block (3-hash union) exit 0"
echo "$OUT" | grep -Eq "TX-ROOT   PASS" && assert true "non-empty TX-ROOT PASS" || assert false "non-empty TX-ROOT PASS"

echo
echo "=== 5. tampered tx_root -> TX-ROOT FAIL, exit 2 ==="
sed "s/\"tx_root\":\"$EMPTY_ROOT\"/\"tx_root\":\"$(printf '0%.0s' {1..64})\"/" "$T/ok.json" > "$T/bad_root.json"
run --block-json "$T/bad_root.json"
assert "$([ $RC -eq 2 ] && echo true || echo false)" "tampered tx_root exit 2"
echo "$OUT" | grep -Eq "TX-ROOT   FAIL" && assert true "TX-ROOT FAIL row" || assert false "TX-ROOT FAIL row"
echo "$OUT" | grep -q "BLOCK-VERIFY: FAIL" && assert true "summary FAIL" || assert false "summary FAIL"

echo
echo "=== 6. malformed: missing tx_root -> STRUCTURE FAIL, TX-ROOT+SIGS SKIP, exit 2 ==="
echo '{"index":1,"prev_hash":"x","timestamp":1,"creators":["n1"],"creator_tx_lists":[[]],"creator_block_sigs":[]}' > "$T/no_root.json"
run --block-json "$T/no_root.json"
assert "$([ $RC -eq 2 ] && echo true || echo false)" "missing tx_root exit 2"
echo "$OUT" | grep -q "missing field 'tx_root'" && assert true "STRUCTURE names missing field" || assert false "STRUCTURE names missing field"
echo "$OUT" | grep -Eq "TX-ROOT   SKIP" && assert true "TX-ROOT SKIP after STRUCTURE fail" || assert false "TX-ROOT SKIP after STRUCTURE fail"

echo
echo "=== 7. malformed: creators wrong type / empty -> STRUCTURE FAIL ==="
echo '{"index":1,"prev_hash":"x","timestamp":1,"creators":"notarray","creator_tx_lists":[[]],"tx_root":"x","creator_block_sigs":[]}' > "$T/wrongtype.json"
run --block-json "$T/wrongtype.json"
echo "$OUT" | grep -Eq "STRUCTURE FAIL" && [ $RC -eq 2 ] && assert true "creators wrong-type -> STRUCTURE FAIL exit 2" || assert false "creators wrong-type -> STRUCTURE FAIL exit 2"
echo '{"index":1,"prev_hash":"x","timestamp":1,"creators":[],"creator_tx_lists":[],"tx_root":"x","creator_block_sigs":[]}' > "$T/empty_creators.json"
run --block-json "$T/empty_creators.json"
echo "$OUT" | grep -q "creators\[\] is empty" && assert true "empty creators[] rejected" || assert false "empty creators[] rejected"

echo
echo "=== 8. {block:{...}} envelope REJECTED (block-verify needs an unwrapped Block) ==="
cat > "$T/env.json" <<EOF
{"block":{"index":1,"prev_hash":"$EMPTY_ROOT","timestamp":1,"creators":["n1"],"creator_tx_lists":[[]],"tx_root":"$EMPTY_ROOT","creator_block_sigs":[]}}
EOF
run --block-json "$T/env.json"
assert "$([ $RC -eq 2 ] && echo true || echo false)" "{block:{...}} envelope rejected (exit 2)"
echo "$OUT" | grep -q "envelope" && assert true "diagnostic names the envelope" || assert false "diagnostic names the envelope"

echo
echo "=== 9. SIGS attempted (committee+digest) but no sigs meet quorum -> SIGS FAIL ==="
# A committee + digest are supplied so SIGS is ATTEMPTED (not SKIP); the empty
# block has zero block_sigs, so committee-signature-verify cannot meet quorum
# and returns non-zero -> SIGS FAIL -> overall FAIL exit 2. This exercises the
# delegation FAIL branch offline (the crypto-PASS branch is in the sibling test).
echo '[{"domain":"node1","ed_pub":"0000000000000000000000000000000000000000000000000000000000000000"}]' > "$T/committee.json"
run --block-json "$T/ok.json" --committee "$T/committee.json" --block-digest "$EMPTY_ROOT"
SIGS_NOT_SKIP=$(echo "$OUT" | grep -E "SIGS" | grep -vq "SKIP" && echo true || echo false)
assert "$SIGS_NOT_SKIP" "SIGS attempted (not SKIP) when committee+digest supplied"
assert "$([ $RC -ne 0 ] && echo true || echo false)" "no quorum -> overall FAIL (exit $RC != 0)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_block_verify"; exit 0
else
  echo "  FAIL: test_wallet_block_verify"; exit 1
fi
