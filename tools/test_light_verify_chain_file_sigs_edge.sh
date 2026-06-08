#!/usr/bin/env bash
# determ-light verify-chain-file — OFFLINE SIGS fail-closed edges (no cluster).
#
# The existing test_light_verify_chain_file.sh boots a 3-node cluster and
# exercises CONTINUITY tamper + sig-strip + manifest paths against a REAL
# exported chain. It never reaches three SIGS fail-closed branches that an
# attacker handing a crafted headers file to an offline verifier WOULD hit,
# because the cluster always supplies the genuine committee + genuine sigs:
#
#   A. GENESIS-ONLY file — a headers file containing ONLY the index-0 header
#      (no committee-signed block). CONTINUITY trivially passes (single linked
#      header), so SIGS must REFUSE to declare the file verified rather than
#      report "0 blocks, all good". Guarded at light/main.cpp:980-981
#      ("only the genesis header present — no committee-signed block to verify").
#      An emptiness-as-success bug here would let an attacker "prove" a chain
#      by handing over just its genesis.
#
#   B. COMMITTEE MISMATCH — a non-genesis block whose creator is ABSENT from the
#      supplied committee. SIGS must reject at the membership gate
#      (light/verify.cpp:223-228, "creator '...' is not in the supplied
#      committee") BEFORE any Ed25519 check. Fail-open here = an attacker swaps
#      in their own creator set + matching committee and forges acceptance.
#
#   C. MEMBER-PRESENT-BUT-FORGED-SIG — creator IS in the committee but the
#      creator_block_sig is garbage. Proves the membership pass in (B) does NOT
#      fail-open into acceptance: the Ed25519 verify (verify.cpp:254-261) still
#      rejects. This is the control that "creator known" != "block authentic".
#
#   D. DEGENERATE COMMITTEE — a committee whose only member has an empty ed_pub
#      (skipped by parse_committee) leaving NO valid members. Must FAIL with
#      "committee file has no valid members" (verify.cpp:98-100), not silently
#      treat an empty committee as vacuously satisfied.
#
# Every fixture is hand-built JSON; CONTINUITY PASSES in all of them (the
# control: the FAILs are the SIGS guard firing, not an incidental parse/chain
# error). Each negative asserts exit 2 + the specific diagnostic + audit=FAIL.
#
# FULLY OFFLINE (no cluster, no RPC, no daemon, no compute_genesis_hash).
# Run from repo root: bash tools/test_light_verify_chain_file_sigs_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi
L="$DETERM_LIGHT"

T=test_light_verify_chain_file_sigs_edge
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

ZERO64=$(printf '0%.0s' {1..64})
GH=$(printf 'c%.0s' {1..64})     # stand-in genesis block_hash
H1=$(printf 'd%.0s' {1..64})     # stand-in index-1 block_hash
EDPUB=$(printf 'b%.0s' {1..64})  # committee member 'real' ed_pub
SIG128=$(printf 'a%.0s' {1..128}) # garbage 64-byte sig (never verifies)

# Committee with exactly one valid member, "real".
cat > "$T/committee.json" <<EOF
[{"domain":"real","ed_pub":"$EDPUB","region":0,"stake":100}]
EOF

# Reusable genesis header (index 0, prev all-zero, no committee sigs).
GEN_HEADER="{\"index\":0,\"prev_hash\":\"$ZERO64\",\"timestamp\":0,\"block_hash\":\"$GH\",\"transactions\":[],\"creators\":[],\"cumulative_rand\":\"$ZERO64\",\"abort_events\":[]}"

# ── A. genesis-only file ──────────────────────────────────────────────────
echo "=== A. genesis-only headers file -> SIGS FAIL exit 2 (refuses to verify nothing) ==="
echo "{\"headers\":[$GEN_HEADER]}" > "$T/genesis_only.json"
set +e
OUT=$("$L" verify-chain-file --in "$T/genesis_only.json" --committee "$T/committee.json" 2>&1); RC=$?
set -e
echo "$OUT" | grep -E "CONTINUITY|SIGS|VERIFY-CHAIN-FILE"
# control: CONTINUITY must PASS (fixture is structurally a valid 1-header chain)
echo "$OUT" | grep -Eq "CONTINUITY  PASS" \
  && assert true "control: CONTINUITY PASS on genesis-only fixture" \
  || assert false "control: CONTINUITY PASS on genesis-only fixture"
echo "$OUT" | grep -Eq "SIGS        FAIL" && echo "$OUT" | grep -q "no committee-signed block" && [ $RC -eq 2 ] \
  && assert true "genesis-only -> SIGS FAIL exit 2 (no committee-signed block)" \
  || assert false "genesis-only -> SIGS FAIL exit 2 (got exit $RC)"
# --json surface must ALSO be fail-closed
JA=$("$L" verify-chain-file --in "$T/genesis_only.json" --committee "$T/committee.json" --json 2>/dev/null \
     | python -c "import json,sys
try: print(json.load(sys.stdin).get('audit'))
except Exception: print('PARSE_ERR')")
assert "$([ "$JA" = "FAIL" ] && echo true || echo false)" "genesis-only --json audit=FAIL (was '$JA')"

# ── B. committee mismatch (creator absent from committee) ─────────────────
echo; echo "=== B. non-genesis creator NOT in committee -> SIGS FAIL exit 2 (membership gate) ==="
cat > "$T/mismatch.json" <<EOF
{"headers":[
$GEN_HEADER,
{"index":1,"prev_hash":"$GH","timestamp":1,"block_hash":"$H1","transactions":[],"creators":["ghost"],"creator_block_sigs":["$SIG128"],"cumulative_rand":"$ZERO64","abort_events":[]}
]}
EOF
set +e
OUT=$("$L" verify-chain-file --in "$T/mismatch.json" --committee "$T/committee.json" 2>&1); RC=$?
set -e
echo "$OUT" | grep -E "SIGS|VERIFY-CHAIN-FILE"
echo "$OUT" | grep -Eq "CONTINUITY  PASS" \
  && assert true "control: CONTINUITY PASS (chain links genesis->block1)" \
  || assert false "control: CONTINUITY PASS (chain links genesis->block1)"
echo "$OUT" | grep -Eq "SIGS        FAIL" && echo "$OUT" | grep -q "not in the supplied committee" && [ $RC -eq 2 ] \
  && assert true "creator 'ghost' absent -> SIGS FAIL exit 2 (membership gate)" \
  || assert false "creator 'ghost' absent -> SIGS FAIL exit 2 (got exit $RC)"

# ── C. member present, forged sig (membership pass must NOT fail-open) ────
echo; echo "=== C. creator IN committee but forged sig -> SIGS FAIL exit 2 (Ed25519 gate) ==="
cat > "$T/forgedsig.json" <<EOF
{"headers":[
$GEN_HEADER,
{"index":1,"prev_hash":"$GH","timestamp":1,"block_hash":"$H1","transactions":[],"creators":["real"],"creator_block_sigs":["$SIG128"],"cumulative_rand":"$ZERO64","abort_events":[]}
]}
EOF
set +e
OUT=$("$L" verify-chain-file --in "$T/forgedsig.json" --committee "$T/committee.json" 2>&1); RC=$?
set -e
echo "$OUT" | grep -E "SIGS|VERIFY-CHAIN-FILE"
echo "$OUT" | grep -Eq "SIGS        FAIL" && echo "$OUT" | grep -q "does NOT verify" && [ $RC -eq 2 ] \
  && assert true "known creator + forged sig -> SIGS FAIL exit 2 (membership pass not fail-open)" \
  || assert false "known creator + forged sig -> SIGS FAIL exit 2 (got exit $RC)"

# ── D. degenerate committee (no valid members) ────────────────────────────
echo; echo "=== D. committee with only an empty-ed_pub member -> SIGS FAIL exit 2 (no valid members) ==="
echo '[{"domain":"real","ed_pub":""}]' > "$T/degenerate_committee.json"
set +e
OUT=$("$L" verify-chain-file --in "$T/forgedsig.json" --committee "$T/degenerate_committee.json" 2>&1); RC=$?
set -e
echo "$OUT" | grep -E "SIGS|VERIFY-CHAIN-FILE"
echo "$OUT" | grep -Eq "SIGS        FAIL" && echo "$OUT" | grep -q "no valid members" && [ $RC -eq 2 ] \
  && assert true "empty-ed_pub-only committee -> SIGS FAIL exit 2 (no valid members)" \
  || assert false "empty-ed_pub-only committee -> SIGS FAIL exit 2 (got exit $RC)"

echo; echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then echo "  PASS: test_light_verify_chain_file_sigs_edge"; exit 0
else echo "  FAIL: test_light_verify_chain_file_sigs_edge"; exit 1; fi
