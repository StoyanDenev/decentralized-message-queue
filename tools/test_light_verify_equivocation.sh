#!/usr/bin/env bash
# determ-light verify-equivocation — OFFLINE EquivocationEvent verifier (FA6).
#
# Pure offline test (no cluster, no daemon, no genesis, no runtime crypto).
# Drives `determ-light verify-equivocation` against a hand-built
# EquivocationEvent (the FA6 double-sign proof carried by the
# EQUIVOCATION_EVIDENCE gossip message + the submit_equivocation RPC) and
# checks that the binary re-runs the daemon's V11 evidence gate independently
# (EQV-height-bind + EQV-gen-bind form): kind <= 1, index_a == index_b ==
# block_index, gen_a == gen_b, body_root_a != body_root_b, sig_a != sig_b, and
# BOTH Ed25519 signatures verify against digests DERIVED from the
# (index, gen, body_root) openings as
# SHA256("DTM-BLKDIG-v3" || index u64 BE || gen u64 BE || body_root) (kind 0),
# against the equivocator's registered key.
#
# The signed fixture below is a FIXED, DETERMINISTIC Ed25519 vector (seed =
# 0x00..0x1f, two sigs over two composed digests at height 7 generation 0 —
# plus one REAL signature composed at height 8 for the height-mismatch leg and
# one at generation 1 for the re-round leg) generated once
# and baked in — so the test needs no Python crypto backend at runtime and is
# reproducible on any host. A real determ-light binary verifies these sigs
# with the SAME OpenSSL Ed25519 backend the daemon uses (src/crypto/keys.cpp),
# so a passing PROVEN run is a genuine cross-tool soundness check.
#
# Verdict / exit contract (mirrors verify-tx-inclusion / decode-wire):
#   EQUIVOCATION-PROVEN → exit 0 (all four V11 conditions hold)
#   NOT-EQUIVOCATION    → exit 3 (a V11 condition fails; fail-closed)
#   I/O / usage error   → exit 1
#
# Assertions:
#   1. Genuine double-sign + correct --pubkey → EQUIVOCATION-PROVEN, exit 0.
#   2. --json carries verdict=EQUIVOCATION-PROVEN + proven=true + both sigs.
#   3. Key resolved from a --committee {domain,ed_pub}[] file → PROVEN exit 0.
#   4. WRONG --pubkey (a different key) → NOT-EQUIVOCATION, exit 3.
#  4b. (EQV-height-bind) index_b=8 with a REAL sig composed at height 8 →
#      NOT-EQUIVOCATION exit 3 "heights do not match" — the cross-height
#      forged-slash replay is refused by the offline verifier too.
#  4c. (EQV-gen-bind) gen_b=1 with a REAL sig composed at generation 1 →
#      NOT-EQUIVOCATION exit 3 "gen_a != gen_b" — an HONEST validator's two
#      same-height signatures from two abort RE-ROUNDS are refused offline too
#      (the Hole-1b forged-slash route).
#   5. body_root_a == body_root_b (replay, not equivocation) → NOT-EQ 3.
#   6. sig_a == sig_b (single signature) → NOT-EQUIVOCATION exit 3.
#   7. Tampered sig_b (one flipped nibble) → NOT-EQUIVOCATION exit 3.
#  7b. (register T-OE4) sig_a INVALID + sig_b VALID → NOT-EQUIVOCATION exit 3
#      — pins the V11 clause-3 (`!sig_a_ok`) reject. No other leg builds this
#      profile (assertion 4 invalidates BOTH sigs; assertion 7 keeps sig_a
#      valid), so a deletion of clause 3 would report a forged sig_a as
#      EQUIVOCATION-PROVEN with no red test. Carries its own PROVEN control.
#   8. --committee with an unknown equivocator domain → usage error exit 1.
#   9. Malformed event (bad-length digest hex) → usage error exit 1.
#  10. Missing --in → usage error exit 1.
#  11. Both --pubkey and --committee supplied → usage error exit 1.
#  12. Event read from stdin (--in -) → PROVEN exit 0.
#
# Run from repo root: bash tools/test_light_verify_equivocation.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3

TMP="build/test_light_verify_equivocation.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# ── Fixed deterministic Ed25519 fixture (RFC 8032; seed = 0x00..0x1f) ──────
PUBKEY="03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
# An UNRELATED key (seed = byte-wise XOR 0xff) for the wrong-key negative.
PUBKEY2="bafc71bead3ac5e4b63e9c8216ee71a34aaec65722eedbca728b4e9b3ccce396"
# body roots = SHA256("light-verify-equivocation-A"/"-B"); each sig is over the
# DERIVED digest
#   SHA256("DTM-BLKDIG-v3" || height u64 BE || gen u64 BE || body_root).
ROOT_A="03d70ec7e6f3721b9c82c77ea10b47186daa14273b823d417323b9a1e73c5d4e"
SIG_A="20446cf81027e288286ce1c16b8ad5abcddbd3f3af53705f57799e172a5421f0c46af7bfa3310e9f781ab2fc53b7529f3b23e4026c90f61f860746fd3afb1902"
ROOT_B="d3672c9732c2ab1d3e273f5cd639b4177a73b8ad2bb36d0b5f8d8b89b2a681d0"
SIG_B="1914e5fba7dffdec58e4cd4c81ddbebc627963687815fbd0ecbe4b429c6460eec93aa78fc545bc93c9947ab39ffc156d764cc6839d500fe5ff8902349a8b0e0e"
# A REAL signature by the same key over compose(8, 0, ROOT_B) — a genuinely
# signed opening at the WRONG height, for the height-mismatch leg.
SIG_B_H8="b33dd1919f82beef87550251e299350d438a0b5d6b54ab9525f1b733eedcef2548c79eff62112b30a7ee6e2f42fc42c8c5d045f309ac576b56861d20527a130d"
# A REAL signature by the same key over compose(7, 1, ROOT_B) — a genuinely
# signed opening in the NEXT abort generation at the SAME height, for the
# re-round leg (EQV-gen-bind).
SIG_B_G1="bb1ba81fb197319ba829ef8ed54cb4c990272fc3566ed06ad22dce3de49fc63956d7aedf03e80a501ced9072435a28298556a6a51c76f2d79fba60e68c95bf0e"

# write_event <out> <root_a> <sig_a> <root_b> <sig_b> [index_b (7)] [gen_b (0)]
write_event() {
  local ib="${6:-7}"
  local gb="${7:-0}"
  cat > "$1" <<EOF
{
  "equivocator": "validator-7.example",
  "block_index": 7,
  "kind": 0,
  "index_a": 7,
  "gen_a": 0,
  "body_root_a": "$2",
  "sig_a": "$3",
  "index_b": $ib,
  "gen_b": $gb,
  "body_root_b": "$4",
  "sig_b": "$5",
  "shard_id": 0,
  "beacon_anchor_height": 0
}
EOF
}

run_verify() {  # run_verify <args...>; sets RC + OUT globals
  set +e
  OUT=$("$DETERM_LIGHT" verify-equivocation "$@" 2>&1)
  RC=$?
  set -e
}

# Canonical genuine double-sign event used by several assertions.
write_event "$TMP/equiv.json" "$ROOT_A" "$SIG_A" "$ROOT_B" "$SIG_B"

echo "=== 1. Genuine double-sign + --pubkey → EQUIVOCATION-PROVEN exit 0 ==="
run_verify --in "$TMP/equiv.json" --pubkey "$PUBKEY"
if [ "$RC" = "0" ] && echo "$OUT" | head -1 | grep -q "EQUIVOCATION-PROVEN"; then
  assert "true" "valid event → EQUIVOCATION-PROVEN exit 0"
else
  echo "$OUT"; assert "false" "valid event → EQUIVOCATION-PROVEN exit 0 (rc=$RC)"
fi

echo
echo "=== 2. --json verdict=EQUIVOCATION-PROVEN + proven + both sigs valid ==="
run_verify --in "$TMP/equiv.json" --pubkey "$PUBKEY" --json
FIELDS=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s/%s' % (d.get('verdict'), d.get('proven'),
        d.get('sig_a_valid'), d.get('sig_b_valid')))
except Exception: print('ERR')
")
if [ "$FIELDS" = "EQUIVOCATION-PROVEN/True/True/True" ]; then
  assert "true" "--json verdict/proven/sig_a/sig_b correct"
else
  echo "$OUT"; assert "false" "--json fields (got $FIELDS)"
fi

echo
echo "=== 3. Key resolved from --committee file → PROVEN exit 0 ==="
cat > "$TMP/committee.json" <<EOF
[
  {"domain": "other.example",       "ed_pub": "$PUBKEY2"},
  {"domain": "validator-7.example", "ed_pub": "$PUBKEY"}
]
EOF
run_verify --in "$TMP/equiv.json" --committee "$TMP/committee.json"
if [ "$RC" = "0" ] && echo "$OUT" | head -1 | grep -q "EQUIVOCATION-PROVEN"; then
  assert "true" "committee-resolved key → PROVEN exit 0"
else
  echo "$OUT"; assert "false" "committee-resolved key → PROVEN exit 0 (rc=$RC)"
fi

echo
echo "=== 4. Wrong --pubkey → NOT-EQUIVOCATION exit 3 ==="
run_verify --in "$TMP/equiv.json" --pubkey "$PUBKEY2"
if [ "$RC" = "3" ] && echo "$OUT" | head -1 | grep -q "NOT-EQUIVOCATION"; then
  assert "true" "wrong key → NOT-EQUIVOCATION exit 3"
else
  echo "$OUT"; assert "false" "wrong key → NOT-EQUIVOCATION exit 3 (rc=$RC)"
fi

echo
echo "=== 4b. Cross-height openings (EQV-height-bind) → NOT-EQUIVOCATION exit 3 ==="
# index_b = 8 with a REAL signature composed at height 8: every other V11
# clause holds (kind valid, roots distinct, sigs distinct, both sigs verify
# against their own derived digests) — ONLY the height bind refuses it. This
# is the exact cross-height forged-slash replay the daemon gate rejects.
write_event "$TMP/xheight.json" "$ROOT_A" "$SIG_A" "$ROOT_B" "$SIG_B_H8" 8
run_verify --in "$TMP/xheight.json" --pubkey "$PUBKEY"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "heights do not match"; then
  assert "true" "cross-height openings → NOT-EQUIVOCATION exit 3 (height bind)"
else
  echo "$OUT"; assert "false" "cross-height openings → exit 3 (rc=$RC)"
fi

echo
echo "=== 4c. Cross-round openings (EQV-gen-bind) → NOT-EQUIVOCATION exit 3 ==="
# gen_b = 1 with a REAL signature composed at generation 1, SAME height 7:
# every other V11 clause holds (kind valid, all heights equal, roots distinct,
# sigs distinct, both sigs verify against their own derived digests) — ONLY the
# round bind refuses it. This is exactly what an HONEST validator emits when a
# round aborts and it re-signs the reselected committee's block, so accepting
# it would be a forged slash of an honest node (DECISION-LOG 2026-08-12 Q2).
write_event "$TMP/xround.json" "$ROOT_A" "$SIG_A" "$ROOT_B" "$SIG_B_G1" 7 1
run_verify --in "$TMP/xround.json" --pubkey "$PUBKEY"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "gen_a != gen_b"; then
  assert "true" "cross-round openings → NOT-EQUIVOCATION exit 3 (round bind)"
else
  echo "$OUT"; assert "false" "cross-round openings → exit 3 (rc=$RC)"
fi

echo
echo "=== 5. body_root_a == body_root_b (replay) → NOT-EQUIVOCATION exit 3 ==="
# Re-sign would be needed for a real same-root pair; using the same root
# with its own sig is enough — V11 rejects on the root equality first.
write_event "$TMP/samedig.json" "$ROOT_A" "$SIG_A" "$ROOT_A" "$SIG_A"
run_verify --in "$TMP/samedig.json" --pubkey "$PUBKEY"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "body_root_a == body_root_b"; then
  assert "true" "equal body roots → NOT-EQUIVOCATION exit 3"
else
  echo "$OUT"; assert "false" "equal body roots → exit 3 (rc=$RC)"
fi

echo
echo "=== 6. sig_a == sig_b (single signature) → NOT-EQUIVOCATION exit 3 ==="
write_event "$TMP/samesig.json" "$ROOT_A" "$SIG_A" "$ROOT_B" "$SIG_A"
run_verify --in "$TMP/samesig.json" --pubkey "$PUBKEY"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "sig_a == sig_b"; then
  assert "true" "equal sigs → NOT-EQUIVOCATION exit 3"
else
  echo "$OUT"; assert "false" "equal sigs → exit 3 (rc=$RC)"
fi

echo
echo "=== 7. Tampered sig_b (flipped nibble) → NOT-EQUIVOCATION exit 3 ==="
# Flip the last hex nibble of sig_b: 0x...08 → 0x...04. Distinct from sig_a,
# so V11's sig-distinctness passes but the Ed25519 verify fails.
SIG_B_BAD="${SIG_B%?}4"
write_event "$TMP/tampered.json" "$ROOT_A" "$SIG_A" "$ROOT_B" "$SIG_B_BAD"
run_verify --in "$TMP/tampered.json" --pubkey "$PUBKEY"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "sig_b does not verify"; then
  assert "true" "tampered sig_b → NOT-EQUIVOCATION exit 3"
else
  echo "$OUT"; assert "false" "tampered sig_b → exit 3 (rc=$RC)"
fi

echo
echo "=== 7b. Clause-3 asymmetry (T-OE4): sig_a INVALID, sig_b VALID → exit 3 ==="
# The V11 else-if chain has FOUR clauses (digests-distinct, sigs-distinct,
# sig_a verifies, sig_b verifies). Assertion 4 (wrong key) invalidates BOTH
# sigs so it reaches clause 3; assertion 7 keeps sig_a VALID so it reaches
# clause 4. Neither builds the sig_a-bad / sig_b-good profile, so deleting
# clause 3 (`else if (!sig_a_ok)`) would let a forged sig_a fall through to
# EQUIVOCATION-PROVEN with no red test. This leg pins clause 3.
# Adjacent positive control: the genuine event still reaches V11 and emits
# PROVEN, so a fixture/path regression fails HERE, not silently in the leg.
run_verify --in "$TMP/equiv.json" --pubkey "$PUBKEY"
if [ "$RC" = "0" ] && echo "$OUT" | head -1 | grep -q "EQUIVOCATION-PROVEN"; then
  assert "true" "control: genuine double-sign reaches V11 → PROVEN exit 0"
else
  echo "$OUT"; assert "false" "control: genuine double-sign → PROVEN exit 0 (rc=$RC)"
fi
# Negative leg: flip sig_a's last nibble (2→b), keep sig_b valid. Still 128-hex
# and distinct from sig_b, so digests_distinct + sigs_distinct pass and clause 3
# is the first true clause.
SIG_A_BAD="${SIG_A%?}b"
write_event "$TMP/tampered_a.json" "$ROOT_A" "$SIG_A_BAD" "$ROOT_B" "$SIG_B"
run_verify --in "$TMP/tampered_a.json" --pubkey "$PUBKEY"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "sig_a does not verify"; then
  assert "true" "tampered sig_a (sig_b valid) → NOT-EQUIVOCATION exit 3"
else
  echo "$OUT"; assert "false" "tampered sig_a → NOT-EQUIVOCATION exit 3 (rc=$RC)"
fi

echo
echo "=== 8. --committee unknown equivocator domain → usage error exit 1 ==="
cat > "$TMP/committee_miss.json" <<EOF
[
  {"domain": "someone-else.example", "ed_pub": "$PUBKEY2"}
]
EOF
run_verify --in "$TMP/equiv.json" --committee "$TMP/committee_miss.json"
if [ "$RC" = "1" ] && echo "$OUT" | grep -qi "not found"; then
  assert "true" "unknown domain → usage error exit 1"
else
  echo "$OUT"; assert "false" "unknown domain → exit 1 (rc=$RC)"
fi

echo
echo "=== 9. Malformed event (short body-root hex) → usage error exit 1 ==="
write_event "$TMP/malformed.json" "deadbeef" "$SIG_A" "$ROOT_B" "$SIG_B"
run_verify --in "$TMP/malformed.json" --pubkey "$PUBKEY"
[ "$RC" = "1" ] && assert "true" "malformed body-root hex → exit 1" \
                || { echo "$OUT"; assert "false" "malformed body-root → exit 1 (rc=$RC)"; }

echo
echo "=== 10. Missing --in → usage error exit 1 ==="
run_verify --pubkey "$PUBKEY"
[ "$RC" = "1" ] && assert "true" "missing --in → exit 1" \
                || { echo "$OUT"; assert "false" "missing --in → exit 1 (rc=$RC)"; }

echo
echo "=== 11. Both --pubkey and --committee → usage error exit 1 ==="
run_verify --in "$TMP/equiv.json" --pubkey "$PUBKEY" --committee "$TMP/committee.json"
[ "$RC" = "1" ] && assert "true" "both key sources → exit 1" \
                || { echo "$OUT"; assert "false" "both key sources → exit 1 (rc=$RC)"; }

echo
echo "=== 12. Event from stdin (--in -) → PROVEN exit 0 ==="
set +e
OUT=$("$DETERM_LIGHT" verify-equivocation --in - --pubkey "$PUBKEY" \
        < "$TMP/equiv.json" 2>&1)
RC=$?
set -e
if [ "$RC" = "0" ] && echo "$OUT" | head -1 | grep -q "EQUIVOCATION-PROVEN"; then
  assert "true" "stdin event → PROVEN exit 0"
else
  echo "$OUT"; assert "false" "stdin event → PROVEN exit 0 (rc=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_verify_equivocation"; exit 0
else
  echo "  FAIL: test_light_verify_equivocation"; exit 1
fi
