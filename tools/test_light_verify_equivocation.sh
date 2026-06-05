#!/usr/bin/env bash
# determ-light verify-equivocation — OFFLINE EquivocationEvent verifier (FA6).
#
# Pure offline test (no cluster, no daemon, no genesis, no runtime crypto).
# Drives `determ-light verify-equivocation` against a hand-built
# EquivocationEvent (the FA6 double-sign proof carried by the
# EQUIVOCATION_EVIDENCE gossip message + the submit_equivocation RPC) and
# checks that the binary re-runs the daemon's V11 slash gate independently:
# digest_a != digest_b, sig_a != sig_b, and BOTH Ed25519 signatures verify
# against the equivocator's registered key.
#
# The signed fixture below is a FIXED, DETERMINISTIC Ed25519 vector (seed =
# 0x00..0x1f, two sigs over two distinct SHA-256 digests) generated once and
# baked in — so the test needs no Python crypto backend at runtime and is
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
#   5. digest_a == digest_b (replay, not equivocation) → NOT-EQUIVOCATION 3.
#   6. sig_a == sig_b (single signature) → NOT-EQUIVOCATION exit 3.
#   7. Tampered sig_b (one flipped nibble) → NOT-EQUIVOCATION exit 3.
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
DIGEST_A="d6491aa2e0ed015bf05e5b7c1ba556257e7404618082b8f38cd10f77e3dcde8a"
SIG_A="330ec28388f5deadeb0bb63916882ceaad07567f5b2431b920f9340d1171446a1880a41c1030dde4e2c92fb1e8574d4b3afacaa9b9ef31debeb39f765c1f060a"
DIGEST_B="edc5be4175b1412ed36d90e28cbed6f8234483eb590e3898b1049f0f425b01ec"
SIG_B="a7bfe5d1acda0c295323e423b4a8f8b432258767ff58c5d56f1a3d80f7f3449f1c8de90b69d85547f12b000bbde72092d68d742e6632f61898c9523260412d05"

# write_event <out> <digest_a> <sig_a> <digest_b> <sig_b>
write_event() {
  cat > "$1" <<EOF
{
  "equivocator": "validator-7.example",
  "block_index": 7,
  "digest_a": "$2",
  "sig_a": "$3",
  "digest_b": "$4",
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
write_event "$TMP/equiv.json" "$DIGEST_A" "$SIG_A" "$DIGEST_B" "$SIG_B"

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
echo "=== 5. digest_a == digest_b (replay) → NOT-EQUIVOCATION exit 3 ==="
# Re-sign would be needed for a real same-digest pair; using the same digest
# with its own sig is enough — V11 rejects on the digest equality first.
write_event "$TMP/samedig.json" "$DIGEST_A" "$SIG_A" "$DIGEST_A" "$SIG_A"
run_verify --in "$TMP/samedig.json" --pubkey "$PUBKEY"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "digest_a == digest_b"; then
  assert "true" "equal digests → NOT-EQUIVOCATION exit 3"
else
  echo "$OUT"; assert "false" "equal digests → exit 3 (rc=$RC)"
fi

echo
echo "=== 6. sig_a == sig_b (single signature) → NOT-EQUIVOCATION exit 3 ==="
write_event "$TMP/samesig.json" "$DIGEST_A" "$SIG_A" "$DIGEST_B" "$SIG_A"
run_verify --in "$TMP/samesig.json" --pubkey "$PUBKEY"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "sig_a == sig_b"; then
  assert "true" "equal sigs → NOT-EQUIVOCATION exit 3"
else
  echo "$OUT"; assert "false" "equal sigs → exit 3 (rc=$RC)"
fi

echo
echo "=== 7. Tampered sig_b (flipped nibble) → NOT-EQUIVOCATION exit 3 ==="
# Flip the last hex nibble of sig_b: 0x...05 → 0x...04. Distinct from sig_a,
# so V11's sig-distinctness passes but the Ed25519 verify fails.
SIG_B_BAD="${SIG_B%?}4"
write_event "$TMP/tampered.json" "$DIGEST_A" "$SIG_A" "$DIGEST_B" "$SIG_B_BAD"
run_verify --in "$TMP/tampered.json" --pubkey "$PUBKEY"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "sig_b does not verify"; then
  assert "true" "tampered sig_b → NOT-EQUIVOCATION exit 3"
else
  echo "$OUT"; assert "false" "tampered sig_b → exit 3 (rc=$RC)"
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
echo "=== 9. Malformed event (short digest hex) → usage error exit 1 ==="
write_event "$TMP/malformed.json" "deadbeef" "$SIG_A" "$DIGEST_B" "$SIG_B"
run_verify --in "$TMP/malformed.json" --pubkey "$PUBKEY"
[ "$RC" = "1" ] && assert "true" "malformed digest hex → exit 1" \
                || { echo "$OUT"; assert "false" "malformed digest → exit 1 (rc=$RC)"; }

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
