#!/usr/bin/env bash
# determ-wallet envelope — randomized round-trip / metadata / tamper FUZZ.
#
# Hardens the AEAD keyfile/envelope shape (DWE1: AES-256-GCM +
# PBKDF2-HMAC-SHA-256) across many random keys+passphrases+plaintexts.
# This is a PROPERTY/ROUND-TRIP fuzzer, complementary to the existing
# single-fixture smoke tests (test_wallet_envelope.sh,
# test_wallet_inspect_envelope.sh, test_envelope.sh). It does NOT
# duplicate them: every case here uses a fresh random plaintext,
# password, AAD, and PBKDF2 iteration count drawn from a fixed-seed
# PRNG, so the run is reproducible yet exercises a wide input space.
#
# SAFE REFERENCE (no cipher/KDF re-implementation — that would just be
# a second buggy oracle): correctness is judged ONLY by
#
#   (R) ROUND-TRIP:    decrypt(encrypt(pt, pw, aad), pw, aad) == pt
#   (M) METADATA:      inspect-envelope --json must echo back exactly
#                      the salt/nonce that appear in the serialized
#                      envelope blob, the iters + aad we asked for, a
#                      ciphertext_body_len equal to the plaintext byte
#                      length, and the canonical 16-byte GCM tag.
#   (T) TAMPER:        XOR-flipping a single random nibble of the
#                      ciphertext body must make decrypt FAIL (AEAD).
#   (W) WRONG-PW:      decrypting with a different passphrase must FAIL.
#
# (M) cross-checks the diagnostic dumper against the actual on-the-wire
# bytes (parsed by simple dot-split, not by AES), so a metadata-vs-bytes
# divergence is caught without any crypto knowledge. (R)/(T)/(W) are
# pure behavioural oracles. Fully OFFLINE — no daemon, no cluster.
#
# Fixed-seed PRNG -> deterministic case set. >=20 random cases.
#
# Run from repo root: bash tools/test_wallet_envelope_roundtrip_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
WALLET="$DETERM_WALLET"

# Per-run scratch dir so concurrent runs don't collide; trap cleanup
# scrubs every secret fixture (envelopes embed passphrase-derived key
# material via the GCM tag) on any exit path.
T="build/test_wallet_envelope_roundtrip_fuzz.$$"
mkdir -p "$T"
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

pass_count=0; fail_count=0
assert() {
  # assert <condition-bool 0|1> <message>
  if [ "$1" = "0" ]; then
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $2"; fail_count=$((fail_count + 1))
  fi
}
assert_eq() {
  if [ "$1" = "$2" ]; then pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}

# ── Fixed-seed PRNG (deterministic 32-bit LCG; glibc constants) ────────────
SEED=2463534242
rnd() {  # echoes next pseudo-random 31-bit integer; advances SEED.
  SEED=$(( (1103515245 * SEED + 12345) & 0x7fffffff ))
  echo "$SEED"
}
rand_hex() {  # rand_hex <num_bytes> -> lowercase hex string of that many bytes
  local n="$1" out="" i
  for ((i = 0; i < n; i++)); do
    out+=$(printf '%02x' $(( $(rnd) & 0xff )))
  done
  echo "$out"
}
rand_range() {  # rand_range <lo> <hi> -> integer in [lo,hi]
  local lo="$1" hi="$2"
  echo $(( lo + ($(rnd) % (hi - lo + 1)) ))
}

# Extract a JSON scalar (string OR number) by key from a flat one-line
# object via grep. No python dependency — keeps the metadata oracle
# portable across CI runners.
jget() {  # jget <json> <key>
  local j="$1" k="$2" v
  v=$(echo "$j" | grep -o "\"$k\":\"[^\"]*\"" | head -1 | sed 's/.*:"//; s/"$//')
  if [ -z "$v" ]; then
    v=$(echo "$j" | grep -o "\"$k\":[0-9][0-9]*" | head -1 | sed 's/.*://')
  fi
  echo "$v"
}

N_CASES=24
ITERS_LO=1000      # keep PBKDF2 cheap; prod uses 600000. Same code path.
ITERS_HI=4000

echo "=== determ-wallet envelope round-trip / metadata / tamper fuzz ==="
echo "    cases=$N_CASES  (fixed-seed PRNG, OFFLINE)"
echo

for ((c = 1; c <= N_CASES; c++)); do
  # Random inputs for this case.
  PT_LEN=$(rand_range 1 48)          # 1..48 plaintext bytes (non-empty: encrypt rejects empty)
  PLAIN=$(rand_hex "$PT_LEN")
  PW_LEN=$(rand_range 4 16)
  PW=$(rand_hex "$PW_LEN")           # hex string used as the passphrase text
  ITERS=$(rand_range "$ITERS_LO" "$ITERS_HI")
  USE_AAD=$(( $(rnd) % 2 ))
  AAD=""
  if [ "$USE_AAD" = "1" ]; then
    AAD=$(rand_hex "$(rand_range 1 8)")
  fi

  # ── encrypt ──────────────────────────────────────────────────────────────
  if [ -n "$AAD" ]; then
    ENV=$($WALLET envelope encrypt --plaintext "$PLAIN" --password "$PW" --aad "$AAD" --iters "$ITERS" | tr -d '\r')
  else
    ENV=$($WALLET envelope encrypt --plaintext "$PLAIN" --password "$PW" --iters "$ITERS" | tr -d '\r')
  fi
  if [ -z "$ENV" ] || ! echo "$ENV" | grep -q '^44574531\.'; then
    echo "  FAIL[case $c]: encrypt produced no DWE1 envelope (pt_len=$PT_LEN)"
    fail_count=$((fail_count + 1)); continue
  fi

  # Parse the serialized blob by dot-split: magic.salt.iters.nonce.aad.ct
  IFS='.' read -r F_MAGIC F_SALT F_ITHEX F_NONCE F_AAD F_CT <<< "$ENV"

  # ── (M) metadata oracle: inspect-envelope --json vs the actual bytes ──────
  ENV_FILE="$T/case_${c}.env"
  printf '%s' "$ENV" > "$ENV_FILE"
  JSON=$($WALLET inspect-envelope --in "$ENV_FILE" --json | tr -d '\r')

  assert_eq "$(jget "$JSON" format)"   "DWE1" "[case $c] json format=DWE1"
  assert_eq "$(jget "$JSON" salt_hex)" "$F_SALT"  "[case $c] json salt_hex matches blob"
  assert_eq "$(jget "$JSON" nonce_hex)" "$F_NONCE" "[case $c] json nonce_hex matches blob"
  assert_eq "$(jget "$JSON" pbkdf2_iters)" "$ITERS" "[case $c] json iters matches input"
  assert_eq "$(jget "$JSON" aad_hex)"  "$AAD"  "[case $c] json aad_hex matches input"
  assert_eq "$(jget "$JSON" aad_len)"  "$(( ${#AAD} / 2 ))" "[case $c] json aad_len matches"
  assert_eq "$(jget "$JSON" ciphertext_body_len)" "$PT_LEN" "[case $c] body_len == plaintext byte length"
  assert_eq "$(jget "$JSON" tag_len)"  "16"    "[case $c] json GCM tag_len=16"

  # ── (R) round-trip oracle ─────────────────────────────────────────────────
  if [ -n "$AAD" ]; then
    DEC=$($WALLET envelope decrypt --envelope "$ENV" --password "$PW" --aad "$AAD" | tr -d '\r')
  else
    DEC=$($WALLET envelope decrypt --envelope "$ENV" --password "$PW" | tr -d '\r')
  fi
  assert_eq "$DEC" "$PLAIN" "[case $c] decrypt recovers original plaintext"

  # ── (T) tamper oracle: XOR-flip one random nibble of the ciphertext body ──
  # F_CT = body(PT_LEN bytes) || tag(16 bytes), all hex. Flip a nibble in the
  # body region so we hit ciphertext, not just the tag. XOR with 0x8 flips one
  # bit -> guaranteed distinct nibble, never a no-op.
  BODY_NIBBLES=$(( PT_LEN * 2 ))
  POS=$(( $(rnd) % BODY_NIBBLES ))
  ORIG_NIB="${F_CT:$POS:1}"
  NEW_NIB=$(printf '%x' $(( 0x$ORIG_NIB ^ 0x8 )))
  TAMPERED_CT="${F_CT:0:$POS}${NEW_NIB}${F_CT:$((POS + 1))}"
  TENV="${F_MAGIC}.${F_SALT}.${F_ITHEX}.${F_NONCE}.${F_AAD}.${TAMPERED_CT}"
  assert "$( [ "$TENV" != "$ENV" ] && echo 0 || echo 1 )" "[case $c] tamper actually changed the blob"
  set +e
  if [ -n "$AAD" ]; then
    $WALLET envelope decrypt --envelope "$TENV" --password "$PW" --aad "$AAD" >/dev/null 2>&1
  else
    $WALLET envelope decrypt --envelope "$TENV" --password "$PW" >/dev/null 2>&1
  fi
  RC_T=$?
  set -e
  assert "$( [ "$RC_T" != "0" ] && echo 0 || echo 1 )" "[case $c] tampered ciphertext rejected (rc=$RC_T, pos=$POS)"

  # ── (W) wrong-passphrase oracle ───────────────────────────────────────────
  # Flip one char of the passphrase deterministically -> guaranteed different
  # passphrase of the same length (PW is hex, so 'a' xor-style swap is simple).
  WPW="${PW}X"   # append a char: always a different passphrase, never empty
  set +e
  if [ -n "$AAD" ]; then
    $WALLET envelope decrypt --envelope "$ENV" --password "$WPW" --aad "$AAD" >/dev/null 2>&1
  else
    $WALLET envelope decrypt --envelope "$ENV" --password "$WPW" >/dev/null 2>&1
  fi
  RC_W=$?
  set -e
  assert "$( [ "$RC_W" != "0" ] && echo 0 || echo 1 )" "[case $c] wrong passphrase rejected (rc=$RC_W)"

  # Scrub this case's fixture immediately (defence-in-depth on top of trap).
  rm -f "$ENV_FILE"
done

# Optional: a single python3 well-formedness check on the last JSON blob,
# purely structural (skipped if python3 is unavailable).
if command -v python3 >/dev/null 2>&1; then
  if echo "$JSON" | python3 -c "import sys,json; json.loads(sys.stdin.read())" >/dev/null 2>&1; then
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: final inspect-envelope JSON not well-formed"; fail_count=$((fail_count + 1))
  fi
else
  echo "  SKIP: python3 unavailable; structural JSON check omitted"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail across $N_CASES random cases"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet envelope round-trip/metadata/tamper fuzz"
  exit 0
else
  echo "  FAIL: determ-wallet envelope fuzz had $fail_count failures"
  exit 1
fi
