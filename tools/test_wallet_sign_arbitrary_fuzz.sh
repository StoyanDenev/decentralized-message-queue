#!/usr/bin/env bash
# determ-wallet sign-arbitrary + verify-arbitrary — FIXED-SEED RANDOMIZED
# round-trip / property / tamper FUZZ.
#
# Distinct from tools/test_wallet_message_sign_verify.sh, which exercises
# the CLI surface (flags, modes, bundle JSON shape) with a handful of
# fixed single-case inputs. THIS test is a property fuzz: for a fixed-seed
# stream of N random (keypair, message) cases it asserts the four core
# Ed25519-signature security properties, judged ONLY by the binary's OWN
# sign/verify agreement (no Ed25519 / hash reimplemented as the oracle):
#
#   P1  CORRECTNESS  — sign(priv_i, msg_i) then verify(pub_i, msg_i, sig)
#                      must ACCEPT (exit 0, result VALID).
#   P2  WRONG KEY    — verify under a DIFFERENT keypair's pubkey must
#                      REJECT (exit 2, result INVALID).
#   P3  TAMPER MSG   — verify the same sig against a 1-byte-mutated copy
#                      of the message must REJECT.
#   P4  TAMPER SIG   — verify a sig with one hex nibble XOR-flipped must
#                      REJECT.
#
# Reference strategy: round-trip + tamper-detection. The trusted oracle is
# "the binary's verify accepts exactly its own honest signature and rejects
# every perturbation." No cipher/KDF/Ed25519 is re-implemented here.
#
# All offline: account-derive-batch (deterministic key derivation from a
# fixed master seed) + sign-arbitrary + verify-arbitrary. No daemon, no
# cluster, no network. Python supplies the fixed-seed RNG, the NUL-safe
# binary message bodies (via --msg-file), and the deterministic tamper
# mutations (1-byte msg flip; 1-nibble hex sig XOR-flip).
#
# Run from repo root: bash tools/test_wallet_sign_arbitrary_fuzz.sh
set -u
# pipefail so `OUT=$(cmd | tr -d '\r'); RC=$?` reports the wallet's exit
# code (0 / 2 / 1), not tr's success — otherwise the REJECT assertions
# would silently always see RC=0.
set -o pipefail
cd "$(dirname "$0")/.."
source tools/common.sh

# ── SKIP gates: binary + Python both required ──────────────────────────────────
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
PY=python
if ! command -v python >/dev/null 2>&1; then
    if command -v python3 >/dev/null 2>&1; then PY=python3
    else echo "  SKIP: python not found (needed for fixed-seed RNG + tamper mutation)"; exit 0; fi
fi

WALLET="$DETERM_WALLET"

# ── Per-run scratch dir + cleanup of all secret fixtures (keyfiles, msgs) ──────
# Relative path under build/ to sidestep MSYS->Windows path translation for
# the native wallet exe (same convention as test_wallet_message_sign_verify.sh).
T="build/test_wallet_sign_arbitrary_fuzz.$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT

NUM_CASES=24            # >= 20 random cases
SEED=20260607          # fixed RNG seed — fully reproducible run-to-run

pass_count=0
fail_count=0
assert() {
  # assert <condition-bool 0|1-ish via test> ... we use string form:
  # assert "<got>" "<expected>" "<label>"
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if printf '%s' "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

# ── Derive NUM_CASES deterministic keypairs from one fixed master seed ─────────
# account-derive-batch: seed_i = SHA-256(master_seed || u32_le(i)); the
# resulting Ed25519 anon address is "0x" || ed_pub_hex, so the verify-time
# --ed-pub is just the address with the 0x stripped.
MASTER=$($PY -c "print('a7'*32)")    # 64 hex = 32-byte master seed
$WALLET account-derive-batch --seed "$MASTER" --count "$NUM_CASES" --out "$T/keys.json" --force >/dev/null 2>&1
if [ ! -s "$T/keys.json" ]; then
    echo "  FAIL: account-derive-batch produced no keyfile"; echo "  FAIL"; exit 1
fi

# Explode the {accounts:[...]} batch into per-index single-account keyfiles
# (the {address,privkey_hex} shape sign-arbitrary's --priv-keyfile expects),
# and emit the fixed-seed per-case plan as TSV lines:
#   idx  wrong_idx  msg_kind  msg_hex  flip_nibble_pos
$PY - "$T/keys.json" "$T" "$NUM_CASES" "$SEED" > "$T/plan.tsv" <<'PY_EOF'
import json, os, random, sys
keys_path, outdir, n, seed = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
accts = json.load(open(keys_path))["accounts"]
assert len(accts) >= n, "not enough derived accounts"

for i, a in enumerate(accts[:n]):
    with open(os.path.join(outdir, "key_%d.json" % i), "w") as f:
        json.dump({"address": a["address"], "privkey_hex": a["privkey_hex"]}, f)

rng = random.Random(seed)
rows = []
for i in range(n):
    # Pick a DIFFERENT keypair index for the wrong-key tamper.
    wrong = rng.randrange(n - 1)
    if wrong >= i:
        wrong += 1
    # Random message: mix of empty, short, and longer bodies spanning the
    # full 0x00..0xFF byte range (NUL-safe; delivered via --msg-file).
    kind = rng.randrange(4)
    if kind == 0:
        length = 0                       # empty message (domain-sep-only beacon)
    elif kind == 1:
        length = rng.randrange(1, 16)    # short
    elif kind == 2:
        length = rng.randrange(16, 200)  # medium
    else:
        length = rng.randrange(200, 1024)  # longer
    body = bytes(rng.randrange(256) for _ in range(length))
    # Deterministic sig-tamper position: which hex nibble to XOR-flip.
    # (sig is 128 hex chars; pick now so the whole run is reproducible.)
    flip = rng.randrange(128)
    # Use "-" sentinel for the empty-message case so the TSV never has an
    # empty field (bash `read` field-splitting is brittle around those).
    rows.append((i, wrong, kind, body.hex() or "-", flip))

for r in rows:
    print("%d\t%d\t%d\t%s\t%d" % r)
PY_EOF
# Strip any CR the Windows-text-mode print may have appended (\r\n line
# endings) so the trailing FLIP column is a clean integer for read/int().
$PY -c "import sys;d=open(sys.argv[1],'rb').read().replace(b'\r\n',b'\n');open(sys.argv[1],'wb').write(d)" "$T/plan.tsv"

if [ ! -s "$T/plan.tsv" ]; then
    echo "  FAIL: fixed-seed plan generation produced no rows"; echo "  FAIL"; exit 1
fi

PLAN_ROWS=$(wc -l < "$T/plan.tsv" | tr -d ' ')
assert "$PLAN_ROWS" "$NUM_CASES" "fixed-seed plan has $NUM_CASES cases"

# Helper: materialize a hex string into a raw binary file (NUL-safe message
# body). The "-" sentinel means empty message -> zero-byte file.
hex_to_file() {
  local hx="$2"
  if [ "$hx" = "-" ]; then hx=""; fi
  $PY -c "import sys; open(sys.argv[1],'wb').write(bytes.fromhex(sys.argv[2]))" "$1" "$hx"
}
# Helper: XOR-flip nibble at position P of a 128-char hex string (low bit).
flip_nibble() {
  $PY - "$1" "$2" <<'PY_EOF'
import sys
s, p = sys.argv[1], int(sys.argv[2])
tab = "0123456789abcdef"
ch = s[p].lower()
# XOR the nibble value with 1 (guaranteed to change it -> different sig byte).
new = tab[tab.index(ch) ^ 1]
sys.stdout.write(s[:p] + new + s[p+1:])
PY_EOF
}

echo "=== Fixed-seed (seed=$SEED) round-trip + tamper fuzz, $NUM_CASES cases ==="
accept_ok=0
reject_wrongkey_ok=0
reject_msg_ok=0
reject_sig_ok=0

while IFS=$'\t' read -r IDX WRONG KIND MSG_HEX FLIP; do
  KEYFILE="$T/key_${IDX}.json"
  MSGFILE="$T/msg_${IDX}.bin"
  hex_to_file "$MSGFILE" "$MSG_HEX"

  PUB=$($PY -c "import json;print(json.load(open('$KEYFILE'))['address'][2:])")
  WRONG_PUB=$($PY -c "import json;print(json.load(open('$T/key_${WRONG}.json'))['address'][2:])")

  # ── Sign (detached, default) ────────────────────────────────────────────────
  SIG=$($WALLET sign-arbitrary --priv-keyfile "$KEYFILE" --msg-file "$MSGFILE" 2>/dev/null | tr -d '\r')
  SRC=$?
  if [ "$SRC" != "0" ] || [ "${#SIG}" != "128" ]; then
    echo "  FAIL: case $IDX sign did not yield a 128-hex sig (rc=$SRC len=${#SIG})"
    fail_count=$((fail_count + 1)); continue
  fi

  # ── P1 CORRECTNESS: honest sig must ACCEPT ─────────────────────────────────
  set +e
  OUT=$($WALLET verify-arbitrary --ed-pub "$PUB" --msg-file "$MSGFILE" --sig-hex "$SIG" 2>/dev/null | tr -d '\r'); RC=$?
  set -e
  if [ "$RC" = "0" ] && printf '%s' "$OUT" | grep -q 'VALID'; then
    accept_ok=$((accept_ok + 1))
  else
    echo "  FAIL: case $IDX P1 honest round-trip REJECTED (rc=$RC out=$OUT)"
    fail_count=$((fail_count + 1))
  fi

  # ── P2 WRONG KEY: verify under another keypair must REJECT ──────────────────
  set +e
  OUT=$($WALLET verify-arbitrary --ed-pub "$WRONG_PUB" --msg-file "$MSGFILE" --sig-hex "$SIG" 2>/dev/null | tr -d '\r'); RC=$?
  set -e
  if [ "$RC" = "2" ] && printf '%s' "$OUT" | grep -q 'INVALID'; then
    reject_wrongkey_ok=$((reject_wrongkey_ok + 1))
  else
    echo "  FAIL: case $IDX P2 wrong-key sig ACCEPTED (rc=$RC out=$OUT)"
    fail_count=$((fail_count + 1))
  fi

  # ── P3 TAMPER MSG: mutate one message byte (append for empty msg) ───────────
  TMSGFILE="$T/msg_${IDX}.tamp.bin"
  $PY - "$MSGFILE" "$TMSGFILE" <<'PY_EOF'
import sys
raw = open(sys.argv[1], "rb").read()
# Flip the low bit of the first byte; if the message is empty, append a byte
# (the empty-message sig must NOT validate a 1-byte message).
mut = bytes([raw[0] ^ 0x01]) + raw[1:] if raw else b"\x01"
open(sys.argv[2], "wb").write(mut)
PY_EOF
  set +e
  OUT=$($WALLET verify-arbitrary --ed-pub "$PUB" --msg-file "$TMSGFILE" --sig-hex "$SIG" 2>/dev/null | tr -d '\r'); RC=$?
  set -e
  if [ "$RC" = "2" ] && printf '%s' "$OUT" | grep -q 'INVALID'; then
    reject_msg_ok=$((reject_msg_ok + 1))
  else
    echo "  FAIL: case $IDX P3 tampered-message sig ACCEPTED (rc=$RC out=$OUT)"
    fail_count=$((fail_count + 1))
  fi
  rm -f "$TMSGFILE"

  # ── P4 TAMPER SIG: XOR-flip one hex nibble of the signature ─────────────────
  TSIG=$(flip_nibble "$SIG" "$FLIP")
  if [ "$TSIG" = "$SIG" ] || [ "${#TSIG}" != "128" ]; then
    echo "  FAIL: case $IDX P4 nibble-flip produced an unchanged/wrong-length sig"
    fail_count=$((fail_count + 1))
  else
    set +e
    OUT=$($WALLET verify-arbitrary --ed-pub "$PUB" --msg-file "$MSGFILE" --sig-hex "$TSIG" 2>/dev/null | tr -d '\r'); RC=$?
    set -e
    if [ "$RC" = "2" ] && printf '%s' "$OUT" | grep -q 'INVALID'; then
      reject_sig_ok=$((reject_sig_ok + 1))
    else
      echo "  FAIL: case $IDX P4 tampered-signature ACCEPTED (rc=$RC out=$OUT)"
      fail_count=$((fail_count + 1))
    fi
  fi

  rm -f "$MSGFILE"
done < "$T/plan.tsv"

echo
echo "=== Property tallies (each must equal $NUM_CASES) ==="
assert "$accept_ok"          "$NUM_CASES" "P1 honest round-trip ACCEPT on all cases"
assert "$reject_wrongkey_ok" "$NUM_CASES" "P2 wrong-key REJECT on all cases"
assert "$reject_msg_ok"      "$NUM_CASES" "P3 tampered-message REJECT on all cases"
assert "$reject_sig_ok"      "$NUM_CASES" "P4 tampered-signature REJECT on all cases"

# ── Reproducibility cross-check: same fixed seed -> identical plan ─────────────
# Regenerate the plan from the same seed into a second file and diff. This
# pins that the fuzz stream is deterministic (a flaky/seedless RNG would
# make this test non-reproducible for CI triage).
$PY - "$T/keys.json" "$T" "$NUM_CASES" "$SEED" > "$T/plan2.tsv" <<'PY_EOF'
import json, os, random, sys
keys_path, outdir, n, seed = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
accts = json.load(open(keys_path))["accounts"]
rng = random.Random(seed)
rows = []
for i in range(n):
    wrong = rng.randrange(n - 1)
    if wrong >= i:
        wrong += 1
    kind = rng.randrange(4)
    if kind == 0:
        length = 0
    elif kind == 1:
        length = rng.randrange(1, 16)
    elif kind == 2:
        length = rng.randrange(16, 200)
    else:
        length = rng.randrange(200, 1024)
    body = bytes(rng.randrange(256) for _ in range(length))
    flip = rng.randrange(128)
    rows.append((i, wrong, kind, body.hex() or "-", flip))
for r in rows:
    print("%d\t%d\t%d\t%s\t%d" % r)
PY_EOF
$PY -c "import sys;d=open(sys.argv[1],'rb').read().replace(b'\r\n',b'\n');open(sys.argv[1],'wb').write(d)" "$T/plan2.tsv"
if cmp -s "$T/plan.tsv" "$T/plan2.tsv"; then
  echo "  PASS: fixed-seed fuzz plan is reproducible (seed=$SEED)"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: fixed-seed fuzz plan differs across runs (RNG not deterministic)"; fail_count=$((fail_count + 1))
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet sign-arbitrary/verify-arbitrary fixed-seed fuzz"
  exit 0
else
  echo "  FAIL: test_wallet_sign_arbitrary_fuzz"
  exit 1
fi
