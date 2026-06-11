#!/usr/bin/env bash
# determ-wallet passphrase-encrypted keyfile LIFECYCLE property/fuzz test.
#
# This is a fixed-seed PROPERTY test, distinct from the per-command CLI tests
# (test_wallet_keyfile_create / _info / _decrypt / _reencrypt / _recover):
# those each pin a single fixed keypair + one or two fixed passphrases and
# exhaustively check one command's argparse / diagnostics. THIS test instead
# drives MANY random (key, passphrase) pairs through the ENTIRE encrypted
# keyfile lifecycle as one closed loop and asserts the cryptographic
# round-trip identities hold for every case.
#
# Commands under test (the S-004 passphrase-encrypted keyfile family):
#   keyfile-create   --priv <hex> --passphrase-from env:NAME --out <f>
#   keyfile-info     --in <f> [--json]            (passive metadata, no pw)
#   keyfile-decrypt  --in <f> --passphrase-from env:NAME --out <f>
#   keyfile-reencrypt --in <f> --out <f> --old-passphrase-env A --new-passphrase-env B
#
# SAFE REFERENCE (oracle = the KNOWN ORIGINAL key, never a reimplemented
# cipher/KDF):
#   P1 round-trip identity:
#       decrypt(create(priv, P)) == priv           (byte-for-byte seed + pubkey)
#   P2 info metadata correctness:
#       keyfile-info(create(priv, P)).pubkey == pubkey-derived-from-priv
#   P3 passphrase rotation preserves the key:
#       decrypt(reencrypt(create(priv, P_old), P_old -> P_new), P_new) == priv
#       AND the on-chain identity (header pubkey) is unchanged.
#   P4 wrong passphrase MUST fail:
#       decrypt(create(priv, P), P') with P' != P  exits 2, no plaintext leak.
#       (also: after rotation, the OLD passphrase no longer decrypts.)
#   P5 ciphertext tamper detection (AEAD):
#       XOR-flip one nibble of the ciphertext field  =>  decrypt exits 2,
#       no plaintext leak. (XOR-flip guarantees a real mutation.)
#
# The original priv seed comes from `account-create-batch --json`, whose
# pubkey/address is the oracle for P2/P3 identity invariance. Passphrases are
# delivered ONLY via env-var NAMES (the commands never take the literal
# secret on the command line).
#
# Determinism: a fixed-seed bash LCG (no external RNG) drives passphrase
# selection and tamper-nibble choice so reruns are byte-identical. Keys are
# inherently random (account-create-batch), but the round-trip identities are
# universal so the assertions are stable regardless.
#
# CASES: 24 random lifecycle iterations (>= 20 required) + fixed edge cases.
#
# Run from repo root: bash tools/test_wallet_keyfile_lifecycle_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# python is required to parse the JSON the commands emit and to perform the
# XOR-flip tamper. Skip cleanly if it is unavailable.
PY=python
if ! command -v python >/dev/null 2>&1; then
    if command -v python3 >/dev/null 2>&1; then
        PY=python3
    else
        echo "  SKIP: python not found (needed to parse JSON + XOR-flip tamper)"
        exit 0
    fi
fi

# Scratch under build/ to dodge MSYS path-translation quirks (matches the
# sibling wallet tests). All fixtures hold TEST-ONLY secret material and are
# wiped by the EXIT trap.
SCRATCH="build/test_wallet_keyfile_lifecycle_fuzz.$$"
mkdir -p "$SCRATCH"
T="$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

pass_count=0
fail_count=0
assert() {
  # assert <cond-bool: 0/1> <message>
  if [ "$1" = "0" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_ne() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       both: $1"; fail_count=$((fail_count + 1)); fi
}
assert_not_exists() {
  if [ ! -e "$1" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2 (file unexpectedly present: $1)"; fail_count=$((fail_count + 1)); fi
}

# ── Fixed-seed deterministic LCG (Numerical Recipes constants) ───────────────
# Used only to pick passphrases + tamper-nibble offsets reproducibly. NOT used
# as a crypto oracle.
RNG_STATE=20260607
rng_next() {  # echoes a non-negative pseudo-random integer, advances state
  RNG_STATE=$(( (1103515245 * RNG_STATE + 12345) & 0x7fffffff ))
  echo "$RNG_STATE"
}

# A small fixed alphabet of passphrase building blocks; the LCG composes them
# so each case gets a distinct, reproducible passphrase pair.
PW_PARTS=(correct horse battery staple tower rooftop evergreen 2026 \
          quartz lantern nimbus cobalt thistle meadow zenith fjord)
make_pw() {  # make_pw <salt-int> -> echoes a composed passphrase
    local s="$1"
    local a=$(( s % ${#PW_PARTS[@]} ))
    local b=$(( (s / 7) % ${#PW_PARTS[@]} ))
    local c=$(( (s / 53) % ${#PW_PARTS[@]} ))
    printf '%s-%s-%s-%s' "${PW_PARTS[$a]}" "${PW_PARTS[$b]}" "${PW_PARTS[$c]}" "$s"
}

# Derive the expected pubkey (oracle) from a fresh keypair JSON line.
extract_priv() { $PY -c "import json,sys;print(json.loads(sys.stdin.read())['accounts'][0]['privkey_hex'])" <<< "$1"; }
extract_addr() { $PY -c "import json,sys;print(json.loads(sys.stdin.read())['accounts'][0]['address'])" <<< "$1"; }

echo "=== 0. Help text mentions the keyfile lifecycle commands ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
for cmd in keyfile-create keyfile-info keyfile-decrypt keyfile-reencrypt; do
    if echo "$H" | grep -q "$cmd"; then
        echo "  PASS: help mentions $cmd"; pass_count=$((pass_count + 1))
    else
        echo "  FAIL: help missing $cmd"; fail_count=$((fail_count + 1))
    fi
done

N_CASES=24
echo
echo "=== 1. Randomized lifecycle property loop ($N_CASES cases) ==="
echo "    (create -> info -> decrypt round-trip; reencrypt rotation; wrong-pw; XOR tamper)"

# Per-case secret material lives in env vars whose NAMES we hand to the CLI.
# We reuse two slots and overwrite them each iteration.
for i in $(seq 1 "$N_CASES"); do
    r1=$(rng_next); r2=$(rng_next); r3=$(rng_next)
    P_OLD=$(make_pw "$r1")
    P_NEW=$(make_pw "$r2")
    # Guard: the two passphrases must differ for the wrong-pw / rotation checks.
    if [ "$P_OLD" = "$P_NEW" ]; then P_NEW="${P_NEW}-x"; fi
    export KFL_OLD="$P_OLD"
    export KFL_NEW="$P_NEW"

    # Fresh random keypair; its pubkey is the oracle for identity invariance.
    KP=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
    PRIV=$(extract_priv "$KP")
    ADDR=$(extract_addr "$KP")
    EXP_PUB=${ADDR#0x}

    ok=0
    [ "${#PRIV}" = "64" ] || ok=1
    [ "${#EXP_PUB}" = "64" ] || ok=1
    if [ "$ok" != "0" ]; then
        echo "  FAIL: case $i fixture malformed (priv=${#PRIV} pub=${#EXP_PUB})"
        fail_count=$((fail_count + 1)); continue
    fi

    ENC="$T/c${i}.enc"
    REENC="$T/c${i}_re.enc"
    DEC="$T/c${i}_dec.json"
    DEC2="$T/c${i}_dec2.json"
    WRONG="$T/c${i}_wrong.json"
    TAMPER="$T/c${i}_tamper.enc"
    TAMPER_OUT="$T/c${i}_tamper.json"

    # ── create under P_OLD ──────────────────────────────────────────────────
    "$WALLET" keyfile-create --priv "$PRIV" --passphrase-from "env:KFL_OLD" \
        --out "$ENC" >/dev/null 2>&1
    rc=$?
    if [ "$rc" != "0" ]; then
        echo "  FAIL: case $i keyfile-create rc=$rc"; fail_count=$((fail_count + 1)); continue
    fi

    # ── P2: info reports the right pubkey WITHOUT a passphrase ───────────────
    INFO=$("$WALLET" keyfile-info --in "$ENC" --json 2>&1 | tr -d '\r')
    INFO_PUB=$($PY -c "import json,sys;print(json.loads(sys.stdin.read()).get('pubkey_hex',''))" <<< "$INFO" 2>/dev/null)
    [ "$INFO_PUB" = "$EXP_PUB" ] && c_p2=0 || c_p2=1

    # ── P1: decrypt(create) recovers the ORIGINAL seed + pubkey ─────────────
    "$WALLET" keyfile-decrypt --in "$ENC" --passphrase-from "env:KFL_OLD" \
        --out "$DEC" >/dev/null 2>&1
    rc=$?
    REC_SEED=$($PY -c "import json;print(json.load(open('$DEC'))['priv_seed'])" 2>/dev/null)
    REC_PUB=$($PY -c "import json;print(json.load(open('$DEC'))['pubkey'])" 2>/dev/null)
    if [ "$rc" = "0" ] && [ "$REC_SEED" = "$PRIV" ] && [ "$REC_PUB" = "$EXP_PUB" ]; then
        c_p1=0; else c_p1=1; fi

    # ── P3: rotate P_OLD -> P_NEW, then decrypt under P_NEW recovers original
    "$WALLET" keyfile-reencrypt --in "$ENC" --out "$REENC" \
        --old-passphrase-env KFL_OLD --new-passphrase-env KFL_NEW >/dev/null 2>&1
    rc=$?
    c_rot_rc=$rc
    "$WALLET" keyfile-decrypt --in "$REENC" --passphrase-from "env:KFL_NEW" \
        --out "$DEC2" >/dev/null 2>&1
    rc2=$?
    REC2_SEED=$($PY -c "import json;print(json.load(open('$DEC2'))['priv_seed'])" 2>/dev/null)
    REC2_PUB=$($PY -c "import json;print(json.load(open('$DEC2'))['pubkey'])" 2>/dev/null)
    if [ "$c_rot_rc" = "0" ] && [ "$rc2" = "0" ] && \
       [ "$REC2_SEED" = "$PRIV" ] && [ "$REC2_PUB" = "$EXP_PUB" ]; then
        c_p3=0; else c_p3=1; fi
    # header pubkey preserved byte-for-byte across the rotation
    H_ORIG=$(sed -n '1p' "$ENC" | tr -d '\r')
    H_RE=$(sed -n '1p' "$REENC" | tr -d '\r')
    [ "$H_ORIG" = "$H_RE" ] && c_hdr=0 || c_hdr=1

    # ── P4a: wrong passphrase on the ORIGINAL file fails (exit 2, no leak) ───
    rm -f "$WRONG"
    "$WALLET" keyfile-decrypt --in "$ENC" --passphrase-from "env:KFL_NEW" \
        --out "$WRONG" >/dev/null 2>&1
    rc=$?
    if [ "$rc" = "2" ] && [ ! -e "$WRONG" ]; then c_p4a=0; else c_p4a=1; fi

    # ── P4b: after rotation the OLD passphrase no longer decrypts the new file
    rm -f "$T/c${i}_oldfail.json"
    "$WALLET" keyfile-decrypt --in "$REENC" --passphrase-from "env:KFL_OLD" \
        --out "$T/c${i}_oldfail.json" >/dev/null 2>&1
    rc=$?
    if [ "$rc" = "2" ] && [ ! -e "$T/c${i}_oldfail.json" ]; then c_p4b=0; else c_p4b=1; fi

    # ── P5: XOR-flip one nibble of the ciphertext field => AEAD rejects ──────
    # The envelope blob (line 2) is dot-separated hex fields; the LAST field is
    # the ciphertext+tag. XOR-flip a deterministically-chosen nibble so the
    # mutation is ALWAYS a real change, then confirm decrypt fails (exit 2).
    nibble_sel=$(( r3 % 997 ))
    $PY - "$ENC" "$TAMPER" "$nibble_sel" <<'PY_EOF'
import sys
inp, outp, sel = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(inp) as f:
    lines = f.read().split("\n")
# locate the blob line (the one with dot-separated hex fields)
bidx = None
for j, ln in enumerate(lines):
    if ln.count(".") >= 4:
        bidx = j; break
assert bidx is not None, "no envelope blob line found"
fields = lines[bidx].split(".")
ct = fields[-1]
assert len(ct) > 0 and all(c in "0123456789abcdefABCDEF" for c in ct), "ciphertext field not hex"
pos = sel % len(ct)
orig = ct[pos]
# XOR the nibble value with 1 -> guaranteed different hex digit
flipped = "%x" % (int(orig, 16) ^ 1)
ct2 = ct[:pos] + flipped + ct[pos+1:]
assert ct2 != ct, "XOR-flip produced no change"
fields[-1] = ct2
lines[bidx] = ".".join(fields)
with open(outp, "w") as f:
    f.write("\n".join(lines))
PY_EOF
    tamper_built=$?
    rm -f "$TAMPER_OUT"
    "$WALLET" keyfile-decrypt --in "$TAMPER" --passphrase-from "env:KFL_OLD" \
        --out "$TAMPER_OUT" >/dev/null 2>&1
    rc=$?
    if [ "$tamper_built" = "0" ] && [ "$rc" = "2" ] && [ ! -e "$TAMPER_OUT" ]; then
        c_p5=0; else c_p5=1; fi

    # Roll the per-case verdicts into one PASS/FAIL line to keep output bounded.
    case_fail=$(( c_p1 + c_p2 + c_p3 + c_hdr + c_p4a + c_p4b + c_p5 ))
    if [ "$case_fail" = "0" ]; then
        echo "  PASS: case $i lifecycle OK (P1 round-trip, P2 info, P3 rotate, P4 wrong-pw, P5 tamper)"
        pass_count=$((pass_count + 1))
    else
        echo "  FAIL: case $i  [P1=$c_p1 P2=$c_p2 P3=$c_p3 hdr=$c_hdr P4a=$c_p4a P4b=$c_p4b P5=$c_p5]"
        echo "        priv=$PRIV pub=$EXP_PUB P_OLD=$P_OLD P_NEW=$P_NEW"
        fail_count=$((fail_count + 1))
    fi

    # Scrub per-case plaintext recoveries promptly (defence in depth; the EXIT
    # trap also nukes the whole scratch dir).
    rm -f "$DEC" "$DEC2"
done
unset KFL_OLD KFL_NEW 2>/dev/null || true

# ── 2. Fresh-salt non-determinism: same (key, passphrase) -> distinct blobs ──
echo
echo "=== 2. Fresh salt/nonce: two creates of the SAME key+passphrase differ ==="
export KFL_FS="fixed-fresh-salt-passphrase"
KP=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
FS_PRIV=$(extract_priv "$KP")
FS_PUB=$(extract_addr "$KP"); FS_PUB=${FS_PUB#0x}
"$WALLET" keyfile-create --priv "$FS_PRIV" --passphrase-from "env:KFL_FS" --out "$T/fs_a.enc" >/dev/null 2>&1
"$WALLET" keyfile-create --priv "$FS_PRIV" --passphrase-from "env:KFL_FS" --out "$T/fs_b.enc" >/dev/null 2>&1
BLOB_A=$(sed -n '2p' "$T/fs_a.enc" | tr -d '\r')
BLOB_B=$(sed -n '2p' "$T/fs_b.enc" | tr -d '\r')
HDR_A=$(sed -n '1p' "$T/fs_a.enc" | tr -d '\r')
HDR_B=$(sed -n '1p' "$T/fs_b.enc" | tr -d '\r')
assert_ne "$BLOB_A" "$BLOB_B" "two encryptions of same key+pw differ (fresh salt+nonce)"
assert_eq "$HDR_A" "$HDR_B" "header (pubkey) is identical across the two encryptions"
# Both must still decrypt to the SAME original seed (distinct envelope, one key).
"$WALLET" keyfile-decrypt --in "$T/fs_a.enc" --passphrase-from "env:KFL_FS" --out "$T/fs_a.json" >/dev/null 2>&1
"$WALLET" keyfile-decrypt --in "$T/fs_b.enc" --passphrase-from "env:KFL_FS" --out "$T/fs_b.json" >/dev/null 2>&1
SA=$($PY -c "import json;print(json.load(open('$T/fs_a.json'))['priv_seed'])" 2>/dev/null)
SB=$($PY -c "import json;print(json.load(open('$T/fs_b.json'))['priv_seed'])" 2>/dev/null)
assert_eq "$SA" "$FS_PRIV" "fresh-salt blob A decrypts to original seed"
assert_eq "$SB" "$FS_PRIV" "fresh-salt blob B decrypts to original seed"
rm -f "$T/fs_a.json" "$T/fs_b.json"
unset KFL_FS 2>/dev/null || true

# ── 3. Salt/nonce tamper also detected (XOR-flip the salt field) ─────────────
echo
echo "=== 3. XOR-flip of the salt field is detected (KDF derives wrong key) ==="
export KFL_S="salt-tamper-passphrase"
KP=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
S_PRIV=$(extract_priv "$KP")
"$WALLET" keyfile-create --priv "$S_PRIV" --passphrase-from "env:KFL_S" --out "$T/salt_src.enc" >/dev/null 2>&1
$PY - "$T/salt_src.enc" "$T/salt_tamper.enc" <<'PY_EOF'
import sys
inp, outp = sys.argv[1], sys.argv[2]
with open(inp) as f:
    lines = f.read().split("\n")
bidx = next(j for j, ln in enumerate(lines) if ln.count(".") >= 4)
fields = lines[bidx].split(".")
# fields: magic.salt.iters.nonce.aad.ciphertext  -> salt is index 1
salt = fields[1]
pos = 0
flipped = "%x" % (int(salt[pos], 16) ^ 1)
fields[1] = salt[:pos] + flipped + salt[pos+1:]
assert fields[1] != salt
lines[bidx] = ".".join(fields)
with open(outp, "w") as f:
    f.write("\n".join(lines))
PY_EOF
rm -f "$T/salt_tamper.json"
"$WALLET" keyfile-decrypt --in "$T/salt_tamper.enc" --passphrase-from "env:KFL_S" \
    --out "$T/salt_tamper.json" >/dev/null 2>&1
rc=$?
assert_eq "$rc" "2" "salt XOR-flip => decrypt exits 2 (wrong key derived)"
assert_not_exists "$T/salt_tamper.json" "no plaintext leak on salt tamper"
unset KFL_S 2>/dev/null || true

# ── Summary ──────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail  ($N_CASES randomized lifecycle cases)"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet keyfile lifecycle property/fuzz"
    exit 0
else
    echo "  FAIL: test_wallet_keyfile_lifecycle_fuzz"
    exit 1
fi
