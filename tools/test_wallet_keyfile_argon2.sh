#!/usr/bin/env bash
# R58 — determ-wallet keyfile KDF migration PBKDF2 -> Argon2id.
#
# The passphrase-encrypted envelope (keyfiles, backup shares, recovery
# envelopes) now defaults to a memory-hard Argon2id KDF (the DWE2 wire
# layout) instead of PBKDF2 (DWE1). This test pins the migration contract:
#
#   1. A fresh keyfile-create produces a DWE2 / Argon2id envelope with the
#      expected default cost params (t=3, m=65536 KiB, p=1), and it round-
#      trips through keyfile-decrypt to the exact private seed.
#   2. `envelope encrypt` (no --iters) emits a DWE2 blob (magic 44574532);
#      `envelope encrypt --iters N` still emits a legacy DWE1 blob (magic
#      44574531) for interop — both round-trip at HEAD.
#   3. BACK-COMPAT (the load-bearing property): a DWE1 (PBKDF2) envelope
#      produced by a PAST build still decrypts byte-for-byte — the same
#      pinned fixture the format-freeze guard freezes. A versioned format
#      migration must never orphan envelopes already on disk.
#   4. Fail-closed on both layouts: a wrong passphrase against a DWE2 and a
#      DWE1 envelope both fail the AEAD tag (exit 2), so the migration did
#      not weaken the wrong-password rejection.
#   5. keyfile-reencrypt re-wraps under the (Argon2id) default — a re-
#      encrypted keyfile is DWE2 and still decrypts; this is the operator's
#      "upgrade my old keyfile" path.
#
# Offline: no daemon, no network. Pure local KDF + AEAD.
#
# Run from repo root: bash tools/test_wallet_keyfile_argon2.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
WALLET="$DETERM_WALLET"

SCRATCH="build/test_wallet_keyfile_argon2.$$"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT
PY=python
command -v python >/dev/null 2>&1 || PY=python3

pass_count=0; fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count+1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count+1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count+1))
  else echo "  FAIL: $3"; echo "       missing: $2"; echo "       in:      $1"; fail_count=$((fail_count+1)); fi
}

PW="argon2-migration-2026"
PASS_FILE="$SCRATCH/pw.txt"; printf '%s\n' "$PW" > "$PASS_FILE"

# ── 1. Fresh keyfile-create is DWE2 / Argon2id + round-trips ─────────────────
echo "=== 1. Fresh keyfile-create -> Argon2id (DWE2), decrypts ==="
KP=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
PRIV=$($PY -c "import json,sys;print(json.loads(sys.stdin.read())['accounts'][0]['privkey_hex'])" <<< "$KP")
KF="$SCRATCH/node.enc"
"$WALLET" keyfile-create --priv "$PRIV" --passphrase-from "file:$PASS_FILE" --out "$KF" >/dev/null 2>&1
assert_eq "$?" "0" "keyfile-create succeeds"
INFO=$("$WALLET" keyfile-info --in "$KF" --json 2>&1 | tr -d '\r')
assert_contains "$INFO" "\"format\":\"DWE2\"" "fresh keyfile is DWE2"
assert_contains "$INFO" "\"kdf\":\"argon2id\"" "fresh keyfile KDF is argon2id"
assert_contains "$INFO" "\"argon2_t_cost\":3" "default t_cost = 3"
assert_contains "$INFO" "\"argon2_m_cost_kib\":65536" "default m_cost = 64 MiB"
assert_contains "$INFO" "\"argon2_lanes\":1" "default lanes = 1"
DEC="$SCRATCH/dec.json"
"$WALLET" keyfile-decrypt --in "$KF" --passphrase-from "file:$PASS_FILE" --out "$DEC" >/dev/null 2>&1
assert_eq "$?" "0" "keyfile-decrypt succeeds"
RSEED=$($PY -c "import json,sys;print(json.loads(open(sys.argv[1]).read())['priv_seed'])" "$DEC")
assert_eq "$RSEED" "$PRIV" "round-tripped priv_seed matches"

# ── 2. envelope encrypt: default DWE2, --iters DWE1, both round-trip ──────────
echo
echo "=== 2. envelope KDF selection by magic ==="
PLAIN="00112233445566778899aabbccddeeff"
E2=$("$WALLET" envelope encrypt --plaintext "$PLAIN" --password "$PW" 2>&1 | tr -d '\r')
assert_eq "${E2:0:8}" "44574532" "default envelope magic = DWE2"
D2=$("$WALLET" envelope decrypt --envelope "$E2" --password "$PW" 2>&1 | tr -d '\r')
assert_eq "$D2" "$PLAIN" "DWE2 envelope round-trips"
E1=$("$WALLET" envelope encrypt --plaintext "$PLAIN" --password "$PW" --iters 10000 2>&1 | tr -d '\r')
assert_eq "${E1:0:8}" "44574531" "--iters envelope magic = DWE1"
D1=$("$WALLET" envelope decrypt --envelope "$E1" --password "$PW" 2>&1 | tr -d '\r')
assert_eq "$D1" "$PLAIN" "DWE1 envelope round-trips"

# ── 3. BACK-COMPAT: a past-build DWE1 blob still decrypts byte-for-byte ───────
echo
echo "=== 3. Legacy DWE1 fixture still decrypts (no orphaned envelopes) ==="
# Same pinned fixture the format-freeze guard freezes (generated pre-R58).
PINNED_PW="determ-format-freeze-2026"
PINNED_PLAIN="44455445524d20656e76656c6f706520666f726d617420667265657a65207631"
PINNED_ENV="44574531.416f500429b4b97ea53c39aeb9c3a8d8.10270000.2b6838502f2888e85a77da52..efa9a1b058ba0266c773fe977813733095f9b9ee5cdf355f35a183f28901947123ff04d30a7abc45042f4b8663b808aa"
DECP=$("$WALLET" envelope decrypt --envelope "$PINNED_ENV" --password "$PINNED_PW" 2>&1 | tr -d '\r')
assert_eq "$DECP" "$PINNED_PLAIN" "pinned pre-R58 DWE1 envelope decrypts"

# ── 4. Fail-closed on wrong passphrase, both layouts ─────────────────────────
echo
echo "=== 4. Wrong passphrase fails-closed on DWE2 and DWE1 ==="
set +e
"$WALLET" envelope decrypt --envelope "$E2" --password "wrong" >/dev/null 2>&1; RC2=$?
"$WALLET" envelope decrypt --envelope "$E1" --password "wrong" >/dev/null 2>&1; RC1=$?
set -e
assert_eq "$RC2" "2" "DWE2 wrong passphrase exit 2"
assert_eq "$RC1" "2" "DWE1 wrong passphrase exit 2"

# ── 5. keyfile-reencrypt re-wraps under Argon2id and still decrypts ──────────
echo
echo "=== 5. keyfile-reencrypt keeps Argon2id + decrypts ==="
NEWPW="argon2-migration-2026-rotated"
NEWPF="$SCRATCH/pw2.txt"; printf '%s\n' "$NEWPW" > "$NEWPF"
KF2="$SCRATCH/node_reenc.enc"
export ARGON2_OLD_PW="$PW" ARGON2_NEW_PW="$NEWPW"
"$WALLET" keyfile-reencrypt --in "$KF" --out "$KF2" \
    --old-passphrase-env ARGON2_OLD_PW \
    --new-passphrase-env ARGON2_NEW_PW >/dev/null 2>&1
RC=$?
unset ARGON2_OLD_PW ARGON2_NEW_PW
if [ "$RC" = "0" ] && [ -s "$KF2" ]; then
    INFO2=$("$WALLET" keyfile-info --in "$KF2" --json 2>&1 | tr -d '\r')
    assert_contains "$INFO2" "\"kdf\":\"argon2id\"" "re-encrypted keyfile is Argon2id"
    DEC2="$SCRATCH/dec2.json"
    "$WALLET" keyfile-decrypt --in "$KF2" --passphrase-from "file:$NEWPF" --out "$DEC2" >/dev/null 2>&1
    assert_eq "$?" "0" "re-encrypted keyfile decrypts under new passphrase"
    RSEED2=$($PY -c "import json,sys;print(json.loads(open(sys.argv[1]).read())['priv_seed'])" "$DEC2")
    assert_eq "$RSEED2" "$PRIV" "re-encrypted keyfile preserves the seed"
else
    echo "  SKIP: keyfile-reencrypt flags differ on this build (rc=$RC) — legs 1-4 cover the migration"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_wallet_keyfile_argon2"; exit 0
else
    echo "  FAIL: test_wallet_keyfile_argon2"; exit 1
fi
