#!/usr/bin/env bash
# Test for tools/operator_keyfile_kdf_audit.sh — the R58 KDF-migration audit.
#
# Builds real fixtures against the shipped determ-wallet and asserts the tool's
# classification + exit-code alert gate:
#
#   1. A DWE2 node keyfile (keyfile-create, Argon2id default) is reported
#      argon2id/OK, and an all-Argon2id --dir exits 0.
#   2. A DWE1 raw envelope (envelope encrypt --iters 10000, legacy PBKDF2) is
#      reported pbkdf2/LEGACY, and a --dir containing it exits 2 (alert gate).
#   3. --json emits the documented shape with counts that parse in python.
#   4. --help exits 0.
#   5. empty dir / no inputs handling: empty dir -> exit 0 (zero legacy);
#      no --dir and no --in -> exit 1 (usage error).
#   6. A garbage file is counted unparseable (skipped), not a crash.
#
# Offline: no daemon, no network. Read-only tool under test.
#
# Run from repo root: bash tools/test_operator_keyfile_kdf_audit.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
WALLET="$DETERM_WALLET"
TOOL="tools/operator_keyfile_kdf_audit.sh"

SCRATCH="build/test_operator_keyfile_kdf_audit.$$"
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

# ── Fixtures ──────────────────────────────────────────────────────────────────
# DWE2 node keyfile via keyfile-create (Argon2id default).
PW="kdf-audit-2026"
PASS_FILE="$SCRATCH/pw.txt"; printf '%s\n' "$PW" > "$PASS_FILE"
KP=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
PRIV=$($PY -c "import json,sys;print(json.loads(sys.stdin.read())['accounts'][0]['privkey_hex'])" <<< "$KP")

# All-Argon2id directory: one DWE2 node keyfile only.
CLEAN_DIR="$SCRATCH/clean"; mkdir -p "$CLEAN_DIR"
NODE_KF="$CLEAN_DIR/node.keyfile"
"$WALLET" keyfile-create --priv "$PRIV" --passphrase-from "file:$PASS_FILE" --out "$NODE_KF" >/dev/null 2>&1
assert_eq "$?" "0" "fixture: keyfile-create (DWE2 node keyfile)"

# DWE1 raw envelope via envelope encrypt --iters (legacy PBKDF2).
PLAIN="00112233445566778899aabbccddeeff"
E1=$("$WALLET" envelope encrypt --plaintext "$PLAIN" --password "$PW" --iters 10000 2>&1 | tr -d '\r')
assert_eq "${E1:0:8}" "44574531" "fixture: --iters envelope is DWE1 (magic 44574531)"

# ── 1. DWE2 node keyfile -> argon2id/OK, all-Argon2id dir exits 0 ─────────────
echo
echo "=== 1. DWE2 node keyfile reported argon2id, clean dir exits 0 ==="
set +e
OUT=$(bash "$TOOL" --dir "$CLEAN_DIR" 2>&1); RC=$?
set -e 2>/dev/null || true
assert_contains "$OUT" "DWE2/argon2id OK" "clean dir: node keyfile reported DWE2/argon2id OK"
assert_contains "$OUT" "1 argon2id, 0 legacy(pbkdf2)" "clean dir digest: 1 argon2id, 0 legacy"
assert_eq "$RC" "0" "clean (all-Argon2id) dir exits 0"

# ── 2. DWE1 raw envelope -> pbkdf2/LEGACY, dir exits 2 ────────────────────────
echo
echo "=== 2. DWE1 raw envelope reported LEGACY, dir exits 2 (alert gate) ==="
LEGACY_DIR="$SCRATCH/legacy"; mkdir -p "$LEGACY_DIR"
RAW_ENV="$LEGACY_DIR/legacy.enc"; printf '%s\n' "$E1" > "$RAW_ENV"
set +e
OUT=$(bash "$TOOL" --dir "$LEGACY_DIR" 2>&1); RC=$?
set -e 2>/dev/null || true
assert_contains "$OUT" "DWE1/pbkdf2-hmac-sha256 LEGACY" "legacy dir: raw envelope reported DWE1/pbkdf2 LEGACY"
assert_eq "$RC" "2" "dir with a legacy DWE1 file exits 2 (alert gate)"

# --in of the legacy file directly also exits 2.
set +e
OUT2=$(bash "$TOOL" --in "$RAW_ENV" 2>&1); RC2=$?
set -e 2>/dev/null || true
assert_contains "$OUT2" "1 legacy(pbkdf2)" "--in legacy file digest counts 1 legacy"
assert_eq "$RC2" "2" "--in a legacy DWE1 file exits 2"

# ── 3. --json shape + counts (mixed dir: 1 argon2id + 1 legacy) ──────────────
echo
echo "=== 3. --json shape + parsed counts ==="
MIX_DIR="$SCRATCH/mix"; mkdir -p "$MIX_DIR"
cp "$NODE_KF" "$MIX_DIR/node.keyfile"
printf '%s\n' "$E1" > "$MIX_DIR/legacy.enc"
set +e
JOUT=$(bash "$TOOL" --dir "$MIX_DIR" --json 2>/dev/null); JRC=$?
set -e 2>/dev/null || true
assert_eq "$JRC" "2" "mixed dir (has legacy) --json exits 2"
# Parse the JSON in python and assert the counts + fields.
PARSED=$(printf '%s' "$JOUT" | "$PY" -c '
import json, sys
j = json.loads(sys.stdin.read())
assert isinstance(j, dict)
assert j["scanned"] == 2, j["scanned"]
assert j["argon2id"] == 1, j["argon2id"]
assert j["pbkdf2_legacy"] == 1, j["pbkdf2_legacy"]
assert j["unparseable"] == 0, j["unparseable"]
assert isinstance(j["files"], list) and len(j["files"]) == 2
stats = sorted(f["status"] for f in j["files"])
assert stats == ["argon2id", "pbkdf2_legacy"], stats
# every file entry carries the four documented keys
for f in j["files"]:
    assert set(f.keys()) == {"path","format","kdf","status"}, f.keys()
print("OK")
' 2>&1)
assert_eq "$PARSED" "OK" "--json: scanned=2, argon2id=1, pbkdf2_legacy=1, unparseable=0, files well-formed"

# JSON on the clean dir parses to zero legacy + exits 0.
set +e
JCLEAN=$(bash "$TOOL" --dir "$CLEAN_DIR" --json 2>/dev/null); JCRC=$?
set -e 2>/dev/null || true
assert_eq "$JCRC" "0" "clean dir --json exits 0"
PARSED2=$(printf '%s' "$JCLEAN" | "$PY" -c '
import json, sys
j = json.loads(sys.stdin.read())
assert j["argon2id"] == 1 and j["pbkdf2_legacy"] == 0 and j["unparseable"] == 0, j
print("OK")
' 2>&1)
assert_eq "$PARSED2" "OK" "clean dir --json: argon2id=1, pbkdf2_legacy=0, unparseable=0"

# ── 4. --help exits 0 ────────────────────────────────────────────────────────
echo
echo "=== 4. --help exits 0 ==="
set +e
HOUT=$(bash "$TOOL" --help 2>&1); HRC=$?
set -e 2>/dev/null || true
assert_eq "$HRC" "0" "--help exits 0"
assert_contains "$HOUT" "keyfile-kdf-audit" "--help mentions the digest name"

# ── 5. empty dir -> exit 0; no inputs -> exit 1 ──────────────────────────────
echo
echo "=== 5. empty dir exits 0; no inputs exits 1 (usage error) ==="
EMPTY_DIR="$SCRATCH/empty"; mkdir -p "$EMPTY_DIR"
set +e
EOUT=$(bash "$TOOL" --dir "$EMPTY_DIR" 2>&1); ERC=$?
set -e 2>/dev/null || true
assert_eq "$ERC" "0" "empty dir exits 0 (zero legacy is clean)"
assert_contains "$EOUT" "0 files, 0 argon2id" "empty dir digest reports 0 files"

set +e
bash "$TOOL" >/dev/null 2>&1; NORC=$?
set -e 2>/dev/null || true
assert_eq "$NORC" "1" "no --dir and no --in exits 1 (usage error)"

# bad --dir (nonexistent) exits 1.
set +e
bash "$TOOL" --dir "$SCRATCH/does_not_exist" >/dev/null 2>&1; BRC=$?
set -e 2>/dev/null || true
assert_eq "$BRC" "1" "nonexistent --dir exits 1 (usage error)"

# ── 6. garbage file -> counted unparseable, no crash ─────────────────────────
echo
echo "=== 6. garbage file counted unparseable, does not crash ==="
GARB_DIR="$SCRATCH/garb"; mkdir -p "$GARB_DIR"
printf 'this is not a keyfile or an envelope at all\n' > "$GARB_DIR/junk.enc"
printf '{not even valid json}\n' > "$GARB_DIR/junk.json"
set +e
GOUT=$(bash "$TOOL" --dir "$GARB_DIR" 2>&1); GRC=$?
set -e 2>/dev/null || true
assert_contains "$GOUT" "unparseable" "garbage file reported unparseable"
assert_contains "$GOUT" "2 unparseable" "digest counts 2 unparseable"
assert_eq "$GRC" "0" "garbage-only dir exits 0 (unparseable is not legacy, not error)"

# garbage mixed with a legacy file still exits 2 (the legacy gate wins).
printf '%s\n' "$E1" > "$GARB_DIR/legacy.enc"
set +e
GOUT2=$(bash "$TOOL" --dir "$GARB_DIR" 2>&1); GRC2=$?
set -e 2>/dev/null || true
assert_eq "$GRC2" "2" "garbage + legacy dir exits 2 (legacy gate)"
assert_contains "$GOUT2" "1 legacy(pbkdf2)" "mixed garbage/legacy digest counts 1 legacy"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: test_operator_keyfile_kdf_audit"; exit 0
else
    echo "  FAIL: test_operator_keyfile_kdf_audit"; exit 1
fi
