#!/usr/bin/env bash
# determ-wallet backup-verify composite verification CLI test.
#
# Verifies the composite-backup structural verification CLI:
#   - Loads a Shamir share-set + per-share AEAD envelope file pair.
#   - Checks both parse, both have the expected shape, and the share
#     x-values match the envelope share_index values 1:1.
#   - Each envelope blob deserializes via envelope::deserialize and
#     has structurally valid metadata.
#   - NEVER attempts AES-GCM, never requires any passphrase.
#
# Assertions:
#   1. Help line mentions backup-verify.
#   2. Valid backup passes (human + JSON modes), exit 0.
#   3. Human output lists every envelope by share_index with metadata.
#   4. JSON output schema matches spec (valid=true, envelope_details
#      array length == share_count, errors=[]).
#   5. --threshold met → [OK] line; --threshold > count → [INFO], exit 0.
#   6. Truncated envelopes file (1 envelope missing) → exit 2.
#   7. Corrupted envelope blob (mutated magic bytes) → exit 2 +
#      "deserialize failed" diagnostic.
#   8. Duplicate share_index in envelopes file → exit 2.
#   9. Mismatched 1:1 mapping (envelope index doesn't match any share)
#      → exit 2 + "do not match" diagnostic.
#  10. Missing --shares file → exit 1.
#  11. Missing --envelopes file → exit 1.
#  12. Malformed shares JSON → exit 1.
#  13. Malformed envelopes JSON → exit 1.
#  14. Envelopes file missing "envelopes" key → exit 2.
#  15. Envelope entry missing share_index → exit 2.
#  16. Envelope entry missing envelope_blob → exit 2.
#  17. --json on invalid → valid=false + non-empty errors.
#  18. NEVER outputs decrypted material (no plaintext_hex / secret_hex).
#  19. Empty envelopes array → exit 2.
#  20. Backup with non-default PBKDF2 iters is reported correctly.
#
# Run from repo root: bash tools/test_wallet_backup_verify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
# Absolutize the wallet binary path so subprocess.run() under native
# Windows Python can resolve it (git-bash's MSYS path translation only
# kicks in for direct shell args, not for Python's CreateProcess call).
if [ "${WALLET#/}" = "$WALLET" ] && [ "${WALLET#?:}" = "$WALLET" ]; then
    # Relative path — prepend project root.
    WALLET_ABS="$PROJECT_ROOT/$WALLET"
else
    WALLET_ABS="$WALLET"
fi

# Use a scratch directory inside build/ so its path is stable Windows-side
# (mktemp -d returns /tmp/... which msys2 maps to %TEMP%, but Python
# subprocesses then need the translated Windows form). build/ is already
# in the repo root so the path stays native on both sides.
SCRATCH="build/test_wallet_backup_verify.$$"
mkdir -p "$SCRATCH"
TMP="$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

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
assert_not_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  FAIL: $3 (unexpected substring: $2)"; fail_count=$((fail_count + 1))
  else echo "  PASS: $3"; pass_count=$((pass_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# Low iters keeps the encrypt loop fast (5 PBKDF2 derivations).
ITERS=10000
SECRET="deadbeefcafebabe0011223344556677"

echo "=== 1. Help text mentions backup-verify ==="
H=$("$WALLET" help 2>&1)
if echo "$H" | grep -q "backup-verify"; then
    echo "  PASS: help mentions backup-verify"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing backup-verify"; fail_count=$((fail_count + 1))
fi

echo
echo "=== Setup: produce a 3-of-5 backup (shares + envelopes) ==="
"$WALLET" shamir-split --secret "$SECRET" --threshold 3 --shares 5 --json \
    | tr -d '\r' > "$TMP/shares.json"
if [ ! -s "$TMP/shares.json" ]; then
    echo "  FAIL: shamir-split produced empty output"; exit 1
fi
echo "  wrote $TMP/shares.json"

# Build the envelopes file by encrypting each share's y_hex under a
# per-keyholder passphrase. The composite is what `backup-verify`
# consumes. Each share gets its own unique passphrase to model the
# real-world threshold-recovery scenario.
$PY - "$TMP/shares.json" "$TMP/envelopes.json" "$WALLET_ABS" "$ITERS" <<'PY_EOF'
import json, subprocess, sys
shares_path, envs_path, wallet, iters = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
shares = json.load(open(shares_path))["shares"]
envs = []
for s in shares:
    pw = f"keyholder-pw-{s['x']}"
    r = subprocess.run(
        [wallet, "envelope", "encrypt", "--plaintext", s["y_hex"],
         "--password", pw, "--iters", iters],
        capture_output=True, text=True, check=True)
    blob = r.stdout.strip().replace("\r", "")
    envs.append({"share_index": s["x"], "envelope_blob": blob})
with open(envs_path, "w") as f:
    json.dump({"envelopes": envs}, f)
print(f"  wrote {envs_path} with {len(envs)} envelopes")
PY_EOF

echo
echo "=== 2. Valid backup passes (human mode) ==="
OUT=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envelopes.json" | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit code 0 on valid backup"
assert_contains "$OUT" "Wallet backup verification" "human header line present"
assert_contains "$OUT" "5 shares, x range 1..5" "reports 5 shares + range"
assert_contains "$OUT" "5 envelopes" "reports 5 envelopes"
assert_contains "$OUT" "\[OK\] 1:1 by share_index" "1:1 mapping confirmed"
assert_contains "$OUT" "Envelope 1:" "envelope 1 listed"
assert_contains "$OUT" "Envelope 5:" "envelope 5 listed"
assert_contains "$OUT" "PBKDF2=$ITERS" "PBKDF2 iters reported"
assert_contains "$OUT" "salt=16B" "salt length reported"
assert_contains "$OUT" "nonce=12B" "nonce length reported"
assert_contains "$OUT" "\[OK\] Backup structurally valid" "overall OK line"

echo
echo "=== 3. Valid backup passes (JSON mode) ==="
JSON=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envelopes.json" --json | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit code 0 on valid backup --json"
$PY - <<PY_EOF
import json, sys
d = json.loads('''$JSON''')
required = {"valid","shares_file","envelopes_file","share_count","envelope_count","mapping_consistent","envelope_details","threshold_satisfied","errors"}
missing = required - set(d.keys())
assert not missing, f"missing fields: {missing}"
assert d["valid"] is True, f"valid != True: {d['valid']}"
assert d["share_count"] == 5
assert d["envelope_count"] == 5
assert d["mapping_consistent"] is True
assert len(d["envelope_details"]) == 5
assert d["threshold_satisfied"] is None
assert d["errors"] == []
# Per-envelope detail schema.
for det in d["envelope_details"]:
    assert {"share_index","pbkdf2_iters","salt_len","nonce_len","aad_len","ciphertext_len"} <= set(det.keys())
    assert det["pbkdf2_iters"] == $ITERS
    assert det["salt_len"] == 16
    assert det["nonce_len"] == 12
    assert det["ciphertext_len"] >= 16
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json schema matches spec"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json schema doesn't match spec"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 4. --threshold met → [OK] line ==="
OUT=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envelopes.json" --threshold 3 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 when threshold met"
assert_contains "$OUT" "\[OK\] Share count (5) >= threshold (3)" "OK on threshold met"

echo
echo "=== 5. --threshold > share count → [INFO], still exit 0 ==="
OUT=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envelopes.json" --threshold 99 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 even when threshold > count"
assert_contains "$OUT" "\[INFO\] Share count (5) < threshold (99)" "INFO on under-threshold"

echo
echo "=== 6. Truncated envelopes file (drop last envelope) → exit 2 ==="
$PY - "$TMP/envelopes.json" "$TMP/envs_truncated.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["envelopes"] = d["envelopes"][:-1]
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
set +e
ERR=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envs_truncated.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on truncated envelopes"
assert_contains "$ERR" "\[FAIL\]" "[FAIL] marker"
assert_contains "$ERR" "share count" "diagnostic mentions count mismatch"

echo
echo "=== 7. Corrupted envelope blob (mutate magic) → exit 2 ==="
$PY - "$TMP/envelopes.json" "$TMP/envs_corrupted.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
# Replace the first 8 hex chars of one envelope blob (the magic field)
# with a garbage value that does NOT match MAGIC_LE ("DWE1" = 44574531).
blob = d["envelopes"][0]["envelope_blob"]
# blob is dot-separated; corrupt the first section (the magic).
parts = blob.split(".")
parts[0] = "deadbeef"  # wrong magic
d["envelopes"][0]["envelope_blob"] = ".".join(parts)
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
set +e
ERR=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envs_corrupted.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on corrupted envelope magic"
assert_contains "$ERR" "deserialize failed" "diagnostic mentions deserialize failed"

echo
echo "=== 8. Duplicate share_index in envelopes file → exit 2 ==="
$PY - "$TMP/envelopes.json" "$TMP/envs_dup.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
# Force the second envelope's share_index to equal the first's.
d["envelopes"][1]["share_index"] = d["envelopes"][0]["share_index"]
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
set +e
ERR=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envs_dup.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on duplicate share_index"
assert_contains "$ERR" "duplicate share_index" "diagnostic mentions duplicate"

echo
echo "=== 9. Mismatched 1:1 mapping (renumber an envelope) → exit 2 ==="
$PY - "$TMP/envelopes.json" "$TMP/envs_mismatch.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
# Pick a share_index that no share x uses. shares are 1..5; use 99.
# Keep count == 5 so the count check passes; only the mapping fails.
d["envelopes"][4]["share_index"] = 99
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
set +e
ERR=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envs_mismatch.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on mismatched mapping"
assert_contains "$ERR" "do not match" "diagnostic mentions mismatched indices"

echo
echo "=== 10. Missing --shares file → exit 1 ==="
set +e
"$WALLET" backup-verify --shares "$TMP/does_not_exist.json" --envelopes "$TMP/envelopes.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing shares file"

echo
echo "=== 11. Missing --envelopes file → exit 1 ==="
set +e
"$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/does_not_exist.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing envelopes file"

echo
echo "=== 12. Malformed shares JSON → exit 1 ==="
echo "not json {{" > "$TMP/malformed_shares.json"
set +e
ERR=$("$WALLET" backup-verify --shares "$TMP/malformed_shares.json" --envelopes "$TMP/envelopes.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on malformed shares JSON"
assert_contains "$ERR" "shares JSON parse" "diagnostic mentions shares JSON"

echo
echo "=== 13. Malformed envelopes JSON → exit 1 ==="
echo "not json }}" > "$TMP/malformed_envs.json"
set +e
ERR=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/malformed_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on malformed envelopes JSON"
assert_contains "$ERR" "envelopes JSON parse" "diagnostic mentions envelopes JSON"

echo
echo "=== 14. Envelopes file missing 'envelopes' key → exit 2 ==="
echo '{"items":[]}' > "$TMP/no_envs_key.json"
set +e
ERR=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/no_envs_key.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on missing envelopes key"
assert_contains "$ERR" "envelopes" "diagnostic mentions envelopes"

echo
echo "=== 15. Envelope entry missing share_index → exit 2 ==="
cat > "$TMP/no_share_idx.json" <<EOF
{"envelopes":[{"envelope_blob":"abc"},{"share_index":2,"envelope_blob":"def"}]}
EOF
set +e
"$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/no_share_idx.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "exit 2 on missing share_index"

echo
echo "=== 16. Envelope entry missing envelope_blob → exit 2 ==="
cat > "$TMP/no_blob.json" <<EOF
{"envelopes":[{"share_index":1},{"share_index":2,"envelope_blob":"def"}]}
EOF
set +e
"$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/no_blob.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "exit 2 on missing envelope_blob"

echo
echo "=== 17. --json on invalid → valid=false + non-empty errors ==="
JSON=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envs_corrupted.json" --json 2>&1 | tr -d '\r')
$PY -c "import json,sys; d=json.loads('''$JSON'''); assert d['valid'] is False; assert len(d['errors']) > 0"
if [ $? = 0 ]; then
    echo "  PASS: --json invalid case has valid=false + non-empty errors"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json invalid case malformed"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== 18. NEVER outputs decrypted material ==="
# Belt-and-suspenders: this CLI must not contain any field named
# plaintext_hex or secret_hex. Only metadata (PBKDF2/salt/nonce/ct lengths)
# is permitted to appear.
JSON=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envelopes.json" --json | tr -d '\r')
assert_not_contains "$JSON" "plaintext_hex" "no plaintext_hex in --json"
assert_not_contains "$JSON" "secret_hex"    "no secret_hex in --json"
OUT=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/envelopes.json" | tr -d '\r')
assert_not_contains "$OUT" "plaintext_hex" "no plaintext_hex in human"
assert_not_contains "$OUT" "secret_hex"    "no secret_hex in human"

echo
echo "=== 19. Empty envelopes array → exit 2 ==="
echo '{"envelopes":[]}' > "$TMP/empty_envs.json"
set +e
ERR=$("$WALLET" backup-verify --shares "$TMP/shares.json" --envelopes "$TMP/empty_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on empty envelopes array"
assert_contains "$ERR" "empty" "diagnostic mentions empty"

echo
echo "=== 20. Backup with non-default PBKDF2 iters reported correctly ==="
ALT_ITERS=12345
"$WALLET" shamir-split --secret "$SECRET" --threshold 2 --shares 3 --json \
    | tr -d '\r' > "$TMP/shares_alt.json"
$PY - "$TMP/shares_alt.json" "$TMP/envs_alt.json" "$WALLET_ABS" "$ALT_ITERS" <<'PY_EOF'
import json, subprocess, sys
shares_path, envs_path, wallet, iters = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
shares = json.load(open(shares_path))["shares"]
envs = []
for s in shares:
    r = subprocess.run(
        [wallet, "envelope", "encrypt", "--plaintext", s["y_hex"],
         "--password", f"pw{s['x']}", "--iters", iters],
        capture_output=True, text=True, check=True)
    envs.append({"share_index": s["x"], "envelope_blob": r.stdout.strip().replace("\r","")})
with open(envs_path, "w") as f:
    json.dump({"envelopes": envs}, f)
PY_EOF
OUT=$("$WALLET" backup-verify --shares "$TMP/shares_alt.json" --envelopes "$TMP/envs_alt.json" | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "alt-iters backup verifies OK"
assert_contains "$OUT" "PBKDF2=$ALT_ITERS" "alt PBKDF2 iters reported"
# And sanity: the previous iter count is not still being echoed.
assert_not_contains "$OUT" "PBKDF2=$ITERS" "alt envelope isn't the previous one"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet backup-verify"; exit 0
else
    echo "  FAIL"; exit 1
fi
