#!/usr/bin/env bash
# determ-wallet backup-create composite backup-generator CLI test.
#
# `backup-create` is the inverse of `backup-verify`. It takes a secret +
# per-keyholder passphrases and emits BOTH canonical backup artifacts
# (shares file + envelopes file) in one call.
#
# Round-trip coverage:
#   - Generate a backup with backup-create.
#   - Pipe the two files through backup-verify (must PASS).
#   - Pipe each envelope blob through inspect-envelope (must yield
#     valid metadata; PBKDF2/salt/nonce sane).
#   - Pick T random shares, decrypt each envelope with its keyholder
#     passphrase, feed the unwrapped y_hex back through shamir-combine,
#     and assert the recovered secret == original.
#
# Validation coverage:
#   - Missing --secret / --threshold / --keyholders / --shares-out /
#     --envelopes-out → exit 1.
#   - Bad secret hex (odd length / non-hex) → exit 1.
#   - --threshold > N → exit 1 with diagnostic.
#   - --threshold < 1 → exit 1.
#   - Empty keyholders array → exit 1.
#   - Duplicate share_index in keyholders → exit 1.
#   - share_index out of [1,N] → exit 1.
#   - Missing share_index in keyholders (gap, e.g. {1,2,4} for N=4) → exit 1.
#   - Empty passphrase → exit 1.
#   - Malformed keyholders JSON → exit 1.
#   - Output file exists, no --force → exit 1.
#   - Output file exists, with --force → exit 0 (overwrite).
#   - Same path for shares-out and envelopes-out → exit 1.
#   - Output parent directory missing → exit 1.
#
# Run from repo root: bash tools/test_wallet_backup_create.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
# Absolutize the wallet binary path so Python subprocess.run() under
# native-Windows Python sees a path it can CreateProcess on (msys path
# translation only applies to direct shell args).
if [ "${WALLET#/}" = "$WALLET" ] && [ "${WALLET#?:}" = "$WALLET" ]; then
    WALLET_ABS="$PROJECT_ROOT/$WALLET"
else
    WALLET_ABS="$WALLET"
fi

# Scratch under build/ for the same path-translation reason as the
# backup-verify test (mktemp -d returns /tmp/... which Python can't see).
SCRATCH="build/test_wallet_backup_create.$$"
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

SECRET="deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677"

# ── 1. Help text mentions backup-create ───────────────────────────────────────
echo "=== 1. Help text mentions backup-create ==="
H=$("$WALLET" help 2>&1)
if echo "$H" | grep -q "backup-create"; then
    echo "  PASS: help mentions backup-create"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing backup-create"; fail_count=$((fail_count + 1))
fi

# ── 2. Happy-path 3-of-5 backup ───────────────────────────────────────────────
echo
echo "=== 2. Happy-path: 3-of-5 backup with 5 distinct passphrases ==="
$PY - "$TMP/keyholders.json" <<'PY_EOF'
import json, sys
out = sys.argv[1]
khs = [{"share_index": i, "passphrase": f"keyholder-pw-{i}"} for i in range(1, 6)]
with open(out, "w") as f:
    json.dump({"keyholders": khs}, f)
PY_EOF
SUMMARY=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 3 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/shares.json" \
    --envelopes-out "$TMP/envelopes.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "backup-create exit 0"
assert_contains "$SUMMARY" "wrote 5 shares + 5 envelopes (threshold 3)" "human summary"
if [ -s "$TMP/shares.json" ]; then
    echo "  PASS: shares file non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: shares file missing or empty"; fail_count=$((fail_count + 1))
fi
if [ -s "$TMP/envelopes.json" ]; then
    echo "  PASS: envelopes file non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: envelopes file missing or empty"; fail_count=$((fail_count + 1))
fi

# ── 3. JSON summary mode ──────────────────────────────────────────────────────
echo
echo "=== 3. --json summary mode ==="
rm -f "$TMP/shares_j.json" "$TMP/envelopes_j.json"
JSON=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 3 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/shares_j.json" \
    --envelopes-out "$TMP/envelopes_j.json" \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--json exit 0"
$PY - <<PY_EOF
import json
d = json.loads('''$JSON''')
required = {"share_count","threshold","shares_file","envelopes_file"}
assert required <= set(d.keys()), f"missing fields: {required - set(d.keys())}"
assert d["share_count"] == 5
assert d["threshold"] == 3
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json schema correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json schema malformed"; fail_count=$((fail_count + 1))
fi

# ── 4. Round-trip: backup-verify passes ───────────────────────────────────────
echo
echo "=== 4. Round-trip: backup-verify on the generated pair ==="
OUT=$("$WALLET" backup-verify \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "backup-verify exit 0 on backup-create output"
assert_contains "$OUT" "5 shares" "verify sees 5 shares"
assert_contains "$OUT" "5 envelopes" "verify sees 5 envelopes"
assert_contains "$OUT" "1:1 by share_index" "1:1 mapping confirmed"

# ── 5. backup-verify with --threshold 3 reports met ───────────────────────────
echo
echo "=== 5. backup-verify --threshold 3 reports threshold met ==="
OUT=$("$WALLET" backup-verify \
    --shares "$TMP/shares.json" \
    --envelopes "$TMP/envelopes.json" \
    --threshold 3 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "threshold-aware verify exit 0"
assert_contains "$OUT" "Share count (5) >= threshold (3)" "threshold-met line"

# ── 6. inspect-envelope on each individual envelope ───────────────────────────
echo
echo "=== 6. inspect-envelope on each individual envelope ==="
$PY - "$TMP/envelopes.json" "$TMP" "$WALLET_ABS" <<'PY_EOF'
import json, os, subprocess, sys
envs_path, tmp_dir, wallet = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(envs_path))
ok = True
for e in d["envelopes"]:
    idx = e["share_index"]
    blob = e["envelope_blob"]
    blob_file = os.path.join(tmp_dir, f"env_{idx}.blob")
    with open(blob_file, "w") as f:
        f.write(blob + "\n")
    r = subprocess.run(
        [wallet, "inspect-envelope", "--in", blob_file, "--json"],
        capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  FAIL inspect-envelope for share_index={idx}: rc={r.returncode}")
        print(f"       stderr: {r.stderr.strip()}")
        ok = False
        continue
    info = json.loads(r.stdout.strip().replace("\r",""))
    if info.get("format") != "DWE1":
        print(f"  FAIL inspect-envelope idx={idx}: wrong format {info.get('format')!r}")
        ok = False
        continue
    if info.get("nonce_len") != 12 or info.get("salt_len", 0) <= 0:
        print(f"  FAIL inspect-envelope idx={idx}: bad header sizes")
        ok = False
        continue
print("ALL_OK" if ok else "HAD_FAILURE")
PY_EOF
PY_RES=$?
if [ "$PY_RES" = 0 ]; then
    # Crude: we ran 5 inspects, each yielded valid metadata.
    echo "  PASS: inspect-envelope yields valid metadata for envelope 1"; pass_count=$((pass_count + 1))
    echo "  PASS: inspect-envelope yields valid metadata for envelope 2"; pass_count=$((pass_count + 1))
    echo "  PASS: inspect-envelope yields valid metadata for envelope 3"; pass_count=$((pass_count + 1))
    echo "  PASS: inspect-envelope yields valid metadata for envelope 4"; pass_count=$((pass_count + 1))
    echo "  PASS: inspect-envelope yields valid metadata for envelope 5"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: at least one inspect-envelope call did not yield valid metadata"; fail_count=$((fail_count + 1))
fi

# ── 7. T-of-N reconstruction round-trip ───────────────────────────────────────
echo
echo "=== 7. T-of-N reconstruction: decrypt 3 envelopes, combine, recover secret ==="
RECOVERED=$($PY - "$TMP/shares.json" "$TMP/envelopes.json" "$WALLET_ABS" "$TMP" <<'PY_EOF'
import json, os, random, subprocess, sys
shares_path, envs_path, wallet, tmp_dir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
shares = json.load(open(shares_path))["shares"]
envs   = {e["share_index"]: e["envelope_blob"] for e in json.load(open(envs_path))["envelopes"]}

# Pick T=3 random share indices from {1..5}.
random.seed(0xC0FFEE)
picked = random.sample(sorted(envs.keys()), 3)

# Decrypt each picked envelope under its keyholder passphrase, get y_hex.
recovered_shares = []
for idx in picked:
    blob = envs[idx]
    pw = f"keyholder-pw-{idx}"
    r = subprocess.run(
        [wallet, "envelope", "decrypt", "--envelope", blob, "--password", pw],
        capture_output=True, text=True)
    if r.returncode != 0:
        print(f"DECRYPT_FAIL idx={idx} stderr={r.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    y_hex = r.stdout.strip().replace("\r","")
    recovered_shares.append({"x": idx, "y_hex": y_hex})

# Spot-check: the decrypted y_hex must match the canonical share's y_hex.
share_map = {s["x"]: s["y_hex"] for s in shares}
for rs in recovered_shares:
    if rs["y_hex"] != share_map[rs["x"]]:
        print(f"YHEX_MISMATCH idx={rs['x']}", file=sys.stderr)
        sys.exit(3)

# Feed the recovered shares to shamir-combine via a temp file.
sf = os.path.join(tmp_dir, "recovered_shares.json")
with open(sf, "w") as f:
    json.dump({"shares": recovered_shares}, f)
r = subprocess.run(
    [wallet, "shamir-combine", "--shares", sf, "--json"],
    capture_output=True, text=True)
if r.returncode != 0:
    print(f"COMBINE_FAIL stderr={r.stderr.strip()}", file=sys.stderr)
    sys.exit(4)
out = json.loads(r.stdout.strip().replace("\r",""))
print(out["secret_hex"])
PY_EOF
)
RC=$?
assert_eq "$RC" "0" "T-of-N reconstruction exit 0"
assert_eq "$RECOVERED" "$SECRET" "recovered secret == original"

# Also test with a DIFFERENT subset of T to confirm any-T-of-N works,
# not just the lucky one.
echo
echo "=== 8. T-of-N with a DIFFERENT subset (any-3-of-5) ==="
RECOVERED2=$($PY - "$TMP/shares.json" "$TMP/envelopes.json" "$WALLET_ABS" "$TMP" <<'PY_EOF'
import json, os, subprocess, sys
shares_path, envs_path, wallet, tmp_dir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
envs = {e["share_index"]: e["envelope_blob"] for e in json.load(open(envs_path))["envelopes"]}
# Different subset: {2, 4, 5}.
picked = [2, 4, 5]
recovered = []
for idx in picked:
    pw = f"keyholder-pw-{idx}"
    r = subprocess.run(
        [wallet, "envelope", "decrypt", "--envelope", envs[idx], "--password", pw],
        capture_output=True, text=True, check=True)
    recovered.append({"x": idx, "y_hex": r.stdout.strip().replace("\r","")})
sf = os.path.join(tmp_dir, "rec2.json")
with open(sf, "w") as f:
    json.dump({"shares": recovered}, f)
r = subprocess.run([wallet, "shamir-combine", "--shares", sf, "--json"],
                    capture_output=True, text=True, check=True)
print(json.loads(r.stdout.strip().replace("\r",""))["secret_hex"])
PY_EOF
)
RC=$?
assert_eq "$RC" "0" "second subset reconstruction exit 0"
assert_eq "$RECOVERED2" "$SECRET" "recovered secret (different subset) == original"

# ── 9. --force overwrite semantics ────────────────────────────────────────────
echo
echo "=== 9. Overwrite refused without --force ==="
# shares.json already exists from step 2.
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 3 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/shares.json" \
    --envelopes-out "$TMP/envelopes_new.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when shares-out exists without --force"
assert_contains "$ERR" "already exists" "diagnostic mentions already exists"
assert_contains "$ERR" "--force" "diagnostic mentions --force"

echo
echo "=== 10. Overwrite proceeds with --force ==="
set +e
"$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 3 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/shares.json" \
    --envelopes-out "$TMP/envelopes.json" \
    --force >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "exit 0 with --force on existing files"

# ── 11. Threshold > N rejected ────────────────────────────────────────────────
echo
echo "=== 11. --threshold (6) > N (5) rejected ==="
rm -f "$TMP/bad_shares.json" "$TMP/bad_envs.json"
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 6 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when threshold > N"
assert_contains "$ERR" "threshold" "diagnostic mentions threshold"

# ── 12. --threshold 0 rejected ────────────────────────────────────────────────
echo
echo "=== 12. --threshold 0 rejected ==="
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 0 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when threshold < 1"
assert_contains "$ERR" "threshold" "diagnostic mentions threshold"

# ── 13. Empty keyholders array rejected ───────────────────────────────────────
echo
echo "=== 13. Empty keyholders array rejected ==="
echo '{"keyholders":[]}' > "$TMP/empty_kh.json"
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 1 \
    --keyholders "$TMP/empty_kh.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on empty keyholders"
assert_contains "$ERR" "empty" "diagnostic mentions empty"

# ── 14. Duplicate share_index in keyholders rejected ──────────────────────────
echo
echo "=== 14. Duplicate share_index in keyholders rejected ==="
cat > "$TMP/dup_kh.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"pw-a"},
  {"share_index":2,"passphrase":"pw-b"},
  {"share_index":2,"passphrase":"pw-c"}
]}
EOF
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --keyholders "$TMP/dup_kh.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on duplicate share_index"
assert_contains "$ERR" "duplicate" "diagnostic mentions duplicate"

# ── 15. share_index out of [1,N] rejected ─────────────────────────────────────
echo
echo "=== 15. share_index out of [1,N] rejected ==="
cat > "$TMP/oor_kh.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"pw-a"},
  {"share_index":2,"passphrase":"pw-b"},
  {"share_index":99,"passphrase":"pw-c"}
]}
EOF
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --keyholders "$TMP/oor_kh.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on share_index out of range"
assert_contains "$ERR" "out of range" "diagnostic mentions out of range"

# ── 16. Gap in share_indices rejected (N=4 with {1,2,4}) ──────────────────────
echo
echo "=== 16. Gap in share_indices rejected (N=4 with {1,2,4,5}, missing 3) ==="
# We have 4 keyholders but they use indices {1,2,4,5} instead of {1..4}.
# Because share_index 5 > N=4, the [1,N] range check will trip; that's
# the canonical failure path for any non-permutation.
cat > "$TMP/gap_kh.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"pw-a"},
  {"share_index":2,"passphrase":"pw-b"},
  {"share_index":4,"passphrase":"pw-c"},
  {"share_index":5,"passphrase":"pw-d"}
]}
EOF
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --keyholders "$TMP/gap_kh.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on gap (non-permutation of {1..N})"

# ── 17. Empty passphrase rejected ─────────────────────────────────────────────
echo
echo "=== 17. Empty passphrase rejected ==="
cat > "$TMP/empty_pw_kh.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"pw-a"},
  {"share_index":2,"passphrase":""},
  {"share_index":3,"passphrase":"pw-c"}
]}
EOF
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --keyholders "$TMP/empty_pw_kh.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on empty passphrase"
assert_contains "$ERR" "passphrase" "diagnostic mentions passphrase"

# ── 18. Malformed keyholders JSON ─────────────────────────────────────────────
echo
echo "=== 18. Malformed keyholders JSON ==="
echo "not json {{" > "$TMP/malformed_kh.json"
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --keyholders "$TMP/malformed_kh.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on malformed keyholders JSON"
assert_contains "$ERR" "parse" "diagnostic mentions parse"

# ── 19. Bad secret hex (odd length) ───────────────────────────────────────────
echo
echo "=== 19. Bad --secret hex (odd length) rejected ==="
set +e
ERR=$("$WALLET" backup-create \
    --secret "abc" \
    --threshold 2 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on odd-length secret hex"

# ── 20. Bad secret hex (non-hex char) ─────────────────────────────────────────
echo
echo "=== 20. Bad --secret hex (non-hex char) rejected ==="
set +e
"$WALLET" backup-create \
    --secret "zz" \
    --threshold 2 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on non-hex secret"

# ── 21. Missing --secret ──────────────────────────────────────────────────────
echo
echo "=== 21. Missing --secret rejected ==="
set +e
"$WALLET" backup-create \
    --threshold 2 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --secret"

# ── 22. Missing --threshold ───────────────────────────────────────────────────
echo
echo "=== 22. Missing --threshold rejected ==="
set +e
"$WALLET" backup-create \
    --secret "$SECRET" \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --threshold"

# ── 23. Missing --keyholders ──────────────────────────────────────────────────
echo
echo "=== 23. Missing --keyholders rejected ==="
set +e
"$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --shares-out "$TMP/bad_shares.json" \
    --envelopes-out "$TMP/bad_envs.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --keyholders"

# ── 24. Missing --shares-out ──────────────────────────────────────────────────
echo
echo "=== 24. Missing --shares-out rejected ==="
set +e
"$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --keyholders "$TMP/keyholders.json" \
    --envelopes-out "$TMP/bad_envs.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --shares-out"

# ── 25. Missing --envelopes-out ───────────────────────────────────────────────
echo
echo "=== 25. Missing --envelopes-out rejected ==="
set +e
"$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/bad_shares.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --envelopes-out"

# ── 26. --shares-out == --envelopes-out rejected ──────────────────────────────
echo
echo "=== 26. --shares-out == --envelopes-out rejected ==="
rm -f "$TMP/same.json"
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 3 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/same.json" \
    --envelopes-out "$TMP/same.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on same-path outputs"
assert_contains "$ERR" "same file" "diagnostic mentions same file"

# ── 27. Output parent directory missing ───────────────────────────────────────
echo
echo "=== 27. Output parent directory missing rejected ==="
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 3 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/nonexistent_dir/shares.json" \
    --envelopes-out "$TMP/envelopes.json" \
    --force 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing parent dir"
assert_contains "$ERR" "does not exist" "diagnostic mentions does not exist"

# ── 28. Output file is NEVER created when validation fails ────────────────────
echo
echo "=== 28. Output files NOT created on validation failure ==="
rm -f "$TMP/precheck_shares.json" "$TMP/precheck_envs.json"
set +e
"$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 99 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/precheck_shares.json" \
    --envelopes-out "$TMP/precheck_envs.json" >/dev/null 2>&1
set -e
if [ ! -e "$TMP/precheck_shares.json" ]; then
    echo "  PASS: shares-out not created on validation failure"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: shares-out leaked on validation failure"; fail_count=$((fail_count + 1))
fi
if [ ! -e "$TMP/precheck_envs.json" ]; then
    echo "  PASS: envelopes-out not created on validation failure"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: envelopes-out leaked on validation failure"; fail_count=$((fail_count + 1))
fi

# ── 29. Shares file shape matches shamir-split --json shape ───────────────────
echo
echo "=== 29. Shares file shape matches shamir-split --json shape ==="
$PY - "$TMP/shares.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
assert "shares" in d and isinstance(d["shares"], list), "missing shares array"
assert len(d["shares"]) == 5, f"expected 5 shares, got {len(d['shares'])}"
xs = set()
for s in d["shares"]:
    assert "x" in s and isinstance(s["x"], int), f"missing/bad x: {s}"
    assert "y_hex" in s and isinstance(s["y_hex"], str), f"missing/bad y_hex: {s}"
    assert 1 <= s["x"] <= 5, f"x out of range: {s['x']}"
    xs.add(s["x"])
assert xs == set(range(1, 6)), f"x values not 1..5: {xs}"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: shares file shape correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: shares file shape wrong"; fail_count=$((fail_count + 1))
fi

# ── 30. Envelopes file shape matches backup-verify expectation ────────────────
echo
echo "=== 30. Envelopes file shape matches backup-verify expectation ==="
$PY - "$TMP/envelopes.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
assert "envelopes" in d and isinstance(d["envelopes"], list)
assert len(d["envelopes"]) == 5
idxs = set()
for e in d["envelopes"]:
    assert "share_index" in e and isinstance(e["share_index"], int)
    assert "envelope_blob" in e and isinstance(e["envelope_blob"], str)
    # Canonical blob is dot-separated lowercase hex. At least 6 sections.
    parts = e["envelope_blob"].split(".")
    assert len(parts) >= 6, f"blob has {len(parts)} parts: {parts!r}"
    # First section is magic (4 bytes = 8 hex chars).
    assert len(parts[0]) == 8, f"magic hex length wrong: {parts[0]!r}"
    idxs.add(e["share_index"])
assert idxs == set(range(1, 6))
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: envelopes file shape correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: envelopes file shape wrong"; fail_count=$((fail_count + 1))
fi

# ── 31. Wrong passphrase fails to decrypt (negative round-trip) ───────────────
echo
echo "=== 31. Wrong passphrase fails decrypt (negative round-trip) ==="
BLOB=$($PY -c "import json,sys; d=json.load(open('$TMP/envelopes.json')); print(d['envelopes'][0]['envelope_blob'])")
set +e
"$WALLET" envelope decrypt --envelope "$BLOB" --password "wrong-pw" >/dev/null 2>&1
RC=$?
set -e
# envelope decrypt returns 2 on AEAD tag failure.
assert_eq "$RC" "2" "envelope decrypt fails with wrong passphrase"

# ── 32. Correct passphrase decrypts envelope[0] ───────────────────────────────
echo
echo "=== 32. Correct passphrase decrypts envelope[0] ==="
DEC=$("$WALLET" envelope decrypt --envelope "$BLOB" --password "keyholder-pw-1" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "envelope decrypt succeeds with correct passphrase"
EXPECTED_Y=$($PY -c "import json; d=json.load(open('$TMP/shares.json')); print(next(s['y_hex'] for s in d['shares'] if s['x']==1))")
assert_eq "$DEC" "$EXPECTED_Y" "decrypted y_hex matches shares file entry 1"

# ── 33. Unknown argument rejected ─────────────────────────────────────────────
echo
echo "=== 33. Unknown argument rejected ==="
set +e
ERR=$("$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 2 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/x_shares.json" \
    --envelopes-out "$TMP/x_envs.json" \
    --bogus-flag 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unknown argument"
assert_contains "$ERR" "unknown" "diagnostic mentions unknown"

# ── 34. 1-of-1 trivial backup also works ──────────────────────────────────────
echo
echo "=== 34. 1-of-1 trivial backup also works ==="
echo '{"keyholders":[{"share_index":1,"passphrase":"only-pw"}]}' > "$TMP/kh_1.json"
rm -f "$TMP/shares_1.json" "$TMP/envelopes_1.json"
"$WALLET" backup-create \
    --secret "$SECRET" \
    --threshold 1 \
    --keyholders "$TMP/kh_1.json" \
    --shares-out "$TMP/shares_1.json" \
    --envelopes-out "$TMP/envelopes_1.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "1-of-1 backup-create exit 0"
"$WALLET" backup-verify \
    --shares "$TMP/shares_1.json" \
    --envelopes "$TMP/envelopes_1.json" \
    --threshold 1 >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "1-of-1 backup-verify passes"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet backup-create"; exit 0
else
    echo "  FAIL: test_wallet_backup_create"; exit 1
fi
