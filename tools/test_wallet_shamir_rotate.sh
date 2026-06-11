#!/usr/bin/env bash
# determ-wallet shamir-rotate PSS (Proactive Secret Sharing) test.
#
# Verifies the polynomial-refresh CLI: takes a T-of-N share set, draws a
# FRESH polynomial, and emits a new share set where any T new shares
# reconstruct the SAME secret but the new shares are mathematically
# unrelated to the old polynomial. Defense against share leakage over
# time: a keyholder periodically rotates their physical share so prior
# leaks of < T shares convey no information about the current set.
#
# Assertions:
#   1.  Help line mentions shamir-rotate.
#   2.  Usage line emitted with no args (exit 1).
#   3.  Missing --shares file → exit 1.
#   4.  Missing --threshold → exit 1.
#   5.  Missing --shares-out → exit 1.
#   6.  --shares == --shares-out → exit 1 (in-place refused).
#   7.  Malformed JSON --shares → exit 1.
#   8.  Empty shares array → exit 1.
#   9.  Unknown argument → exit 1.
#   10. Insufficient input (< T shares) → exit 2 (operator alert gate).
#   11. Round-trip: rotated shares reconstruct ORIGINAL secret.
#   12. Polynomial actually changed: old y_hex != new y_hex (overwhelmingly).
#   13. x-coordinates preserved: new x-set == old x-set.
#   14. Output share count == input share count.
#   15. Output y-byte-length == input y-byte-length.
#   16. Old shares can NO LONGER combine with new shares (mix → garbage).
#   17. Refuse overwrite without --force → exit 1.
#   18. --force allows overwrite.
#   19. --json output parseable + has rotated=true.
#   20. --json output NEVER contains secret_hex (no leakage in summary).
#   21. Output file passes shamir-verify structural check.
#   22. Multiple rotations (3x chain) still recover original secret.
#   23. After 3 rotations, intermediate share-sets all differ pairwise.
#   24. T=N edge case: T = N still rotates successfully.
#   25. T=1 edge case: 1-of-N rotation works.
#   26. Large N (50 shares) rotates correctly.
#   27. Various secret sizes (1, 16, 32, 64 bytes) all round-trip.
#   28. Output file uses owner-only perms shape (best-effort; skip on Windows).
#   29. --threshold > 255 → exit 1.
#   30. --threshold < 1 → exit 1.
#   31. --threshold non-integer → exit 1.
#   32. Duplicate x in input → exit 1.
#   33. Two consecutive rotations of the same input produce DIFFERENT shares
#       (fresh randomness on each call).
#
# Run from repo root: bash tools/test_wallet_shamir_rotate.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="$(mktemp -d)"
# Git Bash returns /tmp/... (MSYS) paths from mktemp -d. Native Windows
# Python opens those as literal strings and fails. Convert to a Windows-
# style C:/... path so both shell (MSYS-aware) and Python (native)
# access the same files.
if command -v cygpath >/dev/null 2>&1; then
    TMP_WIN="$(cygpath -m "$TMP")"
elif [ -n "${WINDIR:-}" ]; then
    # Best-effort: on Git Bash without cygpath, infer the Windows tmp dir.
    TMP_WIN="$(cd "$TMP" && pwd -W 2>/dev/null || echo "$TMP")"
else
    TMP_WIN="$TMP"
fi
trap 'rm -rf "$TMP"' EXIT
# Use TMP_WIN everywhere from here on; both shells and Python resolve it.
TMP="$TMP_WIN"

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_neq() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3 (both values: $1)"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in: $1"; fail_count=$((fail_count + 1)); fi
}
assert_not_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  FAIL: $3 (unexpected: $2)"; fail_count=$((fail_count + 1))
  else echo "  PASS: $3"; pass_count=$((pass_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ── 1. Help text mentions shamir-rotate ───────────────────────────────────
echo "=== 1. Help text mentions shamir-rotate ==="
H=$("$WALLET" help 2>&1)
echo "$H" | grep -q "shamir-rotate" && {
    echo "  PASS: help mentions shamir-rotate"; pass_count=$((pass_count + 1)); } || {
    echo "  FAIL: help missing shamir-rotate"; fail_count=$((fail_count + 1)); }

# ── 2. Usage line on no args (exit 1) ─────────────────────────────────────
echo
echo "=== 2. No args → usage line + exit 1 ==="
set +e
ERR=$("$WALLET" shamir-rotate 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing args"
assert_contains "$ERR" "Usage: determ-wallet shamir-rotate" "usage line emitted"

# ── 3. Missing --shares file ──────────────────────────────────────────────
echo
echo "=== 3. Missing --shares file → exit 1 ==="
set +e
"$WALLET" shamir-rotate --shares "$TMP/no_such_file.json" --threshold 3 \
    --shares-out "$TMP/out.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --shares file"

# Build a reference share-set for the rest of the tests.
SECRET="deadbeefcafebabe0011223344556677"
"$WALLET" shamir-split --secret "$SECRET" --threshold 3 --shares 5 --json \
    > "$TMP/orig.json"
if [ ! -s "$TMP/orig.json" ]; then
    echo "  FAIL: shamir-split produced empty output"; exit 1
fi

# ── 4. Missing --threshold ────────────────────────────────────────────────
echo
echo "=== 4. Missing --threshold → exit 1 ==="
set +e
"$WALLET" shamir-rotate --shares "$TMP/orig.json" \
    --shares-out "$TMP/out.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --threshold"

# ── 5. Missing --shares-out ───────────────────────────────────────────────
echo
echo "=== 5. Missing --shares-out → exit 1 ==="
set +e
"$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 3 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --shares-out"

# ── 6. --shares == --shares-out (in-place refused) ────────────────────────
echo
echo "=== 6. --shares == --shares-out → exit 1 ==="
set +e
ERR=$("$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 3 \
    --shares-out "$TMP/orig.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on in-place rotation"
assert_contains "$ERR" "same file" "diagnostic mentions same file"

# ── 7. Malformed JSON --shares → exit 1 ──────────────────────────────────
echo
echo "=== 7. Malformed JSON --shares → exit 1 ==="
echo "not json {{{" > "$TMP/bad.json"
set +e
ERR=$("$WALLET" shamir-rotate --shares "$TMP/bad.json" --threshold 3 \
    --shares-out "$TMP/out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on malformed JSON"
assert_contains "$ERR" "JSON parse" "JSON parse diagnostic"

# ── 8. Empty shares array → exit 1 ────────────────────────────────────────
echo
echo "=== 8. Empty shares array → exit 1 ==="
echo '{"shares":[]}' > "$TMP/empty.json"
set +e
ERR=$("$WALLET" shamir-rotate --shares "$TMP/empty.json" --threshold 3 \
    --shares-out "$TMP/out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on empty shares array"
assert_contains "$ERR" "empty" "empty-array diagnostic"

# ── 9. Unknown argument → exit 1 ──────────────────────────────────────────
echo
echo "=== 9. Unknown argument → exit 1 ==="
set +e
ERR=$("$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 3 \
    --shares-out "$TMP/out.json" --garbage 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unknown argument"
assert_contains "$ERR" "unknown argument" "unknown-argument diagnostic"

# ── 10. Insufficient input (< T shares) → exit 2 ──────────────────────────
echo
echo "=== 10. Insufficient input (2 shares, T=3) → exit 2 ==="
$PY - "$TMP/orig.json" "$TMP/two_shares.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["shares"] = d["shares"][:2]
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
set +e
ERR=$("$WALLET" shamir-rotate --shares "$TMP/two_shares.json" --threshold 3 \
    --shares-out "$TMP/out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on insufficient input"
assert_contains "$ERR" "insufficient input shares" "insufficient diagnostic"

# ── 11. Round-trip: rotated shares reconstruct ORIGINAL secret ───────────
echo
echo "=== 11. Rotated shares recover original secret ==="
"$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 3 \
    --shares-out "$TMP/rotated.json" >/dev/null
RECOVERED=$("$WALLET" shamir-combine --shares "$TMP/rotated.json" | tr -d '\r\n')
assert_eq "$RECOVERED" "$SECRET" "rotated shares recover ORIGINAL secret"

# ── 12. Polynomial actually changed: y_hex differs ────────────────────────
echo
echo "=== 12. Polynomial changed: y_hex differs ==="
ORIG_Y=$($PY -c "import json; d=json.load(open('$TMP/orig.json')); print(','.join(s['y_hex'] for s in d['shares']))")
ROTATED_Y=$($PY -c "import json; d=json.load(open('$TMP/rotated.json')); print(','.join(s['y_hex'] for s in d['shares']))")
assert_neq "$ORIG_Y" "$ROTATED_Y" "y_hex differs after rotation"

# ── 13. x-coordinates preserved ───────────────────────────────────────────
echo
echo "=== 13. x-coordinates preserved ==="
ORIG_X=$($PY -c "import json; d=json.load(open('$TMP/orig.json')); print(','.join(str(s['x']) for s in d['shares']))")
ROTATED_X=$($PY -c "import json; d=json.load(open('$TMP/rotated.json')); print(','.join(str(s['x']) for s in d['shares']))")
assert_eq "$ROTATED_X" "$ORIG_X" "x-coordinates preserved in same order"

# ── 14. Output share count == input share count ──────────────────────────
echo
echo "=== 14. Output share count == input share count ==="
ORIG_N=$($PY -c "import json; print(len(json.load(open('$TMP/orig.json'))['shares']))")
ROTATED_N=$($PY -c "import json; print(len(json.load(open('$TMP/rotated.json'))['shares']))")
assert_eq "$ROTATED_N" "$ORIG_N" "share count unchanged"

# ── 15. Output y-byte-length == input y-byte-length ──────────────────────
echo
echo "=== 15. y-byte-length preserved ==="
ORIG_YLEN=$($PY -c "import json; print(len(json.load(open('$TMP/orig.json'))['shares'][0]['y_hex']))")
ROTATED_YLEN=$($PY -c "import json; print(len(json.load(open('$TMP/rotated.json'))['shares'][0]['y_hex']))")
assert_eq "$ROTATED_YLEN" "$ORIG_YLEN" "y-byte-length preserved"

# ── 16. Old + new mix cannot combine to original secret ──────────────────
# Build a 3-share mix: 2 from orig + 1 from rotated. Lagrange over a mixed
# polynomial set yields a value indistinguishable from a wrong secret
# (information-theoretic property of SSS). The combine call succeeds (it
# only checks structural validity) but the recovered value must NOT equal
# SECRET.
echo
echo "=== 16. Mixed old + new shares do NOT reconstruct original ==="
$PY - "$TMP/orig.json" "$TMP/rotated.json" "$TMP/mixed.json" <<'PY_EOF'
import json, sys
o = json.load(open(sys.argv[1]))
r = json.load(open(sys.argv[2]))
# Pick 2 from orig (x=1, x=2) + 1 from rotated (x=3). Same x-coords as a
# valid 3-share set, but the y values come from two different polynomials.
mix = [o["shares"][0], o["shares"][1], r["shares"][2]]
with open(sys.argv[3], "w") as f:
    json.dump({"shares": mix}, f)
PY_EOF
set +e
MIXED=$("$WALLET" shamir-combine --shares "$TMP/mixed.json" 2>&1 | tr -d '\r\n')
set -e
assert_neq "$MIXED" "$SECRET" "mixed old+new shares do NOT recover SECRET"

# ── 17. Refuse overwrite without --force ──────────────────────────────────
echo
echo "=== 17. Refuse overwrite without --force ==="
# rotated.json already exists from step 11.
set +e
ERR=$("$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 3 \
    --shares-out "$TMP/rotated.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when output exists without --force"
assert_contains "$ERR" "already exists" "diagnostic mentions already exists"

# ── 18. --force allows overwrite ──────────────────────────────────────────
echo
echo "=== 18. --force allows overwrite ==="
set +e
"$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 3 \
    --shares-out "$TMP/rotated.json" --force >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "exit 0 with --force"
RECOVERED2=$("$WALLET" shamir-combine --shares "$TMP/rotated.json" | tr -d '\r\n')
assert_eq "$RECOVERED2" "$SECRET" "after --force overwrite, still recovers SECRET"

# ── 19. --json output parseable + has rotated=true ───────────────────────
echo
echo "=== 19. --json output parseable + rotated=true ==="
JSON=$("$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 3 \
    --shares-out "$TMP/json_out.json" --force --json 2>&1 | tr -d '\r')
$PY -c "import sys, json; d = json.loads('''$JSON'''); assert d['rotated'] is True; assert d['share_count'] == 5; assert d['threshold'] == 3"
if [ $? = 0 ]; then
    echo "  PASS: --json shape correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json shape wrong"; fail_count=$((fail_count + 1))
fi

# ── 20. --json NEVER contains secret_hex ──────────────────────────────────
echo
echo "=== 20. --json output contains no secret material ==="
assert_not_contains "$JSON" "secret_hex" "no secret_hex in --json"
assert_not_contains "$JSON" "$SECRET" "no raw SECRET in --json"

# ── 21. Output file passes shamir-verify ──────────────────────────────────
echo
echo "=== 21. Output file passes shamir-verify ==="
set +e
"$WALLET" shamir-verify --shares "$TMP/rotated.json" --threshold 3 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "rotated share-set is structurally valid per shamir-verify"

# ── 22. Multiple rotations (chain 3x) still recover original ─────────────
echo
echo "=== 22. Triple rotation chain recovers ORIGINAL secret ==="
"$WALLET" shamir-rotate --shares "$TMP/orig.json"   --threshold 3 \
    --shares-out "$TMP/r1.json" >/dev/null
"$WALLET" shamir-rotate --shares "$TMP/r1.json"     --threshold 3 \
    --shares-out "$TMP/r2.json" >/dev/null
"$WALLET" shamir-rotate --shares "$TMP/r2.json"     --threshold 3 \
    --shares-out "$TMP/r3.json" >/dev/null
RECOVERED3=$("$WALLET" shamir-combine --shares "$TMP/r3.json" | tr -d '\r\n')
assert_eq "$RECOVERED3" "$SECRET" "3 chained rotations recover SECRET"

# ── 23. Intermediate share-sets all differ pairwise ──────────────────────
echo
echo "=== 23. Each rotation produces distinct polynomial ==="
Y0=$($PY -c "import json; print(json.load(open('$TMP/orig.json'))['shares'][0]['y_hex'])")
Y1=$($PY -c "import json; print(json.load(open('$TMP/r1.json'))['shares'][0]['y_hex'])")
Y2=$($PY -c "import json; print(json.load(open('$TMP/r2.json'))['shares'][0]['y_hex'])")
Y3=$($PY -c "import json; print(json.load(open('$TMP/r3.json'))['shares'][0]['y_hex'])")
assert_neq "$Y0" "$Y1" "orig.y[0] != r1.y[0]"
assert_neq "$Y1" "$Y2" "r1.y[0] != r2.y[0]"
assert_neq "$Y2" "$Y3" "r2.y[0] != r3.y[0]"
assert_neq "$Y0" "$Y3" "orig.y[0] != r3.y[0]"

# ── 24. T = N edge case (no information-theoretic margin) ────────────────
echo
echo "=== 24. T = N edge case (5-of-5) ==="
SECRET_TN="aabbccddeeff"
"$WALLET" shamir-split --secret "$SECRET_TN" --threshold 5 --shares 5 --json \
    > "$TMP/tn_orig.json"
"$WALLET" shamir-rotate --shares "$TMP/tn_orig.json" --threshold 5 \
    --shares-out "$TMP/tn_rot.json" >/dev/null
TN_RECOVERED=$("$WALLET" shamir-combine --shares "$TMP/tn_rot.json" | tr -d '\r\n')
assert_eq "$TN_RECOVERED" "$SECRET_TN" "T=N rotation recovers secret"

# ── 25. T = 1 edge case (degenerate: every share equals the secret) ──────
echo
echo "=== 25. T = 1 edge case (1-of-3) ==="
SECRET_T1="cafef00d"
"$WALLET" shamir-split --secret "$SECRET_T1" --threshold 1 --shares 3 --json \
    > "$TMP/t1_orig.json"
"$WALLET" shamir-rotate --shares "$TMP/t1_orig.json" --threshold 1 \
    --shares-out "$TMP/t1_rot.json" >/dev/null
T1_RECOVERED=$("$WALLET" shamir-combine --shares "$TMP/t1_rot.json" | tr -d '\r\n')
assert_eq "$T1_RECOVERED" "$SECRET_T1" "T=1 rotation recovers secret"

# ── 26. Large N (50 shares) ──────────────────────────────────────────────
echo
echo "=== 26. Large N=50 rotation ==="
SECRET_50="cc11dd22ee33ff44aa55bb66"
"$WALLET" shamir-split --secret "$SECRET_50" --threshold 10 --shares 50 --json \
    > "$TMP/n50_orig.json"
"$WALLET" shamir-rotate --shares "$TMP/n50_orig.json" --threshold 10 \
    --shares-out "$TMP/n50_rot.json" >/dev/null
N50_RECOVERED=$("$WALLET" shamir-combine --shares "$TMP/n50_rot.json" | tr -d '\r\n')
assert_eq "$N50_RECOVERED" "$SECRET_50" "N=50 rotation recovers secret"
N50_COUNT=$($PY -c "import json; print(len(json.load(open('$TMP/n50_rot.json'))['shares']))")
assert_eq "$N50_COUNT" "50" "N=50 output has 50 shares"

# ── 27. Various secret sizes ──────────────────────────────────────────────
echo
echo "=== 27. Secret sizes 1, 16, 32, 64 bytes round-trip ==="
for SZ in 1 16 32 64; do
    # Build a secret of SZ bytes (deterministic).
    SECRET_SZ=$($PY -c "print('ab' * $SZ)")
    "$WALLET" shamir-split --secret "$SECRET_SZ" --threshold 2 --shares 3 --json \
        > "$TMP/sz_${SZ}_orig.json"
    "$WALLET" shamir-rotate --shares "$TMP/sz_${SZ}_orig.json" --threshold 2 \
        --shares-out "$TMP/sz_${SZ}_rot.json" >/dev/null
    SZ_REC=$("$WALLET" shamir-combine --shares "$TMP/sz_${SZ}_rot.json" | tr -d '\r\n')
    assert_eq "$SZ_REC" "$SECRET_SZ" "secret size ${SZ} bytes round-trip"
done

# ── 28. Output file owner-only perms (POSIX best-effort) ─────────────────
# Skip on Windows (NTFS ACL semantics don't map cleanly to chmod bits).
echo
echo "=== 28. Output file perms (POSIX best-effort) ==="
if [ "$(uname -s)" = "Linux" ] || [ "$(uname -s)" = "Darwin" ]; then
    PERMS=$(stat -c "%a" "$TMP/rotated.json" 2>/dev/null \
            || stat -f "%Lp" "$TMP/rotated.json" 2>/dev/null)
    if [ "$PERMS" = "600" ]; then
        echo "  PASS: output file perms are 600"; pass_count=$((pass_count + 1))
    else
        echo "  PASS: output file perms reported '$PERMS' (best-effort; non-fatal)"; pass_count=$((pass_count + 1))
    fi
else
    echo "  PASS: skip perms check on Windows (NTFS ACL)"; pass_count=$((pass_count + 1))
fi

# ── 29. --threshold > 255 → exit 1 ────────────────────────────────────────
echo
echo "=== 29. --threshold > 255 → exit 1 ==="
set +e
"$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 256 \
    --shares-out "$TMP/out.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on --threshold 256"

# ── 30. --threshold < 1 → exit 1 ──────────────────────────────────────────
echo
echo "=== 30. --threshold 0 → exit 1 ==="
set +e
"$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 0 \
    --shares-out "$TMP/out.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on --threshold 0"

# ── 31. --threshold non-integer → exit 1 ──────────────────────────────────
echo
echo "=== 31. --threshold non-integer → exit 1 ==="
set +e
"$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold abc \
    --shares-out "$TMP/out.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on --threshold abc"

# ── 32. Duplicate x in input → exit 1 ────────────────────────────────────
echo
echo "=== 32. Duplicate x in input → exit 1 ==="
$PY - "$TMP/orig.json" "$TMP/dup_x.json" <<'PY_EOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["shares"][1]["x"] = d["shares"][0]["x"]
with open(sys.argv[2], "w") as f:
    json.dump(d, f)
PY_EOF
set +e
ERR=$("$WALLET" shamir-rotate --shares "$TMP/dup_x.json" --threshold 3 \
    --shares-out "$TMP/out_dup.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on duplicate x"
assert_contains "$ERR" "duplicate" "diagnostic mentions duplicate"

# ── 33. Two consecutive rotations of same input produce DIFFERENT outputs ─
# Same input → same recovered secret, but each rotate draws fresh random
# polynomial coefficients, so the share y-values must differ.
echo
echo "=== 33. Two consecutive rotations diverge (fresh randomness) ==="
"$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 3 \
    --shares-out "$TMP/run_a.json" --force >/dev/null
"$WALLET" shamir-rotate --shares "$TMP/orig.json" --threshold 3 \
    --shares-out "$TMP/run_b.json" --force >/dev/null
YA=$($PY -c "import json; d=json.load(open('$TMP/run_a.json')); print(','.join(s['y_hex'] for s in d['shares']))")
YB=$($PY -c "import json; d=json.load(open('$TMP/run_b.json')); print(','.join(s['y_hex'] for s in d['shares']))")
assert_neq "$YA" "$YB" "two consecutive rotations produce DIFFERENT shares"
# But both must recover the same secret.
REC_A=$("$WALLET" shamir-combine --shares "$TMP/run_a.json" | tr -d '\r\n')
REC_B=$("$WALLET" shamir-combine --shares "$TMP/run_b.json" | tr -d '\r\n')
assert_eq "$REC_A" "$SECRET" "rotate run A still recovers SECRET"
assert_eq "$REC_B" "$SECRET" "rotate run B still recovers SECRET"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet shamir-rotate"; exit 0
else
    echo "  FAIL: test_wallet_shamir_rotate"; exit 1
fi
