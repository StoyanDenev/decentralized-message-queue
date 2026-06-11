#!/usr/bin/env bash
# determ-wallet derive-shared-secret — ECDH symmetry property fuzz (OFFLINE).
#
# Hardens `derive-shared-secret` (X25519 ECDH) against a SAFE mathematical
# oracle: the Diffie-Hellman SYMMETRY property. No cipher / KDF / X25519 /
# Ed25519 is reimplemented here. The oracle is purely structural:
#
#   For ANY two keypairs (i, j):
#       derive(priv_i, pub_j)  ==  derive(priv_j, pub_i)          (SYMMETRY)
#   For any two DISTINCT unordered pairs {i,j} != {k,l}:
#       secret({i,j})          !=  secret({k,l})                  (DISTINCT)
#
# This complements (does NOT duplicate) test_wallet_derive_shared_secret.sh
# (single-pair smoke + CLI-error matrix) by running a fixed-seed POPULATION
# fuzz: N deterministically-derived accounts, all C(N,2) pairs checked for
# symmetry, and all pair-secrets checked for global distinctness (no two
# unrelated pairs collide). It also adds an XOR-bit-flip tamper assertion on
# the peer pubkey.
#
# Determinism: accounts come from `account-derive-batch --seed <fixed>`
# (seed_i = SHA-256(master_seed || u32_le(i))), so the whole run is
# reproducible from one fixed 32-byte master seed — no RNG, fully offline,
# no daemon / cluster.
#
# `--priv-keyfile` consumes the plaintext single-account JSON shape
# {"address":"0x..","privkey_hex":".."}; the pubkey is the address minus
# the "0x" prefix. No passphrase is involved on this code path.
#
# Cases: 1 setup + C(N,2) symmetry + C(N,2) determinism-cross + global
# distinctness + tamper => well over 20 random-ish property checks at N=8
# (C(8,2)=28 pairs).
#
# Run from repo root: bash tools/test_wallet_ecdh_symmetry_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "  SKIP: python not found (needed for JSON parsing)"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Scratch under build/ to dodge MSYS path-translation quirks (the native
# Windows wallet binary can't read /tmp-style MSYS paths).
T="build/test_wallet_ecdh_symmetry_fuzz.$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT

pass_count=0
fail_count=0
assert() {
  # assert <condition-bool: "0"/"1" or string eq via caller> <label>
  if [ "$1" = "PASS" ]; then
    echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $2"; fail_count=$((fail_count + 1))
  fi
}
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3 (expected '$2' got '$1')"; fail_count=$((fail_count + 1)); fi
}

# Fixed 32-byte master seed (64 hex) — the ONLY source of randomness; makes
# the whole fuzz reproducible. Not a real key; scratch-only, wiped on EXIT.
SEED="a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"
N=8   # C(8,2)=28 unordered pairs => 28 symmetry + 28 determinism checks.

# ── 1. Setup: deterministically derive N accounts ─────────────────────────────
echo "=== 1. Setup: derive $N deterministic accounts from fixed seed ==="
"$WALLET" account-derive-batch --seed "$SEED" --count "$N" --out "$T/batch.json" --json >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "account-derive-batch (count=$N) succeeded"
if [ "$RC" != "0" ] || [ ! -f "$T/batch.json" ]; then
    echo "  FAIL: setup did not produce batch.json — aborting"
    echo "  $pass_count pass / $fail_count fail"
    echo "  FAIL: test_wallet_ecdh_symmetry_fuzz"
    exit 1
fi

# Explode the batch into per-account single-account keyfiles {address,privkey_hex}
# (the shape --priv-keyfile expects) and emit "<index> <pubkey_hex>" lines.
"$PY" -c "
import json
d = json.load(open('$T/batch.json'))
accts = d['accounts']
for a in accts:
    i = a['index']
    json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']},
              open('$T/k%d.json' % i, 'w'))
    print('%d %s' % (i, a['address'][2:]))
" > "$T/pubs.txt"

PUBCOUNT=$(grep -c . "$T/pubs.txt")
assert_eq "$PUBCOUNT" "$N" "exploded $N per-account keyfiles + pubkey table"

# Confirm all N pubkeys are distinct (CSPRNG/derivation sanity).
UNIQ=$(awk '{print $2}' "$T/pubs.txt" | sort -u | grep -c .)
if [ "$UNIQ" = "$N" ]; then
    assert "PASS" "all $N derived pubkeys are distinct"
else
    assert "FAIL" "derived pubkeys collided ($UNIQ unique of $N)"
fi

get_pub() { awk -v i="$1" '$1==i{print $2}' "$T/pubs.txt"; }

# derive(priv_i, pub) -> 64-hex shared secret on stdout; "" on any failure.
sec() {
  local i="$1" pub="$2" out
  out=$("$WALLET" derive-shared-secret --priv-keyfile "$T/k$i.json" --pubkey "$pub" 2>/dev/null | tr -d '\r')
  echo "$out" | "$PY" -c "
import json,sys
try:
    print(json.load(sys.stdin)['shared_secret_hex'])
except Exception:
    print('')
"
}

ZERO="0000000000000000000000000000000000000000000000000000000000000000"

# ── 2. ECDH SYMMETRY over all C(N,2) pairs (the math oracle) ───────────────────
echo
echo "=== 2. ECDH symmetry derive(i,pub_j)==derive(j,pub_i) over all pairs ==="
# Collect each pair's canonical secret into a file for the later distinctness
# sweep: "i j <secret_ij>".
: > "$T/secrets.txt"
sym_pass=0
sym_total=0
for i in $(seq 0 $((N - 1))); do
  for j in $(seq $((i + 1)) $((N - 1))); do
    sym_total=$((sym_total + 1))
    PI=$(get_pub "$i"); PJ=$(get_pub "$j")
    SIJ=$(sec "$i" "$PJ")   # derive(priv_i, pub_j)
    SJI=$(sec "$j" "$PI")   # derive(priv_j, pub_i)
    OK="PASS"
    # Symmetry: the two directions must agree byte-for-byte.
    [ "$SIJ" = "$SJI" ] || OK="FAIL"
    # Shape: 64 lowercase hex chars.
    case "$SIJ" in
      *[!0-9a-f]* | "") OK="FAIL" ;;
    esac
    [ "${#SIJ}" = "64" ] || OK="FAIL"
    # Non-zero point (small-subgroup / contributory-behavior indicator).
    [ "$SIJ" = "$ZERO" ] && OK="FAIL"
    if [ "$OK" = "PASS" ]; then
      sym_pass=$((sym_pass + 1))
      echo "$i $j $SIJ" >> "$T/secrets.txt"
    else
      echo "    pair ($i,$j): SIJ=$SIJ SJI=$SJI"
    fi
  done
done
assert_eq "$sym_pass" "$sym_total" "ECDH symmetry holds for all $sym_total pairs (valid 64-hex non-zero)"

# ── 3. Determinism: re-deriving each pair yields identical bytes ──────────────
echo
echo "=== 3. Determinism: a second derive of every pair matches the first ==="
det_pass=0
det_total=0
while read -r i j s; do
  det_total=$((det_total + 1))
  PJ=$(get_pub "$j")
  AGAIN=$(sec "$i" "$PJ")
  if [ "$AGAIN" = "$s" ]; then det_pass=$((det_pass + 1)); fi
done < "$T/secrets.txt"
assert_eq "$det_pass" "$det_total" "every pair re-derives byte-identical ($det_total pairs)"

# ── 4. Global distinctness: no two unrelated pairs share a secret ─────────────
echo
echo "=== 4. Distinctness: all $sym_total pair-secrets are mutually distinct ==="
TOTAL_SECRETS=$(grep -c . "$T/secrets.txt")
UNIQ_SECRETS=$(awk '{print $3}' "$T/secrets.txt" | sort -u | grep -c .)
assert_eq "$UNIQ_SECRETS" "$TOTAL_SECRETS" "no shared-secret collisions across distinct pairs"

# ── 5. XOR-bit-flip tamper of the peer pubkey ─────────────────────────────────
# Flip one bit of pub_1 and derive against priv_0. A single bit-flip MUST
# change the outcome: either the point no longer decompresses (rc!=0, the
# common case — the flipped byte is no longer a valid Ed25519 pubkey) OR, if
# it happens to land on a valid point, the resulting secret differs from the
# untampered one. It must NEVER yield the SAME secret. We capture the wallet's
# OWN exit code (no pipe between the binary and `$?`) so a tamper-rejection on
# stderr is read correctly.
echo
echo "=== 5. XOR-bit-flip of peer pubkey changes/rejects the derivation ==="
P0=$(get_pub 0)
P1=$(get_pub 1)
GOOD=$(sec 0 "$P1")
FLIP=$("$PY" -c "
p='$P1'
b=bytearray.fromhex(p)
b[0]^=0x01   # flip low bit of the first byte
print(bytes(b).hex())
")
set +e
"$WALLET" derive-shared-secret --priv-keyfile "$T/k0.json" --pubkey "$FLIP" >"$T/tamper.out" 2>"$T/tamper.err"
TRC=$?
set -e
TAMPERED=$("$PY" -c "
import json
try:
    print(json.load(open('$T/tamper.out'))['shared_secret_hex'])
except Exception:
    print('')
")
if [ "$TRC" != "0" ]; then
    assert "PASS" "bit-flipped pubkey rejected (rc=$TRC, invalid Ed25519 point)"
elif [ -n "$TAMPERED" ] && [ "$TAMPERED" != "$GOOD" ]; then
    assert "PASS" "bit-flipped pubkey yields a different shared secret"
else
    assert "FAIL" "bit-flipped pubkey produced the SAME secret as the original (TRC=$TRC, TAMPERED=$TAMPERED)"
fi

# ── 6. Cross-confirm vs a SECOND independent seed (disjoint population) ────────
# A different master seed must produce a wholly disjoint account set; a
# cross-seed secret must differ from the matching same-index in-seed secret.
# Guards against the derivation/secret silently ignoring the private key.
echo
echo "=== 6. A different master seed yields a disjoint, non-overlapping secret ==="
SEED2="ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211"
"$WALLET" account-derive-batch --seed "$SEED2" --count 2 --out "$T/batch2.json" --json >/dev/null 2>&1
"$PY" -c "
import json
d = json.load(open('$T/batch2.json'))
a = d['accounts'][0]
json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']}, open('$T/s2_k0.json','w'))
print(a['address'][2:])
" > "$T/s2_pub.txt"
S2P0=$(grep . "$T/s2_pub.txt")
# secret(seed2.k0, seed1.pub1)  vs  secret(seed1.k0, seed1.pub1)
CROSS=$("$WALLET" derive-shared-secret --priv-keyfile "$T/s2_k0.json" --pubkey "$P1" 2>/dev/null | tr -d '\r' | "$PY" -c "
import json,sys
try: print(json.load(sys.stdin)['shared_secret_hex'])
except Exception: print('')
")
if [ -n "$CROSS" ] && [ "$CROSS" != "$GOOD" ]; then
    assert "PASS" "different-seed private key produces a different secret (priv participates)"
else
    assert "FAIL" "cross-seed secret matched in-seed secret or was empty (priv ignored?!)"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  random/property cases: $sym_total pairs x (symmetry+determinism) + distinctness + tamper + cross-seed"
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet derive-shared-secret ECDH symmetry fuzz"
    exit 0
else
    echo "  FAIL: test_wallet_ecdh_symmetry_fuzz"
    exit 1
fi
