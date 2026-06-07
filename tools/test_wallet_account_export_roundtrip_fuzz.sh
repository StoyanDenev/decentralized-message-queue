#!/usr/bin/env bash
# determ-wallet account-export <-> account-import round-trip PROPERTY FUZZ.
#
# CRYPTO-CRITICAL surface: the export/import path is how an operator moves a
# wallet account between machines, formats, and backup envelopes. If the
# round-trip is not a lossless identity the operator can silently lose access
# to funds (a recovered account whose anon-address or seed differs from the
# original is unspendable). This test hardens that identity across MANY random
# accounts and ALL THREE export formats at once.
#
# SAFE REFERENCE (no re-implementation of Ed25519 / KDF / any cipher):
#   The oracle is the KNOWN ORIGINAL account. We derive a batch of
#   deterministic-but-pseudorandom accounts from a fixed master seed via
#   `account-derive-batch` (fixed-seed RNG -> reproducible fixtures), capture
#   each (address, privkey_hex) as ground truth, then for every account assert:
#
#     import(export(account)) == account
#
#   across the three lossless formats the CLI advertises:
#     - raw-hex      : export emits the 64-hex seed; import --priv re-derives.
#     - json         : export passes through {address, privkey_hex}; we import
#                      the privkey_hex and check both fields round-trip.
#     - backup-bundle: export emits {seed_hex, pubkey_hex, anon_address, ...};
#                      we import seed_hex and check the recovered address equals
#                      both the bundle's anon_address AND the original address.
#
#   Plus a cross-encoding identity (the 64-byte seed||pubkey form must import
#   to the SAME account as the 32-byte seed form) and two TAMPER checks using
#   XOR-style nibble flips so a mutation is always a real change:
#     - flip a nibble in backup-bundle seed_hex  -> recovered address MUST differ
#       from the original (corruption never silently round-trips to the same id).
#     - flip a nibble in the pubkey half of the 64-byte form -> import MUST
#       REJECT with rc=1 (seed/pubkey consistency is enforced).
#
# This is distinct from test_wallet_account_export.sh / _import.sh (single
# fixed account, per-flag scenario coverage): here the contribution is the
# many-cases x all-formats identity matrix plus the tamper oracle.
#
# Fully OFFLINE: no daemon, no cluster, no network. Fixed seed -> reproducible.
#
# Run from repo root: bash tools/test_wallet_account_export_roundtrip_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
WALLET="$DETERM_WALLET"

PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "  SKIP: python not found (needed to parse wallet JSON output)"
    exit 0
fi

# Per-run scratch dir; trap-cleaned. Holds test-only secret material (seeds,
# privkeys for throwaway accounts) — wiped on exit.
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

pass_count=0
fail_count=0
assert() {
  # assert <condition-result 0|nonzero> <message>
  if [ "$1" -eq 0 ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}

# ── Fixed-seed RNG: a pinned 32-byte master seed (64 hex). account-derive-batch
#    expands this deterministically into N child accounts, so the whole fuzz
#    corpus is reproducible across runs/machines. ──────────────────────────────
MASTER_SEED="0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
NUM_CASES=24   # >= 20 required; each case runs the full all-formats matrix.

echo "=== 0. Help line mentions both account-export and account-import ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
echo "$H" | grep -q "account-export"; assert $? "help mentions account-export"
echo "$H" | grep -q "account-import"; assert $? "help mentions account-import"

echo
echo "=== 1. Derive $NUM_CASES deterministic random accounts (the oracle) ==="
"$WALLET" account-derive-batch --seed "$MASTER_SEED" --count "$NUM_CASES" \
    --out "$TMP/batch.json" --json >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "account-derive-batch produced $NUM_CASES accounts"

# Sanity: the batch really holds NUM_CASES distinct accounts with the right
# field shapes. (Also acts as a duplicate-address guard for the RNG.)
N_OK=$($PY -c "
import json, sys, re
d = json.load(open(sys.argv[1]))
accs = d['accounts']
addrs = [a['address'] for a in accs]
privs = [a['privkey_hex'] for a in accs]
ok = (
    len(accs) == int(sys.argv[2]) and
    len(set(addrs)) == len(accs) and
    len(set(privs)) == len(accs) and
    all(re.match(r'^0x[0-9a-f]{64}\$', a) for a in addrs) and
    all(re.match(r'^[0-9a-f]{64}\$', p) for p in privs)
)
print('YES' if ok else 'NO')
" "$TMP/batch.json" "$NUM_CASES")
assert_eq "$N_OK" "YES" "batch: $NUM_CASES distinct accounts, canonical address/privkey shapes"

# Helper: extract field of account #i from the batch.
acc_field() { # acc_field <index> <key>
  $PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][int(sys.argv[2])][sys.argv[3]])" \
     "$TMP/batch.json" "$1" "$2"
}
json_get() { # json_get <stdin-json-string> <key>   (reads $1 as JSON text)
  printf '%s' "$1" | $PY -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$2"
}

echo
echo "=== 2. Per-account all-formats round-trip identity ($NUM_CASES x 3 formats) ==="
rt_raw_ok=0; rt_json_ok=0; rt_bundle_ok=0; xenc_ok=0
for i in $(seq 0 $((NUM_CASES - 1))); do
    ORIG_ADDR=$(acc_field "$i" address)
    ORIG_PRIV=$(acc_field "$i" privkey_hex)

    # Materialize the single-account input file account-export consumes.
    $PY -c "import json,sys; json.dump({'address':sys.argv[2],'privkey_hex':sys.argv[3]}, open(sys.argv[1],'w'))" \
        "$TMP/acc.json" "$ORIG_ADDR" "$ORIG_PRIV"

    # ── raw-hex round-trip: export -> import --priv ──
    EXP_HEX=$("$WALLET" account-export --in "$TMP/acc.json" --format raw-hex 2>/dev/null | tr -d '\r\n')
    IMP=$("$WALLET" account-import --priv "$EXP_HEX" --json 2>/dev/null | tr -d '\r')
    R_ADDR=$(json_get "$IMP" address)
    R_PRIV=$(json_get "$IMP" privkey_hex)
    if [ "$R_ADDR" = "$ORIG_ADDR" ] && [ "$R_PRIV" = "$ORIG_PRIV" ]; then
        rt_raw_ok=$((rt_raw_ok + 1))
    else
        echo "    raw-hex MISMATCH at #$i: addr $R_ADDR vs $ORIG_ADDR"
    fi

    # ── json passthrough round-trip: export json -> import its privkey_hex ──
    EXP_JSON=$("$WALLET" account-export --in "$TMP/acc.json" --format json 2>/dev/null | tr -d '\r')
    J_ADDR=$(json_get "$EXP_JSON" address)
    J_PRIV=$(json_get "$EXP_JSON" privkey_hex)
    IMP2=$("$WALLET" account-import --priv "$J_PRIV" --json 2>/dev/null | tr -d '\r')
    R2_ADDR=$(json_get "$IMP2" address)
    if [ "$J_ADDR" = "$ORIG_ADDR" ] && [ "$J_PRIV" = "$ORIG_PRIV" ] && [ "$R2_ADDR" = "$ORIG_ADDR" ]; then
        rt_json_ok=$((rt_json_ok + 1))
    else
        echo "    json MISMATCH at #$i"
    fi

    # ── backup-bundle round-trip: export bundle -> import seed_hex ──
    BUNDLE=$("$WALLET" account-export --in "$TMP/acc.json" --format backup-bundle 2>/dev/null | tr -d '\r')
    B_SEED=$(json_get "$BUNDLE" seed_hex)
    B_PUB=$(json_get "$BUNDLE" pubkey_hex)
    B_ADDR=$(json_get "$BUNDLE" anon_address)
    IMP3=$("$WALLET" account-import --priv "$B_SEED" --json 2>/dev/null | tr -d '\r')
    R3_ADDR=$(json_get "$IMP3" address)
    # bundle internally consistent (pubkey_hex == address body, seed == priv,
    # anon_address == orig) AND re-import of seed reproduces the original address.
    if [ "$B_SEED" = "$ORIG_PRIV" ] && [ "$B_ADDR" = "$ORIG_ADDR" ] \
       && [ "0x$B_PUB" = "$ORIG_ADDR" ] && [ "$R3_ADDR" = "$ORIG_ADDR" ]; then
        rt_bundle_ok=$((rt_bundle_ok + 1))
    else
        echo "    backup-bundle MISMATCH at #$i"
    fi

    # ── cross-encoding identity: 64-byte (seed||pubkey) import == 32-byte import ──
    PUB_BODY=${ORIG_ADDR#0x}
    KEYPAIR="${ORIG_PRIV}${PUB_BODY}"
    IMP64=$("$WALLET" account-import --priv "$KEYPAIR" --json 2>/dev/null | tr -d '\r')
    R64_ADDR=$(json_get "$IMP64" address)
    R64_PRIV=$(json_get "$IMP64" privkey_hex)
    if [ "$R64_ADDR" = "$ORIG_ADDR" ] && [ "$R64_PRIV" = "$ORIG_PRIV" ]; then
        xenc_ok=$((xenc_ok + 1))
    else
        echo "    64-byte-form MISMATCH at #$i"
    fi
done
assert_eq "$rt_raw_ok"    "$NUM_CASES" "raw-hex round-trip identity holds for all $NUM_CASES accounts"
assert_eq "$rt_json_ok"   "$NUM_CASES" "json passthrough round-trip identity holds for all $NUM_CASES accounts"
assert_eq "$rt_bundle_ok" "$NUM_CASES" "backup-bundle round-trip identity holds for all $NUM_CASES accounts"
assert_eq "$xenc_ok"      "$NUM_CASES" "64-byte seed||pubkey form imports identically to 32-byte seed for all $NUM_CASES"

echo
echo "=== 3. TAMPER (XOR-style nibble flip): corrupted seed must NOT round-trip to original ==="
# Take account #0, flip one nibble of its seed, re-import: the recovered
# anon-address MUST differ from the original (a real mutation never silently
# resolves to the same identity). flip_nibble XORs the chosen hex digit with 1.
flip_nibble() { # flip_nibble <hexstring> <index>  -> echoes mutated hexstring
  $PY -c "
import sys
s = list(sys.argv[1]); i = int(sys.argv[2])
v = int(s[i], 16) ^ 1          # XOR-flip low bit -> guaranteed different digit
s[i] = '%x' % v
print(''.join(s))
" "$1" "$2"
}

T_PRIV=$(acc_field 0 privkey_hex)
T_ADDR=$(acc_field 0 address)
BAD_SEED=$(flip_nibble "$T_PRIV" 5)
# Guard: the flip really changed the seed (XOR low-bit always flips the digit).
if [ "$BAD_SEED" != "$T_PRIV" ]; then
    echo "  PASS: nibble-flip produced a genuinely different seed"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: nibble-flip left the seed unchanged"; fail_count=$((fail_count + 1))
fi
BAD_IMP=$("$WALLET" account-import --priv "$BAD_SEED" --json 2>/dev/null | tr -d '\r')
BAD_ADDR=$(json_get "$BAD_IMP" address)
if [ -n "$BAD_ADDR" ] && [ "$BAD_ADDR" != "$T_ADDR" ]; then
    echo "  PASS: tampered seed re-imports to a DIFFERENT address (no silent identity collision)"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: tampered seed produced the original address (or empty) — corruption masked"
    echo "        orig=$T_ADDR got=$BAD_ADDR"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== 4. TAMPER: 64-byte form with flipped pubkey half must be REJECTED ==="
# Build seed||pubkey then flip one nibble in the PUBKEY half so the supplied
# pubkey no longer matches the seed-derived one. Import MUST reject (rc=1).
PUB_BODY=${T_ADDR#0x}
BAD_PUB=$(flip_nibble "$PUB_BODY" 3)
BAD_KEYPAIR="${T_PRIV}${BAD_PUB}"
set +e
ERR=$("$WALLET" account-import --priv "$BAD_KEYPAIR" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "import rejects 64-byte form whose pubkey half was tampered"
echo "$ERR" | grep -qi "mismatch"; assert $? "rejection diagnostic mentions the seed/pubkey mismatch"

echo
echo "=== 5. Determinism: re-deriving the same master seed reproduces the corpus ==="
"$WALLET" account-derive-batch --seed "$MASTER_SEED" --count "$NUM_CASES" \
    --out "$TMP/batch2.json" --json >/dev/null 2>&1
SAME=$($PY -c "
import json,sys
a=json.load(open(sys.argv[1]))['accounts']
b=json.load(open(sys.argv[2]))['accounts']
print('YES' if a==b else 'NO')
" "$TMP/batch.json" "$TMP/batch2.json")
assert_eq "$SAME" "YES" "fixed master seed deterministically reproduces the identical account corpus"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail  (corpus = $NUM_CASES random accounts)"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-export <-> account-import round-trip fuzz"
    exit 0
else
    echo "  FAIL: determ-wallet account-export <-> account-import round-trip fuzz"
    exit 1
fi
