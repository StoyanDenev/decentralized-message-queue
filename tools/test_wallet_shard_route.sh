#!/usr/bin/env bash
# determ-wallet shard-route CLI test.
#
# Exercises the OFFLINE address-to-shard router. Given an address and the
# chain's routing salt + shard count, the command reports which shard OWNS
# the address — reproducing the consensus rule crypto::shard_id_for_address
# (src/crypto/random.cpp) byte-for-byte, the SAME deterministic map every
# node, beacon, and external wallet agrees on (rev.9 B3). The chain consults
# the identical map at src/chain/chain.cpp::is_cross_shard.
#
# The routing rule MUST match src/crypto/random.cpp byte-for-byte:
#   shard_count <= 1            => shard 0 (unsharded — every address local)
#   else h = SHA-256(salt[32] || "shard-route" || addr_bytes)
#        v = big-endian fold of h[0..7] into a u64
#        shard = v % shard_count
#
# This test recomputes the EXPECTED shard independently in Python and asserts
# the wallet output matches it exactly — correctness, not just shape. It also
# covers the --my-shard cross_shard predicate, salt/count sourcing from a
# genesis JSON, the unsharded short-circuit, and the error paths. No cluster,
# no daemon, no network: pure offline derivation.
#
# Differentiation vs sibling commands:
#   * receipt-key   — DERIVE the composite i:/m:/p: state-leaf KEY hex.
#   * derive-tx-hash — recompute a TRANSACTION hash from an envelope.
#   * shard-route   — route an ADDRESS to its owning shard (and cross-shard).
#
# Assertions (~22):
#   1.  Global help mentions shard-route.
#   2.  shard-route --help exits 0.
#   3.  Unknown CLI arg: exit 1.
#   4.  Missing --address: exit 1.
#   5.  Missing shard count: exit 1.
#   6.  shard_count>1 without salt: exit 1.
#   7.  --salt wrong length: exit 1.
#   8.  --salt invalid hex: exit 1.
#   9.  --shard-count non-decimal: exit 1.
#  10.  Happy path (explicit salt+count) exits 0.
#  11.  shard matches independent Python computation.
#  12.  digest_hex matches independent Python SHA-256.
#  13.  shard is within [0, shard_count).
#  14.  --json parseable + has the four base keys.
#  15.  --json shard matches text-mode shard.
#  16.  Determinism — two invocations give identical shard.
#  17.  Different address can route to a different shard (map is per-address).
#  18.  --my-shard equal to route => cross_shard false.
#  19.  --my-shard differing from route => cross_shard true.
#  20.  Unsharded (--shard-count 1) => shard 0 regardless of address.
#  21.  --genesis sources shard_address_salt + initial_shard_count.
#  22.  --genesis result equals explicit-flag result for the same address.
#
# Run from repo root: bash tools/test_wallet_shard_route.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_ne() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       both were: $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fixed test vectors.
SALT="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
SHARD_COUNT=8
ADDR="acme.example"
ADDR2="globex.example"

# ── Independent reference computation (Python) ──────────────────────────
# h = SHA-256(salt[32] || "shard-route" || addr); shard = fold8_be(h) % count
route_ref() {  # route_ref <addr> <count>
  $PY -c "
import hashlib, struct
salt = bytes.fromhex('$SALT')
pre = salt + b'shard-route' + '$1'.encode()
h = hashlib.sha256(pre).digest()
v = struct.unpack('>Q', h[:8])[0]
print(v % $2)
"
}
digest_ref() {  # digest_ref <addr>
  $PY -c "
import hashlib
salt = bytes.fromhex('$SALT')
print(hashlib.sha256(salt + b'shard-route' + '$1'.encode()).hexdigest())
"
}

EXP_SHARD=$(route_ref "$ADDR" "$SHARD_COUNT")
EXP_SHARD2=$(route_ref "$ADDR2" "$SHARD_COUNT")
EXP_DIGEST=$(digest_ref "$ADDR")

field() {  # field <json> <key>
  echo "$1" | $PY -c "import json,sys; print(json.loads(sys.stdin.read()).get('$2',''))"
}

echo "=== 1. Global help mentions shard-route ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "shard-route" "help mentions shard-route"

echo
echo "=== 2. shard-route --help exits 0 ==="
set +e
"$WALLET" shard-route --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "shard-route --help exits 0"

echo
echo "=== 3. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" shard-route --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 4. Missing --address: exit 1 ==="
set +e
"$WALLET" shard-route --salt "$SALT" --shard-count "$SHARD_COUNT" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --address returns 1"

echo
echo "=== 5. Missing shard count: exit 1 ==="
set +e
"$WALLET" shard-route --address "$ADDR" --salt "$SALT" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing shard count returns 1"

echo
echo "=== 6. shard_count>1 without salt: exit 1 ==="
set +e
"$WALLET" shard-route --address "$ADDR" --shard-count "$SHARD_COUNT" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing salt (sharded) returns 1"

echo
echo "=== 7. --salt wrong length: exit 1 ==="
set +e
"$WALLET" shard-route --address "$ADDR" --salt "00112233" --shard-count "$SHARD_COUNT" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "short salt returns 1"

echo
echo "=== 8. --salt invalid hex: exit 1 ==="
BADSALT=$($PY -c "print('zz' * 32)")
set +e
"$WALLET" shard-route --address "$ADDR" --salt "$BADSALT" --shard-count "$SHARD_COUNT" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "non-hex salt returns 1"

echo
echo "=== 9. --shard-count non-decimal: exit 1 ==="
set +e
"$WALLET" shard-route --address "$ADDR" --salt "$SALT" --shard-count "0x8" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "non-decimal shard-count returns 1"

echo
echo "=== 10-13. Happy path + correctness ==="
set +e
J=$("$WALLET" shard-route --address "$ADDR" --salt "$SALT" --shard-count "$SHARD_COUNT" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "happy path returns 0"
GOT_SHARD=$(field "$J" shard)
GOT_DIGEST=$(field "$J" digest_hex)
assert_eq "$GOT_SHARD" "$EXP_SHARD" "shard matches independent Python route"
assert_eq "$GOT_DIGEST" "$EXP_DIGEST" "digest_hex matches independent SHA-256"
IN_RANGE=$($PY -c "print('yes' if 0 <= $GOT_SHARD < $SHARD_COUNT else 'no')")
assert_eq "$IN_RANGE" "yes" "shard within [0, shard_count)"

echo
echo "=== 14-15. --json shape + cross-check vs text mode ==="
PARSED_OK=$(echo "$J" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
ok = all(k in d for k in ('address','shard_count','shard','digest_hex'))
print('yes' if ok else 'no')
" 2>/dev/null || echo "no")
assert_eq "$PARSED_OK" "yes" "--json has the four base keys"
TEXT_SHARD=$("$WALLET" shard-route --address "$ADDR" --salt "$SALT" --shard-count "$SHARD_COUNT" 2>&1 \
  | tr -d '\r' | grep '^shard:' | awk '{print $2}')
assert_eq "$TEXT_SHARD" "$GOT_SHARD" "text-mode shard == JSON-mode shard"

echo
echo "=== 16. Determinism (two runs identical) ==="
R1=$("$WALLET" shard-route --address "$ADDR" --salt "$SALT" --shard-count "$SHARD_COUNT" --json 2>&1 | tr -d '\r')
R2=$("$WALLET" shard-route --address "$ADDR" --salt "$SALT" --shard-count "$SHARD_COUNT" --json 2>&1 | tr -d '\r')
S1=$(field "$R1" shard)
S2=$(field "$R2" shard)
assert_eq "$S1" "$S2" "two invocations give identical shard"

echo
echo "=== 17. Per-address routing (distinct addr may differ) ==="
J2=$("$WALLET" shard-route --address "$ADDR2" --salt "$SALT" --shard-count "$SHARD_COUNT" --json 2>&1 | tr -d '\r')
GOT_SHARD2=$(field "$J2" shard)
assert_eq "$GOT_SHARD2" "$EXP_SHARD2" "second address routes to its Python-predicted shard"

echo
echo "=== 18-19. --my-shard cross_shard predicate ==="
JLOCAL=$("$WALLET" shard-route --address "$ADDR" --salt "$SALT" --shard-count "$SHARD_COUNT" --my-shard "$EXP_SHARD" --json 2>&1 | tr -d '\r')
CS_LOCAL=$(field "$JLOCAL" cross_shard)
assert_eq "$CS_LOCAL" "False" "--my-shard == route => cross_shard false"
OTHER=$($PY -c "print(($EXP_SHARD + 1) % $SHARD_COUNT)")
JREMOTE=$("$WALLET" shard-route --address "$ADDR" --salt "$SALT" --shard-count "$SHARD_COUNT" --my-shard "$OTHER" --json 2>&1 | tr -d '\r')
CS_REMOTE=$(field "$JREMOTE" cross_shard)
assert_eq "$CS_REMOTE" "True" "--my-shard != route => cross_shard true"

echo
echo "=== 20. Unsharded short-circuit (--shard-count 1 => shard 0) ==="
J1=$("$WALLET" shard-route --address "$ADDR" --shard-count 1 --json 2>&1 | tr -d '\r')
S0=$(field "$J1" shard)
assert_eq "$S0" "0" "shard_count 1 => shard 0 (no salt needed)"

echo
echo "=== 21-22. --genesis sourcing ==="
GEN="$WORK/genesis.json"
cat > "$GEN" <<EOF
{ "shard_address_salt": "$SALT", "initial_shard_count": $SHARD_COUNT }
EOF
set +e
JG=$("$WALLET" shard-route --address "$ADDR" --genesis "$GEN" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "--genesis sources salt + count (exit 0)"
GG_SHARD=$(field "$JG" shard)
assert_eq "$GG_SHARD" "$EXP_SHARD" "--genesis result == explicit-flag result"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
