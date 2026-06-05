#!/usr/bin/env bash
# determ-light shard-route — OFFLINE genesis-pinned address-to-shard routing.
#
# Pure offline test (no cluster, no daemon, no RPC). Crafts minimal genesis
# JSON files BY HAND (only the fields shard-route needs: chain_id,
# initial_shard_count, shard_address_salt), then exercises
# `determ-light shard-route` against them. The load-bearing assertion is a
# CROSS-IMPLEMENTATION conformance check: for the same address + shard_count
# + salt, the light-client's INDEPENDENT inline replica of the routing math
# must agree with the daemon's `determ where-is` (which calls the real
# crypto::shard_id_for_address). The two are written from the SAME spec in
# DIFFERENT code paths and never share a binary, so an agreeing run pins the
# routing primitive across both surfaces.
#
# What shard-route adds over `determ where-is`: it reads BOTH routing
# parameters FROM the pinned genesis (initial_shard_count +
# shard_address_salt) rather than from raw operator flags, and prints the
# locally computed genesis hash so the operator can confirm the routing is
# anchored to the expected chain.
#
# Exit contract:
#   successful routing  → exit 0
#   usage / parse error → exit 1
#   (there is no UNVERIFIABLE state — the genesis IS the trust anchor)
#
# Assertions:
#   1. Sharded genesis (count=4) → shard-route agrees with `where-is` for
#      every probe address (cross-implementation conformance).
#   2. --json carries shard / shard_count / genesis_hash; genesis_hash
#      equals `determ genesis-tool`-independent recompute via re-run
#      determinism (same file → same hash).
#   3. Unsharded genesis (count=1) → every address routes to shard 0.
#   4. Anon-address case normalization (S-028): 0xABC… and 0xabc… route to
#      the same shard, and `anon` is reported true.
#   5. A different salt (different chain identity) → different genesis_hash.
#   6. Missing --address → usage error exit 1 (not a silent shard 0).
#   7. Malformed genesis (bad salt length, S-018) → exit 1.
#
# Run from repo root: bash tools/test_light_shard_route.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3

TMP="build/test_light_shard_route.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# A fixed, known 32-byte salt (64 hex chars) and a second distinct salt.
SALT_A="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
SALT_B="ff01030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

# write_genesis <path> <chain_id> <shard_count> <salt_hex>
write_genesis() {
  cat > "$1" <<EOF
{
  "chain_id": "$2",
  "initial_shard_count": $3,
  "shard_address_salt": "$4"
}
EOF
}

write_genesis "$TMP/gen4.json"  shard-route-test 4 "$SALT_A"
write_genesis "$TMP/gen1.json"  shard-route-test 1 "$SALT_A"
write_genesis "$TMP/gen4b.json" shard-route-test 4 "$SALT_B"

# jget <json-line> <key> — extract a scalar field from a JSON line.
jget() {
  echo "$1" | "$PY" -c "import json,sys;print(json.load(sys.stdin).get('$2',''))"
}

echo "=== 1. Sharded (count=4): shard-route agrees with where-is ==="
ALL_MATCH=true
for ADDR in alice bob carol.org dave.net "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"; do
  LOUT=$($DETERM_LIGHT shard-route --genesis "$TMP/gen4.json" --address "$ADDR" --json 2>&1)
  LRC=$?
  WOUT=$($DETERM where-is "$ADDR" --shard-count 4 --salt-hex "$SALT_A" --json 2>&1)
  WRC=$?
  LSHARD=$(jget "$LOUT" shard)
  WSHARD=$(jget "$WOUT" shard)
  if [ "$LRC" = "0" ] && [ "$WRC" = "0" ] && [ -n "$LSHARD" ] \
     && [ "$LSHARD" = "$WSHARD" ]; then
    echo "    $ADDR -> shard $LSHARD (light) == $WSHARD (where-is)"
  else
    echo "    MISMATCH $ADDR: light='$LOUT' (rc=$LRC) where-is='$WOUT' (rc=$WRC)"
    ALL_MATCH=false
  fi
done
assert "$ALL_MATCH" "shard-route == where-is for every probe address (count=4)"

echo
echo "=== 2. --json shape: shard / shard_count / genesis_hash + determinism ==="
J1=$($DETERM_LIGHT shard-route --genesis "$TMP/gen4.json" --address alice --json 2>&1)
J2=$($DETERM_LIGHT shard-route --genesis "$TMP/gen4.json" --address alice --json 2>&1)
SC=$(jget "$J1" shard_count)
GH=$(jget "$J1" genesis_hash)
GH2=$(jget "$J2" genesis_hash)
if [ "$SC" = "4" ] && [ -n "$GH" ] && [ "$GH" = "$GH2" ]; then
  assert "true" "--json shard_count=4, genesis_hash present + deterministic"
else
  echo "$J1"; assert "false" "--json shape (shard_count=$SC genesis_hash=$GH/$GH2)"
fi

echo
echo "=== 3. Unsharded (count=1): every address routes to shard 0 ==="
ALL_ZERO=true
for ADDR in alice bob "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"; do
  J=$($DETERM_LIGHT shard-route --genesis "$TMP/gen1.json" --address "$ADDR" --json 2>&1)
  S=$(jget "$J" shard)
  [ "$S" = "0" ] || { ALL_ZERO=false; echo "    $ADDR -> $S (expected 0)"; }
done
assert "$ALL_ZERO" "unsharded chain routes every address to shard 0"

echo
echo "=== 4. Anon-address case normalization (S-028) ==="
HEX64="abcDEFabcdefABCDEFabcdefabcdefabcdefabcdefabcdefabcdefabcdefABCD"
UPPER="0x$(echo "$HEX64" | tr 'a-f' 'A-F')"
LOWER="0x$(echo "$HEX64" | tr 'A-F' 'a-f')"
JU=$($DETERM_LIGHT shard-route --genesis "$TMP/gen4.json" --address "$UPPER" --json 2>&1)
JL=$($DETERM_LIGHT shard-route --genesis "$TMP/gen4.json" --address "$LOWER" --json 2>&1)
SU=$(jget "$JU" shard); SL=$(jget "$JL" shard)
ANON=$(jget "$JU" anon)
if [ -n "$SU" ] && [ "$SU" = "$SL" ] && [ "$ANON" = "True" -o "$ANON" = "true" ]; then
  assert "true" "anon 0xABC… and 0xabc… route to same shard ($SU), anon=true"
else
  echo "$JU"; echo "$JL"
  assert "false" "anon case normalization (SU=$SU SL=$SL anon=$ANON)"
fi

echo
echo "=== 5. Different salt → different genesis_hash (distinct chain id) ==="
JA=$($DETERM_LIGHT shard-route --genesis "$TMP/gen4.json"  --address alice --json 2>&1)
JB=$($DETERM_LIGHT shard-route --genesis "$TMP/gen4b.json" --address alice --json 2>&1)
GHA=$(jget "$JA" genesis_hash); GHB=$(jget "$JB" genesis_hash)
if [ -n "$GHA" ] && [ -n "$GHB" ] && [ "$GHA" != "$GHB" ]; then
  assert "true" "salt A vs salt B yield distinct genesis_hash"
else
  echo "  GHA=$GHA GHB=$GHB"
  assert "false" "distinct genesis_hash for distinct salt"
fi

echo
echo "=== 6. Missing --address → usage error exit 1 ==="
set +e
$DETERM_LIGHT shard-route --genesis "$TMP/gen4.json" >/dev/null 2>&1
RC=$?
set -e
[ "$RC" = "1" ] && assert "true" "missing --address → exit 1" \
                || assert "false" "missing --address → exit 1 (got $RC)"

echo
echo "=== 7. Malformed genesis (bad salt length, S-018) → exit 1 ==="
write_genesis "$TMP/genbad.json" shard-route-test 4 "deadbeef"
set +e
OUT=$($DETERM_LIGHT shard-route --genesis "$TMP/genbad.json" --address alice 2>&1)
RC=$?
set -e
[ "$RC" = "1" ] && assert "true" "bad shard_address_salt → exit 1" \
                || { echo "$OUT"; assert "false" "bad salt → exit 1 (got $RC)"; }

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_shard_route"; exit 0
else
  echo "  FAIL: test_light_shard_route"; exit 1
fi
