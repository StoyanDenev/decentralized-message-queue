#!/usr/bin/env bash
# determ-wallet tx_hash / signing_bytes CROSS-COMMAND CONSISTENCY fuzz.
#
# Hardens `derive-tx-hash` and the shared canonical signing_bytes encoder
# (src/chain/block.cpp Transaction::signing_bytes) that FOUR offline wallet
# commands independently re-implement: sign-anon-tx (producer), derive-tx-hash,
# validate-tx, and tx-sign-verify. If any one drifts from the others, a tx that
# one command blesses would be rejected (or worse, silently mis-hashed) by the
# next link in an audit/submission pipeline.
#
# SAFE REFERENCE = CROSS-COMMAND AGREEMENT (no re-implemented hash). For each of
# >= 20 fixed-seed-random transactions we assert all of these AGREE on the SAME
# 32-byte tx_hash, with NO hand-rolled SHA-256 / signing-bytes encoder anywhere
# in this test:
#
#   (P) sign-anon-tx          emits `tx_hash_hex` on stdout AND a `hash` field
#                             in the envelope; the two must be identical.
#   (D) derive-tx-hash        recomputes the hash; --check must agree (exit 0,
#                             match=true) and recomputed_hash == the envelope's
#                             stored hash.
#   (V) validate-tx           must ACCEPT (overall_valid, exit 0) and report the
#                             same tx_hash_recomputed == tx_hash_stored.
#   (S) tx-sign-verify        (after the documented field-name shim
#                             signature->sig, "TRANSFER"->0) must ACCEPT the
#                             Ed25519 sig (exit 0) and report tx_hash_hex ==
#                             computed_signing_bytes_sha256 == the same hash.
#
# Correctness is judged ONLY by these four independent commands converging on
# one value — a re-implementation of the hash here could itself be wrong and
# give false confidence, so we deliberately avoid one.
#
# TAMPER half (tamper-detection reference): for each random tx, XOR-flip the
# first byte of one consensus-bound field at a time and assert the round-trip
# breaks — derive-tx-hash --check exits 2 (recomputed != stored) and validate-tx
# rejects (non-zero). XOR-flip ('%02x'%(int(b,16)^0xff)) guarantees every
# mutation is a REAL change even when the original byte is already 0xff.
#
# Edge shapes covered: amount==1 (minimum legal), fee==0, nonce==0, large
# amount/fee/nonce, self-transfer (from==to), and several distinct sender/
# recipient account pairs — driven by a FIXED RNG seed so failures reproduce.
#
# FULLY OFFLINE (no cluster, no daemon — every command under test is offline).
# Run from repo root: bash tools/test_wallet_tx_hash_cross_command_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
W="$DETERM_WALLET"

PY=python
command -v python >/dev/null 2>&1 || PY=python3

T=build/test_wallet_tx_hash_cross_command_fuzz.$$
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {  # assert <true|false> <label>
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# ── Deterministic key material: account-derive-batch from a FIXED master seed
#    is reproducible (same seed -> same accounts), so the whole test is a pure
#    fixed-seed RNG. 8 sibling accounts give us a pool to draw from/to pairs. ──
SEED=$($PY -c "print('5a'*32)")   # fixed 32-byte master seed
"$W" account-derive-batch --seed "$SEED" --count 8 --out "$T/keys.json" >/dev/null 2>&1
if [ ! -s "$T/keys.json" ]; then
  echo "  FAIL: account-derive-batch produced no keys (cannot run fuzz)"
  echo "  FAIL: test_wallet_tx_hash_cross_command_fuzz"; exit 1
fi

# Emit each account's keyfile (canonical {address,privkey_hex} shape) + a flat
# list of addresses. Done once in Python; the shell only consumes files.
$PY - "$T/keys.json" "$T" <<'PY'
import json, sys, os
keys_path, tdir = sys.argv[1], sys.argv[2]
d = json.load(open(keys_path))
accs = d['accounts']
addrs = []
for i, a in enumerate(accs):
    json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']},
              open(os.path.join(tdir, 'k%d.json' % i), 'w'))
    addrs.append(a['address'])
# Binary write -> LF-only (text mode would emit CRLF on Windows, and the
# trailing \r would corrupt every address read back via `mapfile -t`).
open(os.path.join(tdir, 'addrs.txt'), 'wb').write(('\n'.join(addrs) + '\n').encode())
PY

mapfile -t ADDRS < "$T/addrs.txt"
NACC=${#ADDRS[@]}

# ── Fixed-seed random case table. Emitted by Python (seeded) so the same 24
#    cases run every time. Each line: idx from_idx to_idx amount fee nonce.
#    First six rows are pinned EDGE shapes; the rest are seeded-random. ──
NCASES=24
# NOTE: Python `print` emits CRLF on Windows; the trailing \r would poison the
# last `read` field (e.g. nonce "0\r" -> parse reject). Force LF-only output.
$PY - "$NACC" "$NCASES" <<'PY' | tr -d '\r' > "$T/cases.txt"
import random, sys
nacc  = int(sys.argv[1])
ncase = int(sys.argv[2])
rng = random.Random(0xDE7E12)  # fixed seed -> reproducible cases
rows = []
# Pinned edge shapes (exercise boundary values explicitly):
rows.append((0, 1, 1, 0, 0))                       # min amount, zero fee, zero nonce
rows.append((1, 2, 1, 1, 0))                       # amount==1, fee==1
rows.append((2, 3, 999999999999, 0, 0))            # large amount, zero fee
rows.append((3, 4, 1, 4294967295, 7))              # large fee
rows.append((4, 5, 5000, 2, 9223372036854775807)) # INT64_MAX nonce (parser ceiling)
rows.append((5, 5, 777, 3, 9))                      # self-transfer (from==to)
while len(rows) < ncase:
    fi = rng.randrange(nacc)
    ti = rng.randrange(nacc)
    amt = rng.randint(1, 10**12)        # amount must be > 0
    fee = rng.randint(0, 10**9)
    non = rng.randint(0, 10**12)
    rows.append((fi, ti, amt, fee, non))
for i, (fi, ti, amt, fee, non) in enumerate(rows):
    print(i, fi % nacc, ti % nacc, amt, fee, non)
PY

# Helpers that pull a single JSON scalar via the interpreter (no jq dependency).
jget() {  # jget <file> <key>
  $PY -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2" 2>/dev/null
}
jget_stdin() {  # echo <json> | jget_stdin <key>
  $PY -c "import json,sys; print(json.load(sys.stdin)[sys.argv[1]])" "$1" 2>/dev/null
}

echo "=== cross-command tx_hash agreement over $NCASES fixed-seed-random txs ==="
agree_ok=0
while read -r idx fi ti amt fee non; do
  KF="$T/k${fi}.json"
  TO="${ADDRS[$ti]}"
  PUB_FROM="${ADDRS[$fi]#0x}"     # anon-addr sender pubkey == address minus 0x
  TX="$T/tx_${idx}.json"

  # (P) Producer: sign-anon-tx. Capture stdout (status JSON) + the envelope.
  POUT=$("$W" sign-anon-tx --keyfile "$KF" --to "$TO" --amount "$amt" \
              --fee "$fee" --nonce "$non" --out "$TX" 2>/dev/null | tr -d '\r' | tail -n 1)
  if [ ! -s "$TX" ]; then
    assert false "case $idx: sign-anon-tx produced an envelope"
    continue
  fi
  P_STDOUT_HASH=$(echo "$POUT" | jget_stdin tx_hash_hex)
  ENV_HASH=$(jget "$TX" hash)

  # (D) derive-tx-hash --check --json: recompute + compare to stored hash.
  DJSON=$("$W" derive-tx-hash --tx-json "$TX" --check --json 2>/dev/null | tr -d '\r')
  DRC=$?
  D_RECO=$(echo "$DJSON" | jget_stdin recomputed_hash)
  D_MATCH=$(echo "$DJSON" | jget_stdin match)

  # (V) validate-tx --json: full gate must accept + agree on the hash.
  "$W" validate-tx --tx-json "$TX" --json >"$T/v_${idx}.json" 2>/dev/null
  VRC=$?
  VJSON=$(tr -d '\r' < "$T/v_${idx}.json")
  V_OVERALL=$(echo "$VJSON" | jget_stdin overall_valid)
  V_RECO=$(echo "$VJSON" | jget_stdin tx_hash_recomputed)
  V_STORED=$(echo "$VJSON" | jget_stdin tx_hash_stored)

  # (S) tx-sign-verify (shimmed): signature accept + hash agreement.
  $PY -c "
import json,sys
d=json.load(open(sys.argv[1])); d=dict(d)
d['type']=0; d['sig']=d['signature']
json.dump(d, open(sys.argv[2],'w'))
" "$TX" "$T/txv_${idx}.json"
  SJSON=$("$W" tx-sign-verify --tx "$T/txv_${idx}.json" --pubkey "$PUB_FROM" --json 2>/dev/null | tr -d '\r')
  SRC=$?
  S_VALID=$(echo "$SJSON" | jget_stdin valid)
  S_HASH=$(echo "$SJSON" | jget_stdin tx_hash_hex)
  S_SB=$(echo "$SJSON" | jget_stdin computed_signing_bytes_sha256)

  # One verdict per case: every command accepts AND every reported hash equals
  # the producer's emitted tx_hash_hex. Single string-equality fan-out — the
  # safe cross-command reference, no re-implemented algorithm.
  ok=true
  [ ${#P_STDOUT_HASH} -eq 64 ]            || ok=false   # producer emitted a 32-byte hash
  [ "$ENV_HASH"   = "$P_STDOUT_HASH" ]    || ok=false   # P: stdout hash == envelope hash
  [ "$DRC" -eq 0 ] 2>/dev/null            || ok=false   # D: --check agrees (exit 0)
  [ "$D_MATCH" = "True" ]                 || ok=false   # D: match flag true
  [ "$D_RECO"  = "$P_STDOUT_HASH" ]       || ok=false   # D: recomputed == producer
  [ "$VRC" -eq 0 ] 2>/dev/null            || ok=false   # V: validate-tx exit 0
  [ "$V_OVERALL" = "True" ]               || ok=false   # V: overall_valid
  [ "$V_RECO"   = "$P_STDOUT_HASH" ]      || ok=false   # V: recomputed == producer
  [ "$V_STORED" = "$P_STDOUT_HASH" ]      || ok=false   # V: stored == producer
  [ "$SRC" -eq 0 ] 2>/dev/null            || ok=false   # S: tx-sign-verify exit 0
  [ "$S_VALID" = "True" ]                 || ok=false   # S: sig valid
  [ "$S_HASH"  = "$P_STDOUT_HASH" ]       || ok=false   # S: tx_hash == producer
  [ "$S_SB"    = "$P_STDOUT_HASH" ]       || ok=false   # S: signing_bytes sha256 == producer

  if [ "$ok" = "true" ]; then
    agree_ok=$((agree_ok + 1))
  else
    echo "    DEBUG case $idx (from=$fi to=$ti amt=$amt fee=$fee nonce=$non):"
    echo "      P_stdout=$P_STDOUT_HASH env=$ENV_HASH"
    echo "      D rc=$DRC match=$D_MATCH reco=$D_RECO"
    echo "      V rc=$VRC overall=$V_OVERALL reco=$V_RECO stored=$V_STORED"
    echo "      S rc=$SRC valid=$S_VALID hash=$S_HASH sb=$S_SB"
  fi
done < "$T/cases.txt"
assert "$([ "$agree_ok" -eq "$NCASES" ] && echo true || echo false)" \
       "all $NCASES txs: P/D/V/S agree on tx_hash + all accept ($agree_ok/$NCASES)"

echo
echo "=== tamper-detection: each single-field XOR-flip breaks the round-trip ==="
# Re-use the produced envelopes. For each tx, flip one byte of one field and
# require BOTH derive-tx-hash --check (exit 2) AND validate-tx (non-zero) to
# reject. Fields chosen are exactly the consensus-bound ones the hash covers.
tamper_one() {  # tamper_one <src> <dst> <field> <mode>  -> 0 changed, 1 absent
  $PY - "$1" "$2" "$3" "$4" <<'PY'
import json, sys
src, dst, field, mode = sys.argv[1:5]
d = json.load(open(src))
key = 'signature' if field == 'SIG' else field
if key not in d:
    sys.exit(1)
v = d[key]
if mode == 'incr':              # numeric +1 (handles int or numeric string)
    d[key] = (int(v) + 1) if isinstance(v, int) else str(int(v) + 1)
elif mode == 'xorhex':          # XOR-flip first hex byte -> always a real change
    d[key] = ('%02x' % (int(v[:2], 16) ^ 0xff)) + v[2:]
elif mode == 'xoraddr':         # like xorhex but preserve a leading 0x prefix
    pre = v[:2] if v[:2] == '0x' else ''
    body = v[len(pre):]
    d[key] = pre + ('%02x' % (int(body[:2], 16) ^ 0xff)) + body[2:]
else:
    sys.exit(2)
json.dump(d, open(dst, 'w'))
sys.exit(0)
PY
}

# Sample a subset of the produced txs for the (heavier) tamper sweep.
TAMPER_IDXS="0 1 2 3 5 7 11 13 17 23"
tamper_ok=0; tamper_total=0
for idx in $TAMPER_IDXS; do
  SRC="$T/tx_${idx}.json"
  [ -s "$SRC" ] || continue
  for spec in "amount incr" "fee incr" "nonce incr" "to xoraddr" "from xoraddr" "SIG xorhex" "hash xorhex"; do
    set -- $spec; field=$1; mode=$2
    M="$T/m_${idx}_${field}.json"
    if tamper_one "$SRC" "$M" "$field" "$mode"; then
      tamper_total=$((tamper_total + 1))
      # derive-tx-hash --check must exit 2 (recomputed != stored).  EXCEPT a
      # signature-only flip leaves body+hash intact, so derive-tx-hash --check
      # (body-vs-stored-hash) still matches — that flip is caught by validate-tx
      # (signature verify), which is the gate responsible for it. Route each
      # field to the gate that owns it; require that gate to REJECT.
      if [ "$field" = "SIG" ]; then
        "$W" validate-tx --tx-json "$M" >/dev/null 2>&1
        [ $? -ne 0 ] && tamper_ok=$((tamper_ok + 1))
      else
        "$W" derive-tx-hash --tx-json "$M" --check >/dev/null 2>&1
        dchk=$?
        "$W" validate-tx --tx-json "$M" >/dev/null 2>&1
        vchk=$?
        # both the focused hash-check AND the composite validator must reject
        [ "$dchk" -eq 2 ] && [ "$vchk" -ne 0 ] && tamper_ok=$((tamper_ok + 1))
      fi
    fi
  done
done
assert "$([ "$tamper_ok" -eq "$tamper_total" ] && [ "$tamper_total" -gt 0 ] && echo true || echo false)" \
       "all $tamper_total single-field tampers rejected by owning gate ($tamper_ok/$tamper_total)"

echo
echo "=== control: the untouched producer envelopes still validate ==="
ctrl_ok=0; ctrl_total=0
for idx in $TAMPER_IDXS; do
  SRC="$T/tx_${idx}.json"
  [ -s "$SRC" ] || continue
  ctrl_total=$((ctrl_total + 1))
  "$W" validate-tx --tx-json "$SRC" >/dev/null 2>&1 && \
    "$W" derive-tx-hash --tx-json "$SRC" --check >/dev/null 2>&1 && \
    ctrl_ok=$((ctrl_ok + 1))
done
assert "$([ "$ctrl_ok" -eq "$ctrl_total" ] && [ "$ctrl_total" -gt 0 ] && echo true || echo false)" \
       "all $ctrl_total untouched envelopes pass validate-tx + derive-tx-hash --check ($ctrl_ok/$ctrl_total)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail  (cases=$NCASES, tampers=$tamper_total)"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_tx_hash_cross_command_fuzz"; exit 0
else
  echo "  FAIL: test_wallet_tx_hash_cross_command_fuzz"; exit 1
fi
