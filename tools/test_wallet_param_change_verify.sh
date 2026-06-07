#!/usr/bin/env bash
# determ-wallet param-change-verify — OFFLINE read-only K-of-K governance multisig
# verifier on an assembled PARAM_CHANGE. Counterpart to param-change-build (body
# + per-keyholder signing preimage) and param-change-lint (effectiveness).
#
# SAFE REFERENCE = cross-implementation round-trip + tamper-detection: an
# INDEPENDENT Ed25519 implementation (Python pynacl, RFC 8032) plays the
# keyholders — it signs the canonical sig_msg (name_len|name|value_len|value|
# effective_height, exactly as src/node/validator.cpp:693-701 builds it),
# assembles the payload, and param-change-verify (wallet libsodium) must AGREE:
# PASS when >= threshold valid distinct sigs, FAIL otherwise. No hash/sig
# algorithm is reimplemented as the oracle on the wallet side — the wallet is
# checked against a different standard Ed25519. The sig_msg layout is decoded
# from the authoritative param-change-build payload, not hand-assembled.
#
# FULLY OFFLINE (no cluster). Run from repo root: bash tools/test_wallet_param_change_verify.sh
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
if ! $PY -c "import nacl.signing" >/dev/null 2>&1; then
    echo "  SKIP: python pynacl not available (the independent Ed25519 reference)"; exit 0
fi

T=test_wallet_param_change_verify
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# Build the assembler/reference in Python: given a param-change-build payload
# (sig_count=0), K keyholders, a chosen signer-set + an optional tamper, emit a
# tx-json (assembled payload) + keyholders file.
cat > "$T/assemble.py" <<'PY'
import json, struct, sys, os
import nacl.signing
T, base_payload_hex, k, signer_csv, tamper, seed = sys.argv[1:7]
k = int(k); seed = int(seed)
import random; random.seed(seed)
p = bytes.fromhex(base_payload_hex)
off = 0
nlen = p[off]; off += 1
name = p[off:off+nlen]; off += nlen
vlen = p[off] | (p[off+1] << 8); off += 2
value = p[off:off+vlen]; off += vlen
eff = p[off:off+8]; off += 8
# sig_msg EXACTLY as validator.cpp builds it
sig_msg = bytes([nlen]) + name + bytes([vlen & 0xff, (vlen >> 8) & 0xff]) + value + eff
prefix = bytes([nlen]) + name + bytes([vlen & 0xff, (vlen >> 8) & 0xff]) + value + eff
# K keyholder keypairs (deterministic from seed)
sks = [nacl.signing.SigningKey(bytes(random.getrandbits(8) for _ in range(32))) for _ in range(k)]
pks = [sk.verify_key.encode().hex() for sk in sks]
json.dump(pks, open(f"{T}/kh.json", "w"))
# signer set: comma-separated keyholder indices that actually sign
signers = [int(x) for x in signer_csv.split(",") if x != ""]
entries = []  # (idx, 64-byte sig)
for idx in signers:
    sig = sks[idx].sign(sig_msg).signature
    entries.append((idx, sig))
# optional tamper modes
if tamper == "flipsig" and entries:
    idx, sig = entries[0]; entries[0] = (idx, bytes([sig[0] ^ 0xff]) + sig[1:])
elif tamper == "dup" and entries:
    entries.append(entries[0])           # duplicate the first (idx,sig)
elif tamper == "oor":
    sig = sks[0].sign(sig_msg).signature; entries.append((k + 5, sig))  # index out of range
payload = prefix + bytes([len(entries)]) + b"".join(struct.pack("<H", i) + s for i, s in entries)
json.dump({"payload": payload.hex(), "name": name.decode(errors="replace")},
          open(f"{T}/tx.json", "w"))
print(len(pks))
PY

build_payload() {  # $1=name $2=value-flag-args -> echoes the built payload hex
  "$W" param-change-build $2 --name "$1" --effective-height 100 --nonce 0 --from node1 --out "$T/pcb.json" >/dev/null 2>&1
  $PY -c "import json;print(json.load(open('$T/pcb.json'))['payload'])"
}

echo "=== 1. arg handling ==="
"$W" param-change-verify --help >/dev/null 2>&1;             assert "$([ $? -eq 0 ] && echo true || echo false)" "--help exit 0"
"$W" param-change-verify --tx-json x >/dev/null 2>&1;        assert "$([ $? -eq 1 ] && echo true || echo false)" "missing --keyholders exit 1"

echo; echo "=== 2. happy path: K valid distinct sigs, threshold=K -> PASS exit 0 ==="
BP=$(build_payload MIN_STAKE "--value 1000")
$PY "$T/assemble.py" "$T" "$BP" 3 "0,1,2" none 1 >/dev/null
set +e; "$W" param-change-verify --tx-json "$T/tx.json" --keyholders "$T/kh.json" --threshold 3 >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 0 ] && echo true || echo false)" "3 valid sigs, threshold 3 -> PASS exit 0"

echo; echo "=== 3. K-1 valid, threshold=K -> FAIL exit 2; threshold=K-1 -> PASS ==="
$PY "$T/assemble.py" "$T" "$BP" 3 "0,1" none 2 >/dev/null
set +e; "$W" param-change-verify --tx-json "$T/tx.json" --keyholders "$T/kh.json" --threshold 3 >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 2 ] && echo true || echo false)" "2 valid sigs, threshold 3 -> FAIL exit 2"
set +e; "$W" param-change-verify --tx-json "$T/tx.json" --keyholders "$T/kh.json" --threshold 2 >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 0 ] && echo true || echo false)" "2 valid sigs, threshold 2 -> PASS exit 0"

echo; echo "=== 4. tampered signature -> that keyholder INVALID -> FAIL exit 2 ==="
$PY "$T/assemble.py" "$T" "$BP" 3 "0,1,2" flipsig 3 >/dev/null
set +e; OUT=$("$W" param-change-verify --tx-json "$T/tx.json" --keyholders "$T/kh.json" --threshold 3 --json 2>/dev/null); RC=$?; set -e
BAD=$(echo "$OUT" | $PY -c "import json,sys;d=json.load(sys.stdin);print(sum(1 for s in d['sigs'] if not s['valid']))")
assert "$([ $RC -eq 2 ] && [ "$BAD" -ge 1 ] && echo true || echo false)" "flipped sig -> >=1 INVALID, FAIL exit 2"

echo; echo "=== 5. duplicate keyholder index -> FAIL exit 2 ==="
$PY "$T/assemble.py" "$T" "$BP" 3 "0,1,2" dup 4 >/dev/null
set +e; "$W" param-change-verify --tx-json "$T/tx.json" --keyholders "$T/kh.json" --threshold 3 >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 2 ] && echo true || echo false)" "duplicate index -> FAIL exit 2"

echo; echo "=== 6. out-of-range keyholder index -> FAIL exit 2 ==="
$PY "$T/assemble.py" "$T" "$BP" 3 "0,1,2" oor 5 >/dev/null
set +e; "$W" param-change-verify --tx-json "$T/tx.json" --keyholders "$T/kh.json" --threshold 3 >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 2 ] && echo true || echo false)" "out-of-range index -> FAIL exit 2"

echo; echo "=== 7. wrong keyholders file (different keys) -> all INVALID -> FAIL exit 2 ==="
$PY "$T/assemble.py" "$T" "$BP" 3 "0,1,2" none 6 >/dev/null
cp "$T/tx.json" "$T/tx_ok.json"
$PY "$T/assemble.py" "$T" "$BP" 3 "" none 999 >/dev/null   # regenerate kh.json with unrelated keys
set +e; "$W" param-change-verify --tx-json "$T/tx_ok.json" --keyholders "$T/kh.json" --threshold 3 >/dev/null 2>&1; RC=$?; set -e
assert "$([ $RC -eq 2 ] && echo true || echo false)" "wrong keyholder pubkeys -> all INVALID, FAIL exit 2"

echo; echo "=== 8. FUZZ: 24 random (K, signers, name, value-width, threshold) -> verdict matches good>=threshold ==="
ALL_OK=true
for i in $(seq 1 24); do
  scen=$($PY -c "
import random; random.seed($i*7+1)
names=['MIN_STAKE','SUSPENSION_SLASH','UNSTAKE_DELAY','tx_commit_ms','param_threshold']
k=random.randint(1,5)
signers=sorted(random.sample(range(k), random.randint(0,k)))
thr=random.randint(1,k)
name=random.choice(names)
width=random.choice([8,8,8,4,2])  # mostly 8-byte
val=''.join(random.choice('0123456789abcdef') for _ in range(width*2))
print('%d|%s|%s|%d|%s' % (k, ','.join(map(str,signers)), name, thr, val))")
  K=$(echo "$scen" | cut -d'|' -f1); SIGNERS=$(echo "$scen" | cut -d'|' -f2)
  NAME=$(echo "$scen" | cut -d'|' -f3); THR=$(echo "$scen" | cut -d'|' -f4); VAL=$(echo "$scen" | cut -d'|' -f5)
  BPi=$(build_payload "$NAME" "--value-hex $VAL")
  NUMSIG=$($PY "$T/assemble.py" "$T" "$BPi" "$K" "$SIGNERS" none $((100+i)))
  # expected: PASS iff number of (distinct, all valid) signers >= threshold
  NS=$(echo "$SIGNERS" | tr ',' '\n' | grep -c . || true)
  set +e; "$W" param-change-verify --tx-json "$T/tx.json" --keyholders "$T/kh.json" --threshold "$THR" >/dev/null 2>&1; RC=$?; set -e
  if [ "$NS" -ge "$THR" ]; then want=0; else want=2; fi
  [ "$RC" -eq "$want" ] || { ALL_OK=false; echo "    iter $i: K=$K signers=[$SIGNERS] thr=$THR -> rc=$RC want=$want"; }
done
assert "$ALL_OK" "all 24 random scenarios: PASS iff valid-distinct-sigs >= threshold"

echo; echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then echo "  PASS: test_wallet_param_change_verify"; exit 0
else echo "  FAIL: test_wallet_param_change_verify"; exit 1; fi
