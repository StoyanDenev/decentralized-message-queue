#!/usr/bin/env bash
# determ-wallet validate-tx fuzz — broad tamper-detection over MANY random
# validly-signed TRANSFER envelopes, EXTENDING test_wallet_tx_tamper_fuzz.sh.
#
# validate-tx is the offline tx-envelope gate: it recomputes the canonical
# signing_bytes (src/chain/block.cpp Transaction::signing_bytes), verifies the
# Ed25519 signature against the pubkey DERIVED from the `from` anon-address, and
# checks tx_hash == SHA-256(signing_bytes). Soundness rests on one property: NO
# consensus-bound field can be altered without invalidating the signature or the
# hash. The prior tamper test asserts that on a SINGLE hand-built TRANSFER. This
# fuzz harness asserts it across a FIXED-SEED corpus of random TRANSFERs spanning
# edge shapes (amount==1, fee==0, large 64-bit values, nonce==0/large, swapped
# routing), and EXTENDS coverage beyond the prior test in four ways:
#
#   (1) >= 20 random TRANSFERs (not 1), each from a distinct keypair, so the
#       sender pubkey derivation + signing_bytes layout is exercised broadly.
#   (2) The `payload` field (bound into signing_bytes as raw bytes) is added to
#       the single-field mutation matrix — the prior test never tampered it.
#   (3) MULTI-FIELD combo mutations: tamper two consensus fields at once; the
#       gate must STILL reject (rejection isn't a fragile single-field artifact).
#   (4) CROSS-TX signature graft: lift a VALID signature from tx[i] onto tx[j]
#       (i != j) — the sig is valid for i's body, not j's, so the gate must
#       reject. This catches a "verify sig in isolation, ignore which body it
#       signs" class of bug a single-tx test cannot.
#
# SAFE REFERENCE = tamper-detection. No hash/sig/merkle algorithm is
# reimplemented as an oracle; correctness is judged purely by "untouched signed
# tx VALIDATES (exit 0)" and "any consensus-field mutation is REJECTED (exit
# non-zero)". Hex fields are mutated by XOR-flipping the first byte
# ('%02x'%(int(s[:2],16)^0xff)+s[2:]) so the change is ALWAYS real (an 'ff'+rest
# overwrite is a no-op when the byte is already ff). All signing is done by the
# binary under test via sign-anon-tx; this harness only mutates + re-validates.
#
# Fully OFFLINE (no cluster, no daemon — validate-tx without --rpc-port never
# opens a socket). Run from repo root: bash tools/test_wallet_validate_tx_fuzz.sh
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

T=test_wallet_validate_tx_fuzz
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

ITERS="${FUZZ_ITERS:-24}"   # >= 20 random signed TRANSFERs

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# validate <txfile>: 0 if validate-tx accepts (exit 0), 1 otherwise.
validate() {
  "$W" validate-tx --tx-json "$1" >/dev/null 2>&1
}

# ── Provision keys + a fixed-seed plan of random TRANSFER parameters ──────────
# We need 2 fresh keypairs per iter (signer A_i + destination B_i), plus the
# parameter draws. account-create-batch gives 2*ITERS keypairs in one call; the
# Python planner (fixed seed) assigns pairs + draws amount/fee/nonce/to-variant
# spanning the documented edge shapes. The seed makes the whole run reproducible.
NKEYS=$((ITERS * 2))
"$W" account-create-batch --count "$NKEYS" --out "$T/keys.json" >/dev/null 2>&1
if [ ! -s "$T/keys.json" ]; then
  echo "  FAIL: account-create-batch did not produce $NKEYS keys"
  echo "  FAIL: test_wallet_validate_tx_fuzz"; exit 1
fi

$PY - "$T" "$ITERS" <<'PY'
import json, random, sys
T, iters = sys.argv[1], int(sys.argv[2])
random.seed(0x7A11D8E)  # fixed -> reproducible ("TAMPER" leet, why not)
accts = json.load(open(f"{T}/keys.json"))["accounts"]
plan = []
for it in range(iters):
    a = accts[2 * it]      # signer
    b = accts[2 * it + 1]  # destination
    # Edge-shape coverage across the corpus:
    #   it 0     -> amount=1, fee=0, nonce=0        (minimal everything)
    #   it 1     -> fee=0                           (zero fee, nonzero amount)
    #   it 2     -> huge amount near 2^63           (8-byte big-endian high bits)
    #   it 3     -> huge nonce                      (nonce field stress)
    #   self-send (to == from) on one iter          (routing edge)
    #   otherwise random within sane ranges
    if it == 0:
        amount, fee, nonce = 1, 0, 0
    elif it == 1:
        amount, fee, nonce = random.randint(1, 10**6), 0, random.randint(0, 50)
    elif it == 2:
        amount, fee, nonce = (1 << 62) + random.randint(0, 10**9), random.randint(0, 1000), 7
    elif it == 3:
        amount, fee, nonce = random.randint(1, 10**6), 1, (1 << 40) + random.randint(0, 10**6)
    else:
        amount = random.randint(1, 10**9)
        fee    = random.choice([0, 1, random.randint(1, 10**5)])
        nonce  = random.randint(0, 10**6)
    to_addr = a["address"] if it == 4 else b["address"]   # one self-send edge
    plan.append({
        "it": it,
        "signer_addr": a["address"], "signer_priv": a["privkey_hex"],
        "dest_addr":   b["address"],
        "to": to_addr, "amount": amount, "fee": fee, "nonce": nonce,
    })
    json.dump({"address": a["address"], "privkey_hex": a["privkey_hex"]},
              open(f"{T}/k{it}.json", "w"))
json.dump(plan, open(f"{T}/plan.json", "w"))
print("planned", iters, "random TRANSFERs (edge shapes on it 0..4)")
PY

# ── Sign every planned TRANSFER with the binary under test ───────────────────
echo "=== signing $ITERS random TRANSFERs via sign-anon-tx ==="
i=0
while [ "$i" -lt "$ITERS" ]; do
  to=$($PY -c "import json;print(json.load(open('$T/plan.json'))[$i]['to'])")
  am=$($PY -c "import json;print(json.load(open('$T/plan.json'))[$i]['amount'])")
  fe=$($PY -c "import json;print(json.load(open('$T/plan.json'))[$i]['fee'])")
  no=$($PY -c "import json;print(json.load(open('$T/plan.json'))[$i]['nonce'])")
  "$W" sign-anon-tx --keyfile "$T/k$i.json" --to "$to" --amount "$am" \
       --fee "$fe" --nonce "$no" --out "$T/tx$i.json" >/dev/null 2>&1
  if [ ! -s "$T/tx$i.json" ]; then
    echo "  FAIL: sign-anon-tx produced no tx for iter $i (to=$to am=$am fe=$fe no=$no)"
    echo "  FAIL: test_wallet_validate_tx_fuzz"; exit 1
  fi
  i=$((i + 1))
done

echo "=== signed tx field set (iter 0) ==="
$PY -c "import json;print(sorted(json.load(open('$T/tx0.json')).keys()))"

# ── mutate <src> <dst> <spec...>: apply one or more field mutations ──────────
# Each spec is "FIELD:MODE[:ARG]". Modes:
#   incr    numeric +1 (int or numeric string)
#   set     replace with ARG verbatim
#   xorhex  XOR-flip first hex byte of a hex string field (always a real change)
#   type    flip TRANSFER<->STAKE / 0<->3 (a different valid enum)
#   graftsig copy the 'signature'/'sig' value from the file at ARG (cross-tx)
# SIG resolves to whichever of signature/sig is present. Exit 0 if every spec'd
# field existed + changed; exit 1 if any spec'd field was absent (skip).
mutate() {
  local src="$1" dst="$2"; shift 2
  $PY - "$src" "$dst" "$@" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
specs = sys.argv[3:]
d = json.load(open(src))
def sigkey(o):
    return 'signature' if 'signature' in o else ('sig' if 'sig' in o else None)
for spec in specs:
    parts = spec.split(':', 2)
    field, mode = parts[0], parts[1]
    arg = parts[2] if len(parts) > 2 else ''
    key = sigkey(d) if field == 'SIG' else field
    if key is None or key not in d:
        sys.exit(1)  # field absent -> caller skips this spec set
    v = d[key]
    if mode == 'incr':
        d[key] = (int(v) + 1) if isinstance(v, int) else str(int(v) + 1)
    elif mode == 'set':
        d[key] = arg
    elif mode == 'xorhex':
        d[key] = ('%02x' % (int(v[:2], 16) ^ 0xff)) + v[2:]
    elif mode == 'xoraddr':
        # XOR-flip the first hex byte of an anon address's 0x-prefixed tail,
        # leaving the "0x" intact. Always a real change -> a different (still
        # well-shaped) address the signer never signed `to`. Guards against the
        # self-send no-op a plain "set to a fixed address" would hit.
        pre, tail = v[:2], v[2:]            # "0x", "<64 hex>"
        d[key] = pre + ('%02x' % (int(tail[:2], 16) ^ 0xff)) + tail[2:]
    elif mode == 'type':
        d[key] = ('STAKE' if v == 'TRANSFER' else (3 if v == 0 else 'TRANSFER'))
    elif mode == 'graftsig':
        other = json.load(open(arg))
        ok = sigkey(other)
        if ok is None:
            sys.exit(1)
        d[key] = other[ok]
    else:
        sys.exit(2)
json.dump(d, open(dst, 'w'))
sys.exit(0)
PY
}

# reject <iter> <label> <spec...>: assert the mutated tx is REJECTED.
reject() {
  local it="$1" label="$2"; shift 2
  if mutate "$T/tx$it.json" "$T/m.json" "$@"; then
    if validate "$T/m.json"; then
      assert false "iter $it tamper($label) -> validate-tx WRONGLY ACCEPTED"
    else
      pass_count=$((pass_count + 1))
    fi
  fi   # field absent -> silently skip (shape difference, not a failure)
}

# ── (1) Control: every untouched signed tx VALIDATES ─────────────────────────
echo
echo "=== control: all $ITERS untouched signed txs VALIDATE (exit 0) ==="
CTRL_OK=true
i=0
while [ "$i" -lt "$ITERS" ]; do
  validate "$T/tx$i.json" || { CTRL_OK=false; echo "    iter $i: untouched tx REJECTED (should pass)"; }
  i=$((i + 1))
done
assert "$CTRL_OK" "control: all $ITERS untouched signed TRANSFERs VALIDATE"

# ── (2) Single-field tamper matrix over the whole corpus ─────────────────────
# Every consensus-bound field, on every random tx. `payload` is new vs the prior
# test (it is empty for TRANSFER, so XOR-flip can't apply — use set to a nonzero
# hex byte, which changes signing_bytes length + content => hash + sig break).
echo "=== single-field tamper: every consensus field on all $ITERS txs is REJECTED ==="
i=0
while [ "$i" -lt "$ITERS" ]; do
  reject "$i" amount        "amount:incr"
  reject "$i" fee           "fee:incr"
  reject "$i" nonce         "nonce:incr"
  reject "$i" to-swap       "to:xoraddr"           # redirect funds elsewhere
  reject "$i" from-imperson "from:xoraddr"         # impersonate a different sender
  reject "$i" type          "type:type"
  reject "$i" payload-add   "payload:set:ab"       # inject a body byte (was empty)
  reject "$i" sig-flip      "SIG:xorhex"
  reject "$i" hash-flip     "hash:xorhex"
  i=$((i + 1))
done

# ── (3) Multi-field combos: two consensus fields at once still REJECT ────────
echo "=== multi-field combos: 2 consensus fields at once on all $ITERS txs REJECT ==="
i=0
while [ "$i" -lt "$ITERS" ]; do
  reject "$i" amount+fee    "amount:incr"  "fee:incr"
  reject "$i" nonce+sig     "nonce:incr"   "SIG:xorhex"
  reject "$i" type+hash     "type:type"    "hash:xorhex"
  i=$((i + 1))
done

# ── (4) Cross-tx signature graft: tx[j] body + tx[i] signature must REJECT ────
# Pair iter j with iter (j+1)%ITERS. Skip the rare degenerate case where the two
# txs happen to share identical signing_bytes (different keypairs + params make
# that effectively impossible here, but guard anyway by skipping self-pairs).
echo "=== cross-tx signature graft: foreign sig on a different body REJECTS ==="
i=0
while [ "$i" -lt "$ITERS" ]; do
  j=$(( (i + 1) % ITERS ))
  if [ "$i" -ne "$j" ]; then
    reject "$i" graftsig-from-$j "SIG:graftsig:$T/tx$j.json"
  fi
  i=$((i + 1))
done

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail  (over $ITERS random signed TRANSFERs)"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_validate_tx_fuzz"; exit 0
else
  echo "  FAIL: test_wallet_validate_tx_fuzz"; exit 1
fi
