#!/usr/bin/env bash
# determ-wallet verify-batch — fixed-seed XOR-flip tamper FUZZ (offline).
#
# This is the FUZZ companion to test_wallet_verify_batch.sh. Where that
# wrapper exercises the command's surface (help / args / exit codes / a
# handful of hand-picked single tampers), this one stress-tests the core
# tamper-detection guarantee over MANY randomized mutations from a FIXED
# RNG seed — so it is fully deterministic + reproducible while still
# covering record indices, field choices, and byte positions the
# hand-picked test never touches.
#
# SAFE REFERENCE (no reimplemented crypto). The oracle is a round-trip +
# tamper-detection truth table built ENTIRELY from the wallet's own output:
#
#   1. tx-batch-sign produces a real N-record signed batch (the write dual
#      of verify-batch). We assert verify-batch ACCEPTS it unmodified
#      (all N records valid:true) — that is the known-good baseline.
#   2. For each fuzz case we XOR-flip exactly ONE hex nibble of ONE chosen
#      record's `sig` or `hash`, OR perturb ONE body field (amount/fee/
#      nonce) of ONE record, leaving every sibling byte-identical. By
#      construction the mutation is a REAL change (XOR guarantees the
#      nibble differs; numeric perturbation is +1 / flips a digit), so the
#      targeted record MUST verify false and every untouched sibling MUST
#      still verify true. We never recompute a signature or hash ourselves;
#      we only assert the verdict array the command emits.
#
# Truth table per case (the known-by-construction oracle):
#   tampered index            → valid:false   (with a reason)
#   every other index         → valid:true
#   --strict over the batch   → exit 3 (>=1 invalid)
#   report-only over the batch→ exit 0
#
# Tamper kinds covered (round-robin by the seeded RNG):
#   sig    — flip a nibble of the 128-hex Ed25519 signature → Ed25519 fail
#   hash   — flip a nibble of the 64-hex tx_hash            → hash mismatch
#   amount — +1 on the body amount (sig no longer covers it)→ hash mismatch
#   fee    — +1 on the body fee                             → hash mismatch
#   nonce  — +1 on the body nonce                           → hash mismatch
#
# Fully OFFLINE: no daemon, no cluster, no network. Fixed RNG seed; >=20
# randomized cases. Distinct from test_wallet_verify_batch.sh (surface +
# fixed single tampers) and test_wallet_tx_tamper_fuzz.sh (single-tx
# validate-tx, not the batch verdict array).
#
# Run from repo root: bash tools/test_wallet_verify_batch_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

T="build/test_wallet_verify_batch_fuzz.$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT

PY=python
command -v python >/dev/null 2>&1 || PY=python3

pass_count=0
fail_count=0
assert() {
  # assert <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"
    fail_count=$((fail_count + 1))
  fi
}

# ── 1. Build a real N-record signed batch (the known-good baseline) ──────────
N=8
SEED=20260607          # fixed seed → fully reproducible fuzz
CASES=24               # >=20 randomized tamper cases

"$WALLET" account-create-batch --count 2 --out "$T/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][1]['address'])")
$PY -c "import json; d=json.load(open('$T/keys.json')); json.dump(d['accounts'][0], open('$T/key_a.json','w'))"

# Distinct amounts/fees/nonces per record so a per-index verdict is
# unambiguous and a body-field perturbation can never collide with another
# record's body.
$PY -c "
import json
recs=[]
for i in range($N):
    recs.append({'type':'TRANSFER','from':'$ADDR_A','to':'$ADDR_B',
                 'amount':1000+i*7,'fee':1+i,'nonce':100+i})
json.dump(recs, open('$T/in.json','w'))
"
"$WALLET" tx-batch-sign --keyfile "$T/key_a.json" --in "$T/in.json" \
  --out "$T/signed.json" >/dev/null 2>&1
if [ ! -f "$T/signed.json" ]; then
  echo "  SETUP-FAIL: tx-batch-sign did not produce signed batch"
  echo "  FAIL"; exit 1
fi

count_valid()   { $PY -c "import json,sys; print(sum(1 for v in json.load(open(sys.argv[1])) if v['valid']))" "$1"; }
count_invalid() { $PY -c "import json,sys; print(sum(1 for v in json.load(open(sys.argv[1])) if not v['valid']))" "$1"; }

echo "=== Baseline: clean $N-record batch → all valid:true (round-trip) ==="
set +e
"$WALLET" verify-batch --in "$T/signed.json" --out "$T/rep_clean.json" >/dev/null 2>&1
RC=$?
set -e
assert "$RC" "0" "clean batch verify-batch exits 0"
assert "$(count_valid "$T/rep_clean.json")"   "$N" "all $N records report valid:true"
assert "$(count_invalid "$T/rep_clean.json")" "0"  "no records report valid:false on clean batch"

# ── 2. Generate the fixed-seed fuzz plan + tampered fixtures (deterministic) ──
# One Python pass: seed the RNG, pick (index, kind, position) per case, apply
# an XOR-flip nibble (sig/hash) or a +1 perturbation (amount/fee/nonce),
# write each tampered array to $T/case_<k>.json, and emit a manifest line
# "<k> <idx> <kind>" per case for the bash loop to consume. The mutation is
# ALWAYS a real change (XOR flips the nibble to a different hex digit; +1
# changes the integer), so the targeted record must verify false.
$PY - "$T" "$N" "$SEED" "$CASES" > "$T/manifest.txt" <<'PYEOF'
import json, random, sys
T, N, SEED, CASES = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
base = json.load(open(T + "/signed.json"))
rng = random.Random(SEED)
kinds = ["sig", "hash", "amount", "fee", "nonce"]

def flip_nibble(hexstr, pos):
    # XOR the nibble at pos with a nonzero mask so it is guaranteed to change.
    val = int(hexstr[pos], 16)
    mask = rng.randint(1, 15)          # 1..15 → never a no-op XOR
    newv = val ^ mask
    return hexstr[:pos] + format(newv, "x") + hexstr[pos+1:]

for k in range(CASES):
    arr = json.loads(json.dumps(base))   # deep copy
    idx = rng.randrange(N)
    kind = kinds[k % len(kinds)]         # round-robin so every kind is hit
    rec = arr[idx]
    if kind == "sig":
        s = rec["sig"]
        pos = rng.randrange(len(s))
        rec["sig"] = flip_nibble(s, pos)
    elif kind == "hash":
        h = rec["hash"]
        pos = rng.randrange(len(h))
        rec["hash"] = flip_nibble(h, pos)
    else:
        rec[kind] = rec[kind] + 1        # real integer change; sig now stale
    json.dump(arr, open("%s/case_%d.json" % (T, k), "w"))
    print(k, idx, kind)
PYEOF

NPLAN=$(wc -l < "$T/manifest.txt" | tr -d ' ')
assert "$NPLAN" "$CASES" "fuzz plan generated $CASES cases"

# ── 3. Drive each fuzz case through verify-batch + assert the truth table ────
echo
echo "=== Fuzz: $CASES fixed-seed XOR-flip / body-perturb tamper cases ==="
fuzz_pass=0
while read -r K IDX KIND; do
  [ -z "${K:-}" ] && continue
  IN="$T/case_${K}.json"
  REP="$T/rep_${K}.json"

  # Report-only mode: command exits 0, verdict array carries per-tx results.
  set +e
  "$WALLET" verify-batch --in "$IN" --out "$REP" >/dev/null 2>&1
  RC_REPORT=$?
  set -e

  # --strict mode over the same tampered batch: exactly one invalid → exit 3.
  set +e
  "$WALLET" verify-batch --in "$IN" --strict >/dev/null 2>&1
  RC_STRICT=$?
  set -e

  if [ ! -f "$REP" ]; then
    echo "  FAIL: case $K ($KIND idx $IDX) produced no verdict report"
    fail_count=$((fail_count + 1)); continue
  fi

  # Oracle (known by construction):
  #   exactly 1 invalid, it is at IDX, every other index valid, strict→3.
  RESULT=$($PY - "$REP" "$IDX" "$N" <<'PYEOF'
import json, sys
rep, idx, n = json.load(open(sys.argv[1])), int(sys.argv[2]), int(sys.argv[3])
ninvalid = sum(1 for v in rep if not v["valid"])
target_bad = (not rep[idx]["valid"]) and ("reason" in rep[idx])
siblings_ok = all(rep[i]["valid"] for i in range(n) if i != idx)
order_ok = [v["index"] for v in rep] == list(range(n))
print("OK" if (ninvalid == 1 and target_bad and siblings_ok and order_ok) else "BAD")
PYEOF
)
  if [ "$RESULT" = "OK" ] && [ "$RC_REPORT" = "0" ] && [ "$RC_STRICT" = "3" ]; then
    fuzz_pass=$((fuzz_pass + 1))
  else
    echo "  FAIL: case $K (kind=$KIND idx=$IDX): result=$RESULT report_rc=$RC_REPORT strict_rc=$RC_STRICT"
    fail_count=$((fail_count + 1))
  fi
done < "$T/manifest.txt"

assert "$fuzz_pass" "$CASES" "all $CASES tamper cases detected (target invalid, siblings valid, strict exit 3)"

# ── 4. Control: re-verify the untouched baseline is STILL all-valid ──────────
# Guards against any accidental mutation of the shared signed.json fixture
# during the loop (each case wrote to its own file; the original must be
# pristine).
echo
echo "=== Control: original signed batch still verifies all-valid ==="
set +e
"$WALLET" verify-batch --in "$T/signed.json" --out "$T/rep_final.json" --force >/dev/null 2>&1
RC=$?
set -e
assert "$RC" "0" "control re-verify exits 0"
assert "$(count_valid "$T/rep_final.json")" "$N" "control: original batch still all valid:true (fixture not mutated)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail  ($CASES fuzz cases, seed=$SEED)"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet verify-batch fuzz"; exit 0
else
    echo "  FAIL"; exit 1
fi
