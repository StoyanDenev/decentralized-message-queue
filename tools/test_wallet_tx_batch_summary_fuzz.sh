#!/usr/bin/env bash
# determ-wallet tx-batch-summary — fixed-seed randomized fuzz / known-by-
# construction consistency harness (complements the fixed-case
# test_wallet_tx_batch_summary.sh; distinct file, distinct method).
#
# WHY a separate harness:
#   test_wallet_tx_batch_summary.sh exercises a handful of small, hand-
#   crafted batches (3 TRANSFERs, a 4-row mixed batch, two nonce edge
#   cases). It proves the command is *correct on those inputs* but never
#   stresses the aggregation arithmetic over large, randomly-composed
#   batches with the full type-fold / distinct-collapse / missing-field /
#   nonce-contiguity interaction surface. This harness does exactly that:
#   it generates many randomized batches under a FIXED seed and checks the
#   command's report against a ground truth computed *as the batch is
#   built*.
#
# SAFE REFERENCE (no algorithm is re-implemented as the oracle):
#   The oracle is KNOWN-BY-CONSTRUCTION bookkeeping. Python builds each
#   record one at a time and, in the same loop, folds the record's KNOWN
#   contribution into plain integer/set accumulators (count per type, sum
#   of amount, sum of fee, the from/to sets, the nonce set, the
#   missing-field count). Those accumulators ARE the truth because we put
#   the values there ourselves — there is no hash, signature, Merkle root,
#   or any other primitive being independently re-derived. We then assert
#   the command's --json output equals that truth, field for field.
#
#   The aggregation rules the oracle mirrors (read from the implementation
#   in wallet/main.cpp::cmd_tx_batch_summary):
#     * counted record = has type+from+to+amount+nonce, fee optional but
#       if present must be a non-negative integer. Otherwise the row is
#       NOT counted and bumps records_missing_fields.
#     * total_amount / total_fee sum over COUNTED rows only (fee defaults
#       to 0 when the key is absent).
#     * per_type: TRANSFER(0), STAKE(3), UNSTAKE(4); every other type id
#       folds into `other` and its raw int joins other_types.
#     * distinct_from / distinct_to = set sizes over COUNTED rows.
#     * nonce_contiguous = the COUNTED nonces form a gap-free, duplicate-
#       free run (distinct count == span+1 AND no nonce repeated).
#
#   To deliberately exercise every branch, the generator sometimes injects
#   a corrupt row (drops a required field, or gives fee a string value)
#   and the oracle counts it as a missing-field row excluded from all
#   aggregates — exactly as the command must.
#
# TAMPER sub-case (real mutation, XOR-flip): we take a clean batch, summarize
#   it, then XOR-flip one hex nibble of one recipient address and re-summarize.
#   A genuine change must move distinct_to (the address is now new) without
#   touching counted_records / total_amount — proving the distinct-set logic
#   reacts to an actual byte change rather than to position.
#
# Fully OFFLINE: no daemon, no cluster, no keys, no signing. Fixed seed.
# >= 20 randomized cases (24 here).
#
# Run from repo root: bash tools/test_wallet_tx_batch_summary_fuzz.sh
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

T="build/test_wallet_tx_batch_summary_fuzz.$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT

pass_count=0
fail_count=0
assert() {
  # assert <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3"
    echo "        expected: $2"
    echo "        got:      $1"
    fail_count=$((fail_count + 1))
  fi
}

NUM_CASES=24
SEED=20260607   # fixed — reproducible

echo "=== Fixed-seed randomized known-by-construction fuzz ($NUM_CASES cases) ==="

for i in $(seq 1 "$NUM_CASES"); do
  CASE_SEED=$((SEED + i))
  IN="$T/case_${i}_in.json"
  EXP="$T/case_${i}_exp.json"

  # Python builds the batch AND the ground-truth summary in one pass.
  # The two files it writes are the command input and the oracle.
  "$PY" - "$CASE_SEED" "$IN" "$EXP" <<'PYEOF'
import json, random, sys

seed   = int(sys.argv[1])
in_path  = sys.argv[2]
exp_path = sys.argv[3]
rng = random.Random(seed)

# Type ids the command recognizes by name vs. folds into "other".
# 0=TRANSFER 3=STAKE 4=UNSTAKE are named; everything else -> other.
NAMED = [0, 3, 4]
OTHER = [1, 2, 5, 6, 7, 8, 9, 10]

# Small address pools so distinct-set collapses actually happen.
FROMS = ["0x%02x%02x" % (rng.randint(0, 255), j) for j in range(rng.randint(1, 4))]
TOS   = ["0x%02x%02x" % (rng.randint(0, 255), j) for j in range(rng.randint(1, 6))]

n = rng.randint(1, 40)

# Nonce assignment: with some probability emit a clean contiguous run
# (start..start+counted-1); otherwise scatter to create gaps/dups. The
# oracle does NOT assume contiguity — it derives it from the realized set.
contiguous_intent = rng.random() < 0.5
nonce_start = rng.randint(0, 50)

# ── oracle accumulators (known-by-construction) ────────────────────────
total_records = 0
counted = 0
missing = 0
total_amount = 0
total_fee = 0
ct = {"TRANSFER": 0, "STAKE": 0, "UNSTAKE": 0, "other": 0}
other_types = set()
from_set = set()
to_set = set()
nonce_list = []        # nonces of counted rows (with repeats)

recs = []
next_contig_nonce = nonce_start

def name_of(t):
    return {0: "TRANSFER", 3: "STAKE", 4: "UNSTAKE"}.get(t, "other")

for _ in range(n):
    total_records += 1

    # ~15% of rows are deliberately corrupt -> must count as missing-field
    # and be excluded from every aggregate.
    corrupt = rng.random() < 0.15

    t   = rng.choice(NAMED + OTHER)
    fr  = rng.choice(FROMS)
    to  = rng.choice(TOS)
    amt = rng.randint(0, 1_000_000)

    if contiguous_intent and not corrupt:
        nonce = next_contig_nonce
        next_contig_nonce += 1
    else:
        nonce = rng.randint(0, 60)

    # fee: present (~70%) or omitted (~30%); omitted defaults to 0.
    has_fee = rng.random() < 0.70
    fee = rng.randint(0, 5000)

    rec = {"type": t, "from": fr, "to": to, "amount": amt, "nonce": nonce}
    if has_fee:
        rec["fee"] = fee

    if corrupt:
        mode = rng.choice(["drop_amount", "drop_to", "drop_type", "bad_fee", "drop_nonce"])
        if mode == "drop_amount":
            rec.pop("amount", None)
        elif mode == "drop_to":
            rec.pop("to", None)
        elif mode == "drop_type":
            rec.pop("type", None)
        elif mode == "drop_nonce":
            rec.pop("nonce", None)
        elif mode == "bad_fee":
            rec["fee"] = "not-a-number"   # present-but-wrong-typed -> excluded
        recs.append(rec)
        missing += 1
        continue

    # ── counted row: fold known contribution ──────────────────────────
    recs.append(rec)
    counted += 1
    total_amount += amt
    total_fee += (fee if has_fee else 0)
    ct[name_of(t)] += 1
    if name_of(t) == "other":
        other_types.add(t)
    from_set.add(fr)
    to_set.add(to)
    nonce_list.append(nonce)

# nonce summary (over counted rows)
if nonce_list:
    nmin = min(nonce_list)
    nmax = max(nonce_list)
    distinct = set(nonce_list)
    dup_seen = len(distinct) != len(nonce_list)
    contiguous = (not dup_seen) and ((len(distinct) - 1) == (nmax - nmin))
    nonce_min = nmin
    nonce_max = nmax
    nonce_contiguous = contiguous
else:
    nonce_min = None
    nonce_max = None
    nonce_contiguous = None

exp = {
    "total_records": total_records,
    "counted_records": counted,
    "records_missing_fields": missing,
    "per_type": ct,
    "other_types_sorted": sorted(other_types),
    "total_amount": total_amount,
    "total_fee": total_fee,
    "distinct_from": len(from_set),
    "distinct_to": len(to_set),
    "nonce_min": nonce_min,
    "nonce_max": nonce_max,
    "nonce_contiguous": nonce_contiguous,
}

json.dump(recs, open(in_path, "w"))
json.dump(exp, open(exp_path, "w"))
PYEOF

  OUT="$T/case_${i}_out.json"
  if ! "$WALLET" tx-batch-summary --in "$IN" --json > "$OUT" 2>"$T/case_${i}_err.txt"; then
    echo "  FAIL: case $i — command exited non-zero"
    cat "$T/case_${i}_err.txt"
    fail_count=$((fail_count + 1))
    continue
  fi

  # Compare every documented field of the command output against the oracle.
  # All comparisons happen in one Python pass that prints OK or a diff line.
  CMP=$("$PY" - "$OUT" "$EXP" <<'PYEOF'
import json, sys
got = json.load(open(sys.argv[1]))
exp = json.load(open(sys.argv[2]))

errs = []
def eq(field, g, e):
    if g != e:
        errs.append("%s: got=%r exp=%r" % (field, g, e))

for f in ("total_records", "counted_records", "records_missing_fields",
          "total_amount", "total_fee", "distinct_from", "distinct_to",
          "nonce_min", "nonce_max", "nonce_contiguous"):
    eq(f, got.get(f), exp.get(f))

# per_type sub-fields
for k in ("TRANSFER", "STAKE", "UNSTAKE", "other"):
    eq("per_type." + k, got.get("per_type", {}).get(k), exp["per_type"][k])

# other_types: command emits [{"type":int,"mnemonic":str}, ...]; compare the
# sorted set of raw ints against the oracle's sorted other-type ids.
got_ot = sorted(o["type"] for o in got.get("other_types", []))
eq("other_types", got_ot, exp["other_types_sorted"])

if errs:
    print("DIFF " + " | ".join(errs))
else:
    print("OK")
PYEOF
)
  if [ "$CMP" = "OK" ]; then
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: case $i — $CMP"
    fail_count=$((fail_count + 1))
  fi
done

echo
echo "=== Tamper sub-case: XOR-flip one recipient nibble moves distinct_to ==="
# Build a clean 5-row batch with 5 distinct recipients, all amounts/fees known.
"$PY" - "$T/tamper_in.json" <<'PYEOF'
import json, sys
recs = [
  {"type":"TRANSFER","from":"0xaa","to":"0xb0","amount":10,"fee":1,"nonce":1},
  {"type":"TRANSFER","from":"0xaa","to":"0xb1","amount":20,"fee":1,"nonce":2},
  {"type":"TRANSFER","from":"0xaa","to":"0xb2","amount":30,"fee":1,"nonce":3},
  {"type":"TRANSFER","from":"0xaa","to":"0xb3","amount":40,"fee":1,"nonce":4},
  {"type":"TRANSFER","from":"0xaa","to":"0xb3","amount":50,"fee":1,"nonce":5},
]
json.dump(recs, open(sys.argv[1], "w"))
PYEOF
"$WALLET" tx-batch-summary --in "$T/tamper_in.json" --json > "$T/tamper_base.json" 2>/dev/null
BASE_DT=$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['distinct_to'])" "$T/tamper_base.json")
BASE_CT=$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['counted_records'])" "$T/tamper_base.json")
BASE_AMT=$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['total_amount'])" "$T/tamper_base.json")
# By construction: recipients {b0,b1,b2,b3,b3} -> 4 distinct; the last row's
# 'b3' is the duplicate we will flip to a brand-new address.
assert "$BASE_DT"  "4"   "tamper-base: distinct_to=4 (one duplicate recipient)"
assert "$BASE_CT"  "5"   "tamper-base: counted_records=5"
assert "$BASE_AMT" "150" "tamper-base: total_amount=150"

# XOR-flip the last nibble of the last recipient: 0xb3 -> 0xb3 with '3'^0x1='2'
# i.e. change to 0xb2... no — '3' is 0x33; 0x33 ^ 0x01 = 0x32 = '2'. That would
# collide with b2. Flip a fresh high nibble instead: change 'b3' to 'c3' by
# XOR-flipping the 'b' (0x62 ^ 0x01 = 0x63 = 'c'). Result 0xc3 is brand-new.
"$PY" - "$T/tamper_in.json" "$T/tamper_mut.json" <<'PYEOF'
import json, sys
recs = json.load(open(sys.argv[1]))
addr = recs[-1]["to"]            # "0xb3"
chars = list(addr)
# locate the 'b' (index 2) and XOR-flip it: 'b'(0x62) ^ 0x01 -> 'c'(0x63)
idx = 2
chars[idx] = chr(ord(chars[idx]) ^ 0x01)
mutated = "".join(chars)
assert mutated != addr, "XOR flip must change the address"
recs[-1]["to"] = mutated
json.dump(recs, open(sys.argv[2], "w"))
PYEOF
"$WALLET" tx-batch-summary --in "$T/tamper_mut.json" --json > "$T/tamper_mut_out.json" 2>/dev/null
MUT_DT=$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['distinct_to'])" "$T/tamper_mut_out.json")
MUT_CT=$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['counted_records'])" "$T/tamper_mut_out.json")
MUT_AMT=$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['total_amount'])" "$T/tamper_mut_out.json")
# The duplicate became unique -> distinct_to rises 4 -> 5; counted/total fixed.
assert "$MUT_DT"  "5"   "tamper-mut: distinct_to=5 (duplicate became unique after flip)"
assert "$MUT_CT"  "5"   "tamper-mut: counted_records unchanged at 5"
assert "$MUT_AMT" "150" "tamper-mut: total_amount unchanged at 150"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet tx-batch-summary fuzz"
  exit 0
else
  echo "  FAIL: determ-wallet tx-batch-summary fuzz"
  exit 1
fi
