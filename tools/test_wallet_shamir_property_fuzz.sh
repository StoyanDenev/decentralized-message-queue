#!/usr/bin/env bash
# determ-wallet Shamir property fuzz — round-trip + threshold + tamper.
#
# This is a FIXED-SEED, HIGH-VOLUME property test that hardens the raw
# `shamir-split` / `shamir-combine` CLIs (the JSON-share-file flavor;
# distinct from the colon-format `shamir split|combine` subcommand and
# from the structural-only `shamir-verify`).
#
# It complements — does NOT duplicate — the existing tests:
#   - test_wallet_shamir.sh       : a handful of hand-picked subsets.
#   - test_wallet_shamir_cli.sh   : ONE (T=3,N=5) shape, all C(5,3) subsets,
#                                   plus validation-rejection coverage.
#   - test_wallet_shamir_verify.sh: structural verification only (no math).
#   - test_shamir.sh              : in-process unit test (different binary).
#
# What is NEW here: a seeded RNG drives MANY independent random cases,
# each over a freshly-chosen (secret size, T, N) tuple, and for every
# case we sample SEVERAL random exact-T subsets — sweeping a far wider
# slice of the (which-shares, which-threshold, which-secret) space than
# any single fixed shape can. The seed is fixed so the case stream is
# reproducible; a regression points at a concrete, replayable case.
#
# SAFE REFERENCE (oracle) — never reimplements GF(2^8)/Lagrange math:
#   (A) Round-trip identity: combine(any exact-T subset of split(s)) == s,
#       where s is the KNOWN original secret we fed in. Pure round-trip.
#   (B) Threshold property (documented info-theoretic behavior, confirmed
#       empirically against this build): a (T-1)-share subset combine
#       SUCCEEDS but yields a value != the original (SSS produces an
#       indistinguishable-from-random result below threshold; it does NOT
#       reconstruct). Asserted as combined != original.
#   (C) Tamper / no-false-integrity: XOR-flipping a single byte of one
#       share's y_hex (a guaranteed-real mutation) inside an exact-T
#       subset makes combine yield != original. SSS carries no integrity
#       tag, so the only correct property to assert is "result changed."
#
# Fully OFFLINE: no daemon, no cluster, no network. Only the wallet
# binary + python (for seeded case generation / subset enumeration /
# XOR-flip — python performs NO secret-sharing math, only plumbing).
#
# Run from repo root: bash tools/test_wallet_shamir_property_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# ── SKIP gates ────────────────────────────────────────────────────────────────
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
  echo "  SKIP: determ-wallet binary not found; build with"
  echo "        cmake --build build --config Release --target determ-wallet"
  exit 0
fi
WALLET="$DETERM_WALLET"

PY=python
command -v python >/dev/null 2>&1 || PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "  SKIP: python not found (needed for seeded case generation)"
  exit 0
fi

# ── Test-only scratch dir + cleanup (treat fixtures as secret material) ────────
T="$(mktemp -d)"
cleanup() {
  # Overwrite share/secret fixtures before unlinking — they hold test-only
  # secret material. Best-effort; rm is the real guarantee.
  find "$T" -type f -exec sh -c 'cat /dev/null > "$1" 2>/dev/null || true' _ {} \; 2>/dev/null || true
  rm -rf "$T"
}
trap cleanup EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3"
    echo "       expected: $2"
    echo "       got:      $1"
    fail_count=$((fail_count + 1))
  fi
}
assert_neq() {
  if [ "$1" != "$2" ]; then
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3 (unexpected equality with original)"
    fail_count=$((fail_count + 1))
  fi
}

# Fixed seed → reproducible case stream. >= 20 random cases.
SEED=20240607
NUM_CASES=24

echo "=== determ-wallet Shamir property fuzz (seed=$SEED, cases=$NUM_CASES) ==="
echo

# ── Generate the deterministic case plan ──────────────────────────────────────
# Each line: case_id  secret_hex  T  N
# secret size in {8,16,24,32,48}; N in [3,12]; T in [2,N]; all seeded.
"$PY" - "$SEED" "$NUM_CASES" > "$T/plan.tsv" <<'PY_EOF'
import sys, random
seed = int(sys.argv[1]); ncases = int(sys.argv[2])
rng = random.Random(seed)
sizes = [8, 16, 24, 32, 48]
for cid in range(ncases):
    size = rng.choice(sizes)
    secret = bytes(rng.randrange(256) for _ in range(size)).hex()
    n = rng.randint(3, 12)
    t = rng.randint(2, n)                 # 2 <= T <= N
    print(f"{cid}\t{secret}\t{t}\t{n}")
PY_EOF

CASE_TOTAL=$(wc -l < "$T/plan.tsv" | tr -d ' ')
assert_eq "$CASE_TOTAL" "$NUM_CASES" "case plan produced $NUM_CASES cases"

# ── Drive every case ──────────────────────────────────────────────────────────
# Per case we run, against the KNOWN original secret as oracle:
#   - exact-T subset round-trips (several random subsets, count seeded)
#   - one (T-1) subset must NOT reconstruct (skipped when T==2 -> T-1==1,
#     still meaningful: 1-share combine != original)
#   - one XOR-byte tamper inside an exact-T subset must NOT reconstruct
rt_checks=0
while IFS=$'\t' read -r CID SECRET T_VAL N_VAL; do
  [ -z "${CID:-}" ] && continue

  SPLIT_JSON="$T/case_${CID}_split.json"
  if ! "$WALLET" shamir-split --secret "$SECRET" --threshold "$T_VAL" --shares "$N_VAL" --json \
        > "$SPLIT_JSON" 2>"$T/case_${CID}_err.txt"; then
    echo "  FAIL: case $CID split failed (T=$T_VAL N=$N_VAL): $(tr -d '\r' < "$T/case_${CID}_err.txt")"
    fail_count=$((fail_count + 1))
    continue
  fi

  # Emit the per-case subset fixtures via seeded python:
  #   - K exact-T subsets   -> sub_<j>.json
  #   - 1 (T-1) subset       -> tminus1.json
  #   - 1 tampered exact-T   -> tamper.json   (XOR-flip 1 byte of one y_hex)
  # Python is PLUMBING ONLY: it selects shares + flips one byte; it never
  # performs Lagrange interpolation or any GF(2^8) arithmetic.
  K_SUBSETS=$("$PY" - "$SPLIT_JSON" "$T" "$CID" "$T_VAL" "$SEED" <<'PY_EOF'
import sys, json, random
split_path, outdir, cid, t, seed = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
shares = json.load(open(split_path))["shares"]
n = len(shares)
# Deterministic per-case sub-stream so the whole run is reproducible.
rng = random.Random(seed * 1000003 + int(cid))

# Number of exact-T subsets to sample for this case: 3..6, capped by how
# many distinct T-subsets actually exist (C(n,t) can be small, e.g. T==N).
import math
max_subsets = math.comb(n, t)
k = min(rng.randint(3, 6), max_subsets)

seen = set()
written = 0
attempts = 0
while written < k and attempts < 200:
    attempts += 1
    idx = tuple(sorted(rng.sample(range(n), t)))
    if idx in seen:
        continue
    seen.add(idx)
    sub = [shares[i] for i in idx]
    json.dump({"shares": sub}, open(f"{outdir}/case_{cid}_sub_{written}.json", "w"))
    written += 1

# (T-1) insufficient subset (size t-1 >= 1 since t>=2).
low_idx = sorted(rng.sample(range(n), t - 1))
json.dump({"shares": [shares[i] for i in low_idx]},
          open(f"{outdir}/case_{cid}_tminus1.json", "w"))

# Tampered exact-T subset: pick a fresh exact-T subset, XOR-flip one byte
# of one share's y_hex so the mutation is GUARANTEED to be a real change.
tam_idx = sorted(rng.sample(range(n), t))
tam = [dict(shares[i]) for i in tam_idx]
victim = rng.randrange(len(tam))
yb = bytearray.fromhex(tam[victim]["y_hex"])
pos = rng.randrange(len(yb))
yb[pos] ^= (1 << rng.randrange(8))      # flip exactly one bit -> always differs
tam[victim] = dict(tam[victim])
tam[victim]["y_hex"] = yb.hex()
json.dump({"shares": tam}, open(f"{outdir}/case_{cid}_tamper.json", "w"))

print(written)
PY_EOF
)

  # (A) Round-trip: each exact-T subset must reconstruct the EXACT original.
  j=0
  while [ "$j" -lt "$K_SUBSETS" ]; do
    SUBF="$T/case_${CID}_sub_${j}.json"
    REC=$("$WALLET" shamir-combine --shares "$SUBF" 2>/dev/null | tr -d '\r')
    assert_eq "$REC" "$SECRET" "case $CID (T=$T_VAL N=$N_VAL) exact-T subset #$j round-trips"
    rt_checks=$((rt_checks + 1))
    j=$((j + 1))
  done

  # (B) Threshold: a (T-1) subset must NOT yield the original.
  LOWF="$T/case_${CID}_tminus1.json"
  REC_LOW=$("$WALLET" shamir-combine --shares "$LOWF" 2>/dev/null | tr -d '\r')
  # combine may succeed-with-garbage OR error; either way it must != original.
  [ -z "$REC_LOW" ] && REC_LOW="<combine-refused>"
  assert_neq "$REC_LOW" "$SECRET" "case $CID (T=$T_VAL N=$N_VAL) (T-1)=$((T_VAL-1)) subset does NOT reconstruct"

  # (C) Tamper: XOR-flipped share inside an exact-T subset must NOT yield original.
  TAMF="$T/case_${CID}_tamper.json"
  REC_TAM=$("$WALLET" shamir-combine --shares "$TAMF" 2>/dev/null | tr -d '\r')
  [ -z "$REC_TAM" ] && REC_TAM="<combine-refused>"
  assert_neq "$REC_TAM" "$SECRET" "case $CID (T=$T_VAL N=$N_VAL) one-bit-flipped share corrupts reconstruction"

done < "$T/plan.tsv"

echo
echo "  Round-trip subset checks executed: $rt_checks"

# ── Cross-check: --json secret_hex matches plain output on a representative case ─
# Belt-and-suspenders: the machine-readable path must agree with the human path,
# and both must equal the original. Uses case 0's first subset.
if [ -f "$T/case_0_sub_0.json" ]; then
  FIRST_SECRET=$(head -n1 "$T/plan.tsv" | cut -f2)
  PLAIN=$("$WALLET" shamir-combine --shares "$T/case_0_sub_0.json" 2>/dev/null | tr -d '\r')
  JSON_OUT=$("$WALLET" shamir-combine --shares "$T/case_0_sub_0.json" --json 2>/dev/null | tr -d '\r')
  JSON_HEX=$(printf '%s' "$JSON_OUT" | "$PY" -c 'import json,sys; print(json.loads(sys.stdin.read())["secret_hex"])' 2>/dev/null)
  assert_eq "$PLAIN" "$FIRST_SECRET" "case 0 plain combine == original"
  assert_eq "$JSON_HEX" "$FIRST_SECRET" "case 0 --json secret_hex == original"
  assert_eq "$JSON_HEX" "$PLAIN" "case 0 --json secret_hex == plain output"
fi

# ── Determinism-of-randomness property: same secret split twice yields DIFFERENT
# share bytes (fresh polynomial), yet BOTH reconstruct the original. ─────────────
DET_SECRET="cafebabedeadbeef0123456789abcdef"
"$WALLET" shamir-split --secret "$DET_SECRET" --threshold 3 --shares 6 --json > "$T/det_a.json"
"$WALLET" shamir-split --secret "$DET_SECRET" --threshold 3 --shares 6 --json > "$T/det_b.json"
A=$(tr -d '\r' < "$T/det_a.json")
B=$(tr -d '\r' < "$T/det_b.json")
assert_neq "$A" "$B" "two splits of same secret produce DIFFERENT share sets"
"$PY" - "$T/det_a.json" "$T/det_sub_a.json" <<'PY_EOF'
import json,sys
d=json.load(open(sys.argv[1]))["shares"]
json.dump({"shares":[d[0],d[2],d[4]]}, open(sys.argv[2],"w"))
PY_EOF
"$PY" - "$T/det_b.json" "$T/det_sub_b.json" <<'PY_EOF'
import json,sys
d=json.load(open(sys.argv[1]))["shares"]
json.dump({"shares":[d[1],d[3],d[5]]}, open(sys.argv[2],"w"))
PY_EOF
REC_DA=$("$WALLET" shamir-combine --shares "$T/det_sub_a.json" 2>/dev/null | tr -d '\r')
REC_DB=$("$WALLET" shamir-combine --shares "$T/det_sub_b.json" 2>/dev/null | tr -d '\r')
assert_eq "$REC_DA" "$DET_SECRET" "split-A subset reconstructs original"
assert_eq "$REC_DB" "$DET_SECRET" "split-B subset reconstructs original"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet shamir-split/shamir-combine property fuzz"
  exit 0
else
  echo "  FAIL: test_wallet_shamir_property_fuzz"
  exit 1
fi
