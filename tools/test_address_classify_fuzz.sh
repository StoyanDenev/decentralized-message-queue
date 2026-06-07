#!/usr/bin/env bash
# OFFLINE fixed-seed FUZZ / truth-table property test for
# `determ-wallet address-classify`.
#
# Hardens the S-028 account-identifier classifier (anon | domain |
# invalid) + canonicalizer. Pure local string work — no SHA-256, no
# RPC, no daemon, no network (we only read a local @file). Cluster-free.
#
# SAFE REFERENCE (no algorithm re-implementation):
#   Every fuzz case is constructed so its TRUE class is known a priori,
#   and the wallet's own commands are the only source of "ground truth":
#
#     * ANON addresses come from `determ-wallet account-derive-batch
#       --seed <fixed> --count N`. That command's whole job is to emit
#       valid "0x"+64-hex anon addresses; by construction every entry it
#       returns is a canonical anon address. We classify them and assert
#       kind == anon. We ALSO round-trip: the classifier's reported
#       pubkey_hex, re-wrapped as "0x"+pubkey_hex, must equal the
#       canonical address it was derived from (one command's output
#       feeds the assertion about another).
#
#     * NON-CANONICAL ANON cases take a known-anon address and upper-case
#       a fixed-seed-chosen subset of the hex-tail nibbles. The class is
#       STILL anon (case-insensitive on input per S-028); the canonical
#       form is the original lowercase address; changed must be true iff
#       at least one letter (a-f) nibble was actually flipped to A-F.
#
#     * DOMAIN cases are fixed-seed-chosen names that are NOT "0x"+64hex
#       (e.g. "node7.validator"). By construction kind == domain and the
#       canonical form is the input verbatim.
#
#     * INVALID cases take a known-anon address and corrupt it so it can
#       no longer be a valid anon id, while staying 0x-prefixed (so the
#       classifier cannot fall back to "domain"). Two corruption kinds:
#         - hex XOR-flip: pick a tail nibble, XOR its value by a non-zero
#           amount, then map the result to a GUARANTEED non-hex glyph so
#           the mutation is always a real, class-changing change (never a
#           no-op, never another valid hex digit).
#         - truncation: drop a fixed-seed-chosen number of tail chars so
#           the length is wrong. Still "0x..." => still not a domain.
#       By construction kind == invalid and submit_tx_ok == false.
#
#   The expected class for each case is therefore KNOWN BY CONSTRUCTION,
#   independent of the binary under test. We then feed ALL cases in one
#   batch through `--addresses @file --json` and check, per result, that
#   the reported kind/canonical/changed/submit_tx_ok/pubkey match the
#   construction-time expectation, and that the summary tally agrees.
#
# Differentiation vs the hand-picked sibling test_wallet_address_classify.sh:
#   that test exercises a small set of hand-written single/multi cases for
#   CLI surface + exit codes. THIS test is a fixed-seed randomized property
#   sweep: >=24 mutated cases drawn from a seeded RNG, asserting the full
#   truth table + the pubkey round-trip + the batch summary, with XOR-based
#   hex corruption so every "invalid" mutation is a guaranteed real change.
#
# Run from repo root: bash tools/test_address_classify_fuzz.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# SKIP cleanly if the wallet binary is absent (house convention).
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
WALLET="$DETERM_WALLET"

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# Fixture dir + cleanup trap.
T="build/test_address_classify_fuzz.$$"
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT

pass_count=0
fail_count=0
assert() {
  # assert <actual> <expected> <message>
  if [ "$1" = "$2" ]; then
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3"
    echo "        expected: [$2]"
    echo "        got:      [$1]"
    fail_count=$((fail_count + 1))
  fi
}

# Fixed seed so the whole sweep is reproducible.
SEED_HEX="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
N=24   # >= 20 cases required.

echo "=== address-classify fuzz: deriving $N known-anon base addresses ==="
# Ground-truth anon addresses (canonical, lowercase "0x"+64hex) BY
# CONSTRUCTION — account-derive-batch only emits valid anon addresses.
"$WALLET" account-derive-batch --seed "$SEED_HEX" --count "$N" \
    --out "$T/accounts.json" --force >/dev/null 2>&1
if [ ! -s "$T/accounts.json" ]; then
  echo "  FAIL: account-derive-batch produced no output file"
  echo "Total: PASS=$pass_count FAIL=1"
  exit 1
fi

# Pull the N base addresses into a bash array. Python on Windows emits
# CRLF on stdout, so strip \r before mapfile to keep the strings clean.
mapfile -t BASE_ADDRS < <("$PY" - "$T/accounts.json" <<'PYEOF' | tr -d '\r'
import json, sys
d = json.load(open(sys.argv[1]))
for a in d["accounts"]:
    print(a["address"])
PYEOF
)
assert "${#BASE_ADDRS[@]}" "$N" "derived exactly N=$N base anon addresses"

# Python helper (fixed-seed RNG) builds, for each base address, ONE fuzz
# case with a known class. It writes two tab-separated files:
#   cases.txt   : the identifier strings, one per line, in order
#   expect.tsv  : input \t exp_kind \t exp_canonical \t exp_changed \t
#                 exp_submit_ok \t exp_pubkey   (pubkey "" when N/A)
# Class is chosen round-robin by index so every class is well represented.
"$PY" - "$T" "$SEED_HEX" "${BASE_ADDRS[@]}" <<'PYEOF'
import sys, random

outdir = sys.argv[1]
seed_hex = sys.argv[2]
bases = sys.argv[3:]

rng = random.Random(int(seed_hex, 16) & ((1 << 64) - 1))

HEXSET = set("0123456789abcdef")
# Domain label parts for the "domain" class — none of these is 0x+64hex.
DOM_NAMES = ["validator", "node", "exch", "payroll", "treasury",
             "ops", "relay", "shard", "vault", "gw"]

def upper_subset(tail):
    """Upper-case a random non-empty subset of nibble positions."""
    idxs = list(range(len(tail)))
    rng.shuffle(idxs)
    k = rng.randint(1, len(tail))
    chosen = set(idxs[:k])
    out = []
    flipped_letter = False
    for i, c in enumerate(tail):
        if i in chosen and c in "abcdef":
            out.append(c.upper())
            flipped_letter = True
        elif i in chosen:
            out.append(c)  # digit upper-cases to itself
        else:
            out.append(c)
    return "".join(out), flipped_letter

def corrupt_to_nonhex(tail):
    """XOR-flip one nibble, then force the result to a guaranteed
    NON-hex glyph so the mutation is always a real class change."""
    pos = rng.randrange(len(tail))
    orig = tail[pos]
    # XOR the nibble value by a non-zero amount (real change), then map
    # to a glyph that is definitely NOT a hex digit. We pick from a pool
    # of non-hex letters; XOR just selects which one deterministically.
    nonhex = "ghijklmnopqrstuvwxyz"
    val = int(orig, 16)
    flip = rng.randint(1, 15)
    pick = (val ^ flip) % len(nonhex)
    bad = nonhex[pick]
    assert bad not in HEXSET
    return tail[:pos] + bad + tail[pos + 1:]

cases = []   # (ident, kind, canonical, changed, submit_ok, pubkey)
for i, base in enumerate(bases):
    assert base.startswith("0x") and len(base) == 66
    tail = base[2:]
    cls = i % 4
    if cls == 0:
        # ANON canonical: verbatim. round-trip pubkey == tail.
        cases.append((base, "anon", base, "false", "true", tail))
    elif cls == 1:
        # NON-CANONICAL ANON: upper-case a subset of the tail.
        upper_tail, flipped = upper_subset(tail)
        ident = "0x" + upper_tail
        changed = "true" if flipped else "false"
        submit = "false" if flipped else "true"
        # Canonical is always the lowercase form == base.
        cases.append((ident, "anon", base, changed, submit, tail))
    elif cls == 2:
        # DOMAIN: a name that is not 0x+64hex.
        name = "%s%d.%s" % (rng.choice(DOM_NAMES), i,
                            rng.choice(DOM_NAMES))
        cases.append((name, "domain", name, "false", "true", ""))
    else:
        # INVALID: either non-hex corruption or truncation, both 0x-led.
        if rng.random() < 0.5:
            bad_tail = corrupt_to_nonhex(tail)
            ident = "0x" + bad_tail
        else:
            drop = rng.randint(1, 10)
            ident = "0x" + tail[:64 - drop]
        cases.append((ident, "invalid", "", "false", "false", ""))

# newline="\n" forces clean LF endings even on Windows (default text
# mode would translate to CRLF and break bash read/grep/wc parsing).
with open(outdir + "/cases.txt", "w", newline="\n") as f:
    for c in cases:
        f.write(c[0] + "\n")

with open(outdir + "/expect.tsv", "w", newline="\n") as f:
    for c in cases:
        f.write("\t".join(c) + "\n")

print("wrote %d cases" % len(cases))
PYEOF

NCASES=$(wc -l < "$T/cases.txt" | tr -d ' ')
assert "$NCASES" "$N" "built exactly N=$N fuzz cases"
echo "  built $NCASES fixed-seed fuzz cases (anon / noncanon-anon / domain / invalid)"

echo
echo "=== batch-classify all cases via --addresses @file --json ==="
# Note: the batch will contain at least one invalid case, so exit code 2
# is EXPECTED (and itself part of the truth table). Capture the wallet's
# OWN exit status — write raw output to a file first so a `tr` pipe can't
# mask $? (a pipeline reports the LAST command's status).
set +e
"$WALLET" address-classify --addresses "@$T/cases.txt" --json > "$T/out.raw" 2>&1
RC=$?
set -e
tr -d '\r' < "$T/out.raw" > "$T/out.json"
# Exit 2 = "at least one identifier invalid" — our construction guarantees
# the invalid-class cases exist, so 2 is correct.
assert "$RC" "2" "batch with invalids exits 2 (per documented exit codes)"

# Parse output JSON and emit one line per result:
#   input \t kind \t canonical \t changed \t submit_tx_ok \t pubkey
# Pipe through `tr -d '\r'` so Windows-Python CRLF stdout lands as clean
# LF in got.tsv (bash read/grep/sed parse it line by line).
"$PY" - "$T/out.json" <<'PYEOF' | tr -d '\r' > "$T/got.tsv"
import json, sys
d = json.load(open(sys.argv[1]))
for r in d["results"]:
    print("\t".join([
        r.get("input", ""),
        r.get("kind", ""),
        r.get("canonical", ""),
        "true" if r.get("changed") else "false",
        "true" if r.get("submit_tx_ok") else "false",
        r.get("pubkey_hex", ""),
    ]))
# Summary tallies on a trailing line, marker-prefixed.
s = d["summary"]
print("__SUMMARY__\t%d\t%d\t%d\t%d\t%d" % (
    s["anon"], s["domain"], s["invalid"], s["changed"], s["submit_tx_ok"]))
PYEOF

# Count of result rows (excluding the summary marker line).
GOT_ROWS=$(grep -vc "^__SUMMARY__" "$T/got.tsv")
assert "$GOT_ROWS" "$N" "classifier returned exactly N=$N results"

echo
echo "=== per-case truth-table assertions (kind/canonical/changed/submit/pubkey) ==="
# Walk expect.tsv and the result rows in lock-step (order is preserved by
# the classifier — input order == output order).
exp_anon=0; exp_domain=0; exp_invalid=0; exp_changed=0; exp_submit=0
line_no=0
while IFS=$'\t' read -r e_in e_kind e_canon e_chg e_sub e_pub; do
  line_no=$((line_no + 1))
  # Pull the matching result row (Nth non-summary line).
  g_row=$(grep -v "^__SUMMARY__" "$T/got.tsv" | sed -n "${line_no}p")
  IFS=$'\t' read -r g_in g_kind g_canon g_chg g_sub g_pub <<< "$g_row"

  assert "$g_in"    "$e_in"    "case $line_no: input echoed verbatim"
  assert "$g_kind"  "$e_kind"  "case $line_no: kind=$e_kind ($e_in)"
  assert "$g_canon" "$e_canon" "case $line_no: canonical matches construction"
  assert "$g_chg"   "$e_chg"   "case $line_no: changed=$e_chg"
  assert "$g_sub"   "$e_sub"   "case $line_no: submit_tx_ok=$e_sub"

  if [ "$e_kind" = "anon" ]; then
    # pubkey round-trip: "0x"+pubkey_hex must equal the canonical address.
    assert "$g_pub"        "$e_pub"        "case $line_no: pubkey_hex round-trips"
    assert "0x$g_pub"      "$e_canon"      "case $line_no: 0x+pubkey == canonical (round-trip)"
  fi

  # Tally expected summary as we go.
  case "$e_kind" in
    anon)    exp_anon=$((exp_anon + 1)) ;;
    domain)  exp_domain=$((exp_domain + 1)) ;;
    invalid) exp_invalid=$((exp_invalid + 1)) ;;
  esac
  [ "$e_chg" = "true" ] && exp_changed=$((exp_changed + 1))
  [ "$e_sub" = "true" ] && exp_submit=$((exp_submit + 1))
done < "$T/expect.tsv"

echo
echo "=== batch summary tally matches construction-time expectation ==="
SUMMARY=$(grep "^__SUMMARY__" "$T/got.tsv")
IFS=$'\t' read -r _ g_sa g_sd g_si g_sc g_ss <<< "$SUMMARY"
assert "$g_sa" "$exp_anon"    "summary.anon == $exp_anon"
assert "$g_sd" "$exp_domain"  "summary.domain == $exp_domain"
assert "$g_si" "$exp_invalid" "summary.invalid == $exp_invalid"
assert "$g_sc" "$exp_changed" "summary.changed == $exp_changed"
assert "$g_ss" "$exp_submit"  "summary.submit_tx_ok == $exp_submit"

# Sanity: every class must be represented (round-robin guarantees this).
[ "$exp_anon" -ge 1 ]    && pass_count=$((pass_count + 1)) || { echo "  FAIL: no anon cases"; fail_count=$((fail_count + 1)); }
[ "$exp_domain" -ge 1 ]  && pass_count=$((pass_count + 1)) || { echo "  FAIL: no domain cases"; fail_count=$((fail_count + 1)); }
[ "$exp_invalid" -ge 1 ] && pass_count=$((pass_count + 1)) || { echo "  FAIL: no invalid cases"; fail_count=$((fail_count + 1)); }

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  echo "FAIL: address-classify fuzz/truth-table found mismatches"
  exit 1
fi
echo "PASS: address-classify fuzz/truth-table (all $pass_count assertions green)"
exit 0
