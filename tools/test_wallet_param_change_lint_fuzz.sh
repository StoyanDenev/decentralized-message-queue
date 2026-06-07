#!/usr/bin/env bash
# determ-wallet param-change-lint FUZZ — exhaustive truth-table + --tx-json round-trip.
#
# COMPLEMENT to tools/test_wallet_param_change_lint.sh (which hand-picks a few
# fixtures). This harness drives the lint verdict across the FULL cross product of
#   {the 9 whitelisted governance names} x {value widths 0 / 4 / 8 / 16 bytes}
#   + a set of OFF-list names (random + structural near-misses)
# and asserts both the verdict string AND the process exit code against a SMALL
# EXHAUSTIVE TRUTH TABLE that IS the spec — NOT a reimplemented algorithm:
#
#   EFFECTIVE       iff name in {MIN_STAKE, SUSPENSION_SLASH, UNSTAKE_DELAY}
#                   AND value is EXACTLY 8 bytes                       -> exit 0
#   INERT_BAD_WIDTH iff name in those same 3 numeric chain-scalars
#                   AND value width != 8 bytes (parse_u64 rejects)     -> exit 2
#   HOOK_ONLY       iff name in the other 6 whitelisted names
#                   (tx_commit_ms / block_sig_ms / abort_claim_ms /
#                    bft_escalation_threshold / param_keyholders /
#                    param_threshold) — any width, hook-forwarded       -> exit 0
#   UNKNOWN_NAME    iff name is OFF the whitelist (validator rejects)   -> exit 2
#
# The table encodes the rule (3 numeric scalars are 8-byte-gated; 6 are hook
# pass-throughs; everything else is unknown). It is the specification, so a wrong
# binary fails the table — there is no second algorithm here that could itself be
# wrong.
#
# Then the --tx-json arm builds a real PARAM_CHANGE via `param-change-build` with
# a FIXED-seed random name+width, lints the BUILT tx via --tx-json, and asserts
# the payload-decoded verdict EXACTLY matches what the same name+width produces on
# the direct --name/--value-hex path (cross-path round-trip — the built payload
# must re-decode to the identical width the table predicts).
#
# Fully OFFLINE (no cluster, no daemon — param-change-lint/build are offline).
# Run from repo root: bash tools/test_wallet_param_change_lint_fuzz.sh
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

T=test_wallet_param_change_lint_fuzz
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# ── SAFE REFERENCE: the truth table, encoded as pure spec rules. ───────────────
# expected_verdict <name> <value_bytes> -> echoes the verdict string the spec
# mandates. This is the SPEC, not a reimplementation of any chain algorithm.
NUMERIC="MIN_STAKE SUSPENSION_SLASH UNSTAKE_DELAY"          # 8-byte-gated scalars
HOOKS="tx_commit_ms block_sig_ms abort_claim_ms bft_escalation_threshold param_keyholders param_threshold"
in_set() { case " $1 " in *" $2 "*) return 0;; *) return 1;; esac; }
expected_verdict() {  # $1=name  $2=value_bytes
  if in_set "$NUMERIC" "$1"; then
    if [ "$2" -eq 8 ]; then echo EFFECTIVE; else echo INERT_BAD_WIDTH; fi
  elif in_set "$HOOKS" "$1"; then
    echo HOOK_ONLY
  else
    echo UNKNOWN_NAME
  fi
}
expected_rc() {  # exit-code half of the spec
  case "$1" in EFFECTIVE|HOOK_ONLY) echo 0;; *) echo 2;; esac
}

# Read the lint verdict via --json (authoritative parse, avoids stdout-format drift).
verdict_of() { "$W" param-change-lint --name "$1" --value-hex "$2" --json 2>/dev/null \
  | $PY -c "import json,sys;print(json.load(sys.stdin)['verdict'])" 2>/dev/null; }

# Build a hex string of N zero-bytes (N>=0; N=0 -> empty string).
zhex() { $PY -c "print('00'*$1)"; }

cases=0  # count random/spec cases exercised

echo "=== A. EXHAUSTIVE truth table: 9 whitelisted names x widths {0,4,8,16} ==="
# Every whitelisted name crossed with every edge width. 9 x 4 = 36 cells, each
# asserting BOTH verdict string and exit code against the spec table.
for n in $NUMERIC $HOOKS; do
  for bytes in 0 4 8 16; do
    vh=$(zhex "$bytes")
    exp_v=$(expected_verdict "$n" "$bytes")
    exp_rc=$(expected_rc "$exp_v")
    "$W" param-change-lint --name "$n" --value-hex "$vh" >/dev/null 2>&1; rc=$?
    got_v=$(verdict_of "$n" "$vh")
    assert "$([ "$got_v" = "$exp_v" ] && [ "$rc" = "$exp_rc" ] && echo true || echo false)" \
      "$n + $bytes bytes -> $exp_v exit $exp_rc (got $got_v exit $rc)"
    cases=$((cases + 1))
  done
done

echo "=== B. OFF-list names -> UNKNOWN_NAME exit 2 (incl. structural near-misses) ==="
# Random off-list names + deliberate near-misses (wrong case, const-leaf-but-not-
# whitelisted, trailing space-ish). All must be UNKNOWN regardless of width.
OFFLIST="bogus_param block_subsidy MIN_stake Min_Stake TX_COMMIT_MS unstake_delay param_keyholder min_stake_x SUSPENSION_slash"
for n in $OFFLIST; do
  for bytes in 0 8; do
    vh=$(zhex "$bytes")
    "$W" param-change-lint --name "$n" --value-hex "$vh" >/dev/null 2>&1; rc=$?
    got_v=$(verdict_of "$n" "$vh")
    assert "$([ "$got_v" = "UNKNOWN_NAME" ] && [ "$rc" = "2" ] && echo true || echo false)" \
      "off-list '$n' + $bytes bytes -> UNKNOWN_NAME exit 2 (got $got_v exit $rc)"
    cases=$((cases + 1))
  done
done

echo "=== C. FIXED-SEED FUZZ: random name x random width, verdict == truth table ==="
# >= 20 random cases. Names drawn from {9 whitelisted} U {a few off-list}; widths
# drawn from {0,1,2,4,7,8,9,16,32} (every parity + the 8-byte boundary +/- 1).
# The non-8/non-numeric widths exercise the INERT_BAD_WIDTH boundary precisely.
$PY - "$T" <<'PY'
import json, random, sys
T = sys.argv[1]
random.seed(0xC0FFEE07)  # fixed -> reproducible
names = ["MIN_STAKE","SUSPENSION_SLASH","UNSTAKE_DELAY",
         "tx_commit_ms","block_sig_ms","abort_claim_ms",
         "bft_escalation_threshold","param_keyholders","param_threshold",
         "bogus_param","block_subsidy","MIN_stake"]
widths = [0,1,2,4,7,8,9,16,32]
cases = []
for _ in range(36):
    n = random.choice(names)
    b = random.choice(widths)
    # random value bytes of width b (content is irrelevant to the verdict — only
    # name + width matter — but randomize anyway to prove content-independence)
    vh = ''.join('%02x' % random.getrandbits(8) for _ in range(b))
    cases.append({"name": n, "bytes": b, "value_hex": vh})
json.dump(cases, open(f"{T}/fuzz.json", "w"))
PY
NF=$($PY -c "import json;print(len(json.load(open('$T/fuzz.json'))))")
i=0
while [ "$i" -lt "$NF" ]; do
  n=$($PY -c "import json;print(json.load(open('$T/fuzz.json'))[$i]['name'])")
  b=$($PY -c "import json;print(json.load(open('$T/fuzz.json'))[$i]['bytes'])")
  vh=$($PY -c "import json;print(json.load(open('$T/fuzz.json'))[$i]['value_hex'])")
  exp_v=$(expected_verdict "$n" "$b")
  exp_rc=$(expected_rc "$exp_v")
  "$W" param-change-lint --name "$n" --value-hex "$vh" >/dev/null 2>&1; rc=$?
  got_v=$(verdict_of "$n" "$vh")
  assert "$([ "$got_v" = "$exp_v" ] && [ "$rc" = "$exp_rc" ] && echo true || echo false)" \
    "fuzz[$i] $n + $b bytes -> $exp_v exit $exp_rc (got $got_v exit $rc)"
  cases=$((cases + 1))
  i=$((i + 1))
done

echo "=== D. --tx-json ROUND-TRIP: build a real PARAM_CHANGE, lint the built tx ==="
# Build via param-change-build with random whitelisted name + width, then lint the
# BUILT tx via --tx-json. The payload-decoded verdict must EXACTLY equal what the
# direct --name/--value-hex path yields for the same name+width (cross-path
# agreement) AND the truth-table prediction. Catches any payload-encode/decode
# width drift (the value bytes are spliced into the PARAM_CHANGE payload and must
# re-decode to the identical byte count).
#
# param-change-build requires a whitelisted name (off-list names are rejected at
# build time), so this arm draws only from the 9 whitelisted names.
$PY - "$T" <<'PY'
import json, random, sys
T = sys.argv[1]
random.seed(0x5EED0B71)  # distinct fixed seed for the build arm
names = ["MIN_STAKE","SUSPENSION_SLASH","UNSTAKE_DELAY",
         "tx_commit_ms","block_sig_ms","abort_claim_ms",
         "bft_escalation_threshold","param_keyholders","param_threshold"]
widths = [0,1,2,4,7,8,9,16]   # span the 8-byte boundary both ways
cases = []
for _ in range(24):
    n = random.choice(names)
    b = random.choice(widths)
    vh = ''.join('%02x' % random.getrandbits(8) for _ in range(b))
    cases.append({"name": n, "bytes": b, "value_hex": vh})
json.dump(cases, open(f"{T}/build.json", "w"))
PY
NB=$($PY -c "import json;print(len(json.load(open('$T/build.json'))))")
j=0
while [ "$j" -lt "$NB" ]; do
  n=$($PY -c "import json;print(json.load(open('$T/build.json'))[$j]['name'])")
  b=$($PY -c "import json;print(json.load(open('$T/build.json'))[$j]['bytes'])")
  vh=$($PY -c "import json;print(json.load(open('$T/build.json'))[$j]['value_hex'])")

  # Build the canonical PARAM_CHANGE body. --value-hex accepts empty for 0-byte.
  if [ "$b" -eq 0 ]; then
    "$W" param-change-build --name "$n" --value-hex "" --effective-height 100 \
        --nonce 0 --from node1 --out "$T/b$j.json" >/dev/null 2>&1
  else
    "$W" param-change-build --name "$n" --value-hex "$vh" --effective-height 100 \
        --nonce 0 --from node1 --out "$T/b$j.json" >/dev/null 2>&1
  fi
  if [ ! -s "$T/b$j.json" ]; then
    assert false "build[$j] $n + $b bytes produced no tx file"
    cases=$((cases + 1)); j=$((j + 1)); continue
  fi

  exp_v=$(expected_verdict "$n" "$b")
  exp_rc=$(expected_rc "$exp_v")

  # Lint the BUILT tx via the --tx-json arm; capture verdict + rc.
  bt_v=$("$W" param-change-lint --tx-json "$T/b$j.json" --json 2>/dev/null \
    | $PY -c "import json,sys;print(json.load(sys.stdin)['verdict'])" 2>/dev/null)
  "$W" param-change-lint --tx-json "$T/b$j.json" >/dev/null 2>&1; bt_rc=$?

  # Cross-path: direct --name/--value-hex on the SAME inputs must agree too.
  direct_v=$(verdict_of "$n" "$vh")

  assert "$([ "$bt_v" = "$exp_v" ] && [ "$bt_rc" = "$exp_rc" ] && [ "$direct_v" = "$exp_v" ] && echo true || echo false)" \
    "tx-json[$j] $n + $b bytes -> $exp_v exit $exp_rc (built=$bt_v/$bt_rc direct=$direct_v)"

  # And the built payload must re-decode to the SAME byte width we asked for.
  dec_b=$("$W" param-change-lint --tx-json "$T/b$j.json" --json 2>/dev/null \
    | $PY -c "import json,sys;print(json.load(sys.stdin)['value_bytes'])" 2>/dev/null)
  assert "$([ "$dec_b" = "$b" ] && echo true || echo false)" \
    "tx-json[$j] payload re-decodes to $b bytes (got $dec_b)"

  cases=$((cases + 2))
  j=$((j + 1))
done

echo "=== E. arg-validation edges (parse-failure exit 1, NOT a verdict) ==="
# These are NOT verdict cases — the lint must exit 1 (args/parse error), distinct
# from the 0/2 verdict codes. Confirms width/format rejection happens before the
# truth-table classification.
"$W" param-change-lint --name MIN_STAKE --value-hex 012 >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "odd-length hex -> exit 1 (parse error)"
"$W" param-change-lint --name MIN_STAKE --value-hex zzzz >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "non-hex value -> exit 1 (parse error)"
"$W" param-change-lint --name MIN_STAKE --value-hex 0000000000000000 --tx-json "$T/x.json" >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "--name + --tx-json mutually exclusive -> exit 1"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail  (over $cases truth-table + fuzz + round-trip cases)"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_wallet_param_change_lint_fuzz"; exit 0
else
  echo "  FAIL: test_wallet_param_change_lint_fuzz"; exit 1
fi
