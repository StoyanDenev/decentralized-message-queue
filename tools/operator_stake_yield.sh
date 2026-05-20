#!/usr/bin/env bash
# operator_stake_yield.sh — Per-validator yield audit (subsidy + fees
# earned per unit stake) over a window of finalized blocks.
#
# Member of the operator_*.sh family. Read-only RPC composition; safe
# against a running daemon. The script walks the requested window via
# `determ block-info <h> --json` (one round-trip per block) to collect
# each block's `creators` list + per-transaction `fee` field, then
# attributes per-creator earnings using the apply-side FA-Apply-6 /
# FA-Apply-7 distribution rule from chain.cpp::apply_block:
#
#   total_distributed = total_fees + subsidy_this_block
#   per_creator       = total_distributed / |creators|
#   dust              = total_distributed % |creators|  → credited to creators[0]
#
# The script splits the per-creator credit into a subsidy component
# (subsidy_this_block / |creators|) and a fees component (total_fees /
# |creators|) so operators can see where the yield is coming from.
# Per-creator totals for the window sum the per-block contributions.
#
# RPC-shape note: identical to operator_subsidy_audit.sh — there is no
# "supply as-of-block-N" RPC; the chain only exposes
# `accumulated_subsidy` at the current head. We therefore estimate
# per-block subsidy as `accumulated_subsidy_head / height_head` (the
# lifetime average mint per block). For FLAT subsidy mode (default) this
# is exact. For E3 lottery mode it is an expectation (jackpot blocks
# pay block_subsidy * M, miss blocks pay 0; the average is identical).
#
# Fees note: chain.cpp's `charge_fee` only accumulates fee on *successful*
# applies (failed fee-charge → `continue` skip; A1 invariant verifies at
# end of apply). Without replay we cannot tell which txs were skipped.
# We therefore sum `block.transactions[].fee` as a best-effort upper
# bound on `total_fees`; in practice the divergence is tiny because
# (a) most block-included txs have already passed mempool admission
# (which already checks sender balance / nonce) and (b) the script
# documents this as an estimate. Operators wanting exact per-block fees
# can replay against the snapshot.
#
# Window: --from H --to H (inclusive). Default = last 1000 blocks
# ending at current head, clamped to genesis.
#
# Yield formulas:
#   window_earnings    = subsidy_earned + fees_earned   (per validator)
#   window_yield       = window_earnings / current_stake
#   annualized_yield   = window_yield * (seconds_per_year / window_seconds)
#                      where window_seconds = block[to].timestamp -
#                                             block[from].timestamp
#                      If window_seconds <= 0 (clock skew / 1-block
#                      window), annualized_yield is reported as -1
#                      (unavailable) instead of inf.
#
# Anomaly flags (--anomalies-only filters output to only these and
# changes exit code to 2 if any fired):
#   * concentration         single validator's yield > 5x median yield
#                           (block-creation concentration → fairness
#                           red flag; selection rotation may need
#                           tuning, see RegionalSharding R4)
#   * zero_earnings         validator with stake but earned NOTHING
#                           over the window (likely offline; operator
#                           should check node health / committee
#                           selection eligibility — see S-020)
#   * negative_yield        earnings < 0 (slashing exceeded rewards in
#                           the window). NOTE: in the current chain
#                           model fees + subsidy are non-negative and
#                           slashing affects `locked` not earnings, so
#                           this is a forward-compatibility hook for
#                           future reward-claw-back semantics; today
#                           it cannot fire.
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_stake_yield.sh [--rpc-port N] [--json]
                                [--from H] [--to H]
                                [--anomalies-only]

Per-validator yield audit. Walks a window of finalized blocks, attributes
per-creator subsidy + fees per the apply-side distribution rule, and
divides by current stake to surface yield + annualized yield, plus
top-10 / bottom-10 distribution + median.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Lower window bound (inclusive). Default:
                      max(0, head - 1000 + 1)
  --to H              Upper window bound (inclusive). Default: head
  --anomalies-only    Print only flagged validators; exit 2 if any
                      anomaly fired
  -h, --help          Show this help

Anomaly flags:
  concentration      validator yield > 5x median (block-creation
                     concentration / fairness red flag)
  zero_earnings      validator with stake earned 0 in window (offline?)
  negative_yield     earnings < 0 (forward-compat; cannot fire today)

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";  shift 2 ;;
    --json)            JSON_OUT=1;     shift ;;
    --from)            FROM_H="${2:-}"; shift 2 ;;
    --to)              TO_H="${2:-}";   shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;    shift ;;
    *) echo "operator_stake_yield: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_stake_yield: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_stake_yield: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_stake_yield: jq is required (block JSON is too nested for grep)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_stake_yield: python (or python3) is required for the per-block walk" >&2
  exit 1
fi
PYTHON=python
command -v python >/dev/null 2>&1 || PYTHON=python3

# ── Step 1: chain head + lifetime subsidy ─────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_yield: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_stake_yield: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1 (height is the NEXT-to-produce).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Lifetime accumulated_subsidy via supply --field (bare scalar).
ACCUM=$("$DETERM" supply --field accumulated_subsidy --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_yield: cannot reach supply RPC (port $PORT)" >&2
  exit 1
}
case "$ACCUM" in *[!0-9]*|"")
  echo "operator_stake_yield: supply returned non-numeric '$ACCUM' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at top (per spec).
FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))}
TO=${TO_H:-$TOP}
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_stake_yield: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# Estimated per-block subsidy (lifetime average; see header).
if [ "$HEIGHT" -gt 0 ]; then
  EST_PER_BLOCK_SUBSIDY=$(( ACCUM / HEIGHT ))
else
  EST_PER_BLOCK_SUBSIDY=0
fi

# ── Step 2: stakes table ──────────────────────────────────────────────────────
STAKES_JSON=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_yield: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}
VALIDATOR_COUNT=$(printf '%s' "$STAKES_JSON" | jq 'length')

# Build target-domain → stake map (locked == stake field on `validators` RPC).
TMP_STAKES=$(mktemp 2>/dev/null) || {
  echo "operator_stake_yield: cannot create temp file" >&2; exit 1;
}
TMP_LEDGER=$(mktemp 2>/dev/null) || {
  echo "operator_stake_yield: cannot create temp file" >&2; exit 1;
}
TMP_WIN=$(mktemp 2>/dev/null) || {
  echo "operator_stake_yield: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STAKES" "$TMP_LEDGER" "$TMP_WIN" 2>/dev/null' EXIT

printf '%s' "$STAKES_JSON" | jq -r '.[] | [.domain, .stake] | @tsv' >"$TMP_STAKES"

# ── Step 3: per-block walk + per-creator subsidy/fees attribution ────────────
# Python driver: parse block JSON, sum fees, split distribution into
# subsidy share + fees share per creator. Output TSV ledger:
#   domain<TAB>blocks_present<TAB>subsidy_earned<TAB>fees_earned
# Plus a one-line TMP_WIN: <window_seconds>\t<first_ts>\t<last_ts>\t<empty_blocks>
"$PYTHON" - "$DETERM" "$PORT" "$FROM" "$TO" "$EST_PER_BLOCK_SUBSIDY" \
                     "$TMP_STAKES" "$TMP_LEDGER" "$TMP_WIN" <<'PY' || {
  echo "operator_stake_yield: block walk failed" >&2; exit 1;
}
import json, subprocess, sys
from collections import defaultdict

(determ, port, from_h, to_h, est_per_block_subsidy,
 stakes_path, ledger_path, win_path) = sys.argv[1:9]
from_h        = int(from_h)
to_h          = int(to_h)
est_per_block_subsidy = int(est_per_block_subsidy)

# Load validator-domain set (we only track these; non-validator creators
# are normal — pre-active stakers or post-deregistered domains can still
# appear in `creators[]` during their active window, but if they are not
# currently in `determ stakes` we have no current-stake denominator to
# compute yield against, so we skip them).
validator_stakes = {}
with open(stakes_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line: continue
        parts = line.split("\t")
        if len(parts) != 2: continue
        d, s = parts
        try:
            validator_stakes[d] = int(s)
        except ValueError:
            continue

blocks_present = defaultdict(int)
subsidy_earned = defaultdict(int)
fees_earned    = defaultdict(int)

empty_blocks    = 0
first_ts        = None
last_ts         = None

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_stake_yield: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_stake_yield: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_stake_yield: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    # Timestamp tracking for annualization window.
    ts = blk.get("timestamp", None)
    if isinstance(ts, int):
        if first_ts is None: first_ts = ts
        last_ts = ts

    creators = blk.get("creators") or []
    if not isinstance(creators, list) or len(creators) == 0:
        empty_blocks += 1
        continue

    # Sum block.transactions[].fee (best-effort upper bound; header note).
    total_fees = 0
    for tx in (blk.get("transactions") or []):
        if not isinstance(tx, dict): continue
        f = tx.get("fee", 0)
        try:
            total_fees += int(f)
        except (TypeError, ValueError):
            continue

    m         = len(creators)
    sub_each  = est_per_block_subsidy // m
    sub_rem   = est_per_block_subsidy - sub_each * m
    fee_each  = total_fees // m
    fee_rem   = total_fees - fee_each * m

    for c in creators:
        if not isinstance(c, str): continue
        blocks_present[c] += 1
        subsidy_earned[c] += sub_each
        fees_earned[c]    += fee_each
    # Apply-side: dust to creators[0] (we split it across the two
    # components separately for readable accounting; the sum still
    # matches apply-side total_distributed dust crediting).
    if creators and isinstance(creators[0], str):
        subsidy_earned[creators[0]] += sub_rem
        fees_earned[creators[0]]    += fee_rem

# Emit one TSV row per VALIDATOR (zero-earning validators included so
# operators see the "stake but offline" anomaly).
with open(ledger_path, "w", encoding="utf-8") as f:
    for d in sorted(validator_stakes.keys()):
        bp  = blocks_present.get(d, 0)
        sub = subsidy_earned.get(d, 0)
        fee = fees_earned.get(d, 0)
        f.write(f"{d}\t{bp}\t{sub}\t{fee}\t{validator_stakes[d]}\n")

# Window metadata.
window_seconds = 0
if first_ts is not None and last_ts is not None and last_ts > first_ts:
    window_seconds = last_ts - first_ts
with open(win_path, "w", encoding="utf-8") as f:
    f.write(f"{window_seconds}\t{first_ts if first_ts is not None else 0}\t"
            f"{last_ts  if last_ts  is not None else 0}\t{empty_blocks}\n")
PY

# Read window metadata.
WIN_LINE=$(head -1 "$TMP_WIN" 2>/dev/null || echo "0\t0\t0\t0")
WINDOW_SECONDS=$(printf '%s' "$WIN_LINE" | cut -f1)
FIRST_TS=$(printf '%s' "$WIN_LINE" | cut -f2)
LAST_TS=$(printf '%s' "$WIN_LINE" | cut -f3)
EMPTY_BLOCKS=$(printf '%s' "$WIN_LINE" | cut -f4)
case "$WINDOW_SECONDS" in *[!0-9]*|"") WINDOW_SECONDS=0 ;; esac
case "$EMPTY_BLOCKS"   in *[!0-9]*|"") EMPTY_BLOCKS=0   ;; esac

# ── Step 4: build per-validator rows + aggregate stats (jq + python) ─────────
# Convert ledger TSV → JSON array, compute earnings + yield + annualized.
# Yields are stored as fractions (ratio): yield 0.017 == 1.7%.
ROWS_JSON=$("$PYTHON" - "$TMP_LEDGER" "$WINDOW_SECONDS" <<'PY'
import json, sys
ledger_path, window_seconds = sys.argv[1], int(sys.argv[2])
SECONDS_PER_YEAR = 365.25 * 24 * 3600

rows = []
with open(ledger_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line: continue
        parts = line.split("\t")
        if len(parts) != 5: continue
        d, bp, sub, fee, stake = parts
        bp     = int(bp)
        sub    = int(sub)
        fee    = int(fee)
        stake  = int(stake)
        earnings = sub + fee
        # Yield = earnings / stake; stake==0 → yield = 0 (avoid div0;
        # zero-stake validators shouldn't normally appear in `stakes`).
        if stake > 0:
            yld = earnings / stake
        else:
            yld = 0.0
        # Annualized: window_yield * (year / window_seconds). If we
        # don't have a positive window, report -1 (unavailable).
        if window_seconds > 0:
            ann = yld * (SECONDS_PER_YEAR / window_seconds)
        else:
            ann = -1.0
        rows.append({
            "domain":         d,
            "stake":          stake,
            "blocks_created": bp,
            "subsidy_earned": sub,
            "fees_earned":    fee,
            "earnings":       earnings,
            "yield":          yld,
            "annualized_yield": ann,
        })
# Sort by yield desc, ties by earnings desc, ties by domain asc.
rows.sort(key=lambda r: (-r["yield"], -r["earnings"], r["domain"]))
print(json.dumps(rows))
PY
)

# Aggregate stats (median, mean, max, top-10, bottom-10) via Python.
AGG_JSON=$("$PYTHON" - <<PY
import json
rows = json.loads('''$ROWS_JSON''')
n = len(rows)
if n == 0:
    print(json.dumps({"n":0,"median":0,"mean":0,"max":0,"min":0,
                      "top_10":[],"bottom_10":[]}))
else:
    yields = sorted(r["yield"] for r in rows)
    mid = n // 2
    if n % 2 == 1:
        median = yields[mid]
    else:
        median = (yields[mid - 1] + yields[mid]) / 2.0
    mean = sum(yields) / n
    mx   = max(yields)
    mn   = min(yields)
    # rows is already sorted by yield desc; top-10 is head, bottom-10 is tail.
    top_10    = rows[:10]
    bottom_10 = rows[-10:] if n > 10 else rows[:]
    # Reverse bottom_10 to ascend (lowest yield first → easier to spot
    # zero-earnings validators at the top of the bottom list).
    bottom_10 = list(reversed(bottom_10))
    print(json.dumps({"n":n,"median":median,"mean":mean,"max":mx,"min":mn,
                      "top_10":top_10,"bottom_10":bottom_10}))
PY
)

MEDIAN=$(printf '%s' "$AGG_JSON" | jq -r '.median')
MEAN=$(printf '%s' "$AGG_JSON" | jq -r '.mean')
MAX_Y=$(printf '%s' "$AGG_JSON" | jq -r '.max')
N_VALIDATORS=$(printf '%s' "$AGG_JSON" | jq -r '.n')

# ── Step 5: anomaly classification ───────────────────────────────────────────
# concentration : yield > 5x median   (only if median > 0)
# zero_earnings : stake>0 AND earnings==0
# negative_yield: yield < 0           (forward-compat)
ROWS_WITH_FLAGS=$(printf '%s' "$ROWS_JSON" | "$PYTHON" - "$MEDIAN" <<'PY'
import json, sys
median = float(sys.argv[1])
rows = json.loads(sys.stdin.read())
for r in rows:
    flags = []
    if median > 0 and r["yield"] > 5 * median:
        flags.append("concentration")
    if r["stake"] > 0 and r["earnings"] == 0:
        flags.append("zero_earnings")
    if r["yield"] < 0:
        flags.append("negative_yield")
    r["flags"]   = flags
    r["anomaly"] = len(flags) > 0
print(json.dumps(rows))
PY
)
ANOM_COUNT=$(printf '%s' "$ROWS_WITH_FLAGS" | jq '[.[] | select(.anomaly)] | length')

# Helper: render a float yield as "NN.NN%" (2 decimals). Negative → "n/a".
render_pct() {
  local raw="$1"
  "$PYTHON" - "$raw" <<'PY'
import sys
v = float(sys.argv[1])
if v < 0:
    print("n/a")
else:
    print(f"{v*100:.2f}%")
PY
}

# ── Step 6: emit output ──────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Build full JSON envelope.
  if [ "$ANOM_ONLY" = "1" ]; then
    ROWS_EMIT=$(printf '%s' "$ROWS_WITH_FLAGS" | jq -c '[.[] | select(.anomaly)]')
  else
    ROWS_EMIT="$ROWS_WITH_FLAGS"
  fi
  ANOMALIES=$(printf '%s' "$ROWS_WITH_FLAGS" | jq -c '[.[] | select(.anomaly) | {domain, flags}]')

  printf '%s' "$ROWS_EMIT" | jq -c \
    --argjson from "$FROM" --argjson to "$TO" --argjson blocks "$WIN_BLOCKS" \
    --argjson seconds "$WINDOW_SECONDS" --argjson empty "$EMPTY_BLOCKS" \
    --argjson median "$MEDIAN" --argjson mean "$MEAN" --argjson max "$MAX_Y" \
    --argjson n "$N_VALIDATORS" --argjson port "$PORT" \
    --argjson est_subsidy "$EST_PER_BLOCK_SUBSIDY" \
    --argjson accum "$ACCUM" --argjson head "$HEIGHT" \
    --argjson anomalies "$ANOMALIES" \
    '{window:{from:$from,to:$to,blocks:$blocks,seconds:$seconds,
              empty_creators_blocks:$empty},
      per_validator: .,
      median_yield:  $median,
      mean_yield:    $mean,
      max_yield:     $max,
      n_validators:  $n,
      est_per_block_subsidy: $est_subsidy,
      lifetime_accumulated_subsidy: $accum,
      head_height: $head,
      anomalies: $anomalies,
      rpc_port:  $port}'
  echo
else
  # Human renderer.
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_stake_yield: no anomalies (port $PORT, window [$FROM..$TO])"
  else
    echo "=== Stake yield (port $PORT, window [$FROM..$TO], $WIN_BLOCKS blocks) ==="
    if [ "$WINDOW_SECONDS" -gt 0 ]; then
      echo "Window span     : ${WINDOW_SECONDS}s (first_ts=$FIRST_TS, last_ts=$LAST_TS)"
    else
      echo "Window span     : (annualization unavailable — single block or non-monotone timestamps)"
    fi
    echo "Est subsidy/blk : $EST_PER_BLOCK_SUBSIDY  (lifetime accumulated_subsidy=$ACCUM / height=$HEIGHT)"
    echo "Empty-creators  : $EMPTY_BLOCKS blocks skipped (apply-side: no payout)"
    echo "Validators      : $N_VALIDATORS"
    if [ "$N_VALIDATORS" = "0" ]; then
      echo "(no validators in active stakes; nothing to audit)"
    else
      if [ "$ANOM_ONLY" != "1" ]; then
        echo
        echo "Per-validator (sorted by yield desc):"
        # Use python to render the rows (bash lacks float formatting).
        printf '%s' "$ROWS_WITH_FLAGS" | "$PYTHON" - <<'PY'
import json, sys
rows = json.loads(sys.stdin.read())
for r in rows:
    yld_pct = f"{r['yield']*100:.2f}%"
    if r['annualized_yield'] < 0:
        ann_pct = "n/a"
    else:
        # Cap display at "very high" — annualized can blow up on tiny
        # window with one rich block. Print real number; operator
        # judges.
        ann_pct = f"{r['annualized_yield']*100:.0f}%"
        if r['annualized_yield'] > 100:  # >10000% annualized → flag visually
            ann_pct = ann_pct + " (extrapolated)"
    print(f"  {r['domain']:<28s}: stake={r['stake']}, "
          f"earned={r['earnings']} (subsidy={r['subsidy_earned']}, "
          f"fees={r['fees_earned']}), blocks={r['blocks_created']}, "
          f"yield={yld_pct}, annualized={ann_pct}")
PY
      fi
      echo
      printf 'Median yield    : %s\n' "$(render_pct "$MEDIAN")"
      printf 'Mean   yield    : %s\n' "$(render_pct "$MEAN")"
      printf 'Max    yield    : %s\n' "$(render_pct "$MAX_Y")"

      if [ "$ANOM_ONLY" != "1" ] && [ "$N_VALIDATORS" -gt 10 ]; then
        echo
        echo "Top-10 by yield:"
        printf '%s' "$AGG_JSON" | jq -c '.top_10[]' | while IFS= read -r row; do
          D=$(printf '%s' "$row" | jq -r '.domain')
          Y=$(printf '%s' "$row" | jq -r '.yield')
          E=$(printf '%s' "$row" | jq -r '.earnings')
          BP=$(printf '%s' "$row" | jq -r '.blocks_created')
          printf '  %-28s yield=%s, earned=%s (%s blocks)\n' \
            "$D" "$(render_pct "$Y")" "$E" "$BP"
        done
        echo
        echo "Bottom-10 by yield:"
        printf '%s' "$AGG_JSON" | jq -c '.bottom_10[]' | while IFS= read -r row; do
          D=$(printf '%s' "$row" | jq -r '.domain')
          Y=$(printf '%s' "$row" | jq -r '.yield')
          E=$(printf '%s' "$row" | jq -r '.earnings')
          BP=$(printf '%s' "$row" | jq -r '.blocks_created')
          printf '  %-28s yield=%s, earned=%s (%s blocks)\n' \
            "$D" "$(render_pct "$Y")" "$E" "$BP"
        done
      fi
      echo
      if [ "$ANOM_COUNT" = "0" ]; then
        echo "[OK] No yield anomalies"
      else
        echo "[ANOMALY] $ANOM_COUNT validator(s) flagged:"
        printf '%s' "$ROWS_WITH_FLAGS" | jq -c '.[] | select(.anomaly) | {domain, flags}' \
          | while IFS= read -r entry; do
          D=$(printf '%s' "$entry" | jq -r '.domain')
          F=$(printf '%s' "$entry" | jq -r '.flags | join(",")')
          echo "  $D : $F"
        done
      fi
    fi
  fi
fi

# ── Step 7: exit-code policy ─────────────────────────────────────────────────
# Same convention as the rest of the operator_*.sh family: exit 2 only
# when --anomalies-only is set AND ≥1 anomaly fired. Informational mode
# always exits 0 on a successful RPC walk.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
