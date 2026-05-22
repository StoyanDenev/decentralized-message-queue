#!/usr/bin/env bash
# operator_subsidy_audit.sh — Audit E1/E3/E4 subsidy distribution over a
# window of blocks. Reports total subsidy minted, per-validator share,
# nef_pool / subsidy_pool drain (live snapshots), and flags
# distribution-drift / pool-exhaustion / concentration anomalies.
#
# Read-only RPC composition; safe against a running daemon. The script
# walks the requested window via `determ block-info <h> --json` (one
# round-trip per block) to collect each block's `creators` list, then
# attributes a per-block subsidy share across creators per the apply-side
# distribution rule in `chain.cpp::apply_block`:
#
#     total_distributed = total_fees + subsidy_this_block
#     per_creator       = total_distributed / m
#     remainder         = total_distributed % m       → creator[0]
#
# This audit isolates the *subsidy* component only — fee distribution is
# covered by sibling `operator_fee_distribution_audit.sh`. We assume FLAT
# E3 mode for the per-block estimate; the chain's accumulated_subsidy
# counter (sampled before + after the walk) is the authoritative window
# total. Sibling `operator_subsidy_lottery_audit.sh` handles LOTTERY
# (E3 mode 1) fairness analysis.
#
# Three economic surfaces touched, all per the project memory's E-track:
#
#   E1 (Negative Entry Fee — NEF):  pool seeded at genesis via
#       `zeroth_pool_initial`, held in the canonical ZEROTH_ADDRESS
#       pseudo-account, halves on each *first-time* REGISTER. Drains
#       geometrically toward 0 (E4 finite-pool drain). The script reads
#       the live ZEROTH_ADDRESS balance (single `determ balance` call)
#       as the operator-facing E1 surface; once it hits 0, subsequent
#       first-time REGISTERs receive no NEF subsidy.
#
#   E3 (block_subsidy distribution):  the per-block mint that funds
#       creators on top of transaction fees. In FLAT mode this is exactly
#       block_subsidy_ per block; in LOTTERY mode it's a two-point draw
#       with same expectation. The audit attributes window subsidy across
#       creators using the apply-side equal-split + remainder-to-creator[0]
#       rule, and reports per-validator selections + total credited + the
#       avg per selection.
#
#   E4 (finite-pool drain):  when `subsidy_pool_initial != 0` the chain
#       hard-caps cumulative subsidy at that pool value. Once
#       accumulated_subsidy reaches subsidy_pool_initial, every
#       subsequent block pays 0 subsidy and the chain runs on fees alone.
#       The audit estimates remaining-pool by comparing window subsidy
#       delta to a configurable critical-low threshold.
#
# RPC-shape note: there is no "supply as-of-block-N" RPC; the chain
# exposes `accumulated_subsidy` (and ZEROTH_ADDRESS balance) only at
# the current head. The audit therefore (a) snapshots both counters
# BEFORE walking the window, (b) walks the window, (c) snapshots again
# AFTER, and (d) treats the delta as the authoritative window total.
# For windows that don't include the head, the delta only captures
# subsidy minted during the walk itself — operators auditing historical
# windows on an idle chain see delta ≈ 0; the per-block estimate
# (--block-subsidy or the accumulated_subsidy/height heuristic) is the
# fallback distribution basis.
#
# Usage:
#   tools/operator_subsidy_audit.sh --rpc-port N
#                                   [--from H] [--to H] [--last N]
#                                   [--block-subsidy V]
#                                   [--subsidy-pool-initial V]
#                                   [--subsidy-pool-critical-low V]
#                                   [--json] [--anomalies-only]
#
# RPC dependencies (all read-only):
#   - head                                        (current chain height)
#   - supply  (--field accumulated_subsidy)       (E3/E4 cumulative mint)
#   - balance (--rpc-port, ZEROTH_ADDRESS arg)    (E1 NEF pool balance)
#   - block-info <h>                              (per-block JSON walk)
#
# Anomaly flags (each adds an entry to anomalies[]):
#
#   subsidy_distribution_drift   — Σ per-validator subsidy credit (from
#                                   the per-block attribution loop) ≠
#                                   Σ per-block subsidy (cross-check).
#                                   Tolerance: 1 unit (rounds out integer-
#                                   division remainder which already goes
#                                   to creator[0] but might accumulate
#                                   in edge-case float promotion). Bug-
#                                   signal: implies an apply-layer
#                                   accounting drift.
#
#   nef_pool_exhausted           — live ZEROTH_ADDRESS balance == 0.
#                                   E4 drain hit on the NEF pool: any
#                                   first-time REGISTER from this point
#                                   on will receive no NEF subsidy.
#                                   Informational (not a defect) — but
#                                   operators should know.
#
#   subsidy_pool_critical_low    — remaining_subsidy_pool < threshold.
#                                   Requires --subsidy-pool-initial to
#                                   be set (otherwise the chain runs in
#                                   perpetual-subsidy mode — there's no
#                                   pool to drain). Threshold defaults
#                                   to 5× per-block subsidy (≈ 5 more
#                                   blocks of full payout before the
#                                   pool drains), overridable via
#                                   --subsidy-pool-critical-low.
#
#   subsidy_concentration_high   — top-1 validator received > 30% of
#                                   total subsidy in window. Tighter
#                                   gate than operator_fee_distribution's
#                                   50% top-1 threshold: subsidy is the
#                                   structural reward (independent of tx
#                                   activity); a single creator owning
#                                   >30% of it signals committee-skew
#                                   beyond what statistical noise would
#                                   produce in a healthy K≥3 chain.
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_subsidy_audit.sh --rpc-port N
                                 [--from H] [--to H] [--last N]
                                 [--block-subsidy V]
                                 [--subsidy-pool-initial V]
                                 [--subsidy-pool-critical-low V]
                                 [--json] [--anomalies-only]

Audit E1/E3/E4 subsidy distribution over a block window. Walks blocks
via `determ block-info <h> --json`, attributes per-block subsidy across
creators per the apply-side split rule (1/m each + remainder to
creators[0]), and reports per-validator selections + concentration +
nef_pool / subsidy_pool live snapshots.

Required:
  --rpc-port N                    RPC port to query (no default — refuses
                                  to guess the daemon on multi-instance
                                  hosts).

Window (mutually exclusive groups; --last cannot be combined with
--from / --to):
  --from H                        Start of audit window (inclusive)
  --to H                          End   of audit window (inclusive)
                                  Default: [max(0, tip-100), tip]
  --last N                        Shorthand for [tip-N+1, tip]

Distribution basis (optional — operator-authoritative overrides):
  --block-subsidy V               Per-block subsidy value (FLAT-mode
                                  authoritative). If omitted, the script
                                  uses (accumulated_subsidy / height) as
                                  a lifetime-average heuristic.
  --subsidy-pool-initial V        E4 finite-pool size (from genesis).
                                  Without this, subsidy_pool_critical_low
                                  cannot fire (perpetual-subsidy mode).
  --subsidy-pool-critical-low V   Critical threshold for remaining pool;
                                  default = 5 × block_subsidy.

Output:
  --json                          Emit structured JSON envelope.
  --anomalies-only                Print only flagged anomalies; exit 2
                                  if any fire.
  -h, --help                      Show this help

Anomaly flags:
  subsidy_distribution_drift      Σ per-validator credit ≠ Σ per-block
                                  subsidy (apply-layer accounting bug)
  nef_pool_exhausted              live ZEROTH_ADDRESS balance == 0
                                  (E4 hit the NEF pool — no more E1)
  subsidy_pool_critical_low       remaining_subsidy_pool < threshold
                                  (E4 about to terminate block subsidy)
  subsidy_concentration_high      top-1 validator > 30% of window subsidy

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
LAST_N=""
BLOCK_SUBSIDY_OVR=""
SUBSIDY_POOL_INITIAL=""
SUBSIDY_POOL_CRIT_LOW=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                       usage; exit 0 ;;
    --rpc-port)                      PORT="${2:-}";                 shift 2 ;;
    --json)                          JSON_OUT=1;                    shift ;;
    --from)                          FROM_H="${2:-}";               shift 2 ;;
    --to)                            TO_H="${2:-}";                 shift 2 ;;
    --last)                          LAST_N="${2:-}";               shift 2 ;;
    --block-subsidy)                 BLOCK_SUBSIDY_OVR="${2:-}";    shift 2 ;;
    --subsidy-pool-initial)          SUBSIDY_POOL_INITIAL="${2:-}"; shift 2 ;;
    --subsidy-pool-critical-low)     SUBSIDY_POOL_CRIT_LOW="${2:-}";shift 2 ;;
    --anomalies-only)                ANOM_ONLY=1;                   shift ;;
    *) echo "operator_subsidy_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (sibling-script convention; refuses to guess
# the daemon on multi-instance hosts — matches operator_committee_audit).
if [ -z "$PORT" ]; then
  echo "operator_subsidy_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_subsidy_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# --last is mutually exclusive with --from / --to (avoids the ambiguous
# case where an operator sets both and the intent is unclear).
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_subsidy_audit: --last cannot be combined with --from / --to" >&2
  exit 1
fi
for v in "$FROM_H" "$TO_H" "$LAST_N" \
         "$BLOCK_SUBSIDY_OVR" "$SUBSIDY_POOL_INITIAL" "$SUBSIDY_POOL_CRIT_LOW"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_subsidy_audit: numeric option must be unsigned integer (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST_N" ] && [ "$LAST_N" = "0" ]; then
  echo "operator_subsidy_audit: --last must be >= 1" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works
# the same on Linux/Mac/Git Bash (matches operator_dapp_inventory.sh +
# operator_committee_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ZEROTH_ADDRESS canonical anon address (matches
# include/determ/chain/params.hpp::ZEROTH_ADDRESS exactly). Hard-coded
# here rather than re-read per call — it's a chain constant.
ZEROTH_ADDR="0x0000000000000000000000000000000000000000000000000000000000000000"

# ── Step 1: resolve current tip + take "before" snapshot ────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_subsidy_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Lifetime accumulated_subsidy via supply --field (single bare scalar).
# Two snapshots (before + after walk) give us the authoritative subsidy
# minted during the window-walk interval — useful for windows that
# include the head and the chain is producing during the audit.
ACCUM_BEFORE=$("$DETERM" supply --field accumulated_subsidy --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot reach supply RPC (port $PORT)" >&2
  exit 1
}
case "$ACCUM_BEFORE" in *[!0-9]*|"")
  echo "operator_subsidy_audit: supply returned non-numeric '$ACCUM_BEFORE' (port $PORT)" >&2
  exit 1 ;;
esac

# NEF pool live balance (ZEROTH_ADDRESS). The E1 pool. Halves on each
# first-time REGISTER; drains geometrically toward 0 (E4 finite-pool).
# Note: `determ balance` returns JSON {"balance": N, ...}; extract the
# scalar with python (jq is optional in the project test env).
NEF_BEFORE_RAW=$("$DETERM" balance "$ZEROTH_ADDR" --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot reach balance RPC (port $PORT)" >&2
  exit 1
}
NEF_BEFORE=$(printf '%s' "$NEF_BEFORE_RAW" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('balance', 0)))
except Exception:
    print('')
")
case "$NEF_BEFORE" in *[!0-9]*|"")
  echo "operator_subsidy_audit: balance for ZEROTH_ADDRESS returned non-numeric '$NEF_BEFORE'" >&2
  exit 1 ;;
esac

# ── Step 2: resolve window bounds ────────────────────────────────────────────
# Precedence: --last > (--from / --to) > defaults (last 100).
#
# Index semantics: `head --field height` returns *total block count*
# (block 0 = genesis, blocks 1..(height-1) are produced). Highest valid
# index = height - 1. Block-info on an out-of-range index errors out
# (see operator_committee_audit.sh's same handling).
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ -n "$LAST_N" ]; then
  if [ "$LAST_N" -gt $(( TOP + 1 )) ]; then LAST_N=$(( TOP + 1 )); fi
  FROM=$(( TOP + 1 - LAST_N ))
  TO=$TOP
else
  FROM=${FROM_H:-$(( TOP > 100 ? TOP - 100 : 0 ))}
  TO=${TO_H:-$TOP}
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_subsidy_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: determine per-block subsidy basis ─────────────────────────────────
# Precedence: --block-subsidy override > lifetime average heuristic.
# The override is the FLAT-mode authoritative value (operator must
# supply the same value the chain's genesis encoded). The heuristic
# is exact for any FLAT chain that ran without slashing-during-apply,
# and an expectation for LOTTERY chains (jackpot rates → block_subsidy
# in the long run).
if [ -n "$BLOCK_SUBSIDY_OVR" ]; then
  EST_PER_BLOCK=$BLOCK_SUBSIDY_OVR
  EST_SOURCE="override"
elif [ "$HEAD_H" -gt 0 ]; then
  EST_PER_BLOCK=$(( ACCUM_BEFORE / HEAD_H ))
  EST_SOURCE="heuristic"
else
  EST_PER_BLOCK=0
  EST_SOURCE="zero-height"
fi

# ── Step 4: walk the window + attribute per-creator shares ────────────────────
# Python driver: handles JSON parsing + per-creator accumulation. Each
# non-empty-creator block contributes EST_PER_BLOCK to its creators
# (equal split via integer division; remainder to creators[0]).
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$EST_PER_BLOCK" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, est_per_block, out_path = sys.argv[1:7]
from_h        = int(from_h)
to_h          = int(to_h)
est_per_block = int(est_per_block)

# Per-validator state.
# selections[domain]      = count of blocks in [from, to] where domain
#                           appeared in the `creators` list
# subsidy_credit[domain]  = sum over those blocks of (est_per_block / m
#                           + remainder if domain == creators[0]).
# Matches chain.cpp::apply_block split:
#     per_creator = total / m
#     remainder   = total % m  → creators[0]
# We attribute the *subsidy* component only — fee component covered by
# operator_fee_distribution_audit.sh.
selections     = defaultdict(int)
subsidy_credit = defaultdict(int)
empty_blocks   = 0       # blocks with zero creators (no subsidy paid)
per_block_sum  = 0       # sum of est_per_block over non-empty-creator blocks
                         # (subsidy-distribution-drift cross-check)

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_subsidy_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_subsidy_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_subsidy_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue
    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []
    if len(creators) == 0:
        empty_blocks += 1
        continue   # apply-side: no creators ⇒ no subsidy credited

    per_block_sum += est_per_block
    m = len(creators)
    each = est_per_block // m
    rem  = est_per_block - each * m   # equivalent to est_per_block % m
    for c in creators:
        if not isinstance(c, str):
            continue
        selections[c]    += 1
        subsidy_credit[c] += each
    # Remainder credited to first creator only (matches chain.cpp).
    first = creators[0] if creators else None
    if isinstance(first, str):
        subsidy_credit[first] += rem

# Per-validator ledger sorted by subsidy_credit desc (ties by name asc).
rows = sorted(
    subsidy_credit.items(),
    key=lambda kv: (-kv[1], kv[0])
)

# Cross-check: Σ per-validator credit should equal Σ per-block subsidy.
# Tolerance of 1 unit covers any integer-rounding artifact (in practice
# the remainder allocation reconciles exactly).
total_credit = sum(v for _, v in rows)

per_validator = []
for c, credit in rows:
    n_sel = selections[c]
    avg = credit // n_sel if n_sel > 0 else 0
    per_validator.append({
        "validator":            c,
        "selections":           n_sel,
        "subsidy_credit":       credit,
        "avg_credit_per_sel":   avg,
        "share_bps":            (credit * 10000 // total_credit) if total_credit > 0 else 0,
    })

# Top-N concentration (top-1 + top-3 — same shape as fee audit).
top_1_share_bps = per_validator[0]["share_bps"] if per_validator else 0
top_1_validator = per_validator[0]["validator"] if per_validator else ""
top_3_amt = sum((row["subsidy_credit"] for row in per_validator[:3]), 0)
top_3_share_bps = (top_3_amt * 10000 // total_credit) if total_credit > 0 else 0

distinct_validators = len(selections)

result = {
    "total_credit":         total_credit,
    "per_block_sum":        per_block_sum,
    "distinct_validators":  distinct_validators,
    "empty_blocks":         empty_blocks,
    "top_1_share_bps":      top_1_share_bps,
    "top_3_share_bps":      top_3_share_bps,
    "top_1_validator":      top_1_validator,
    "per_validator":        per_validator,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_subsidy_audit: block-walk failed" >&2
  exit 1
fi

# ── Step 5: take "after" snapshot of supply + nef_pool ────────────────────────
# The post-walk delta on accumulated_subsidy is the authoritative
# window subsidy total IF the chain was producing during the walk AND
# the window's `--to` matched the head. For historical windows the
# delta is ~0 and we report the per-block estimate as the canonical
# distribution basis.
ACCUM_AFTER=$("$DETERM" supply --field accumulated_subsidy --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot reach supply RPC for post-snapshot" >&2
  exit 1
}
case "$ACCUM_AFTER" in *[!0-9]*|"") ACCUM_AFTER=$ACCUM_BEFORE ;; esac

NEF_AFTER_RAW=$("$DETERM" balance "$ZEROTH_ADDR" --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot reach balance RPC for post-snapshot" >&2
  exit 1
}
NEF_AFTER=$(printf '%s' "$NEF_AFTER_RAW" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('balance', 0)))
except Exception:
    print('')
")
case "$NEF_AFTER" in *[!0-9]*|"") NEF_AFTER=$NEF_BEFORE ;; esac

# Deltas (post-walk minus pre-walk). subsidy_delta represents fresh mint
# observed during the walk; nef_pool_delta represents fresh first-time
# REGISTERs that drained the pool.
SUBSIDY_DELTA=$(( ACCUM_AFTER - ACCUM_BEFORE ))
NEF_DELTA=$(( NEF_BEFORE - NEF_AFTER ))    # pool drains, so before >= after
if [ "$SUBSIDY_DELTA" -lt 0 ]; then SUBSIDY_DELTA=0; fi   # defensive

# E4 remaining-pool projection (when subsidy_pool_initial is supplied).
REMAINING_POOL=""
SUBSIDY_POOL_THRESHOLD=""
SUBSIDY_POOL_LOW=0
if [ -n "$SUBSIDY_POOL_INITIAL" ]; then
  if [ "$SUBSIDY_POOL_INITIAL" -ge "$ACCUM_AFTER" ]; then
    REMAINING_POOL=$(( SUBSIDY_POOL_INITIAL - ACCUM_AFTER ))
  else
    REMAINING_POOL=0
  fi
  # Threshold default: 5 × block_subsidy (≈ 5 more blocks before drain).
  # Override via --subsidy-pool-critical-low.
  if [ -n "$SUBSIDY_POOL_CRIT_LOW" ]; then
    SUBSIDY_POOL_THRESHOLD=$SUBSIDY_POOL_CRIT_LOW
  else
    SUBSIDY_POOL_THRESHOLD=$(( EST_PER_BLOCK * 5 ))
  fi
  if [ "$REMAINING_POOL" -lt "$SUBSIDY_POOL_THRESHOLD" ]; then
    SUBSIDY_POOL_LOW=1
  fi
fi

# ── Step 6: classify anomalies + render ──────────────────────────────────────
# Hand the result + thresholds + snapshot deltas to a second Python pass
# that renders the JSON or human envelope. Keeps the rendering layer in
# one place and avoids duplicate bash-side arithmetic.
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" \
        "$PORT" "$FROM" "$TO" "$WIN_BLOCKS" "$HEAD_H" \
        "$EST_PER_BLOCK" "$EST_SOURCE" \
        "$ACCUM_BEFORE" "$ACCUM_AFTER" "$SUBSIDY_DELTA" \
        "$NEF_BEFORE" "$NEF_AFTER" "$NEF_DELTA" \
        "$SUBSIDY_POOL_INITIAL" "$REMAINING_POOL" \
        "$SUBSIDY_POOL_THRESHOLD" "$SUBSIDY_POOL_LOW" <<'PY'
import json, sys

(json_out_s, anom_only_s, out_path,
 port_s, from_s, to_s, win_blocks_s, head_h_s,
 est_per_block_s, est_source,
 accum_before_s, accum_after_s, subsidy_delta_s,
 nef_before_s, nef_after_s, nef_delta_s,
 pool_initial_s, remaining_pool_s,
 pool_threshold_s, pool_low_s) = sys.argv[1:21]

json_out          = json_out_s == "1"
anom_only         = anom_only_s == "1"
port              = int(port_s)
from_h            = int(from_s)
to_h              = int(to_s)
win_blocks        = int(win_blocks_s)
head_h            = int(head_h_s)
est_per_block     = int(est_per_block_s)
accum_before      = int(accum_before_s)
accum_after       = int(accum_after_s)
subsidy_delta     = int(subsidy_delta_s)
nef_before        = int(nef_before_s)
nef_after         = int(nef_after_s)
nef_delta         = int(nef_delta_s)
pool_initial      = int(pool_initial_s) if pool_initial_s else None
remaining_pool    = int(remaining_pool_s) if remaining_pool_s else None
pool_threshold    = int(pool_threshold_s) if pool_threshold_s else None
pool_low          = pool_low_s == "1"

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total_credit  = r["total_credit"]
per_block_sum = r["per_block_sum"]
per_validator = r["per_validator"]
top1_bps      = r["top_1_share_bps"]
top3_bps      = r["top_3_share_bps"]
top1_v        = r["top_1_validator"]
distinct      = r["distinct_validators"]
empty_blocks  = r["empty_blocks"]

# ── Anomaly classification ──────────────────────────────────────────────────
anomalies = []

# (a) subsidy_distribution_drift: Σ per-validator ≠ Σ per-block (tolerance 1).
# In a correctly-attributed walk these always equal exactly because the
# remainder-to-creators[0] rule is bookkept symmetrically on both sides.
# A non-trivial drift here would indicate a script bug — flagged for
# operator visibility regardless.
drift = per_block_sum - total_credit
if drift < 0:
    drift = -drift
drift_ok = drift <= 1
if not drift_ok:
    anomalies.append("subsidy_distribution_drift")

# (b) nef_pool_exhausted: live ZEROTH balance == 0. The post-walk snapshot
# is the operator-facing fact; the pre-walk snapshot is informational.
if nef_after == 0:
    anomalies.append("nef_pool_exhausted")

# (c) subsidy_pool_critical_low: only when --subsidy-pool-initial set.
if pool_low:
    anomalies.append("subsidy_pool_critical_low")

# (d) subsidy_concentration_high: top-1 > 30%. Tighter gate than fee
# distribution's 50% — subsidy is structural reward.
if top1_bps > 3000:
    anomalies.append("subsidy_concentration_high")

anom_count = len(anomalies)

def render_pct(bps):
    """bps in 0..10000 → 'NN.N%' (one decimal)."""
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

if json_out:
    envelope = {
        "rpc_port":             port,
        "head_height":          head_h,
        "window":               {"from": from_h, "to": to_h, "blocks": win_blocks},
        "est_per_block_subsidy": est_per_block,
        "est_source":           est_source,
        "total_subsidy_credit": total_credit,
        "per_block_sum":        per_block_sum,
        "distribution_drift":   per_block_sum - total_credit,
        "distinct_validators":  distinct,
        "empty_blocks":         empty_blocks,
        "accumulated_subsidy_before": accum_before,
        "accumulated_subsidy_after":  accum_after,
        "subsidy_delta_during_walk":  subsidy_delta,
        "nef_pool_before":      nef_before,
        "nef_pool_after":       nef_after,
        "nef_pool_drain":       nef_delta,
        "subsidy_pool_initial": pool_initial,
        "remaining_subsidy_pool": remaining_pool,
        "subsidy_pool_threshold": pool_threshold,
        "top_1_share_bps":      top1_bps,
        "top_3_share_bps":      top3_bps,
        "top_1_validator":      top1_v,
        "per_validator":        per_validator,
        "anomalies":            anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# ── Human-readable layout ───────────────────────────────────────────────────
if anom_only and anom_count == 0:
    print(f"operator_subsidy_audit: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}])")
    sys.exit(0)

print(f"=== Subsidy audit (port {port}, window [{from_h}..{to_h}], "
      f"{win_blocks} blocks) ===")
print(f"Per-block subsidy basis  : {est_per_block}  (source: {est_source})")
print(f"Total subsidy attributed : {total_credit}")
print(f"Distinct validators      : {distinct}")
print(f"Empty-creators blocks    : {empty_blocks}")

# E1 + E4 snapshots
print()
print(f"E1  NEF pool (ZEROTH)    : before={nef_before}  after={nef_after}  drain={nef_delta}")
if pool_initial is not None:
    print(f"E3  Subsidy delta in walk: {subsidy_delta} "
          f"(accumulated: {accum_before} -> {accum_after})")
    print(f"E4  Subsidy pool         : initial={pool_initial}  "
          f"remaining={remaining_pool}  threshold={pool_threshold}")
else:
    print(f"E3  Subsidy delta in walk: {subsidy_delta} "
          f"(accumulated: {accum_before} -> {accum_after})")
    print(f"E4  Subsidy pool         : (perpetual mode; no --subsidy-pool-initial)")

if per_validator and not anom_only:
    print()
    print("Per-validator subsidy (sorted by credit desc):")
    rank = 0
    for row in per_validator:
        rank += 1
        pct = render_pct(row["share_bps"]) if total_credit > 0 else "-"
        tag = "  [top-1]" if rank == 1 else ""
        print(f"  {row['validator']:<28} : "
              f"credit={row['subsidy_credit']:<12} "
              f"sels={row['selections']:<6} "
              f"avg={row['avg_credit_per_sel']:<8} "
              f"share={pct}{tag}")

print()
if per_validator:
    print(f"Top-1 share : {render_pct(top1_bps)}")
    print(f"Top-3 share : {render_pct(top3_bps)}")

# Distribution-drift summary.
delta_signed = per_block_sum - total_credit
if delta_signed == 0:
    print(f"Distribution check: OK (sum per-validator = sum per-block = {total_credit})")
else:
    print(f"Distribution check: drift={delta_signed} "
          f"(per-block sum={per_block_sum}, per-validator total={total_credit})")

print()
if anom_count == 0:
    print("[OK] No E1/E3/E4 anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "subsidy_distribution_drift" in anomalies:
        print(f"  subsidy_distribution_drift   : drift={delta_signed} (> 1 unit; apply-layer bug?)")
    if "nef_pool_exhausted" in anomalies:
        print(f"  nef_pool_exhausted           : ZEROTH balance = 0 (E4 hit; no more E1)")
    if "subsidy_pool_critical_low" in anomalies:
        print(f"  subsidy_pool_critical_low    : remaining={remaining_pool} < threshold={pool_threshold}")
    if "subsidy_concentration_high" in anomalies:
        print(f"  subsidy_concentration_high   : top-1 ({top1_v}) share = "
              f"{render_pct(top1_bps)} (> 30% threshold)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_subsidy_audit: rendering failed (rc=$RC)" >&2
  exit 1
fi

# ── Step 7: exit-code policy ────────────────────────────────────────────────
# Mirrors operator_fee_distribution_audit / operator_stake_yield: exit 2
# only when --anomalies-only is set AND ≥1 anomaly fired. Default
# informational mode always exits 0 if the RPC walk succeeded.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT

python - "$TMP_OUT" "$TMP_ANOM" \
        "$NEF_AFTER" "$SUBSIDY_POOL_LOW" \
        "$(python - "$TMP_OUT" "$EST_PER_BLOCK" <<'PY2'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
per_block_sum = r["per_block_sum"]
total_credit  = r["total_credit"]
top1_bps      = r["top_1_share_bps"]
drift_signed  = per_block_sum - total_credit
drift_abs     = drift_signed if drift_signed >= 0 else -drift_signed
flags = 0
if drift_abs > 1: flags += 1
if top1_bps > 3000: flags += 1
print(flags)
PY2
)" <<'PY'
import sys
out, anom_path, nef_after_s, pool_low_s, base_flags_s = sys.argv[1:6]
flags = int(base_flags_s)
if int(nef_after_s) == 0:
    flags += 1
if pool_low_s == "1":
    flags += 1
with open(anom_path, "w", encoding="utf-8") as f:
    f.write(str(flags))
PY

ANOM_COUNT=$(cat "$TMP_ANOM" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
