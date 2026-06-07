#!/usr/bin/env bash
# operator_committee_rotation.sh — Audit how the K-of-K consensus
# committee composition shifts across a window of finalized blocks on a
# running determ daemon.
#
# Sibling tools:
#   operator_committee_audit.sh   — single-block (current-epoch) snapshot
#                                   of the committee, regional join +
#                                   threshold-quorum classification.
#   operator_validator_history.sh — per-validator history (appearances,
#                                   sig participation, abort + equiv
#                                   slashing) over a window.
# This script answers the *committee-level* question: across
# [--from..--to], how stable was the committee membership and what
# rotation events occurred? It complements both by treating the
# committee as a multiset evolving over time.
#
# Per-block: extract `block.creators[]` via `determ block-info H --json`.
# Aggregate:
#   * distinct_creators                — unique domains observed
#   * size_distribution                — histogram of committee size K
#                                        across the window (BFT
#                                        escalation manifests as K
#                                        deviating from the genesis K)
#   * per_creator                      — first_seen / last_seen /
#                                        appearances / participation_rate
#                                        / class ∈ {core, rotating, other}
#                                        - core      : ≥80% participation
#                                        - rotating  : <50% participation
#                                        - other     : 50% ≤ rate <80%
#   * rotation_events                  — count of consecutive blocks
#                                        whose creators[] differs as a
#                                        multiset (i.e. the committee
#                                        membership turned over between
#                                        block H and H+1)
#   * rotation_rate                    — rotation_events / (N - 1)
#                                        where N = window size; 0 if N<2
#
# Anomalies (alert-worthy, gate exit code 2 under --anomalies-only):
#   committee_size_variance     — ≥2 distinct committee sizes observed
#                                 in window (BFT escalation OR producer
#                                 inconsistency). A healthy run on a
#                                 stable K-of-K should be single-valued.
#   single_dominant_creator     — one creator > 95% participation while
#                                 every other observed creator stayed
#                                 below 50% (fixed-leader / non-rotating
#                                 pattern; flags Sybil-style centralized
#                                 production even on a multi-validator
#                                 chain).
#   high_rotation_rate          — rotation_rate > 0.50 (committee turns
#                                 over more often than not — operator
#                                 instability or churning registry).
#
# Args:
#   [--rpc-port N]      RPC port to query (default: 7778)
#   [--from H]          Lower window bound (inclusive). Default =
#                       max(0, head - 1000 + 1).
#   [--to H]            Upper window bound (inclusive). Default = head.
#   [--json]            Emit structured JSON envelope
#   [--anomalies-only]  Suppress non-anomaly output; exit 2 on alert
#   [-h|--help]         Show this help
#
# Exit codes:
#   0   success, no anomalies (or --anomalies-only not set)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 alert-worthy anomaly detected
#
# Read-only RPC; safe against any running daemon. Requires `jq` for
# JSON traversal; per-block walk is driven from a Python heredoc to keep
# wall-clock acceptable on wide windows (one subprocess per block).
set -u

usage() {
  cat <<'EOF'
Usage: operator_committee_rotation.sh [--rpc-port N] [--json]
                                      [--from H] [--to H]
                                      [--anomalies-only]

Audit committee composition transitions over a window of finalized
blocks. Walks `determ block-info <i> --json` for each H in
[--from..--to], extracts block.creators[], and aggregates:
  - Distinct creators observed
  - Committee size distribution (single-valued ⇒ stable K; multi-valued
    ⇒ BFT escalation / committee resize occurred)
  - Per-creator first/last appearance + participation rate + class
    (core ≥80%, rotating <50%, other 50-80%)
  - Rotation events (consecutive blocks with different creators[] as
    multisets) and the rotation rate

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --from H            Lower window bound (inclusive). Default:
                      max(0, head - 1000 + 1).
  --to H              Upper window bound (inclusive). Default: head.
  --json              Emit structured JSON envelope
  --anomalies-only    Print only when ≥1 alert-worthy anomaly is
                      detected; exit 2 in that case.
  -h, --help          Show this help

JSON shape:
  {"window":{"from":F,"to":T,"blocks":N},
   "distinct_creators":D,
   "size_distribution":{"K":count,...},
   "per_creator":[{"domain":"…","appearances":A,"participation_rate":R,
                   "first_seen_block":F,"last_seen_block":L,"class":"core|rotating|other"},…],
   "rotation_events":E,
   "rotation_rate":R,
   "anomalies":["…",…],
   "rpc_port":N}

Anomalies:
  committee_size_variance   ≥2 distinct committee sizes in window
  single_dominant_creator   one creator >95% AND all others <50%
  high_rotation_rate        rotation_rate > 0.50

Exit codes:
  0   success
  1   RPC error / bad args
  2   --anomalies-only AND ≥1 anomaly detected
EOF
}

PORT=7778
JSON_OUT=0
FROM=""
TO=""
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";    shift 2 ;;
    --json)           JSON_OUT=1;       shift ;;
    --from)           FROM="${2:-}";    shift 2 ;;
    --to)             TO="${2:-}";      shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;      shift ;;
    *) echo "operator_committee_rotation: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_committee_rotation: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM" "$TO"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_committee_rotation: --from / --to must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_committee_rotation: jq is required (block JSON is too nested for the grep fallback)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_committee_rotation: python (or python3) is required for the per-block walk" >&2
  exit 1
fi
PYTHON=python
command -v python >/dev/null 2>&1 || PYTHON=python3

# ── Step 1: chain head ────────────────────────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_rotation: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_committee_rotation: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1 (height is the NEXT-to-produce).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
if [ -z "$TO" ]; then TO=$TOP; fi
if [ -z "$FROM" ]; then
  FROM=$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_committee_rotation: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi

WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: per-block walk + aggregation (Python) ─────────────────────────────
TMP_AGG=$(mktemp)
trap 'rm -f "$TMP_AGG"' EXIT

# Drive the walk in Python so one subprocess per block is the only RPC
# cost — jq + bash per block would multiply that 3-4×. Emits one JSON
# object with all aggregates as a single line so the bash side can pipe
# it straight to jq.
"$PYTHON" - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_AGG" <<'PY' || {
import json, subprocess, sys

determ, port, from_h, to_h, out_path = sys.argv[1:6]
from_h, to_h = int(from_h), int(to_h)

# Per-creator counters.
creators_seen = {}   # domain → {appearances, first_seen_block, last_seen_block}
size_dist     = {}   # K (int) → count
rotation_events = 0  # consecutive-block multiset-difference count
prev_committee  = None  # tuple(sorted(creators_for_prev_block))

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=10
        )
    except Exception as e:
        sys.stderr.write(f"operator_committee_rotation: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_committee_rotation: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_committee_rotation: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []

    # Filter to string entries; defensive against schema drift.
    creators = [c for c in creators if isinstance(c, str)]

    # Size histogram.
    K = len(creators)
    size_dist[K] = size_dist.get(K, 0) + 1

    # Per-creator counters.
    for dom in creators:
        rec = creators_seen.get(dom)
        if rec is None:
            creators_seen[dom] = {
                "appearances":      1,
                "first_seen_block": h,
                "last_seen_block":  h,
            }
        else:
            rec["appearances"] += 1
            rec["last_seen_block"] = h

    # Rotation event detection: compare as sorted tuple (multiset
    # equivalence — order in creators[] is selection order and varies
    # between epochs even when membership is identical, so we normalize
    # to a sorted tuple before comparison).
    cur = tuple(sorted(creators))
    if prev_committee is not None and cur != prev_committee:
        rotation_events += 1
    prev_committee = cur

# Build per-creator output sorted by appearances desc, then domain asc.
N = to_h - from_h + 1
def classify(rate):
    if rate >= 0.80: return "core"
    if rate <  0.50: return "rotating"
    return "other"

per_creator = []
for dom, rec in creators_seen.items():
    rate = (rec["appearances"] / N) if N > 0 else 0.0
    per_creator.append({
        "domain":             dom,
        "appearances":        rec["appearances"],
        "participation_rate": rate,
        "first_seen_block":   rec["first_seen_block"],
        "last_seen_block":    rec["last_seen_block"],
        "class":              classify(rate),
    })
per_creator.sort(key=lambda r: (-r["appearances"], r["domain"]))

# Rotation rate: events / (N - 1). 0 when N < 2.
rotation_rate = (rotation_events / (N - 1)) if N >= 2 else 0.0

# Size distribution emitted with stringified K keys (JSON object keys
# must be strings); the renderer prints the underlying int.
out = {
    "window":            {"from": from_h, "to": to_h, "blocks": N},
    "distinct_creators": len(creators_seen),
    "size_distribution": {str(k): v for k, v in sorted(size_dist.items())},
    "per_creator":       per_creator,
    "rotation_events":   rotation_events,
    "rotation_rate":     rotation_rate,
}
with open(out_path, "w", encoding="utf-8") as f:
    f.write(json.dumps(out))
PY
  echo "operator_committee_rotation: block walk failed" >&2; exit 1;
}

# ── Step 3: classify anomalies ────────────────────────────────────────────────
# Anomaly detection is done in jq so it's coherent with the JSON output.
RAW=$(cat "$TMP_AGG")

# committee_size_variance: ≥2 distinct sizes.
NUM_SIZES=$(printf '%s' "$RAW" | jq '.size_distribution | length')

# single_dominant_creator: one creator >95% AND every OTHER creator <50%.
# Edge case: a single-creator window (distinct_creators == 1 and that
# creator appears in every block) is degenerate, not a fixed-leader
# anomaly per se — but operators DO want to know about it. Flag the
# anomaly only when there are ≥2 distinct creators (so we're really
# looking at a dominant-vs-others pattern, not just a one-validator chain).
HAS_DOMINANT=$(printf '%s' "$RAW" | jq '
  if (.distinct_creators >= 2) then
    (
      ([.per_creator[] | select(.participation_rate > 0.95)] | length) > 0
      and
      ([.per_creator[] | select(.participation_rate <= 0.95 and .participation_rate >= 0.50)] | length) == 0
    )
  else
    false
  end
')

# high_rotation_rate: > 0.50 (default float comparison in jq).
HIGH_ROT=$(printf '%s' "$RAW" | jq '.rotation_rate > 0.50')

ANOMALIES_JSON='[]'
if [ "$NUM_SIZES" -gt 1 ]; then
  ANOMALIES_JSON=$(printf '%s' "$ANOMALIES_JSON" | jq '. + ["committee_size_variance"]')
fi
if [ "$HAS_DOMINANT" = "true" ]; then
  ANOMALIES_JSON=$(printf '%s' "$ANOMALIES_JSON" | jq '. + ["single_dominant_creator"]')
fi
if [ "$HIGH_ROT" = "true" ]; then
  ANOMALIES_JSON=$(printf '%s' "$ANOMALIES_JSON" | jq '. + ["high_rotation_rate"]')
fi

ANOM_COUNT=$(printf '%s' "$ANOMALIES_JSON" | jq 'length')

# Inject anomalies + rpc_port into the envelope.
ENVELOPE=$(printf '%s' "$RAW" | jq --argjson a "$ANOMALIES_JSON" --argjson p "$PORT" \
  '. + {anomalies: $a, rpc_port: $p}')

# ── Step 4: rendering ─────────────────────────────────────────────────────────
emit_json() {
  printf '%s' "$ENVELOPE" | jq .
}

emit_human() {
  echo "=== Committee rotation (port $PORT, window [$FROM..$TO], $WINDOW blocks) ==="
  DISTINCT=$(printf '%s' "$ENVELOPE" | jq -r '.distinct_creators')
  echo "Distinct creators in window: $DISTINCT"

  # Size distribution line: "{K: count, K: count}" with mode K + escalation note.
  SIZE_PAIRS=$(printf '%s' "$ENVELOPE" | jq -r '
    .size_distribution
    | to_entries
    | sort_by(.key | tonumber)
    | map("\(.key): \(.value)")
    | join(", ")
  ')
  # Mode (highest-count) K — used in the human-readable summary suffix.
  MODE_K=$(printf '%s' "$ENVELOPE" | jq -r '
    .size_distribution
    | to_entries
    | sort_by(-.value, (.key | tonumber))
    | .[0].key
  ')
  MODE_COUNT=$(printf '%s' "$ENVELOPE" | jq -r '
    .size_distribution
    | to_entries
    | sort_by(-.value, (.key | tonumber))
    | .[0].value
  ')
  if [ "$NUM_SIZES" -gt 1 ]; then
    OTHER_COUNT=$(( WINDOW - MODE_COUNT ))
    echo "Committee sizes observed: {$SIZE_PAIRS} (mode K=$MODE_K, BFT escalation in $OTHER_COUNT blocks)"
  else
    echo "Committee sizes observed: {$SIZE_PAIRS} (stable K=$MODE_K)"
  fi

  if [ "$DISTINCT" = "0" ]; then
    echo "Per-creator participation: (empty — no creators observed in window)"
  else
    echo "Per-creator participation:"
    # Column widths: pick longest domain for clean padding, capped at 24.
    MAXLEN=$(printf '%s' "$ENVELOPE" | jq -r '
      [.per_creator[].domain | length] | max // 0
    ')
    [ "$MAXLEN" -gt 24 ] && MAXLEN=24
    [ "$MAXLEN" -lt 8  ] && MAXLEN=8
    # Print rows: "  <domain>: <appearances> / <N> (<rate>%) [class]"
    printf '%s' "$ENVELOPE" | jq -r --argjson w "$WINDOW" --argjson pad "$MAXLEN" '
      .per_creator[]
      | (
          .domain                                        as $d
          | .appearances                                 as $a
          | (.participation_rate * 1000 | round / 10)    as $pct
          | (if .class == "core"
               then "[core]"
             elif .class == "rotating"
               then "[rotating]"
             else "[other]"
             end)                                        as $cls
          | "  \($d):\("                                          " | .[0:($pad - ($d|length) + 1)]) \($a) / \($w) (\($pct)%) \($cls)"
        )
    '
  fi

  EVENTS=$(printf '%s' "$ENVELOPE" | jq -r '.rotation_events')
  if [ "$WINDOW" -lt 2 ]; then
    echo "Rotation events: n/a (window has $WINDOW block; need ≥2)"
  else
    PAIRS=$(( WINDOW - 1 ))
    RATE_PCT=$(printf '%s' "$ENVELOPE" | jq -r '.rotation_rate * 1000 | round / 10')
    echo "Rotation events (consecutive blocks with different creators): $EVENTS / $PAIRS (${RATE_PCT}%)"
  fi

  if [ "$ANOM_COUNT" = "0" ]; then
    echo "[OK] No anomalies"
  else
    printf '%s' "$ANOMALIES_JSON" | jq -r '.[]' | while IFS= read -r A; do
      case "$A" in
        committee_size_variance)
          echo "[WARN] Committee size variance: $NUM_SIZES distinct sizes in window"
          ;;
        single_dominant_creator)
          echo "[WARN] Single dominant creator (>95% participation while others <50%)"
          ;;
        high_rotation_rate)
          echo "[WARN] High rotation rate (>50% of consecutive blocks differ — operator instability signal)"
          ;;
      esac
    done
  fi
}

# --anomalies-only mode: suppress output unless an anomaly was detected.
if [ "$ANOM_ONLY" = "1" ]; then
  if [ "$ANOM_COUNT" -gt 0 ]; then
    if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi
    exit 2
  fi
  # silent success
  exit 0
fi

if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi
exit 0
