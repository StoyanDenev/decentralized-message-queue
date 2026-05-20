#!/usr/bin/env bash
# operator_validator_uptime.sh — Per-validator uptime tracking via block
# signing participation rate over a window of finalized blocks on a
# running determ daemon.
#
# Where this differs from operator_validator_history.sh:
#   * history → per-validator event tape (REGISTER / DEREGISTER / ABORT /
#                EQUIVOCATE / committee + sig counts) with status rejoin
#                against `determ stakes`.
#   * uptime  → ONLY the "did the validator sign blocks they were on
#                committee for" angle, bucketed into uptime tiers
#                (high / moderate / low) for at-a-glance health, plus
#                an "active fault" cross-reference against abort_events.
#
# A validator appears in `block.creators[i]` for each block on whose
# committee they were drawn. In parallel `block.creator_block_sigs[i]`
# is either a 64-byte zero sentinel (didn't sign / wasn't received in
# time) or their actual Ed25519 signature. Per-validator uptime is:
#
#     participation_rate = signed_count / appeared_count
#
# Tiers:
#     high       participation_rate ≥ 0.95
#     moderate   0.80 ≤ participation_rate < 0.95
#     low        participation_rate < 0.80
#
# Anomaly flags (--anomalies-only filters output to only these):
#   * low_uptime        participation_rate < 0.80 AND appeared ≥ 1
#                       (validator was selected but stayed offline /
#                        dropped packets / their signature gossip
#                        wasn't reaching the producer in time)
#   * silent_validator  participation_rate == 0.0 AND appeared ≥ 1
#                       AND no abort_events attributed in window
#                       (validator appeared in committee but signed
#                        nothing AND wasn't even detected as a Phase-1
#                        aborter — strongest "actively down" signal)
#   * active_fault      participation_rate == 0.0 AND appeared ≥ 1
#                       AND ≥1 abort_event attributed in window
#                       (validator was actively faulting; abort events
#                        likely captured the slashing — sanity check
#                        that they were)
#
# Exit codes:
#   0   success (no anomalies, or --anomalies-only not asserted)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly detected
#
# Read-only RPC; safe against any running daemon. Requires `jq` for
# JSON traversal of nested block payloads and `python` for the per-
# block walk (one subprocess per block; jq + bash for each multiplies
# wall-clock 3-4× on wide windows).
set -u

usage() {
  cat <<'EOF'
Usage: operator_validator_uptime.sh [--rpc-port N] [--json]
                                    [--from H] [--to H]
                                    [--anomalies-only]
                                    [--sort-by {uptime|appearances|domain}]

Per-validator uptime audit over a window of finalized blocks. For each
validator that appeared in at least one committee, computes signing
participation rate (signed_count / appeared_count) and buckets into
high (>=95%), moderate (80-95%), or low (<80%) uptime tiers.

The validator universe is taken from observed committees in the window
(NOT the current `determ stakes` snapshot) — this surfaces validators
who participated earlier but have since deregistered, which is the
right behavior for an "uptime" lens.

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --json               Emit structured JSON envelope
  --from H             Lower window bound (inclusive). Default:
                       max(0, head - 1000 + 1).
  --to H               Upper window bound (inclusive). Default:
                       current head (= chain.height - 1).
  --anomalies-only     Print only validators with >=1 anomaly flag; in
                       this mode exit 2 if any anomaly was found.
  --sort-by KEY        Sort order. One of:
                         uptime         (participation_rate asc)  [default]
                         appearances    (committee appearances desc)
                         domain         (domain ascending)
  -h, --help           Show this help

Uptime tiers:
  high       participation_rate >= 0.95
  moderate   0.80 <= participation_rate < 0.95
  low        participation_rate <  0.80

Anomaly flags:
  low_uptime          participation_rate < 0.80 (validator likely down)
  silent_validator    participation_rate == 0.0 AND no abort_events
                      (appeared but signed nothing AND wasn't even
                      detected as a Phase-1 aborter)
  active_fault        participation_rate == 0.0 AND >=1 abort_event
                      attributed (sanity check that slashing fired)

JSON envelope shape:
  {"window":{"from":F,"to":T,"blocks":W},
   "rpc_port":N,
   "validators_seen":COUNT,
   "tier_counts":{"high":H,"moderate":M,"low":L},
   "per_validator":[
     {"domain":"...","appeared":A,"signed":S,"participation_rate":R,
      "tier":"high|moderate|low","abort_count":AC,"flags":[...],
      "anomaly":bool}, ...],
   "anomalies_total":N}

Exit codes:
  0   success
  1   RPC error / bad args
  2   --anomalies-only AND >=1 anomaly found
EOF
}

PORT=7778
JSON_OUT=0
FROM=""
TO=""
ANOM_ONLY=0
SORT_BY="uptime"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";    shift 2 ;;
    --json)           JSON_OUT=1;       shift ;;
    --from)           FROM="${2:-}";    shift 2 ;;
    --to)             TO="${2:-}";      shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;      shift ;;
    --sort-by)        SORT_BY="${2:-}"; shift 2 ;;
    *) echo "operator_validator_uptime: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_validator_uptime: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM" "$TO"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_validator_uptime: --from / --to must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done
case "$SORT_BY" in
  uptime|appearances|domain) ;;
  *) echo "operator_validator_uptime: --sort-by must be one of {uptime|appearances|domain} (got '$SORT_BY')" >&2
     exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_validator_uptime: jq is required (block JSON is too nested for the grep fallback)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_validator_uptime: python (or python3) is required for the per-block walk" >&2
  exit 1
fi
PYTHON=python
command -v python >/dev/null 2>&1 || PYTHON=python3

# ── Step 1: chain head ─────────────────────────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_validator_uptime: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_validator_uptime: malformed head JSON (height='$HEIGHT')" >&2
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
  echo "operator_validator_uptime: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: per-block walk + aggregation (Python) ─────────────────────────────
TMP_AGG=$(mktemp)
trap 'rm -f "$TMP_AGG"' EXIT

# Drive the walk in Python so one subprocess per block is the only RPC
# cost. The Python pass tallies (appeared, signed, abort_count) per
# domain as discovered from observed committees, then writes one JSON
# envelope back to the bash side for rendering.
"$PYTHON" - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_AGG" <<'PY' || {
  echo "operator_validator_uptime: block walk failed" >&2; exit 1;
}
import json, subprocess, sys

determ, port, from_h, to_h, out_path = sys.argv[1:6]
from_h, to_h = int(from_h), int(to_h)

ZERO_SIG_HEX = "0" * 128  # 64 bytes of zero = "didn't sign"

# Per-domain counters; populated lazily as committees are observed.
# Pre-populating from `determ stakes` would miss validators who
# deregistered mid-window — and the "uptime" lens specifically wants
# those surfaced (a validator who appeared then went silent IS the
# anomaly we want to flag).
stats = {}   # domain -> {appeared, signed, abort_count}

def get(dom):
    if dom not in stats:
        stats[dom] = {"appeared": 0, "signed": 0, "abort_count": 0}
    return stats[dom]

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=10
        )
    except Exception as e:
        sys.stderr.write(f"operator_validator_uptime: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_validator_uptime: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_validator_uptime: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    # Committee appearances + signature participations.
    creators = blk.get("creators") or []
    sigs     = blk.get("creator_block_sigs") or []
    if not isinstance(creators, list): creators = []
    if not isinstance(sigs,     list): sigs     = []

    for idx, dom in enumerate(creators):
        if not isinstance(dom, str) or not dom:
            continue
        s = get(dom)
        s["appeared"] += 1
        # Sig at parallel index is either a 64-byte all-zero sentinel
        # ("didn't sign / wasn't received") or the actual Ed25519
        # signature in hex. Any non-zero hex string of the right shape
        # counts as a signature participation.
        if idx < len(sigs) and isinstance(sigs[idx], str) \
           and sigs[idx] and sigs[idx] != ZERO_SIG_HEX:
            s["signed"] += 1

    # Abort attribution — needed to split "silent" from "active fault".
    # A validator who signed 0% AND was caught aborting is a different
    # operator story than one who signed 0% with no abort attribution.
    for ae in (blk.get("abort_events") or []):
        if not isinstance(ae, dict):
            continue
        dom = ae.get("aborting_node", "")
        if not isinstance(dom, str) or not dom:
            continue
        # Only count aborts for validators we've actually seen in
        # committee within the window. An abort_event for a validator
        # who appeared in committee BEFORE --from but was slashed
        # within the window would otherwise inflate validators_seen
        # with a record that has appeared=0.
        if dom in stats:
            stats[dom]["abort_count"] += 1

# Classify + flag.
records = []
tier_counts = {"high": 0, "moderate": 0, "low": 0}

for dom, s in stats.items():
    appeared = s["appeared"]
    signed   = s["signed"]
    aborts   = s["abort_count"]
    rate     = (signed / appeared) if appeared > 0 else 0.0

    if   rate >= 0.95: tier = "high"
    elif rate >= 0.80: tier = "moderate"
    else:              tier = "low"
    tier_counts[tier] += 1

    flags = []
    # low_uptime: validator was selected but signed less than 80%.
    if appeared >= 1 and rate < 0.80:
        flags.append("low_uptime")
    # silent_validator vs active_fault: only one of the two fires
    # when participation_rate == 0.0 (mutual exclusion on abort_count).
    if appeared >= 1 and signed == 0:
        if aborts == 0:
            flags.append("silent_validator")
        else:
            flags.append("active_fault")

    records.append({
        "domain":              dom,
        "appeared":            appeared,
        "signed":              signed,
        "participation_rate":  rate,
        "tier":                tier,
        "abort_count":         aborts,
        "flags":               flags,
        "anomaly":             len(flags) > 0,
    })

out = {
    "window":           {"from": from_h, "to": to_h, "blocks": to_h - from_h + 1},
    "validators_seen":  len(records),
    "tier_counts":      tier_counts,
    "per_validator":    records,
    "anomalies_total":  sum(1 for r in records if r["anomaly"]),
}
with open(out_path, "w", encoding="utf-8") as f:
    f.write(json.dumps(out))
PY

# ── Step 3: load envelope, sort + filter ─────────────────────────────────────
RAW=$(cat "$TMP_AGG")

# Inject rpc_port for self-describing envelope.
ENVELOPE=$(printf '%s' "$RAW" | jq --argjson p "$PORT" '. + {rpc_port: $p}')

# Sort per --sort-by; stable tie-break by domain ascending.
case "$SORT_BY" in
  uptime)
    ENVELOPE=$(printf '%s' "$ENVELOPE" | jq '
      .per_validator |= sort_by(.participation_rate, .domain)
    ') ;;
  appearances)
    ENVELOPE=$(printf '%s' "$ENVELOPE" | jq '
      .per_validator |= sort_by(-(.appeared), .domain)
    ') ;;
  domain)
    ENVELOPE=$(printf '%s' "$ENVELOPE" | jq '
      .per_validator |= sort_by(.domain)
    ') ;;
esac

ANOM_COUNT=$(printf '%s' "$ENVELOPE" | jq '.anomalies_total')

# Anomaly filter (cosmetic; alert gate uses pre-filter counts).
if [ "$ANOM_ONLY" = "1" ]; then
  ENVELOPE=$(printf '%s' "$ENVELOPE" | jq '
    .per_validator |= map(select(.anomaly))
  ')
fi

# ── Step 4: rendering ────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '%s' "$ENVELOPE" | jq .
else
  COUNT=$(printf '%s' "$ENVELOPE" | jq '.per_validator | length')
  SEEN=$(printf '%s' "$ENVELOPE" | jq -r '.validators_seen')

  echo "=== Validator uptime (port $PORT, window [$FROM..$TO], $WINDOW blocks) ==="

  if [ "$SEEN" = "0" ]; then
    echo "Validators in committee at least once: 0"
    echo "[INFO] No committee activity observed in window"
    exit 0
  fi

  echo "Validators in committee at least once: $SEEN"

  # Tier summary line.
  TH=$(printf '%s' "$ENVELOPE" | jq -r '.tier_counts.high')
  TM=$(printf '%s' "$ENVELOPE" | jq -r '.tier_counts.moderate')
  TL=$(printf '%s' "$ENVELOPE" | jq -r '.tier_counts.low')
  echo "Tier breakdown: high=$TH (>=95%), moderate=$TM (80-95%), low=$TL (<80%)"

  if [ "$ANOM_ONLY" = "1" ] && [ "$COUNT" = "0" ]; then
    echo "[OK] No anomalies"
    exit 0
  fi

  echo "Per-validator uptime:"

  # Compute column width for nice alignment. Cap at 24 chars.
  MAXLEN=$(printf '%s' "$ENVELOPE" | jq -r '
    [.per_validator[].domain | length] | max // 0
  ')
  [ "$MAXLEN" -gt 24 ] && MAXLEN=24
  [ "$MAXLEN" -lt 8  ] && MAXLEN=8

  printf '%s' "$ENVELOPE" | jq -r --argjson pad "$MAXLEN" '
    .per_validator[]
    | (
        .domain                                          as $d
        | .appeared                                      as $a
        | .signed                                        as $s
        | (.participation_rate * 1000 | round / 10)      as $pct
        | .tier                                          as $t
        | .abort_count                                   as $ab
        | (if (.anomaly) then " *" else "" end)          as $star
        | (
            "  \($d):\("                                          " | .[0:($pad - ($d|length) + 1)]) appeared \($a), signed \($s) (\($pct)%) [\($t)]"
            + (if $ab > 0 then "  aborts=\($ab)" else "" end)
            + $star
          )
      )
  '

  # Anomaly summary footer.
  if [ "$ANOM_COUNT" = "0" ]; then
    echo "[OK] No anomalies"
  else
    echo "Anomalies ($ANOM_COUNT):"
    printf '%s' "$ENVELOPE" | jq -r '
      .per_validator[]
      | select(.anomaly)
      | .domain as $d
      | .flags[]
      | "  " + $d + ": " + .
    ' | while IFS= read -r L; do
      case "$L" in
        *": low_uptime")
          echo "[WARN]$L (<80% signature participation)"
          ;;
        *": silent_validator")
          echo "[WARN]$L (appeared but signed nothing; no abort attribution)"
          ;;
        *": active_fault")
          echo "[WARN]$L (signed nothing; >=1 abort_event attributed in window)"
          ;;
        *)
          echo "[WARN]$L"
          ;;
      esac
    done
  fi
fi

# Exit-code policy mirrors operator_validator_history: --anomalies-only
# set AND >=1 anomaly (pre-filter) → exit 2; otherwise exit 0.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
