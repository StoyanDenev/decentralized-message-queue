#!/usr/bin/env bash
# operator_chain_diff.sh — Pairwise block-level divergence detector between
# two running RPC daemons. Two honest nodes following the same chain MUST
# agree on block_hash and state_root at every finalized height (FA1 +
# S-033 + S-038); a divergence at any height indicates either (a) a fork
# (one daemon followed a different chain after a partition), (b) an
# apply-determinism break (state_root recompute drift), or (c) a
# consensus bug.
#
# Sibling positioning:
#   * operator_consensus_lag.sh — N-way HEIGHT lag check across a fleet.
#     Treats unreachable peers as max-lag stragglers. Right tool for
#     "who is behind?", not "do these two AGREE at the heights they
#     share?".
#   * operator_replay_validation.sh — SINGLE-daemon replay-determinism
#     round-trip (snapshot-restore + per-block field consistency).
#     Catches apply-path non-determinism on one daemon. Right tool when
#     you suspect ONE node's state machine is broken.
#   * operator_chain_diff.sh (THIS) — PAIRWISE BLOCK comparison across
#     two daemons at the heights they share. Catches cross-node
#     divergence (silent fork, apply-determinism break that only shows
#     up between honest peers). The right tool for "are these two
#     daemons actually on the same chain?".
#   * operator_committee_audit.sh — per-validator fairness audit on ONE
#     daemon's recent window. Orthogonal — fairness vs identity.
#
# Approach:
#   1. Probe `determ head --json` on both daemons. Record head_a / head_b.
#   2. Resolve window: [--from .. --to], clamped to min(head_a, head_b)-1
#      (last finalized height present on both daemons).
#   3. For each sampled height (stride-aware), fetch the requested
#      --fields from each daemon via `determ block-info <h> --field F`.
#      Any per-field mismatch is recorded as a divergence row.
#   4. Anomalies:
#        block_hash_divergence            — block_hash differs at any
#                                            height. HARD FORK signal.
#        state_root_divergence            — state_root differs at any
#                                            height. HARD FORK or
#                                            apply-determinism break.
#        head_delta_large                 — |head_a - head_b| > 10. One
#                                            daemon is significantly
#                                            lagging; cross-ref
#                                            operator_consensus_lag.
#        head_a_eq_head_b_but_hashes_differ
#                                          — both daemons at the same
#                                            head height BUT the
#                                            block_hash at that height
#                                            differs. FATAL — silent
#                                            fork at exactly the tip.
#
# Read-only RPC; safe against any running daemons. Both ports must be
# listening on 127.0.0.1.
#
# Usage:
#   tools/operator_chain_diff.sh --rpc-port-a N --rpc-port-b N
#                                [--from H] [--to H] [--stride N]
#                                [--fields block_hash,state_root,prev_hash,timestamp]
#                                [--json] [--anomalies-only]
#
# Exit codes:
#   0   no divergences detected
#   1   RPC error / args error / malformed response
#   2   divergences detected (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_diff.sh --rpc-port-a N --rpc-port-b N
                              [--from H] [--to H] [--stride N]
                              [--fields LIST] [--json] [--anomalies-only]

Pairwise block-level divergence detector between two RPC daemons.
Two honest nodes following the same chain MUST agree on block_hash and
state_root at every finalized height. Any divergence is either a fork
or a consensus bug.

Required:
  --rpc-port-a N      First daemon RPC port (127.0.0.1)
  --rpc-port-b N      Second daemon RPC port (127.0.0.1)

Options:
  --from H            Lower height bound, inclusive (default: 0)
  --to H              Upper height bound, inclusive (default: min of
                      head_a-1, head_b-1 — last finalized index present
                      on both daemons)
  --stride N          Probe every Nth height. Default 100 for windows
                      > 100 blocks, 1 otherwise. Use --stride 1 to
                      force every-block diff.
  --fields LIST       Comma-separated field names to compare. Default:
                      block_hash,state_root. Allowed:
                        block_hash, state_root, prev_hash, timestamp
                      Order is preserved for output.
  --json              Emit single-line JSON envelope (see below)
  --anomalies-only    Suppress per-height OK rows in human output; only
                      print divergent heights + summary.
  -h, --help          Show this help

Exit codes:
  0   no divergences
  1   RPC error / args / malformed response
  2   divergences detected

JSON envelope (--json):
  {"port_a": N, "port_b": N,
   "head_a": N, "head_b": N, "head_delta": N,
   "range": {"from": H, "to": H, "stride": N, "sampled": N},
   "fields": ["block_hash","state_root", ...],
   "divergences": [
     {"height": H, "field": "block_hash|state_root|...",
      "a": "<value>", "b": "<value>"}, ...
   ],
   "summary": {
     "n_divergent_heights": N,
     "fields_with_divergence": ["block_hash", ...]
   },
   "anomalies": [
     "block_hash_divergence" | "state_root_divergence" |
     "head_delta_large" | "head_a_eq_head_b_but_hashes_differ", ...
   ]}

Examples:
  # Full chain pairwise diff, default stride.
  tools/operator_chain_diff.sh --rpc-port-a 7778 --rpc-port-b 7779

  # Force every-block diff on a short suspect range.
  tools/operator_chain_diff.sh --rpc-port-a 7778 --rpc-port-b 7779 \
      --from 5000 --to 5100 --stride 1

  # Include timestamp + prev_hash for forensic drill-down.
  tools/operator_chain_diff.sh --rpc-port-a 7778 --rpc-port-b 7779 \
      --fields block_hash,state_root,prev_hash,timestamp --json
EOF
}

PORT_A=""
PORT_B=""
FROM=""
TO=""
STRIDE=""
FIELDS_RAW=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port-a)      PORT_A="${2:-}"; shift 2 ;;
    --rpc-port-b)      PORT_B="${2:-}"; shift 2 ;;
    --from)            FROM="${2:-}";   shift 2 ;;
    --to)              TO="${2:-}";     shift 2 ;;
    --stride)          STRIDE="${2:-}"; shift 2 ;;
    --fields)          FIELDS_RAW="${2:-}"; shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_chain_diff: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORT_A" ] || [ -z "$PORT_B" ]; then
  echo "operator_chain_diff: --rpc-port-a and --rpc-port-b are required" >&2
  usage >&2
  exit 1
fi
for label_val in "rpc-port-a:$PORT_A" "rpc-port-b:$PORT_B"; do
  label=${label_val%%:*}
  v=${label_val#*:}
  case "$v" in *[!0-9]*|"")
    echo "operator_chain_diff: --$label must be a positive integer (got '$v')" >&2
    exit 1 ;;
  esac
  if [ "$v" -lt 1 ] || [ "$v" -gt 65535 ]; then
    echo "operator_chain_diff: --$label must be 1..65535 (got '$v')" >&2
    exit 1
  fi
done
for label_val in "from:$FROM" "to:$TO" "stride:$STRIDE"; do
  label=${label_val%%:*}
  v=${label_val#*:}
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_chain_diff: --$label must be a non-negative integer (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

# --fields default + validation. Empty → "block_hash,state_root".
if [ -z "$FIELDS_RAW" ]; then
  FIELDS_RAW="block_hash,state_root"
fi
FIELDS=""
IFS=',' read -ra _FIELDS <<<"$FIELDS_RAW"
for raw in "${_FIELDS[@]}"; do
  f="${raw#"${raw%%[![:space:]]*}"}"
  f="${f%"${f##*[![:space:]]}"}"
  [ -z "$f" ] && continue
  case "$f" in
    block_hash|state_root|prev_hash|timestamp) ;;
    *)
      echo "operator_chain_diff: --fields entry '$f' not allowed; allowed: block_hash,state_root,prev_hash,timestamp" >&2
      exit 1 ;;
  esac
  # Dedup while preserving operator-supplied order.
  case " $FIELDS " in
    *" $f "*) continue ;;
  esac
  if [ -z "$FIELDS" ]; then FIELDS="$f"; else FIELDS="$FIELDS $f"; fi
done
if [ -z "$FIELDS" ]; then
  echo "operator_chain_diff: --fields resolved to an empty list" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

extract_num() {
  # extract_num <json> <key>
  if [ "$HAVE_JQ" = "1" ]; then
    printf '%s' "$1" | jq -r ".${2} // 0"
  else
    printf '%s' "$1" | grep -o "\"${2}\":[^,}]*" | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//'
  fi
}

# ── Probe head on both daemons. ───────────────────────────────────────────────
HEAD_A_OUT=$("$DETERM" head --json --rpc-port "$PORT_A" 2>/dev/null) || {
  echo "operator_chain_diff: RPC error querying head on port $PORT_A (is daemon running?)" >&2
  exit 1
}
HEAD_B_OUT=$("$DETERM" head --json --rpc-port "$PORT_B" 2>/dev/null) || {
  echo "operator_chain_diff: RPC error querying head on port $PORT_B (is daemon running?)" >&2
  exit 1
}
HEAD_A=$(extract_num "$HEAD_A_OUT" height)
HEAD_B=$(extract_num "$HEAD_B_OUT" height)
case "$HEAD_A" in *[!0-9]*|"")
  echo "operator_chain_diff: head height on port $PORT_A not numeric (got '$HEAD_A')" >&2
  exit 1 ;;
esac
case "$HEAD_B" in *[!0-9]*|"")
  echo "operator_chain_diff: head height on port $PORT_B not numeric (got '$HEAD_B')" >&2
  exit 1 ;;
esac
if [ "$HEAD_A" = "0" ] && [ "$HEAD_B" = "0" ]; then
  echo "operator_chain_diff: both daemons report height=0 (chain empty); nothing to diff" >&2
  exit 1
fi

# head_delta = |head_a - head_b|.
if [ "$HEAD_A" -ge "$HEAD_B" ]; then
  HEAD_DELTA=$(( HEAD_A - HEAD_B ))
else
  HEAD_DELTA=$(( HEAD_B - HEAD_A ))
fi

# Last finalized index present on BOTH daemons is min(head_a, head_b) - 1.
# (`head` returns height = next index to be written; last finalized = height-1.)
if [ "$HEAD_A" -le "$HEAD_B" ]; then
  COMMON_HEAD=$HEAD_A
else
  COMMON_HEAD=$HEAD_B
fi
if [ "$COMMON_HEAD" = "0" ]; then
  # One daemon has no finalized blocks at all → no overlap to diff. Treat
  # as RPC/state error rather than divergence — the diff is undefined.
  echo "operator_chain_diff: no common finalized height (head_a=$HEAD_A head_b=$HEAD_B)" >&2
  exit 1
fi
COMMON_TIP=$(( COMMON_HEAD - 1 ))

# Resolve window. Default [0..COMMON_TIP].
if [ -z "$FROM" ]; then FROM=0; fi
if [ -z "$TO" ];   then TO=$COMMON_TIP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_chain_diff: invalid window: --from $FROM > --to $TO" >&2
  exit 1
fi
if [ "$TO" -gt "$COMMON_TIP" ]; then
  echo "operator_chain_diff: --to $TO exceeds common finalized tip $COMMON_TIP (head_a=$HEAD_A head_b=$HEAD_B)" >&2
  exit 1
fi

# Default stride: 100 for ranges > 100, 1 otherwise.
WINDOW_LEN=$(( TO - FROM + 1 ))
if [ -z "$STRIDE" ]; then
  if [ "$WINDOW_LEN" -gt 100 ]; then STRIDE=100; else STRIDE=1; fi
fi
if [ "$STRIDE" -le 0 ]; then
  echo "operator_chain_diff: --stride must be > 0 (got $STRIDE)" >&2
  exit 1
fi

DIVERGENCES_FILE=$(mktemp 2>/dev/null) || { echo "operator_chain_diff: cannot create tmp file" >&2; exit 1; }
ANOMALIES_FILE=$(mktemp 2>/dev/null)   || { echo "operator_chain_diff: cannot create tmp file" >&2; exit 1; }
FIELDS_DIVERGED_FILE=$(mktemp 2>/dev/null) || { echo "operator_chain_diff: cannot create tmp file" >&2; exit 1; }
DIVERGENT_HEIGHTS_FILE=$(mktemp 2>/dev/null) || { echo "operator_chain_diff: cannot create tmp file" >&2; exit 1; }
trap 'rm -f "$DIVERGENCES_FILE" "$ANOMALIES_FILE" "$FIELDS_DIVERGED_FILE" "$DIVERGENT_HEIGHTS_FILE"' EXIT

push_divergence() {
  # push_divergence <height> <field> <a_value> <b_value>
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$DIVERGENCES_FILE"
  printf '%s\n' "$2" >> "$FIELDS_DIVERGED_FILE"
  printf '%s\n' "$1" >> "$DIVERGENT_HEIGHTS_FILE"
}
push_anomaly() {
  printf '%s\n' "$1" >> "$ANOMALIES_FILE"
}
has_anomaly() {
  grep -Fxq "$1" "$ANOMALIES_FILE" 2>/dev/null
}

# ── head_delta_large anomaly. ────────────────────────────────────────────────
if [ "$HEAD_DELTA" -gt 10 ]; then
  push_anomaly "head_delta_large"
fi

# ── head_a_eq_head_b_but_hashes_differ anomaly (silent fork at tip). ─────────
# Pre-check before the main walk so the operator sees the "fatal at tip"
# signal even if the requested --to excludes COMMON_TIP. Only meaningful
# when both daemons report the SAME head height AND that height >= 1
# (head_hash at height 0 is undefined; finalized tip is height-1).
if [ "$HEAD_A" = "$HEAD_B" ] && [ "$HEAD_A" -ge 1 ]; then
  TIP_HASH_A=$("$DETERM" block-info "$COMMON_TIP" --field block_hash --rpc-port "$PORT_A" 2>/dev/null | tr -d '[:space:]')
  TIP_HASH_B=$("$DETERM" block-info "$COMMON_TIP" --field block_hash --rpc-port "$PORT_B" 2>/dev/null | tr -d '[:space:]')
  if [ -n "$TIP_HASH_A" ] && [ -n "$TIP_HASH_B" ] && [ "$TIP_HASH_A" != "$TIP_HASH_B" ]; then
    push_anomaly "head_a_eq_head_b_but_hashes_differ"
    # Also record the tip-level divergence row so it shows up in the table
    # even if --stride would have skipped this height.
    push_divergence "$COMMON_TIP" "block_hash" "$TIP_HASH_A" "$TIP_HASH_B"
  fi
fi

# ── Per-height field diff walk. ──────────────────────────────────────────────
emit_row() {
  [ "$JSON_OUT" = "1" ] && return 0
  [ "$ANOM_ONLY" = "1" ] && return 0
  printf '%s\n' "$1"
}

SAMPLED=0
H=$FROM
while [ "$H" -le "$TO" ]; do
  ROW_DIVERGED=0
  for f in $FIELDS; do
    VA=$("$DETERM" block-info "$H" --field "$f" --rpc-port "$PORT_A" 2>/dev/null | tr -d '[:space:]')
    RC_A=$?
    if [ "$RC_A" -ne 0 ]; then
      echo "operator_chain_diff: RPC error fetching block-info $H field=$f on port $PORT_A" >&2
      exit 1
    fi
    VB=$("$DETERM" block-info "$H" --field "$f" --rpc-port "$PORT_B" 2>/dev/null | tr -d '[:space:]')
    RC_B=$?
    if [ "$RC_B" -ne 0 ]; then
      echo "operator_chain_diff: RPC error fetching block-info $H field=$f on port $PORT_B" >&2
      exit 1
    fi
    if [ "$VA" != "$VB" ]; then
      push_divergence "$H" "$f" "$VA" "$VB"
      ROW_DIVERGED=1
      case "$f" in
        block_hash)
          has_anomaly "block_hash_divergence" || push_anomaly "block_hash_divergence" ;;
        state_root)
          has_anomaly "state_root_divergence" || push_anomaly "state_root_divergence" ;;
      esac
    fi
  done
  SAMPLED=$(( SAMPLED + 1 ))

  # Progress / per-height row in human mode.
  if [ "$JSON_OUT" = "0" ]; then
    if [ "$ROW_DIVERGED" = "1" ]; then
      # Always show divergent rows, even with --anomalies-only.
      :  # detail printed in the dedicated divergence table below
    elif [ "$ANOM_ONLY" = "0" ]; then
      # Cap chatter — only print every Nth where N is max(stride, 100).
      CHATTER=$STRIDE
      if [ "$CHATTER" -lt 100 ]; then CHATTER=100; fi
      if [ "$(( H % CHATTER ))" = "0" ] || [ "$H" = "$TO" ]; then
        emit_row "block $H: agree on $(echo $FIELDS | tr ' ' ',')"
      fi
    fi
  fi

  H=$(( H + STRIDE ))
done

# ── Summary aggregation. ─────────────────────────────────────────────────────
DIV_COUNT=0
if [ -s "$DIVERGENCES_FILE" ]; then
  DIV_COUNT=$(wc -l < "$DIVERGENCES_FILE" | tr -d '[:space:]')
fi
N_DIVERGENT_HEIGHTS=0
if [ -s "$DIVERGENT_HEIGHTS_FILE" ]; then
  N_DIVERGENT_HEIGHTS=$(sort -u "$DIVERGENT_HEIGHTS_FILE" | wc -l | tr -d '[:space:]')
fi
FIELDS_DIVERGED_UNIQ=""
if [ -s "$FIELDS_DIVERGED_FILE" ]; then
  FIELDS_DIVERGED_UNIQ=$(sort -u "$FIELDS_DIVERGED_FILE" | tr '\n' ' ')
fi

ANOM_COUNT=0
if [ -s "$ANOMALIES_FILE" ]; then
  sort -u "$ANOMALIES_FILE" > "$ANOMALIES_FILE.dedup"
  mv "$ANOMALIES_FILE.dedup" "$ANOMALIES_FILE"
  ANOM_COUNT=$(wc -l < "$ANOMALIES_FILE" | tr -d '[:space:]')
fi

RC=0
[ "$DIV_COUNT" -gt 0 ] && RC=2
[ "$ANOM_COUNT" -gt 0 ] && RC=2

# ── JSON emit. ───────────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Build divergences JSON via python (escapes arbitrary content safely).
  DIV_JSON="[]"
  if [ -s "$DIVERGENCES_FILE" ]; then
    PYEXE=""
    if command -v python3 >/dev/null 2>&1; then PYEXE=python3
    elif command -v python >/dev/null 2>&1; then PYEXE=python
    fi
    if [ -n "$PYEXE" ]; then
      DIV_JSON=$("$PYEXE" - "$DIVERGENCES_FILE" <<'PY'
import json, sys
rows = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        h = parts[0]
        try:    height = int(h)
        except ValueError: height = h
        rows.append({
            "height": height,
            "field":  parts[1],
            "a":      parts[2],
            "b":      parts[3],
        })
print(json.dumps(rows, separators=(",", ":")))
PY
)
    else
      # Hand-rolled fallback (values are hashes / integers / RPC-safe names).
      DIV_JSON="["
      first=1
      while IFS=$'\t' read -r h fld a b; do
        [ -z "$h" ] && continue
        if [ "$first" = "1" ]; then first=0; else DIV_JSON="$DIV_JSON,"; fi
        DIV_JSON="$DIV_JSON{\"height\":$h,\"field\":\"$fld\",\"a\":\"$a\",\"b\":\"$b\"}"
      done < "$DIVERGENCES_FILE"
      DIV_JSON="$DIV_JSON]"
    fi
  fi

  ANOM_JSON="[]"
  if [ "$ANOM_COUNT" -gt 0 ]; then
    ANOM_JSON="["
    first=1
    while IFS= read -r a; do
      [ -z "$a" ] && continue
      if [ "$first" = "1" ]; then first=0; else ANOM_JSON="$ANOM_JSON,"; fi
      ANOM_JSON="$ANOM_JSON\"$a\""
    done < "$ANOMALIES_FILE"
    ANOM_JSON="$ANOM_JSON]"
  fi

  FIELDS_JSON="["
  first=1
  for f in $FIELDS; do
    if [ "$first" = "1" ]; then first=0; else FIELDS_JSON="$FIELDS_JSON,"; fi
    FIELDS_JSON="$FIELDS_JSON\"$f\""
  done
  FIELDS_JSON="$FIELDS_JSON]"

  FIELDS_DIVERGED_JSON="["
  first=1
  for f in $FIELDS_DIVERGED_UNIQ; do
    [ -z "$f" ] && continue
    if [ "$first" = "1" ]; then first=0; else FIELDS_DIVERGED_JSON="$FIELDS_DIVERGED_JSON,"; fi
    FIELDS_DIVERGED_JSON="$FIELDS_DIVERGED_JSON\"$f\""
  done
  FIELDS_DIVERGED_JSON="$FIELDS_DIVERGED_JSON]"

  cat <<EOF
{"port_a":$PORT_A,"port_b":$PORT_B,"head_a":$HEAD_A,"head_b":$HEAD_B,"head_delta":$HEAD_DELTA,"range":{"from":$FROM,"to":$TO,"stride":$STRIDE,"sampled":$SAMPLED},"fields":$FIELDS_JSON,"divergences":$DIV_JSON,"summary":{"n_divergent_heights":$N_DIVERGENT_HEIGHTS,"fields_with_divergence":$FIELDS_DIVERGED_JSON},"anomalies":$ANOM_JSON}
EOF
  exit $RC
fi

# ── Human render. ────────────────────────────────────────────────────────────
echo ""
echo "=== Chain diff (port_a=$PORT_A vs port_b=$PORT_B) ==="
echo "Heads:       a=$HEAD_A  b=$HEAD_B  delta=$HEAD_DELTA"
echo "Window:      [$FROM..$TO]  ($WINDOW_LEN blocks, stride $STRIDE => $SAMPLED sampled)"
echo "Fields:      $(echo $FIELDS | tr ' ' ',')"
echo "Common tip:  $COMMON_TIP"

if [ "$DIV_COUNT" -gt 0 ]; then
  echo ""
  echo "Divergences ($DIV_COUNT entries across $N_DIVERGENT_HEIGHTS heights):"
  printf '  %-8s  %-12s  %-32s  %-32s\n' "height" "field" "a (port $PORT_A)" "b (port $PORT_B)"
  printf '  %-8s  %-12s  %-32s  %-32s\n' "--------" "------------" "--------------------------------" "--------------------------------"
  while IFS=$'\t' read -r h fld a b; do
    [ -z "$h" ] && continue
    # Truncate long hash values for table readability.
    a_disp="$a"
    b_disp="$b"
    if [ "${#a_disp}" -gt 32 ]; then a_disp="${a_disp:0:29}..."; fi
    if [ "${#b_disp}" -gt 32 ]; then b_disp="${b_disp:0:29}..."; fi
    printf '  %-8s  %-12s  %-32s  %-32s\n' "$h" "$fld" "$a_disp" "$b_disp"
  done < "$DIVERGENCES_FILE"
fi

if [ "$ANOM_COUNT" -gt 0 ]; then
  echo ""
  echo "Anomalies ($ANOM_COUNT):"
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    echo "  [!] $a"
  done < "$ANOMALIES_FILE"
fi

echo ""
echo "Summary: n_divergent_heights=$N_DIVERGENT_HEIGHTS  fields_with_divergence=[$(echo $FIELDS_DIVERGED_UNIQ | tr -s ' ' | sed 's/ /, /g; s/, $//')]"
echo ""
if [ "$RC" = "0" ]; then
  echo "[OK] No divergences detected between port_a=$PORT_A and port_b=$PORT_B over [$FROM..$TO]."
else
  echo "[X]  Divergences detected — daemons disagree on chain history (see anomalies above)."
fi
exit $RC
