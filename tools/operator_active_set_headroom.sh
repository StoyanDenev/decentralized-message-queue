#!/usr/bin/env bash
# operator_active_set_headroom.sh — Live ACTIVE-CREATOR-SET headroom +
# registry-ineligibility margin audit for a running determ daemon.
# Read-only RPC composition; safe against a producing chain. Single
# snapshot query then exit (no block walk, no --watch).
#
# THE OPERATOR QUESTION THIS ANSWERS
#   "Right now, can my chain still form a committee — and how much
#    margin do I have before it can't? How many registered nodes are
#    NOT currently committee-eligible (the churn/backlog overhang), and
#    is that overhang large enough to worry about?"
#
# WHY THIS IS A REAL, UNCOVERED SIGNAL
#   Determ selects a fresh committee per block from the ELIGIBLE pool —
#   the registered nodes that have crossed active_from, have not crossed
#   inactive_from, clear min_stake, and are not abort-suspended. That
#   filtering happens server-side in
#   src/node/registry.cpp::build_from_chain (lines 60-64: the four
#   `continue` gates), so `determ validators --json` returns EXACTLY the
#   eligible set — its array length is the live eligible-pool size.
#
#   `determ status` separately reports:
#     node_count  = registry_.size()  (src/node/node.cpp:2466) — the
#                   TOTAL registry, including pending-activation,
#                   exiting, suspended, and under-min-stake entries.
#     m_creators  = cfg_.m_creators   (src/node/node.cpp:2469) — the
#                   genesis-pinned full K-of-K committee-size target.
#     k_block_sigs= cfg_.k_block_sigs (src/node/node.cpp:2470) — the
#                   strong-mode required-signature count (== m_creators
#                   for full mutual distrust; < m_creators for hybrid).
#
#   The committee cannot be drawn at full size unless
#       eligible_count >= m_creators
#   and the chain cannot even form the BFT-degraded committee unless
#       eligible_count >= k_bft = ceil(2 * m_creators / 3)
#   where k_bft is the first of the two shrinkages in
#   src/node/producer.cpp::required_block_sigs (lines 541-552:
#   `return (2 * committee_size + 2) / 3`, the integer ceil form). Below
#   k_bft the chain is in under-quorum-merge / liveness-stall territory.
#
#   The gap between node_count and eligible_count is the registry's
#   INELIGIBILITY OVERHANG: registered nodes that exist but cannot serve
#   on a committee this block (pending activation, on the DEREGISTER exit
#   pipeline, abort-suspended, or under min_stake). A large or growing
#   overhang relative to the total registry is a churn / mis-stake signal.
#
# SIBLING-SCRIPT POSITIONING (none compute live eligible-vs-target margin)
#   operator_stake_activation_audit.sh   Per-validator ENTRY lifecycle:
#                                         registered_at -> active_from
#                                         latency + pending/active/exiting
#                                         classification. Reads stakes +
#                                         show-account per domain. Never
#                                         reads m_creators / k_block_sigs /
#                                         node_count, never frames the
#                                         pool's committee-formation margin.
#   operator_validator_unstake_pipeline.sh
#                                         EXIT pipeline (DEREGISTER ->
#                                         UNSTAKE pairing across a window).
#   operator_committee_snapshot.sh        Single-height committee MEMBERS
#                                         + required_sigs gate for ONE
#                                         block's creators[]; not the live
#                                         pool-size-vs-target headroom.
#   operator_committee_audit.sh /
#   operator_validator_committee_share.sh Per-validator stake-proportional
#                                         SELECTION fairness over a block
#                                         window; orthogonal to pool margin.
#   operator_config_audit.sh              Reads m_creators / k_block_sigs
#                                         from a STATIC config.json FILE
#                                         (--config), not the live registry
#                                         eligible-pool size. No headroom math.
#   operator_active_set_headroom.sh (THIS)
#                                         Live eligible_count vs m_creators
#                                         (full) and k_bft (BFT) headroom,
#                                         plus the node_count-vs-eligible
#                                         ineligibility overhang. The pool's
#                                         committee-formation safety margin.
#
# Cost is two lock-free RPC calls total (`determ status` + `determ
# validators --json`) regardless of pool size — O(1), not O(N).
#
# Args:
#   [--rpc-port N]         RPC port to query (default: 7778)
#   [--json]               Emit a structured JSON envelope
#   [--anomalies-only]     Print only when >=1 anomaly fires; exit 2 then
#   [--min-full-headroom N]
#                          Flag thin_full_headroom when
#                          0 <= (eligible - m_creators) < N (default: 2).
#                          The pool can still form a full committee but
#                          has little buffer against churn.
#   [--max-ineligible-pct P]
#                          Flag high_ineligible_overhang when the
#                          ineligible fraction (ineligible / node_count)
#                          exceeds P percent (default: 50).
#   [-h|--help]            Show this help
#
# Anomaly flags:
#   cannot_form_bft_committee  eligible_count < k_bft = ceil(2*m_creators/3)
#                              — HARD liveness stall: not even the
#                              BFT-degraded committee can be drawn.
#   cannot_form_full_committee eligible_count < m_creators — full K-of-K
#                              committee cannot be drawn (chain is forced
#                              into the BFT-degraded / merge path).
#   thin_full_headroom         0 <= (eligible - m_creators) <
#                              --min-full-headroom — a full committee
#                              forms but the buffer is thin.
#   high_ineligible_overhang   ineligible / node_count > --max-ineligible-pct%
#                              — large registered-but-not-eligible overhang
#                              (churn / mis-stake / activation backlog).
#
# Exit codes:
#   0   audit ran, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND >=1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_active_set_headroom.sh [--rpc-port N] [--json]
                                       [--anomalies-only]
                                       [--min-full-headroom N]
                                       [--max-ineligible-pct P]

Live active-creator-set headroom audit. Queries `determ status`
(node_count, m_creators, k_block_sigs) and `determ validators --json`
(the eligible active set) and computes the committee-formation margin:

  eligible_count   = len(validators[])           (live eligible pool)
  k_bft            = ceil(2 * m_creators / 3)     (BFT-degraded floor)
  headroom_full    = eligible_count - m_creators  (margin above full K)
  headroom_bft     = eligible_count - k_bft       (margin above BFT floor)
  ineligible_count = node_count - eligible_count  (registered, not eligible)
  ineligible_pct   = 100 * ineligible_count / node_count

Options:
  --rpc-port N            RPC port to query (default: 7778)
  --json                  Emit a structured JSON envelope
  --anomalies-only        Print only when >=1 anomaly fires; exit 2 then
  --min-full-headroom N   thin_full_headroom when 0 <= headroom_full < N
                          (default: 2)
  --max-ineligible-pct P  high_ineligible_overhang when ineligible_pct > P
                          (default: 50)
  -h, --help              Show this help

Anomalies:
  cannot_form_bft_committee   eligible_count < k_bft (hard liveness stall)
  cannot_form_full_committee  eligible_count < m_creators
  thin_full_headroom          0 <= headroom_full < --min-full-headroom
  high_ineligible_overhang    ineligible_pct > --max-ineligible-pct

JSON shape:
  {"node_count": N, "eligible_count": E, "ineligible_count": I,
   "ineligible_pct": P, "m_creators": M, "k_block_sigs": KS, "k_bft": KB,
   "headroom_full": HF, "headroom_bft": HB,
   "regions": [{"region": "...", "eligible": N}, ...],
   "anomalies": [...], "rpc_port": P,
   "thresholds": {"min_full_headroom": N, "max_ineligible_pct": P}}

Exit codes:
  0   success, no anomalies (or default informational mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND >=1 anomaly detected
EOF
}

PORT=7778
JSON=0
ANOM_ONLY=0
MIN_FULL_HEADROOM=2
MAX_INELIGIBLE_PCT=50
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)              usage; exit 0 ;;
    --rpc-port)             PORT="${2:-}";                shift 2 ;;
    --json)                 JSON=1;                       shift ;;
    --anomalies-only)       ANOM_ONLY=1;                  shift ;;
    --min-full-headroom)    MIN_FULL_HEADROOM="${2:-}";   shift 2 ;;
    --max-ineligible-pct)   MAX_INELIGIBLE_PCT="${2:-}";  shift 2 ;;
    *) echo "operator_active_set_headroom: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_active_set_headroom: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$MIN_FULL_HEADROOM" in *[!0-9]*|"")
  echo "operator_active_set_headroom: --min-full-headroom must be a non-negative integer (got '$MIN_FULL_HEADROOM')" >&2
  exit 1 ;;
esac
case "$MAX_INELIGIBLE_PCT" in *[!0-9]*|"")
  echo "operator_active_set_headroom: --max-ineligible-pct must be an integer 0..100 (got '$MAX_INELIGIBLE_PCT')" >&2
  exit 1 ;;
esac
if [ "$MAX_INELIGIBLE_PCT" -gt 100 ]; then
  echo "operator_active_set_headroom: --max-ineligible-pct must be <= 100 (got '$MAX_INELIGIBLE_PCT')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: status snapshot (node_count, m_creators, k_block_sigs) ────────────
# Daemon-unreachable here is the clean SKIP path: emit an INFO line (or a
# {"skipped":true} envelope) and exit 0 so a scheduled census never pages
# on a node that is simply down / not yet up.
STATUS_OUT=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON" = "1" ]; then
    printf '{"skipped":true,"reason":"daemon_unreachable","rpc_port":%s}\n' "$PORT"
  else
    echo "INFO: operator_active_set_headroom: daemon unreachable on port $PORT — SKIP"
  fi
  exit 0
}

if [ "$HAVE_JQ" = "1" ]; then
  NODE_COUNT=$(printf '%s' "$STATUS_OUT"  | jq -r '.node_count   // empty')
  M_CREATORS=$(printf '%s' "$STATUS_OUT"  | jq -r '.m_creators   // empty')
  K_BLOCK_SIGS=$(printf '%s' "$STATUS_OUT"| jq -r '.k_block_sigs // empty')
else
  NODE_COUNT=$(printf '%s' "$STATUS_OUT"  | grep -o '"node_count":[^,}]*'   | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  M_CREATORS=$(printf '%s' "$STATUS_OUT"  | grep -o '"m_creators":[^,}]*'   | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  K_BLOCK_SIGS=$(printf '%s' "$STATUS_OUT"| grep -o '"k_block_sigs":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
fi

case "$NODE_COUNT"   in *[!0-9]*|"") echo "operator_active_set_headroom: malformed status JSON (node_count='$NODE_COUNT')" >&2;   exit 1 ;; esac
case "$M_CREATORS"   in *[!0-9]*|"") echo "operator_active_set_headroom: malformed status JSON (m_creators='$M_CREATORS')" >&2;   exit 1 ;; esac
case "$K_BLOCK_SIGS" in *[!0-9]*|"") echo "operator_active_set_headroom: malformed status JSON (k_block_sigs='$K_BLOCK_SIGS')" >&2; exit 1 ;; esac

# ── Step 2: eligible active set (validators --json), with region tally ────────
# `determ validators --json` returns the server-filtered eligible pool
# (src/node/registry.cpp::build_from_chain). Its array length is the live
# eligible_count; each entry carries a `region` ("" = global).
VAL_OUT=$("$DETERM" validators --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_active_set_headroom: RPC error from \`determ validators\` (port $PORT)" >&2
  exit 1
}

# A per-region eligible tally lets a regional-sharding operator see WHICH
# region is thin, not just the global aggregate. Parsing is driven through
# Python (already a hard dependency of the sibling audit scripts) so the
# region grouping stays robust without jq.
REGION_TALLY=$(printf '%s' "$VAL_OUT" | python -c "
import sys, json
try:
    arr = json.load(sys.stdin)
except Exception:
    sys.stderr.write('PARSE_ERR\n'); sys.exit(3)
if not isinstance(arr, list):
    sys.stderr.write('NOT_ARRAY\n'); sys.exit(3)
counts = {}
for v in arr:
    if not isinstance(v, dict):
        continue
    r = v.get('region', '')
    if not isinstance(r, str) or r == '':
        r = '(global)'
    counts[r] = counts.get(r, 0) + 1
# First line: total eligible. Following lines: region<TAB>count, sorted.
print(len(arr))
for r in sorted(counts):
    print('{}\t{}'.format(r, counts[r]))
")
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_active_set_headroom: malformed validators JSON (port $PORT)" >&2
  exit 1
fi

ELIGIBLE_COUNT=$(printf '%s' "$REGION_TALLY" | head -1)
case "$ELIGIBLE_COUNT" in *[!0-9]*|"")
  echo "operator_active_set_headroom: could not derive eligible_count" >&2
  exit 1 ;;
esac
# Region rows = everything after the first line.
REGION_ROWS=$(printf '%s\n' "$REGION_TALLY" | tail -n +2)

# ── Step 3: derived metrics ──────────────────────────────────────────────────
# k_bft = ceil(2 * m_creators / 3) = (2*M + 2) / 3  (integer ceil),
# matching src/node/producer.cpp::required_block_sigs:552.
K_BFT=$(( (2 * M_CREATORS + 2) / 3 ))

# Ineligibility overhang. node_count should never be < eligible_count
# (eligible is a subset of registered); clamp defensively at 0 so a
# transient race never produces a negative count.
if [ "$NODE_COUNT" -ge "$ELIGIBLE_COUNT" ]; then
  INELIGIBLE_COUNT=$(( NODE_COUNT - ELIGIBLE_COUNT ))
else
  INELIGIBLE_COUNT=0
fi

# Integer-percent ineligible (floor). Zero registry → 0%.
if [ "$NODE_COUNT" -gt 0 ]; then
  INELIGIBLE_PCT=$(( INELIGIBLE_COUNT * 100 / NODE_COUNT ))
else
  INELIGIBLE_PCT=0
fi

# Signed headroom values (may be negative when the pool is starved).
HEADROOM_FULL=$(( ELIGIBLE_COUNT - M_CREATORS ))
HEADROOM_BFT=$(( ELIGIBLE_COUNT - K_BFT ))

# ── Step 4: anomaly classification ───────────────────────────────────────────
ANOMS=""
add_anom() { if [ -z "$ANOMS" ]; then ANOMS="$1"; else ANOMS="$ANOMS $1"; fi; }

# Hard stall first (most severe). Only meaningful when m_creators > 0.
if [ "$M_CREATORS" -gt 0 ] && [ "$ELIGIBLE_COUNT" -lt "$K_BFT" ]; then
  add_anom "cannot_form_bft_committee"
fi
# Full-committee shortfall (a chain below k_bft is also below m_creators;
# both flags fire so the operator sees the full severity ladder).
if [ "$M_CREATORS" -gt 0 ] && [ "$ELIGIBLE_COUNT" -lt "$M_CREATORS" ]; then
  add_anom "cannot_form_full_committee"
fi
# Thin (but non-negative) full headroom — only when a full committee can
# still form (headroom_full >= 0) but the buffer is below the floor.
if [ "$HEADROOM_FULL" -ge 0 ] && [ "$HEADROOM_FULL" -lt "$MIN_FULL_HEADROOM" ]; then
  add_anom "thin_full_headroom"
fi
# High ineligibility overhang.
if [ "$INELIGIBLE_PCT" -gt "$MAX_INELIGIBLE_PCT" ]; then
  add_anom "high_ineligible_overhang"
fi

# Count anomalies.
ANOM_COUNT=0
for _a in $ANOMS; do ANOM_COUNT=$(( ANOM_COUNT + 1 )); done

# ── Step 5: emit output ──────────────────────────────────────────────────────
if [ "$JSON" = "1" ]; then
  # Region array.
  REGIONS_JSON="["
  FIRST=1
  if [ -n "$REGION_ROWS" ]; then
    while IFS=$'\t' read -r RNAME RCNT; do
      [ -z "$RNAME" ] && continue
      [ "$FIRST" = "1" ] || REGIONS_JSON="$REGIONS_JSON,"
      FIRST=0
      # Escape backslash + double-quote in region names for valid JSON.
      RESC=$(printf '%s' "$RNAME" | sed 's/\\/\\\\/g; s/"/\\"/g')
      REGIONS_JSON="$REGIONS_JSON{\"region\":\"$RESC\",\"eligible\":$RCNT}"
    done <<EOF
$REGION_ROWS
EOF
  fi
  REGIONS_JSON="$REGIONS_JSON]"

  # Anomalies array.
  ANOM_JSON="["
  FIRST=1
  for _a in $ANOMS; do
    [ "$FIRST" = "1" ] || ANOM_JSON="$ANOM_JSON,"
    FIRST=0
    ANOM_JSON="$ANOM_JSON\"$_a\""
  done
  ANOM_JSON="$ANOM_JSON]"

  printf '{"node_count":%s,"eligible_count":%s,"ineligible_count":%s,"ineligible_pct":%s,"m_creators":%s,"k_block_sigs":%s,"k_bft":%s,"headroom_full":%s,"headroom_bft":%s,"regions":%s,"anomalies":%s,"rpc_port":%s,"thresholds":{"min_full_headroom":%s,"max_ineligible_pct":%s}}\n' \
    "$NODE_COUNT" "$ELIGIBLE_COUNT" "$INELIGIBLE_COUNT" "$INELIGIBLE_PCT" \
    "$M_CREATORS" "$K_BLOCK_SIGS" "$K_BFT" "$HEADROOM_FULL" "$HEADROOM_BFT" \
    "$REGIONS_JSON" "$ANOM_JSON" "$PORT" "$MIN_FULL_HEADROOM" "$MAX_INELIGIBLE_PCT"
else
  # --anomalies-only: suppress the normal digest unless an anomaly fired.
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -eq 0 ]; then
    echo "operator_active_set_headroom: no anomalies (port $PORT, eligible $ELIGIBLE_COUNT / node_count $NODE_COUNT, m_creators $M_CREATORS)"
  else
    echo "operator_active_set_headroom (port $PORT):"
    echo "  registry total (node_count) : $NODE_COUNT"
    echo "  eligible active set         : $ELIGIBLE_COUNT"
    echo "  ineligible overhang         : $INELIGIBLE_COUNT (${INELIGIBLE_PCT}%)"
    echo "  m_creators (full K target)  : $M_CREATORS"
    echo "  k_block_sigs (strong sigs)  : $K_BLOCK_SIGS"
    echo "  k_bft = ceil(2*M/3)         : $K_BFT"
    echo "  headroom vs full committee  : $HEADROOM_FULL"
    echo "  headroom vs BFT floor       : $HEADROOM_BFT"
    if [ -n "$REGION_ROWS" ]; then
      echo "  eligible by region:"
      while IFS=$'\t' read -r RNAME RCNT; do
        [ -z "$RNAME" ] && continue
        printf '    %-20s %s\n' "$RNAME" "$RCNT"
      done <<EOF
$REGION_ROWS
EOF
    fi
    echo
    if [ "$ANOM_COUNT" -eq 0 ]; then
      echo "[OK] Active set healthy — full committee forms with adequate headroom"
    else
      for _a in $ANOMS; do
        case "$_a" in
          cannot_form_bft_committee)
            echo "[ANOMALY] cannot_form_bft_committee — eligible $ELIGIBLE_COUNT < k_bft $K_BFT (hard liveness stall)" ;;
          cannot_form_full_committee)
            echo "[ANOMALY] cannot_form_full_committee — eligible $ELIGIBLE_COUNT < m_creators $M_CREATORS (forced into BFT/merge path)" ;;
          thin_full_headroom)
            echo "[ANOMALY] thin_full_headroom — headroom_full $HEADROOM_FULL < --min-full-headroom $MIN_FULL_HEADROOM (little churn buffer)" ;;
          high_ineligible_overhang)
            echo "[ANOMALY] high_ineligible_overhang — ${INELIGIBLE_PCT}% of registry ineligible > ${MAX_INELIGIBLE_PCT}% (churn / activation backlog)" ;;
          *)
            echo "[ANOMALY] $_a" ;;
        esac
      done
    fi
  fi
fi

# ── Step 6: exit-code policy ─────────────────────────────────────────────────
# Mirrors the sibling convention: exit 2 ONLY fires in --anomalies-only
# mode when an anomaly is present. Default / informational mode always
# exits 0 once the RPC layer was healthy, so a scheduled census can run
# without paging; operator alerting is opt-in via --anomalies-only.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
