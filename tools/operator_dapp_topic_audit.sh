#!/usr/bin/env bash
# operator_dapp_topic_audit.sh — Audit DApp topic registration patterns
# across the on-chain DApp registry of a running determ daemon.
#
# Companion to:
#   - operator_dapp_audit.sh       (per-DApp lifecycle / metadata)
#   - operator_dapp_call_audit.sh  (call-level activity over a window)
#
# This script focuses on the *topic* dimension of v2.18 DAPP_REGISTER
# entries: a DApp may declare zero or more pubsub topics in its
# RegisterPayload.topics vector (see include/determ/chain/block.hpp).
# Topics drive subscriber routing for v2.19 DAPP_CALL / pubsub messages
# and are also the unit of operator-side spam / collision analysis.
#
# Methodology:
#   1. `determ dapp-list --json --rpc-port N` → enumerate domains.
#   2. For each domain, `determ dapp-info --domain D --rpc-port N` →
#      pull the canonical .topics array (per src/chain/block.cpp
#      RegisterPayload::to_json).
#   3. Aggregate: total distinct topics, per-DApp distribution
#      (mean / median / max), top-20 most-popular topics, zero-topic
#      DApps (pubsub-only DApps via mt-pubsub default channel),
#      broad-scope DApps (> 10 topics).
#
# Anomaly flags (--anomalies-only):
#   - spam_registration     any DApp with > 50 topics (likely registry
#                           spam; the chain has no per-DApp topic cap,
#                           so the operator-side audit is the gate)
#   - topic_collision       single topic claimed by > 80% of DApps
#                           (potential topic-namespace squat / collision
#                           attack — concentrates routing through one
#                           channel)
#
# Output (default human):
#   === DApp topic audit (port 7778) ===
#   Total DApps: 12
#   Distinct topics: 47
#   Topics-per-DApp: mean 3.9, median 3, max 18
#   Top topics:
#     daily-digest:    used by 5 DApps
#     weather-alert:   used by 3 DApps
#     ...
#   [OK] No anomalies
#
# JSON envelope:
#   {"total_dapps":12,"distinct_topics":47,"topics_per_dapp":{...},
#    "top_topics":[...],"anomalies":[],"rpc_port":7778}
#
# Exit codes (mirrors operator_dapp_call_audit.sh):
#   0   audit ran successfully (including zero-DApp registry)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_topic_audit.sh [--rpc-port N] [--json]
                                    [--anomalies-only]

Audit DApp topic registration patterns across the on-chain DApp
registry. Walks dapp-list, fetches per-domain dapp-info, aggregates
topic-usage statistics, and flags spam-registration / topic-collision
anomalies.

Options:
  --rpc-port N      RPC port to query (default: 7778)
  --json            Emit structured JSON envelope instead of human table
  --anomalies-only  Print only flagged anomalies; exit 2 if any fire
  -h, --help        Show this help

Anomaly flags:
  spam_registration  any DApp with > 50 topics (likely registry spam)
  topic_collision    single topic claimed by > 80% of DApps
                     (namespace-squat / routing-collision signal)

Exit codes:
  0   success (or informational mode, including zero-DApp registry)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}"; shift 2 ;;
    --json)            JSON_OUT=1;    shift ;;
    --anomalies-only)  ANOM_ONLY=1;   shift ;;
    *) echo "operator_dapp_topic_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guard on user-supplied port.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_topic_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_dapp_topic_audit: requires 'jq' (not found on PATH)" >&2
  exit 1
fi

# ── Step 1: enumerate DApps via dapp-list ────────────────────────────────────
LIST_OUT=$("$DETERM" dapp-list --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_topic_audit: RPC error querying dapp-list (port $PORT)" >&2
  exit 1
}

DAPPS_TYPE=$(printf '%s' "$LIST_OUT" | jq -r '.dapps | type' 2>/dev/null || true)
if [ "$DAPPS_TYPE" != "array" ]; then
  echo "operator_dapp_topic_audit: malformed dapp-list response (no .dapps array)" >&2
  exit 1
fi

DOMAINS=$(printf '%s' "$LIST_OUT" | jq -r '.dapps[].domain')

# ── Step 2: per-domain dapp-info → write JSONL into a temp file ──────────────
# JSONL keeps the Python aggregator decoupled from shell-loop quoting.
TMP_IN=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_topic_audit: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_topic_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_IN" "$TMP_OUT" 2>/dev/null' EXIT

# Empty registry → emit nothing to TMP_IN; Python handles the zero case.
if [ -n "$DOMAINS" ]; then
  while IFS= read -r DOMAIN; do
    [ -z "$DOMAIN" ] && continue
    INFO_OUT=$("$DETERM" dapp-info --domain "$DOMAIN" --rpc-port "$PORT" 2>/dev/null) || {
      echo "operator_dapp_topic_audit: RPC error querying dapp-info for '$DOMAIN'" >&2
      exit 1
    }
    # Race vs deregister: skip rather than abort.
    ERR=$(printf '%s' "$INFO_OUT" | jq -r '.error // empty')
    [ -n "$ERR" ] && continue
    # Re-emit as compact JSONL: {domain, topics:[...]}.
    printf '%s' "$INFO_OUT" \
      | jq -c --arg d "$DOMAIN" '{domain: $d, topics: (.topics // [])}' \
      >> "$TMP_IN"
  done <<EOF
$DOMAINS
EOF
fi

# ── Step 3: aggregate in Python (heredoc; mirrors operator_dapp_call_audit) ──
python - "$TMP_IN" "$TMP_OUT" <<'PY'
import json, sys
from collections import Counter

in_path, out_path = sys.argv[1], sys.argv[2]

dapps = []        # list of {"domain": str, "topics": [str, ...]}
try:
    with open(in_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if not isinstance(rec, dict): continue
            d = rec.get("domain", "")
            t = rec.get("topics", []) or []
            # Defensive: topics field shape is array<string> per spec, but
            # filter to strings to avoid surfacing schema regressions as
            # crashes in the aggregator.
            t = [x for x in t if isinstance(x, str)]
            dapps.append({"domain": d, "topics": t})
except FileNotFoundError:
    pass

total_dapps  = len(dapps)
counts       = [len(d["topics"]) for d in dapps]
all_topics   = Counter()
for d in dapps:
    # de-dupe per-DApp so a DApp with ["X","X"] counts X once toward
    # "used by N DApps". RegisterPayload validation should already
    # reject duplicates, but be defensive at the audit layer.
    for t in set(d["topics"]):
        all_topics[t] += 1

distinct_topics = len(all_topics)

# Distribution: mean (1 decimal), median, max.
if counts:
    mean_tpd = sum(counts) / len(counts)
    s        = sorted(counts)
    mid      = len(s) // 2
    median_tpd = s[mid] if len(s) % 2 == 1 else (s[mid - 1] + s[mid]) / 2
    max_tpd    = max(counts)
else:
    mean_tpd = 0.0
    median_tpd = 0
    max_tpd = 0

# Top-20 most-popular topics. Ties: usage_count desc, topic asc.
top_topics = sorted(
    all_topics.items(),
    key=lambda kv: (-kv[1], kv[0])
)[:20]

# Zero-topic DApps (informational): rely on mt-pubsub default channel.
zero_topic_dapps = sorted([d["domain"] for d in dapps if not d["topics"]])

# Broad-scope DApps (> 10 topics; informational): broad routing surface,
# not yet at the spam threshold (> 50) but worth surfacing.
broad_scope = sorted(
    [{"domain": d["domain"], "topic_count": len(d["topics"])}
     for d in dapps if len(d["topics"]) > 10],
    key=lambda r: (-r["topic_count"], r["domain"])
)

# Anomaly classification.
anomalies     = []
spam_dapps    = sorted(
    [{"domain": d["domain"], "topic_count": len(d["topics"])}
     for d in dapps if len(d["topics"]) > 50],
    key=lambda r: (-r["topic_count"], r["domain"])
)
if spam_dapps:
    anomalies.append("spam_registration")

# Topic-collision: > 80% of DApps registered the same topic.
# Use integer basis-points to avoid float-equality fragility (matches
# the bps pattern in operator_dapp_call_audit.sh).
collision_topics = []
if total_dapps > 0 and top_topics:
    threshold_bps = 8000  # 80.00%
    for t, n in top_topics:
        pct_bps = n * 10000 // total_dapps
        if pct_bps > threshold_bps:
            collision_topics.append({
                "topic":       t,
                "dapp_count":  n,
                "pct_bps":     pct_bps,
            })
if collision_topics:
    anomalies.append("topic_collision")

result = {
    "total_dapps":      total_dapps,
    "distinct_topics":  distinct_topics,
    "topics_per_dapp":  {
        # mean rounded to 1 decimal for stable JSON output.
        "mean":   round(mean_tpd, 1),
        "median": median_tpd,
        "max":    max_tpd,
    },
    "top_topics":       [{"topic": t, "dapp_count": n} for t, n in top_topics],
    "zero_topic_dapps": zero_topic_dapps,
    "broad_scope":      broad_scope,
    "spam_dapps":       spam_dapps,
    "collision_topics": collision_topics,
    "anomalies":        anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_dapp_topic_audit: aggregation failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human table) ────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

total_dapps     = r["total_dapps"]
distinct_topics = r["distinct_topics"]
tpd             = r["topics_per_dapp"]
top_topics      = r["top_topics"]
anomalies       = r["anomalies"]
anom_count      = len(anomalies)

if json_out:
    envelope = {
        "total_dapps":      total_dapps,
        "distinct_topics":  distinct_topics,
        "topics_per_dapp":  tpd,
        "top_topics":       top_topics,
        "zero_topic_dapps": r["zero_topic_dapps"],
        "broad_scope":      r["broad_scope"],
        "spam_dapps":       r["spam_dapps"],
        "collision_topics": r["collision_topics"],
        "anomalies":        anomalies,
        "rpc_port":         port,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# ── Human-readable layout ────────────────────────────────────────────────────
if anom_only and anom_count == 0:
    print(f"operator_dapp_topic_audit: no anomalies (port {port}, {total_dapps} DApps)")
    sys.exit(0)

print(f"=== DApp topic audit (port {port}) ===")
print(f"Total DApps: {total_dapps}")
print(f"Distinct topics: {distinct_topics}")

# Pretty-print mean as fixed 1-decimal; median may be int or .5 fraction.
mean_disp = f"{tpd['mean']:.1f}"
med = tpd["median"]
if isinstance(med, float) and med.is_integer():
    med_disp = str(int(med))
elif isinstance(med, float):
    med_disp = f"{med:.1f}"
else:
    med_disp = str(med)
print(f"Topics-per-DApp: mean {mean_disp}, median {med_disp}, max {tpd['max']}")

if not anom_only:
    print()
    print("Top topics:")
    if not top_topics:
        print("  (none)")
    else:
        # Compute column width for clean alignment; cap at 32 to keep
        # ultra-long topic names from breaking the table.
        w = min(32, max((len(t["topic"]) for t in top_topics), default=0))
        for t in top_topics:
            tn = t["topic"]
            if len(tn) > 32: tn = tn[:29] + "..."
            print(f"  {tn:<{w}}  used by {t['dapp_count']} DApps")

    if r["zero_topic_dapps"]:
        print()
        print(f"Zero-topic DApps ({len(r['zero_topic_dapps'])}; pubsub-only via mt-pubsub):")
        # Cap visible list at 20 to bound output; full list is in --json.
        for d in r["zero_topic_dapps"][:20]:
            print(f"  {d}")
        extra = len(r["zero_topic_dapps"]) - 20
        if extra > 0:
            print(f"  ... and {extra} more (see --json for full list)")

    if r["broad_scope"]:
        print()
        print(f"Broad-scope DApps ({len(r['broad_scope'])}; > 10 topics):")
        for d in r["broad_scope"][:20]:
            print(f"  {d['domain']}: {d['topic_count']} topics")
        extra = len(r["broad_scope"]) - 20
        if extra > 0:
            print(f"  ... and {extra} more (see --json for full list)")

print()
if anom_count == 0:
    print("[OK] No anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "spam_registration" in anomalies:
        for d in r["spam_dapps"]:
            print(f"  - spam_registration: '{d['domain']}' registered "
                  f"{d['topic_count']} topics (> 50 threshold)")
    if "topic_collision" in anomalies:
        for c in r["collision_topics"]:
            whole = c["pct_bps"] // 100
            frac  = (c["pct_bps"] % 100) // 10
            print(f"  - topic_collision: '{c['topic']}' claimed by "
                  f"{c['dapp_count']} / {total_dapps} DApps "
                  f"({whole}.{frac}% > 80% threshold)")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_topic_audit: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy (matches operator_dapp_call_audit.sh) ───────────
# Read anomaly count back from the aggregator's JSON snapshot.
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_topic_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_IN" "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
python - "$TMP_OUT" "$TMP_ANOM" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(str(len(r.get("anomalies", []))))
PY
ANOM_COUNT=$(cat "$TMP_ANOM" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
