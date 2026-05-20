#!/usr/bin/env bash
# operator_dapp_message_audit.sh — Audit v2.19 DAPP_CALL message-content
# layer over a window of blocks on a running determ daemon.
#
# Distinct from operator_dapp_call_audit.sh — that script audits
# tx-level metadata (per-target aggregation, fees, payload-size
# distribution) by walking block-info. This script drills into the
# *message-content* layer via the retrospective DAPP_CALL poll RPC
# (`determ dapp-messages --domain D [--from H --to H] [--topic T]`,
# 256/page; src/node/node.cpp::rpc_dapp_messages). The pivot is the
# topic field decoded from the canonical payload framing — useful
# for DApp operators to understand topic distribution, user base
# (top callers), payload-size shape, and average amount routed.
#
# Required scope selector (exactly one):
#   --target-domain D    Audit a single DApp identified by domain D
#   --all                Audit every DApp discovered via `dapp-list`
#                        (one dapp_messages RPC per DApp; reports
#                        per-DApp aggregation)
#
# Aggregations (per DApp):
#   - total messages
#   - by topic breakdown (count + share %)
#   - payload-size distribution (<=64B / 64B-1KB / 1KB-4KB / 4KB-16KB
#     and an >16KB defense-in-depth bucket — validator already rejects
#     such, any non-zero count is an alert)
#   - top 20 senders (by message count) — helps operators understand
#     their user base
#   - time-distribution bucket counts (configurable bucket size via
#     --bucket-blocks; defaults to ⌈win/10⌉ for trend analysis)
#   - avg + median amount routed per message (payment-routed-with-call
#     statistics)
#
# Anomalies (flagged via anomalies[] in JSON, [ANOMALY] line in human):
#   - sender_dominance      single sender > 50% of messages (potential
#                            DoS / spam; abuse signal)
#   - oversize_payload      any payload exceeding MAX_DAPP_CALL_PAYLOAD
#                            (16 KB) — validator should have rejected;
#                            non-zero count means the validator gate is
#                            broken (defense-in-depth)
#   - topic_drift            DApp's observed topic set ⊄ registered
#                            topic set in DApp registry (would indicate
#                            registry/payload-topic drift; pulled via
#                            `dapp-info --domain D`)
#
# Usage:
#   tools/operator_dapp_message_audit.sh
#     {--target-domain D | --all}
#     [--rpc-port N] [--json]
#     [--from H] [--to H]
#     [--topic T]
#     [--bucket-blocks N]
#     [--anomalies-only]
#
# Options:
#   --target-domain D    Single DApp to audit (canonical domain string)
#   --all                Iterate every DApp from `dapp-list`
#   --rpc-port N         RPC port (default: 7778)
#   --json               Emit structured JSON envelope
#   --from H             Start of audit window (inclusive; default: 0)
#                        Note: dapp_messages RPC treats the window as
#                        [from_height, to_height) — half-open;
#                        operator_dapp_message_audit.sh hides this and
#                        reports an inclusive window in output
#   --to H               End of audit window (inclusive; default: head)
#   --topic T            Restrict to messages with this topic
#   --bucket-blocks N    Width of each time-distribution bucket in
#                        blocks (default: ⌈window/10⌉; min 1)
#   --anomalies-only     Print only anomaly lines; exit 2 if any fire
#   -h, --help           Show this help
#
# RPC dependencies (all read-only):
#   head                 (current chain height; via `determ head`)
#   dapp_list            (iterate domains when --all)
#   dapp_info            (registered topic set; for topic_drift check)
#   dapp_messages        (per-DApp message page; 256-event pages)
#
# Pagination behaviour: dapp_messages caps each response at 256 events
# with {"truncated": bool, "last_scanned": H}; this script paginates
# by resuming from (last_scanned + 1) until truncated is false or the
# window is exhausted.
#
# Exit codes:
#   0   audit ran successfully (including zero messages in window)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_message_audit.sh
         {--target-domain D | --all}
         [--rpc-port N] [--json]
         [--from H] [--to H]
         [--topic T]
         [--bucket-blocks N]
         [--anomalies-only]

Audit v2.19 DAPP_CALL message-content layer for one or all DApps over
a window of blocks. Pivots on the dapp_messages RPC (per-DApp page;
256/page) to surface topic distribution, top callers, payload-size
shape, time-distribution buckets, and amount-routed statistics.

Exactly one of --target-domain or --all must be supplied.

Options:
  --target-domain D    Single DApp domain to audit
  --all                Iterate every DApp discovered via dapp-list
  --rpc-port N         RPC port (default: 7778)
  --json               Emit structured JSON envelope
  --from H             Start of window (inclusive; default: 0)
  --to H               End of window (inclusive; default: tip)
  --topic T            Restrict to messages with this topic
  --bucket-blocks N    Time-distribution bucket width in blocks
                        (default: ceil(window/10); min 1)
  --anomalies-only     Print only anomaly lines; exit 2 if any fire
  -h, --help           Show this help

Anomaly flags:
  sender_dominance   single sender > 50% of messages (abuse / DoS)
  oversize_payload   any payload > MAX_DAPP_CALL_PAYLOAD (16 KB);
                      validator should have rejected — investigate
  topic_drift        observed topic ⊄ registered topic set
                      (registry/payload mismatch)

Exit codes:
  0   success (including zero messages)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
TARGET=""
ALL=0
TOPIC=""
BUCKET=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --from)            FROM_H="${2:-}"; shift 2 ;;
    --to)              TO_H="${2:-}";   shift 2 ;;
    --target-domain)   TARGET="${2:-}"; shift 2 ;;
    --all)             ALL=1;           shift ;;
    --topic)           TOPIC="${2:-}";  shift 2 ;;
    --bucket-blocks)   BUCKET="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_dapp_message_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Scope selector must be exactly one.
if [ -z "$TARGET" ] && [ "$ALL" = "0" ]; then
  echo "operator_dapp_message_audit: must supply --target-domain <D> OR --all" >&2
  usage >&2
  exit 1
fi
if [ -n "$TARGET" ] && [ "$ALL" = "1" ]; then
  echo "operator_dapp_message_audit: --target-domain and --all are mutually exclusive" >&2
  exit 1
fi

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_message_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$BUCKET"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_dapp_message_audit: --from / --to / --bucket-blocks must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$BUCKET" ] && [ "$BUCKET" -lt 1 ]; then
  echo "operator_dapp_message_audit: --bucket-blocks must be >= 1 (got '$BUCKET')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_message_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_dapp_message_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: [0..tip]. We intentionally do NOT use a small default
# window: --all over many DApps with a 1000-block default could miss
# the bulk of activity; let the operator opt-in explicitly.
FROM=${FROM_H:-0}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_dapp_message_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# Default time-bucket: ⌈win/10⌉ (min 1).
if [ -z "$BUCKET" ]; then
  BUCKET=$(( (WIN_BLOCKS + 9) / 10 ))
  if [ "$BUCKET" -lt 1 ]; then BUCKET=1; fi
fi

# ── Step 2: resolve target DApp set ──────────────────────────────────────────
TMP_DOMAINS=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_message_audit: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_message_audit: cannot create temp file" >&2
  rm -f "$TMP_DOMAINS" 2>/dev/null
  exit 1;
}
trap 'rm -f "$TMP_DOMAINS" "$TMP_OUT" 2>/dev/null' EXIT

if [ -n "$TARGET" ]; then
  printf '%s\n' "$TARGET" > "$TMP_DOMAINS"
else
  # --all: pull domain set via dapp-list. We tolerate empty topic
  # (server-side filter is empty-matches-all per src/node/node.cpp).
  LIST_OUT=$("$DETERM" dapp-list --rpc-port "$PORT" 2>/dev/null) || {
    echo "operator_dapp_message_audit: dapp-list RPC failed (port $PORT)" >&2
    exit 1
  }
  python - "$LIST_OUT" "$TMP_DOMAINS" <<'PY'
import json, sys
raw, out_path = sys.argv[1], sys.argv[2]
try:
    j = json.loads(raw)
except Exception:
    sys.stderr.write("operator_dapp_message_audit: malformed dapp-list response\n")
    sys.exit(1)
dapps = j.get("dapps") if isinstance(j, dict) else None
if not isinstance(dapps, list):
    sys.stderr.write("operator_dapp_message_audit: dapp-list missing .dapps array\n")
    sys.exit(1)
with open(out_path, "w", encoding="utf-8") as f:
    for d in dapps:
        if isinstance(d, dict):
            dom = d.get("domain")
            if isinstance(dom, str) and dom:
                f.write(dom + "\n")
PY
  if [ "$?" -ne 0 ]; then exit 1; fi
fi

# Count domains we're going to audit.
N_DOMAINS=$(grep -c . "$TMP_DOMAINS" 2>/dev/null || true)
case "$N_DOMAINS" in *[!0-9]*|"") N_DOMAINS=0 ;; esac

# ── Step 3: per-DApp pagination + aggregation ────────────────────────────────
# Pagination contract per src/node/node.cpp::rpc_dapp_messages:
#   - Each response caps at 256 events; sets truncated=true & last_scanned=H
#   - Resume by calling again with from_height = (last_scanned + 1)
#   - When truncated=false and last_scanned >= to_height-1, we're done
#   - dapp_messages's [from_height, to_height) window is HALF-OPEN
#     server-side; we send to_height = TO+1 to make our inclusive
#     --to flag behave inclusively (matches operator_dapp_call_audit's
#     inclusive convention)
python - "$DETERM" "$PORT" "$FROM" "$TO" "$TOPIC" "$BUCKET" \
         "$TMP_DOMAINS" "$TMP_OUT" <<'PY'
import json, subprocess, sys, statistics
from collections import defaultdict, OrderedDict

(determ, port, from_h, to_h, topic_filter, bucket_w,
 doms_path, out_path) = sys.argv[1:9]
from_h    = int(from_h)
to_h      = int(to_h)
bucket_w  = int(bucket_w)

# Server-side window is [from_height, to_height) half-open;
# add 1 to make the user's --to inclusive.
RPC_TO_H = to_h + 1

MAX_DAPP_CALL_PAYLOAD = 16384  # bytes; per include/determ/chain/block.hpp

def classify_size(n):
    if n <= 64:    return "le_64"
    if n <= 1024:  return "64_1k"
    if n <= 4096:  return "1k_4k"
    if n <= MAX_DAPP_CALL_PAYLOAD: return "4k_16k"
    return "over_16k"

def run_dapp_info(domain):
    # Return the registered topic set for topic-drift detection.
    # On error, return None so the script doesn't false-flag drift
    # when dapp-info is transiently unavailable.
    try:
        r = subprocess.run(
            [determ, "dapp-info", "--domain", domain, "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0:
            return None
        j = json.loads(r.stdout)
        if isinstance(j, dict):
            t = j.get("topics")
            if isinstance(t, list):
                return [str(x) for x in t if isinstance(x, str)]
    except Exception:
        return None
    return None

def fetch_page(domain, page_from):
    try:
        args = [determ, "dapp-messages",
                "--domain", domain,
                "--from",   str(page_from),
                "--to",     str(RPC_TO_H),
                "--rpc-port", port]
        # Note: dapp-messages also accepts --topic, but server-side
        # topic-filtering would mask topic_drift detection. Filter
        # client-side so we can still spot drift even when --topic
        # is set (we report on the matched topic only).
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except Exception as e:
        return None, f"subprocess exception: {e}"
    if r.returncode != 0:
        return None, f"dapp-messages rc={r.returncode}: {r.stderr.strip()}"
    try:
        return json.loads(r.stdout), None
    except Exception:
        return None, "non-JSON response"

# Domain set (preserves dapp-list order; dedup).
domains = []
seen = set()
with open(doms_path, "r", encoding="utf-8") as f:
    for line in f:
        d = line.strip()
        if d and d not in seen:
            seen.add(d)
            domains.append(d)

per_dapp_results = []
overall_anomalies = set()

for domain in domains:
    registered_topics = run_dapp_info(domain)

    # Paginate.
    events_buf = []
    page_from  = from_h
    pages_fetched = 0
    while page_from < RPC_TO_H:
        page, err = fetch_page(domain, page_from)
        if err is not None:
            sys.stderr.write(
                f"operator_dapp_message_audit: dapp-messages "
                f"{domain} from={page_from}: {err}\n")
            sys.exit(1)
        pages_fetched += 1
        evs = page.get("events", []) if isinstance(page, dict) else []
        if isinstance(evs, list):
            events_buf.extend(evs)
        truncated   = bool(page.get("truncated", False))
        last_scan   = int(page.get("last_scanned", page_from))
        # Progress guard: server-side last_scanned must advance to
        # avoid infinite loop on a malformed daemon.
        if last_scan < page_from:
            sys.stderr.write(
                f"operator_dapp_message_audit: dapp-messages "
                f"{domain} regressed last_scanned ({last_scan} < {page_from})\n")
            sys.exit(1)
        if not truncated:
            break
        page_from = last_scan + 1

    # Aggregate.
    total_msgs   = 0
    topic_counts = defaultdict(int)
    sender_counts= defaultdict(int)
    size_buckets = OrderedDict([
        ("le_64", 0), ("64_1k", 0), ("1k_4k", 0),
        ("4k_16k", 0), ("over_16k", 0)])
    amounts      = []
    bucket_counts= defaultdict(int)
    oversize     = 0
    observed_topics = set()

    for e in events_buf:
        if not isinstance(e, dict): continue
        topic = str(e.get("topic", "") or "")
        if topic_filter and topic != topic_filter: continue
        observed_topics.add(topic)
        total_msgs += 1
        topic_counts[topic] += 1
        sender = str(e.get("from", "") or "")
        sender_counts[sender] += 1
        try:
            amt = int(e.get("amount", 0) or 0)
        except Exception:
            amt = 0
        amounts.append(amt)
        # Payload size = len(payload_hex)/2 (RPC returns hex string).
        ph = e.get("payload_hex", "") or ""
        psize = len(ph) // 2 if isinstance(ph, str) else 0
        size_buckets[classify_size(psize)] += 1
        if psize > MAX_DAPP_CALL_PAYLOAD:
            oversize += 1
        try:
            h = int(e.get("block_height", 0) or 0)
        except Exception:
            h = 0
        # Bucket index relative to FROM.
        rel = max(0, h - from_h)
        bidx = rel // bucket_w
        bucket_counts[bidx] += 1

    # Top topics (ties: name asc).
    by_topic = sorted(
        topic_counts.items(),
        key=lambda kv: (-kv[1], kv[0])
    )
    # Top 20 senders.
    top_senders = sorted(
        sender_counts.items(),
        key=lambda kv: (-kv[1], kv[0])
    )[:20]

    # Time buckets — emit as ordered list keyed by start-block.
    time_buckets = []
    if total_msgs > 0:
        max_bidx = max(bucket_counts.keys()) if bucket_counts else 0
        for i in range(max_bidx + 1):
            start = from_h + i * bucket_w
            end   = min(start + bucket_w - 1, to_h)
            time_buckets.append({
                "from_block": start,
                "to_block":   end,
                "count":      bucket_counts.get(i, 0),
            })

    # Amount stats (integer-safe).
    avg_amount    = (sum(amounts) // total_msgs) if total_msgs > 0 else 0
    median_amount = int(statistics.median(amounts)) if amounts else 0
    total_amount  = sum(amounts)

    # Anomaly classification.
    anomalies = []
    top_sender_name = ""
    top_sender_pct_bps = 0
    if total_msgs > 0 and top_senders:
        top_sender_name    = top_senders[0][0]
        top_sender_pct_bps = top_senders[0][1] * 10000 // total_msgs
        if top_sender_pct_bps > 5000:
            anomalies.append("sender_dominance")
    if oversize > 0:
        anomalies.append("oversize_payload")
    # topic_drift: observed topics not all in registered set.
    drift_topics = []
    if registered_topics is not None and observed_topics:
        reg_set = set(registered_topics)
        for t in sorted(observed_topics):
            # Skip empty-string topic (untagged messages — unusual but
            # not necessarily a registry mismatch; surface separately
            # via the by_topic dump rather than as drift).
            if t == "":
                continue
            if t not in reg_set:
                drift_topics.append(t)
        if drift_topics:
            anomalies.append("topic_drift")

    for a in anomalies:
        overall_anomalies.add(a)

    per_dapp_results.append({
        "domain":         domain,
        "total_messages": total_msgs,
        "pages_fetched":  pages_fetched,
        "by_topic": [
            {"topic": t, "count": n,
             "pct_bps": (n * 10000 // total_msgs) if total_msgs > 0 else 0}
            for t, n in by_topic
        ],
        "payload_distribution": dict(size_buckets),
        "oversize_count": oversize,
        "top_senders": [
            {"sender": s, "count": n} for s, n in top_senders
        ],
        "distinct_senders":     len(sender_counts),
        "avg_amount":           avg_amount,
        "median_amount":        median_amount,
        "total_amount_routed":  total_amount,
        "time_buckets":         time_buckets,
        "top_sender_name":      top_sender_name,
        "top_sender_pct_bps":   top_sender_pct_bps,
        "drift_topics":         drift_topics,
        "registered_topics":    (registered_topics or []),
        "anomalies":            anomalies,
    })

with open(out_path, "w", encoding="utf-8") as f:
    json.dump({
        "per_dapp":          per_dapp_results,
        "overall_anomalies": sorted(overall_anomalies),
    }, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_dapp_message_audit: aggregation pass failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human) ──────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" \
         "$WIN_BLOCKS" "$TARGET" "$ALL" "$TOPIC" "$BUCKET" <<'PY'
import json, sys

json_out   = sys.argv[1] == "1"
anom_only  = sys.argv[2] == "1"
out_path   = sys.argv[3]
port       = int(sys.argv[4])
from_h     = int(sys.argv[5])
to_h       = int(sys.argv[6])
win_blocks = int(sys.argv[7])
target     = sys.argv[8]
all_mode   = sys.argv[9] == "1"
topic_f    = sys.argv[10]
bucket_w   = int(sys.argv[11])

with open(out_path, "r", encoding="utf-8") as f:
    agg = json.load(f)

per_dapp           = agg["per_dapp"]
overall_anomalies  = agg["overall_anomalies"]
anom_count         = len(overall_anomalies)

def render_pct_bps(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

def pct_int(n, total):
    if total <= 0: return "-"
    return render_pct_bps(n * 10000 // total)

if json_out:
    envelope = {
        "target":          target if target else None,
        "all":             all_mode,
        "window": {
            "from":   from_h,
            "to":     to_h,
            "blocks": win_blocks,
        },
        "topic_filter":    topic_f if topic_f else None,
        "bucket_blocks":   bucket_w,
        "dapps":           per_dapp,
        "n_dapps":         len(per_dapp),
        "total_messages":  sum(d["total_messages"] for d in per_dapp),
        "anomalies":       overall_anomalies,
        "rpc_port":        port,
    }
    # Convenience top-level fields for the single-target case.
    if len(per_dapp) == 1:
        d = per_dapp[0]
        envelope["by_topic"]              = d["by_topic"]
        envelope["payload_distribution"]  = d["payload_distribution"]
        envelope["top_senders"]           = d["top_senders"]
        envelope["avg_amount"]            = d["avg_amount"]
        envelope["median_amount"]         = d["median_amount"]
        envelope["total_amount_routed"]   = d["total_amount_routed"]
        envelope["distinct_senders"]      = d["distinct_senders"]
        envelope["drift_topics"]          = d["drift_topics"]
        envelope["registered_topics"]     = d["registered_topics"]
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
scope_disp = f"target={target}" if target else "scope=ALL"
topic_disp = f", topic={topic_f}" if topic_f else ""

if anom_only and anom_count == 0:
    print(f"operator_dapp_message_audit: no anomalies (port {port}, "
          f"window [{from_h}..{to_h}], {scope_disp}{topic_disp})")
    sys.exit(0)

print(f"=== DApp message audit (port {port}, {scope_disp}, "
      f"window [{from_h}..{to_h}], {win_blocks} blocks{topic_disp}) ===")

if not per_dapp:
    print("(no DApps in scope — empty dapp-list or unknown target)")
    sys.exit(0)

for idx, d in enumerate(per_dapp):
    if anom_only and not d["anomalies"]:
        continue
    if len(per_dapp) > 1:
        if idx > 0: print()
        print(f"--- DApp: {d['domain']} ---")
    total = d["total_messages"]
    print(f"Total messages: {total}")
    if total == 0:
        if d["anomalies"]:
            print(f"[ANOMALY] {','.join(d['anomalies'])}")
        continue

    print(f"Distinct senders: {d['distinct_senders']}")
    print(f"Pages fetched: {d['pages_fetched']}")

    print("By topic:")
    if not d["by_topic"]:
        print("  (none)")
    else:
        for t in d["by_topic"][:20]:
            tname = t["topic"] if t["topic"] else "(empty)"
            print(f"  {tname}: {t['count']} ({render_pct_bps(t['pct_bps'])})")

    print("Payload size:")
    pd = d["payload_distribution"]
    print(f"  <=64B:     {pd['le_64']} ({pct_int(pd['le_64'], total)})")
    print(f"  64B-1KB:   {pd['64_1k']} ({pct_int(pd['64_1k'], total)})")
    print(f"  1KB-4KB:   {pd['1k_4k']} ({pct_int(pd['1k_4k'], total)})")
    print(f"  4KB-16KB:  {pd['4k_16k']} ({pct_int(pd['4k_16k'], total)})")
    if pd.get("over_16k", 0) > 0:
        print(f"  >16KB:     {pd['over_16k']} ({pct_int(pd['over_16k'], total)})  "
              "[INVALID — exceeds MAX_DAPP_CALL_PAYLOAD]")

    print("Top senders:")
    if not d["top_senders"]:
        print("  (none)")
    else:
        for s in d["top_senders"]:
            print(f"  {s['sender']}: {s['count']} messages")

    print(f"Avg amount routed: {d['avg_amount']} per message  "
          f"(median {d['median_amount']}; total {d['total_amount_routed']})")

    print(f"Time distribution (bucket = {bucket_w} blocks):")
    if not d["time_buckets"]:
        print("  (none)")
    else:
        for tb in d["time_buckets"]:
            print(f"  [{tb['from_block']:>10}..{tb['to_block']:>10}]: {tb['count']}")

    if d["anomalies"]:
        print()
        detail = []
        if "sender_dominance" in d["anomalies"]:
            detail.append(
                f"sender_dominance: '{d['top_sender_name']}' = "
                f"{render_pct_bps(d['top_sender_pct_bps'])} of messages (> 50% threshold)"
            )
        if "oversize_payload" in d["anomalies"]:
            detail.append(
                f"oversize_payload: {d['oversize_count']} message(s) exceed MAX_DAPP_CALL_PAYLOAD (16 KB); "
                "validator should have rejected — investigate"
            )
        if "topic_drift" in d["anomalies"]:
            detail.append(
                f"topic_drift: observed topic(s) not in registered set: "
                f"{','.join(d['drift_topics'])}"
            )
        print(f"[ANOMALY] {len(d['anomalies'])} flag(s): {','.join(d['anomalies'])}")
        for det in detail:
            print(f"  - {det}")

print()
if anom_count == 0:
    print("[OK] No anomalies across audited DApps")
else:
    print(f"[ANOMALY] overall: {','.join(overall_anomalies)}")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_message_audit: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_message_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_DOMAINS" "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
python - "$TMP_OUT" "$TMP_ANOM" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    j = json.load(f)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(str(len(j.get("overall_anomalies", []))))
PY
ANOM_COUNT=$(cat "$TMP_ANOM" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
