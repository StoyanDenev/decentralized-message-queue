#!/usr/bin/env bash
# operator_dapp_message_audit.sh — Per-DApp message-volume + topic
# distribution + lifecycle classification (ACTIVE / DORMANT /
# ABANDONED) audit over a window of blocks on a running determ daemon.
#
# Scope contrast with neighbouring DApp operator scripts:
#   operator_dapp_inventory.sh        compact registry digest (single
#                                     dapp-messages page; no anomalies)
#   operator_dapp_balance_audit.sh    accrued-balance + DAPP_CALL revenue
#                                     (joins block-info walk against
#                                     show-account; revenue concentration)
#   operator_dapp_message_audit.sh    THIS — per-DApp message volume,
#                                     global topic distribution, and
#                                     lifecycle (ACTIVE / DORMANT /
#                                     ABANDONED) classification driven
#                                     entirely off dapp-messages pages.
#                                     Surfaces "which DApps are busy?",
#                                     "which topics dominate?", and
#                                     "which DApps are abandoned but
#                                     still on the registry?".
#
# Pipeline (read-only RPC):
#   1. Enumerate registered DApps via `determ dapp-list --json`.
#   2. Per DApp, paginate `determ dapp-messages --from H --to H` across
#      the requested window. Aggregate: count, distinct topics,
#      distinct senders, oldest message block, newest message block.
#   3. Lifecycle classify each DApp against the *whole-chain* most-recent
#      message block (NOT confined to the audit window — abandonment
#      needs the long view to be meaningful), using
#      --dormant-threshold-blocks:
#        - ACTIVE     newest_block_chainwide ≥ head - threshold
#        - DORMANT    head - 5×threshold < newest < head - threshold
#                      OR no on-chain messages but registry-active < grace
#        - ABANDONED  newest < head - 5×threshold AND dapp.active == true
#   4. Aggregate global topic distribution across all DApps (count + share).
#   5. Cross-reference accrued balance via `determ show-account D --json`
#      for the `abandoned_dapps_with_balance` anomaly leg.
#
# Anomaly flags (--anomalies-only; exit 2 if any fire):
#   - dapp_concentration_high      top-1 DApp > 40% of all in-window
#                                  messages. Single-DApp-dominance
#                                  signal worth review.
#   - mass_dormant                 > 50% of registered DApps are DORMANT.
#                                  Registry-bloat signal — operators may
#                                  want to encourage deregistration.
#   - topic_concentration_high     a single topic > 50% of total in-window
#                                  messages. Possible spam-bot / single-
#                                  purpose chain signal.
#   - abandoned_dapps_with_balance any ABANDONED DApp carries a non-zero
#                                  accrued balance. Operator-action needed
#                                  (orphaned funds; coordinate sweep
#                                  with DApp owner before DAPP_GRACE
#                                  expiry takes them out of reach).
#
# RPC dependencies (all read-only):
#   head           current chain height
#   dapp_list      iterate registered DApps + active flag
#   dapp_messages  per-DApp event page (256/page; paginated)
#   account        per-DApp balance (only for ABANDONED DApps, lazy)
#
# Usage:
#   tools/operator_dapp_message_audit.sh --rpc-port N
#     [--from H] [--to H]
#     [--dormant-threshold-blocks N]
#     [--top-N N] [--top-topic-N N]
#     [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N                    RPC port (REQUIRED)
#   --from H                        Start block of audit window (default:
#                                   max(0, head - 4999))
#   --to H                          End block of audit window (default: head)
#   --dormant-threshold-blocks N    DApps with no messages in last N
#                                   blocks are DORMANT (default: 1000;
#                                   ABANDONED at 5*N)
#   --top-N N                       Top-N most active DApps in human table
#                                   (default: 20)
#   --top-topic-N N                 Top-N topics in human histogram
#                                   (default: 10)
#   --json                          Emit machine-readable JSON envelope
#   --anomalies-only                Print only anomaly lines; exit 2 if any fire
#   -h, --help                      Show this help
#
# Pagination contract: dapp_messages returns at most 256 events per
# response with {truncated: bool, last_scanned: H}. We resume from
# last_scanned+1 until truncated is false. Window is [from_height,
# to_height) half-open server-side; we send to_height = TO+1 so the
# user's --to flag behaves inclusively.
#
# Exit codes:
#   0   audit ran successfully (no anomalies OR anomalies in default mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_message_audit.sh --rpc-port N
         [--from H] [--to H]
         [--dormant-threshold-blocks N]
         [--top-N N] [--top-topic-N N]
         [--json] [--anomalies-only]

Per-DApp message-volume + topic distribution + lifecycle classification
(ACTIVE / DORMANT / ABANDONED) audit. Walks every registered DApp,
paginates dapp_messages over [--from..--to] (default: last 5000 blocks),
aggregates topic-distribution globally, and lifecycle-classifies each
DApp against --dormant-threshold-blocks.

Options:
  --rpc-port N                    RPC port (REQUIRED)
  --from H                        Start of audit window (default: max(0, head-4999))
  --to H                          End of audit window (default: head)
  --dormant-threshold-blocks N    DApp DORMANT cutoff in blocks (default: 1000)
                                   (ABANDONED = no messages in 5*N AND active)
  --top-N N                       Top-N DApps in human table (default: 20)
  --top-topic-N N                 Top-N topics in human histogram (default: 10)
  --json                          Emit machine-readable JSON envelope
  --anomalies-only                Print only anomaly lines; exit 2 if any fire
  -h, --help                      Show this help

Anomaly flags:
  dapp_concentration_high       top-1 DApp > 40% of total messages
  mass_dormant                  > 50% of registered DApps are DORMANT
  topic_concentration_high      single topic > 50% of total messages
  abandoned_dapps_with_balance  ABANDONED DApp has non-zero accrued balance

Exit codes:
  0   success (with or without anomalies in default mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
FROM_H=""
TO_H=""
DORM_THRESH=1000
TOP_N=20
TOP_TOPIC_N=10
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                      usage; exit 0 ;;
    --rpc-port)                     PORT="${2:-}";         shift 2 ;;
    --from)                         FROM_H="${2:-}";       shift 2 ;;
    --to)                           TO_H="${2:-}";         shift 2 ;;
    --dormant-threshold-blocks)     DORM_THRESH="${2:-}";  shift 2 ;;
    --top-N|--top-n)                TOP_N="${2:-}";        shift 2 ;;
    --top-topic-N|--top-topic-n)    TOP_TOPIC_N="${2:-}";  shift 2 ;;
    --json)                         JSON_OUT=1;            shift ;;
    --anomalies-only)               ANOM_ONLY=1;           shift ;;
    *) echo "operator_dapp_message_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port required (per sibling operator script convention; refuses
# to silently guess on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_dapp_message_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_message_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_dapp_message_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$DORM_THRESH" in *[!0-9]*|"")
  echo "operator_dapp_message_audit: --dormant-threshold-blocks must be a positive integer (got '$DORM_THRESH')" >&2
  exit 1 ;;
esac
if [ "$DORM_THRESH" -lt 1 ]; then
  echo "operator_dapp_message_audit: --dormant-threshold-blocks must be >= 1 (got '$DORM_THRESH')" >&2
  exit 1
fi
case "$TOP_N" in *[!0-9]*|"")
  echo "operator_dapp_message_audit: --top-N must be a positive integer (got '$TOP_N')" >&2
  exit 1 ;;
esac
if [ "$TOP_N" -lt 1 ]; then
  echo "operator_dapp_message_audit: --top-N must be >= 1 (got '$TOP_N')" >&2
  exit 1
fi
case "$TOP_TOPIC_N" in *[!0-9]*|"")
  echo "operator_dapp_message_audit: --top-topic-N must be a positive integer (got '$TOP_TOPIC_N')" >&2
  exit 1 ;;
esac
if [ "$TOP_TOPIC_N" -lt 1 ]; then
  echo "operator_dapp_message_audit: --top-topic-N must be >= 1 (got '$TOP_TOPIC_N')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to absolute path (some Windows shells trip on relative
# paths inside subprocess.run — mirror operator_dapp_inventory.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current chain head ────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_message_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_dapp_message_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 5000 blocks ending at tip.
if [ -z "$FROM_H" ]; then
  if [ "$HEAD_H" -ge 5000 ]; then
    FROM=$(( HEAD_H - 4999 ))
  else
    FROM=0
  fi
else
  FROM="$FROM_H"
fi
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_dapp_message_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: enumerate DApps ───────────────────────────────────────────────────
TMP_LIST=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_message_audit: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_message_audit: cannot create temp file" >&2
  rm -f "$TMP_LIST" 2>/dev/null
  exit 1;
}
trap 'rm -f "$TMP_LIST" "$TMP_OUT" 2>/dev/null' EXIT

if ! "$DETERM" dapp-list --rpc-port "$PORT" > "$TMP_LIST" 2>/dev/null; then
  echo "operator_dapp_message_audit: dapp-list RPC failed (port $PORT)" >&2
  exit 1
fi

# ── Step 3: drive aggregation pipeline in Python ──────────────────────────────
# Single-process pipeline: parse dapp-list, paginate dapp-messages per
# DApp, lifecycle-classify, aggregate topic distribution globally, and
# lazy-fetch show-account ONLY for ABANDONED DApps (avoids O(N) account
# RPCs in the common-case where no DApp is abandoned).
python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$HEAD_H" \
         "$DORM_THRESH" "$TMP_LIST" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port, from_s, to_s, head_s,
 dorm_s, list_path, out_path) = sys.argv[1:9]
from_h      = int(from_s)
to_h        = int(to_s)
head_h      = int(head_s)
dorm_thresh = int(dorm_s)

# Server-side dapp_messages window is [from_height, to_height) half-open.
RPC_TO_H = to_h + 1

# Chain-wide newest-message cutoff: we walk dapp_messages from 0 to head+1
# for the *abandonment* check; this matters when --from is recent but a
# DApp has been silent for a long time.
WHOLE_CHAIN_RPC_TO_H = head_h + 1

def run_rpc(args, what):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=60)
    except Exception as e:
        sys.stderr.write(f"operator_dapp_message_audit: {what} exception: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(
            f"operator_dapp_message_audit: {what} rc={r.returncode}: "
            f"{r.stderr.strip()}\n")
        sys.exit(1)
    try:
        return json.loads(r.stdout)
    except Exception:
        sys.stderr.write(
            f"operator_dapp_message_audit: {what} non-JSON response\n")
        sys.exit(1)

# ── Load dapp-list (one shot) ──────────────────────────────────────────────
try:
    with open(list_path, "r", encoding="utf-8") as f:
        listed = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_dapp_message_audit: dapp-list parse failed: {e}\n")
    sys.exit(1)

dapps_listed = listed.get("dapps")
if not isinstance(dapps_listed, list):
    sys.stderr.write(
        "operator_dapp_message_audit: dapp-list missing .dapps array\n")
    sys.exit(1)

# Per-domain registry-active flag from dapp-list (active = inactive_from > head).
dapps_meta = []
for d in dapps_listed:
    if isinstance(d, dict):
        dom = d.get("domain")
        if isinstance(dom, str) and dom:
            dapps_meta.append({
                "domain":   dom,
                "active":   bool(d.get("active", False)),
            })

# ── Per-DApp: paginate dapp-messages over [FROM..TO] ──────────────────────
# Plus a single "chainwide newest_block" probe for lifecycle classification.
# To avoid a doubled walk we collect events in TWO passes:
#   (a) Window pass: full pagination over [from_h, to_h+1) — aggregates
#       count/topics/senders/oldest/newest within the audit window.
#   (b) Chainwide newest pass: only fires when window pass returned 0
#       events AND we need to know whether the DApp is DORMANT (silent
#       in window) vs ABANDONED (silent since long before window).
#       Walks [0, head+1) — but in practice this is rare AND the server
#       breaks early once a single event is found (we only need the
#       newest_block, not the full set; we still paginate until we
#       have at least one event from the *latest* page).
#
# Tactical: we paginate the window, then if window count == 0 we do
# *one* dapp-messages page over [0, head+1) to fetch the absolute
# newest message. Since dapp-messages walks low → high and stops at
# 256, we'd need to paginate to the END to get the chainwide newest.
# Cheaper approach: rely on the dapp-messages "last_scanned" + "events"
# pair — by paginating the whole chain we capture the highest
# block_height in the last non-empty page. We cap this fallback to
# avoid runaway on adversarial daemons: at most ceil(head/256)+1 RPCs.

MAX_FALLBACK_PAGES = max(1, (head_h // 256) + 4)

per_dapp = []
total_messages_window = 0
topic_counts_global   = defaultdict(int)

for meta in dapps_meta:
    domain = meta["domain"]
    msg_count        = 0
    distinct_topics  = set()
    distinct_senders = set()
    oldest_block     = None
    newest_block     = None

    # ── (a) Window pass: paginate [from_h, to_h+1) ──────────────────────
    page_from     = from_h
    pages_fetched = 0
    while page_from < RPC_TO_H:
        page = run_rpc(
            [determ, "dapp-messages",
             "--domain", domain,
             "--from",   str(page_from),
             "--to",     str(RPC_TO_H),
             "--rpc-port", port],
            f"dapp-messages {domain} from={page_from}")
        pages_fetched += 1
        if not isinstance(page, dict):
            sys.stderr.write(
                f"operator_dapp_message_audit: dapp-messages {domain} "
                f"non-object response\n")
            sys.exit(1)
        evs = page.get("events") if isinstance(page.get("events"), list) else []
        for e in evs:
            if not isinstance(e, dict): continue
            msg_count += 1
            topic = str(e.get("topic", "") or "")
            distinct_topics.add(topic)
            topic_counts_global[topic] += 1
            sender = str(e.get("from", "") or "")
            distinct_senders.add(sender)
            try:
                h = int(e.get("block_height", 0) or 0)
            except Exception:
                h = 0
            if oldest_block is None or h < oldest_block: oldest_block = h
            if newest_block is None or h > newest_block: newest_block = h
        truncated = bool(page.get("truncated", False))
        try:
            last_scan = int(page.get("last_scanned", page_from) or 0)
        except Exception:
            last_scan = page_from
        if last_scan < page_from:
            sys.stderr.write(
                f"operator_dapp_message_audit: dapp-messages {domain} "
                f"regressed last_scanned ({last_scan} < {page_from})\n")
            sys.exit(1)
        if not truncated:
            break
        page_from = last_scan + 1

    total_messages_window += msg_count

    # ── (b) Chainwide newest probe (only if window had 0 events AND
    # we need to disambiguate DORMANT vs ABANDONED). ────────────────────
    chainwide_newest = newest_block  # default: window-newest
    if msg_count == 0 and head_h > 0:
        cw_page_from = 0
        cw_pages     = 0
        cw_newest    = None
        while cw_page_from < WHOLE_CHAIN_RPC_TO_H and cw_pages < MAX_FALLBACK_PAGES:
            cw_page = run_rpc(
                [determ, "dapp-messages",
                 "--domain", domain,
                 "--from",   str(cw_page_from),
                 "--to",     str(WHOLE_CHAIN_RPC_TO_H),
                 "--rpc-port", port],
                f"dapp-messages {domain} chainwide from={cw_page_from}")
            cw_pages += 1
            cw_evs = cw_page.get("events") if isinstance(cw_page.get("events"), list) else []
            for e in cw_evs:
                if not isinstance(e, dict): continue
                try:
                    h = int(e.get("block_height", 0) or 0)
                except Exception:
                    h = 0
                if cw_newest is None or h > cw_newest:
                    cw_newest = h
            cw_trunc = bool(cw_page.get("truncated", False))
            try:
                cw_last = int(cw_page.get("last_scanned", cw_page_from) or 0)
            except Exception:
                cw_last = cw_page_from
            if cw_last < cw_page_from:
                break
            if not cw_trunc:
                break
            cw_page_from = cw_last + 1
        chainwide_newest = cw_newest

    # ── Lifecycle classification ───────────────────────────────────────
    # ACTIVE      newest message within last `dorm_thresh` blocks of head
    # DORMANT     newest message older than that, but newer than head-5×thresh
    #             (or never had messages but dapp.active is still true)
    # ABANDONED   newest message older than head-5×thresh AND dapp.active
    abandoned_cutoff = head_h - 5 * dorm_thresh
    dormant_cutoff   = head_h - dorm_thresh
    if chainwide_newest is not None and chainwide_newest >= dormant_cutoff:
        state = "ACTIVE"
    elif chainwide_newest is not None and chainwide_newest >= abandoned_cutoff:
        state = "DORMANT"
    elif chainwide_newest is None:
        # Never sent a message. Classify by registry activity:
        #   if dapp.active AND head < abandoned_cutoff worth of blocks
        #   since registration → DORMANT (could just be new)
        #   else                                                  → ABANDONED
        # We don't have registered_at on dapp-list, so be conservative:
        # treat any never-messaged registered-active DApp as DORMANT
        # (less alarming than ABANDONED); ABANDONED requires a
        # confirmed silence past the abandoned_cutoff *with* prior life.
        state = "DORMANT" if meta["active"] else "ABANDONED"
    else:
        # chainwide_newest < abandoned_cutoff: silent past cutoff.
        # If dapp.active still true → ABANDONED; else still INACTIVE
        # but we surface as ABANDONED if active flag is set (registry
        # bloat).
        state = "ABANDONED" if meta["active"] else "DORMANT"

    per_dapp.append({
        "domain":              domain,
        "message_count":       msg_count,
        "distinct_topics":     len(distinct_topics),
        "distinct_senders":    len(distinct_senders),
        "state":               state,
        "oldest_message_block": oldest_block if oldest_block is not None else 0,
        "newest_message_block": newest_block if newest_block is not None else 0,
        "chainwide_newest_block": (chainwide_newest if chainwide_newest is not None
                                   else 0),
        "active_in_registry":  meta["active"],
        "balance":             0,   # filled lazily below for ABANDONED
        "pages_fetched":       pages_fetched,
    })

# ── Lazy show-account for ABANDONED DApps (anomaly leg) ────────────────────
for d in per_dapp:
    if d["state"] != "ABANDONED": continue
    try:
        r = subprocess.run(
            [determ, "show-account", d["domain"], "--json",
             "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(
            f"operator_dapp_message_audit: show-account {d['domain']} "
            f"failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        # Non-fatal for the audit: missing account state means
        # balance=0 by definition (no on-chain credit ever arrived).
        d["balance"] = 0
        continue
    try:
        acct = json.loads(r.stdout) if r.stdout.strip() else {}
    except Exception:
        d["balance"] = 0
        continue
    if acct is None or acct == {}:
        d["balance"] = 0
    else:
        try:
            d["balance"] = int(acct.get("balance", 0) or 0)
        except Exception:
            d["balance"] = 0

# ── Topic-distribution global aggregate ────────────────────────────────────
total_messages = sum(d["message_count"] for d in per_dapp)
topics_global = []
for t, n in sorted(topic_counts_global.items(), key=lambda kv: (-kv[1], kv[0])):
    share_bps = (n * 10000 // total_messages) if total_messages > 0 else 0
    topics_global.append({
        "topic":     t,
        "count":     n,
        "share_bps": share_bps,
    })

# ── Lifecycle counts ───────────────────────────────────────────────────────
total_dapps = len(per_dapp)
n_active    = sum(1 for d in per_dapp if d["state"] == "ACTIVE")
n_dormant   = sum(1 for d in per_dapp if d["state"] == "DORMANT")
n_abandoned = sum(1 for d in per_dapp if d["state"] == "ABANDONED")

# ── Top-1 DApp share for dapp_concentration_high ───────────────────────────
top1_share_bps = 0
top1_name      = ""
if per_dapp and total_messages > 0:
    sorted_for_top = sorted(per_dapp,
                            key=lambda d: (-d["message_count"], d["domain"]))
    if sorted_for_top[0]["message_count"] > 0:
        top1_name      = sorted_for_top[0]["domain"]
        top1_share_bps = sorted_for_top[0]["message_count"] * 10000 // total_messages

# ── Anomaly classification ─────────────────────────────────────────────────
anomalies = []
if top1_share_bps > 4000:
    anomalies.append("dapp_concentration_high")
if total_dapps > 0 and (n_dormant * 100) > (total_dapps * 50):
    anomalies.append("mass_dormant")
top_topic_share_bps = topics_global[0]["share_bps"] if topics_global else 0
top_topic_name      = topics_global[0]["topic"]      if topics_global else ""
if top_topic_share_bps > 5000:
    anomalies.append("topic_concentration_high")
abandoned_with_balance = [d for d in per_dapp
                          if d["state"] == "ABANDONED" and d["balance"] > 0]
if abandoned_with_balance:
    anomalies.append("abandoned_dapps_with_balance")

# Sort per-DApp output by message_count desc, then domain asc (deterministic).
per_dapp_sorted = sorted(per_dapp,
                         key=lambda d: (-d["message_count"], d["domain"]))

result = {
    "window": {"from": from_h, "to": to_h, "blocks": to_h - from_h + 1},
    "dapps":              per_dapp_sorted,
    "topics":             topics_global,
    "summary": {
        "total_dapps":           total_dapps,
        "active":                n_active,
        "dormant":               n_dormant,
        "abandoned":             n_abandoned,
        "total_messages":        total_messages,
        "top1_share_bps":        top1_share_bps,
        "top1_name":             top1_name,
        "top_topic_share_bps":   top_topic_share_bps,
        "top_topic_name":        top_topic_name,
        "abandoned_with_balance_count": len(abandoned_with_balance),
        "anomalies":             anomalies,
    },
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_dapp_message_audit: aggregation pass failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human) ───────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" \
         "$WIN_BLOCKS" "$DORM_THRESH" "$TOP_N" "$TOP_TOPIC_N" <<'PY'
import json, sys

json_out      = sys.argv[1] == "1"
anom_only     = sys.argv[2] == "1"
out_path      = sys.argv[3]
port          = int(sys.argv[4])
from_h        = int(sys.argv[5])
to_h          = int(sys.argv[6])
win_blocks    = int(sys.argv[7])
dorm_thresh   = int(sys.argv[8])
top_n         = int(sys.argv[9])
top_topic_n   = int(sys.argv[10])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

summary    = r["summary"]
anomalies  = summary["anomalies"]
anom_count = len(anomalies)

def render_pct_bps(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

if json_out:
    envelope = {
        "window":        r["window"],
        "dapps": [
            {
                "domain":                d["domain"],
                "message_count":         d["message_count"],
                "distinct_topics":       d["distinct_topics"],
                "distinct_senders":      d["distinct_senders"],
                "state":                 d["state"],
                "oldest_message_block":  d["oldest_message_block"],
                "newest_message_block":  d["newest_message_block"],
                "chainwide_newest_block": d["chainwide_newest_block"],
                "active_in_registry":    d["active_in_registry"],
                "balance":               d["balance"],
            } for d in r["dapps"]
        ],
        "topics": [
            {
                "topic":      t["topic"],
                "count":      t["count"],
                "share":      render_pct_bps(t["share_bps"]),
                "share_bps":  t["share_bps"],
            } for t in r["topics"]
        ],
        "summary": {
            "total_dapps":             summary["total_dapps"],
            "active":                  summary["active"],
            "dormant":                 summary["dormant"],
            "abandoned":               summary["abandoned"],
            "total_messages":          summary["total_messages"],
            "top1_share":              render_pct_bps(summary["top1_share_bps"]),
            "top1_share_bps":          summary["top1_share_bps"],
            "top1_name":               summary["top1_name"],
            "top_topic_share":         render_pct_bps(summary["top_topic_share_bps"]),
            "top_topic_share_bps":     summary["top_topic_share_bps"],
            "top_topic_name":          summary["top_topic_name"],
            "abandoned_with_balance_count": summary["abandoned_with_balance_count"],
            "anomalies":               anomalies,
        },
        "rpc_port":                    port,
        "dormant_threshold_blocks":    dorm_thresh,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_dapp_message_audit: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {win_blocks} blocks)")
    sys.exit(0)

print(f"=== DApp message audit (port {port}, window [{from_h}..{to_h}], "
      f"{win_blocks} blocks; dormant_threshold={dorm_thresh}) ===")

if summary["total_dapps"] == 0:
    print("(no DApps registered)")
    sys.exit(0)

if not anom_only:
    # Top-N DApp table (message_count desc).
    print()
    print(f"Top {top_n} DApps by message count:")
    if not r["dapps"] or summary["total_messages"] == 0:
        print("  (no in-window messages)")
    else:
        for d in r["dapps"][:top_n]:
            oldest_age = (to_h - d["oldest_message_block"]
                          if d["message_count"] > 0 else "-")
            newest_age = (to_h - d["newest_message_block"]
                          if d["message_count"] > 0 else "-")
            print(f"  {d['domain']:32s}  "
                  f"msgs={d['message_count']:>7}  "
                  f"topics={d['distinct_topics']:>4}  "
                  f"senders={d['distinct_senders']:>5}  "
                  f"[{d['state']:>9s}]  "
                  f"oldest_age={oldest_age}  newest_age={newest_age}")

    # Top-N topic histogram.
    print()
    print(f"Top {top_topic_n} topics (global):")
    if not r["topics"]:
        print("  (none)")
    else:
        for t in r["topics"][:top_topic_n]:
            tname = t["topic"] if t["topic"] else "(empty)"
            print(f"  {tname:32s}  count={t['count']:>7}  "
                  f"({render_pct_bps(t['share_bps'])})")

    # Lifecycle summary.
    print()
    print("Lifecycle summary:")
    print(f"  ACTIVE:    {summary['active']:>4} "
          f"(messages in last {dorm_thresh} blocks)")
    print(f"  DORMANT:   {summary['dormant']:>4} "
          f"(no messages in last {dorm_thresh} blocks)")
    print(f"  ABANDONED: {summary['abandoned']:>4} "
          f"(no messages in last {5*dorm_thresh} blocks, still active)")
    print(f"  TOTAL:     {summary['total_dapps']:>4}")

    # Summary footer.
    print()
    print(f"Total in-window messages: {summary['total_messages']}")
    if summary["top1_name"]:
        print(f"Top DApp: {summary['top1_name']} "
              f"({render_pct_bps(summary['top1_share_bps'])} of messages)")
    if summary["top_topic_name"]:
        ttname = summary["top_topic_name"] or "(empty)"
        print(f"Top topic: {ttname} "
              f"({render_pct_bps(summary['top_topic_share_bps'])} of messages)")

# Anomaly lines.
print()
if anom_count == 0:
    print("[OK] No anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "dapp_concentration_high" in anomalies:
        print(f"  - dapp_concentration_high: '{summary['top1_name']}' = "
              f"{render_pct_bps(summary['top1_share_bps'])} of total messages "
              "(> 40% threshold)")
    if "mass_dormant" in anomalies:
        print(f"  - mass_dormant: {summary['dormant']} of "
              f"{summary['total_dapps']} DApps are DORMANT "
              "(> 50% — registry bloat signal)")
    if "topic_concentration_high" in anomalies:
        ttname = summary["top_topic_name"] or "(empty)"
        print(f"  - topic_concentration_high: '{ttname}' = "
              f"{render_pct_bps(summary['top_topic_share_bps'])} of total messages "
              "(> 50% — possible spam-bot or single-purpose chain)")
    if "abandoned_dapps_with_balance" in anomalies:
        print(f"  - abandoned_dapps_with_balance: "
              f"{summary['abandoned_with_balance_count']} ABANDONED DApp(s) "
              "carry non-zero accrued balance (operator-action: coordinate "
              "sweep before DAPP_GRACE expiry)")
        for d in r["dapps"]:
            if d["state"] == "ABANDONED" and d["balance"] > 0:
                print(f"      {d['domain']}: balance={d['balance']}, "
                      f"newest_block={d['chainwide_newest_block']}")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_message_audit: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ──────────────────────────────────────────────────
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_message_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_LIST" "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
python - "$TMP_OUT" "$TMP_ANOM" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
with open(sys.argv[2], "w", encoding="utf-8") as f:
    f.write(str(len(r["summary"].get("anomalies", []))))
PY
ANOM_COUNT=$(cat "$TMP_ANOM" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
