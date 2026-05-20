#!/usr/bin/env bash
# operator_dapp_inventory.sh — Enumerate every registered DApp on a
# running determ daemon and report a compact per-DApp summary:
# service_pubkey, endpoint_url, registered block, and a recent-
# message count over the last --message-window blocks.
#
# Scope contrast with neighbouring scripts:
#   operator_dapp_audit.sh         lifecycle classification (ACTIVE /
#                                  DEACTIVATING / INACTIVE) + topic
#                                  count + endpoint table. No message
#                                  counts.
#   operator_dapp_message_audit.sh deep message-content analytics
#                                  (topics, top senders, payload sizes,
#                                  anomalies). Multi-page paginated.
#   operator_dapp_inventory.sh     THIS — minimal one-line-per-DApp
#                                  inventory, single page (256-event
#                                  cap is intentional: this is a
#                                  "what's registered, how busy?"
#                                  digest, not an audit).
#
# Read-only RPC; safe against any running daemon.
#
# Usage:
#   tools/operator_dapp_inventory.sh --rpc-port N
#                                    [--message-window N]
#                                    [--json]
#
# Options:
#   --rpc-port N        RPC port to query (REQUIRED)
#   --message-window N  Count messages over last N blocks (default: 100;
#                       capped client-side at the chain head — empty-
#                       chain or N > height clamps to [0..height])
#   --json              Emit machine-readable JSON envelope
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   status           current chain height
#   dapp_list        iterate registered DApps
#   dapp_info        per-DApp full record (service_pubkey, registered_at)
#   dapp_messages    per-DApp event page (last --message-window blocks)
#
# Recent-message count semantics:
#   - Window is the last N blocks: [max(0, height - N + 1) .. height].
#   - dapp_messages caps each response at 256 events with truncated=true;
#     we use the single-page count and note the truncation in human
#     output / set truncated=true in the JSON record. Operators who
#     need precise counts run operator_dapp_message_audit.sh.
#
# Exit codes:
#   0   inventory ran successfully (including zero DApps registered)
#   1   RPC error / daemon unreachable / malformed response / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_inventory.sh --rpc-port N
                                  [--message-window N]
                                  [--json]

Enumerate registered DApps on a running determ daemon and report a
compact per-DApp summary: service_pubkey, endpoint_url, registered
block, and recent-message count over the last --message-window blocks.

Options:
  --rpc-port N        RPC port to query (REQUIRED)
  --message-window N  Count messages over last N blocks (default: 100)
  --json              Emit machine-readable JSON envelope
  -h, --help          Show this help

Exit codes:
  0   inventory ran successfully (including zero DApps registered)
  1   RPC error / daemon unreachable / malformed response / bad args
EOF
}

PORT=""
WINDOW=100
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --message-window)  WINDOW="${2:-}"; shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    *) echo "operator_dapp_inventory: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (operator scripts that default the port can
# silently target the wrong daemon on multi-instance hosts; this script
# refuses to guess).
if [ -z "$PORT" ]; then
  echo "operator_dapp_inventory: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_inventory: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$WINDOW" in *[!0-9]*|"")
  echo "operator_dapp_inventory: --message-window must be a positive integer (got '$WINDOW')" >&2
  exit 1 ;;
esac
if [ "$WINDOW" -lt 1 ]; then
  echo "operator_dapp_inventory: --message-window must be >= 1 (got '$WINDOW')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# common.sh sets $DETERM to a path relative to the repo root (e.g.
# build/Release/determ.exe). Python's subprocess.run runs with the
# shell's cwd which is the repo root, so the relative path SHOULD
# resolve, but Windows' CreateProcess can be picky about relative
# paths inside subprocess.run — promote to an absolute path so it
# works the same on Linux / Mac / Git Bash.
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain height via status ──────────────────────────────────
# `determ status` emits a JSON object with .height. We use status here
# (rather than `head`) to mirror the pattern most operators use when
# checking liveness (status returns more fields; we just need height).
STATUS_OUT=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_inventory: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}

HEIGHT=$(printf '%s' "$STATUS_OUT" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('height', 0)))
except Exception:
    print('')")
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_dapp_inventory: malformed status response (no .height field; port $PORT)" >&2
  exit 1 ;;
esac

# Clamp the window to [0..HEIGHT].
WIN_FROM=0
if [ "$HEIGHT" -ge "$WINDOW" ]; then
  WIN_FROM=$(( HEIGHT - WINDOW + 1 ))
fi

# ── Step 2: enumerate DApps via dapp-list ────────────────────────────────────
LIST_OUT=$("$DETERM" dapp-list --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_inventory: dapp-list RPC failed (port $PORT)" >&2
  exit 1
}

# Pull the domain list out into a newline-separated string. We dedupe
# defensively even though dapp_list returns unique domains by construction.
DOMAINS=$(printf '%s' "$LIST_OUT" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
except Exception:
    sys.stderr.write('operator_dapp_inventory: malformed dapp-list response\n')
    sys.exit(1)
if not isinstance(j, dict):
    sys.stderr.write('operator_dapp_inventory: dapp-list not a JSON object\n')
    sys.exit(1)
dapps = j.get('dapps')
if not isinstance(dapps, list):
    sys.stderr.write('operator_dapp_inventory: dapp-list missing .dapps array\n')
    sys.exit(1)
seen = set()
for d in dapps:
    if isinstance(d, dict):
        dom = d.get('domain')
        if isinstance(dom, str) and dom and dom not in seen:
            seen.add(dom)
            print(dom)
")
if [ "$?" -ne 0 ]; then exit 1; fi

# ── Step 3: per-DApp dapp-info + dapp-messages pass ──────────────────────────
# We pass the domain list through a temp file (not stdin) because the
# python heredoc itself consumes stdin — piping into `python - <<PY`
# would let the heredoc win and the loop would read nothing. For each
# DApp we collect: service_pubkey (full hex), endpoint_url, registered_at
# block, and the count of DAPP_CALL events in [WIN_FROM..HEIGHT].
#
# dapp_messages returns at most 256 events per page; we deliberately
# do NOT paginate here — this is an inventory digest, not a forensic
# audit. If the count saturates at 256 we surface "truncated=true" in
# the per-DApp record and the human output suffix "(>=256)" so the
# operator knows to use operator_dapp_message_audit.sh for the precise
# count.
#
# dapp_messages uses [from_height, to_height) HALF-OPEN; we pass
# to_height = HEIGHT + 1 so our --message-window upper bound is
# inclusive of the tip.
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_inventory: cannot create temp file" >&2
  exit 1
}
TMP_DOMS=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_inventory: cannot create temp file" >&2
  rm -f "$TMP_OUT" 2>/dev/null
  exit 1
}
trap 'rm -f "$TMP_OUT" "$TMP_DOMS" 2>/dev/null' EXIT
printf '%s\n' "$DOMAINS" > "$TMP_DOMS"

python - "$DETERM_ABS" "$PORT" "$WIN_FROM" "$HEIGHT" "$TMP_DOMS" "$TMP_OUT" <<'PY'
import json, subprocess, sys

determ, port, win_from_s, height_s, doms_path, out_path = sys.argv[1:7]
win_from = int(win_from_s)
height   = int(height_s)
rpc_to   = height + 1  # half-open -> inclusive

def run_rpc(args, what):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except Exception as e:
        sys.stderr.write(f"operator_dapp_inventory: {what} exception: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_dapp_inventory: {what} rc={r.returncode}: {r.stderr.strip()}\n")
        sys.exit(1)
    try:
        return json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_dapp_inventory: {what} non-JSON response\n")
        sys.exit(1)

records = []
with open(doms_path, "r", encoding="utf-8") as f:
    domains = [line.strip() for line in f if line.strip()]

for domain in domains:
    info = run_rpc(
        [determ, "dapp-info", "--domain", domain, "--rpc-port", port],
        f"dapp-info {domain}")
    if isinstance(info, dict) and info.get("error"):
        # Race vs. deregister between dapp-list and dapp-info — skip
        # quietly; the registry can mutate between RPC calls.
        continue

    svc = str(info.get("service_pubkey", "")) if isinstance(info, dict) else ""
    ep  = str(info.get("endpoint_url",   "")) if isinstance(info, dict) else ""
    try:
        reg_at = int(info.get("registered_at", 0) or 0) if isinstance(info, dict) else 0
    except Exception:
        reg_at = 0

    # Recent-message count over the configured window.
    msg_count       = 0
    msg_truncated   = False
    if height > 0:
        msgs = run_rpc(
            [determ, "dapp-messages",
             "--domain", domain,
             "--from",   str(win_from),
             "--to",     str(rpc_to),
             "--rpc-port", port],
            f"dapp-messages {domain}")
        if isinstance(msgs, dict):
            try:
                msg_count = int(msgs.get("count", 0) or 0)
            except Exception:
                msg_count = 0
            msg_truncated = bool(msgs.get("truncated", False))

    records.append({
        "domain":               domain,
        "service_pubkey":       svc,
        "endpoint_url":         ep,
        "registered_block":     reg_at,
        "recent_message_count": msg_count,
        "recent_truncated":     msg_truncated,
    })

# Stable ordering: ascending by registered_block, then by domain.
records.sort(key=lambda r: (r["registered_block"], r["domain"]))

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(records, f)
PY
if [ "$?" -ne 0 ]; then
  exit 1
fi

# ── Step 4: render envelope ──────────────────────────────────────────────────
python - "$JSON_OUT" "$TMP_OUT" "$HEIGHT" "$WINDOW" "$WIN_FROM" "$PORT" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
out_path  = sys.argv[2]
height    = int(sys.argv[3])
window    = int(sys.argv[4])
win_from  = int(sys.argv[5])
port      = int(sys.argv[6])

with open(out_path, "r", encoding="utf-8") as f:
    records = json.load(f)

if json_out:
    envelope = {
        "chain_height":     height,
        "message_window":   window,
        "window_from":      win_from,
        "window_to":        height,
        "rpc_port":         port,
        "dapp_count":       len(records),
        "dapps": [
            {
                "domain":               r["domain"],
                "service_pubkey":       r["service_pubkey"],
                "endpoint_url":         r["endpoint_url"],
                "registered_block":     r["registered_block"],
                "recent_message_count": r["recent_message_count"],
                "recent_truncated":     r["recent_truncated"],
            }
            for r in records
        ],
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
print(f"DApp inventory at chain height {height}")
print("================================")

if not records:
    print("(no DApps registered)")
    sys.exit(0)

for i, r in enumerate(records):
    if i > 0:
        print()
    print(f"DApp: {r['domain']}")
    print(f"  service_pubkey: {r['service_pubkey']}")
    print(f"  endpoint_url: {r['endpoint_url']}")
    print(f"  registered_block: {r['registered_block']}")
    count_str = str(r["recent_message_count"])
    if r["recent_truncated"]:
        count_str += " (>=256; truncated single page)"
    print(f"  recent_messages (last {window}): {count_str}")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_inventory: rendering failed" >&2
  exit 1
fi

exit 0
