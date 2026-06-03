#!/usr/bin/env bash
# operator_dapp_census.sh — On-chain DApp registry CENSUS / ownership
# inventory for a running determ daemon. Produces a one-glance roster
# of every registered DApp:
#
#     domain | owner | service_pubkey(short) | endpoint_url | [msg_count]
#
# plus a summary line ("N DApps registered").
#
# Use case: a consortium operator wants an at-a-glance inventory of the
# DApp ecosystem on the chain — WHO owns each DApp, their service
# endpoint, and (opt-in) how active each one is — for ecosystem
# monitoring + ownership audit. The defining question this script
# answers is "who registered what, and is every DApp still owned by a
# member that is itself a registered, active validator?"
#
# Ownership model (see include/determ/chain/chain.hpp DAppEntry):
#   A DApp has no separate "owner" field — it is KEYED BY the owning
#   Determ domain (the domain that issued DAPP_REGISTER, which must
#   itself be a REGISTER'd registrant). So the registry key == owner
#   identity. This script surfaces that owning domain as the "owner"
#   column AND cross-references it against the live validator set
#   (`determ validators`) to flag the consortium-audit signals:
#     owner_registered  — owner domain currently appears in the registry
#     owner_active      — owner domain is an active_from-eligible validator
#   A DApp whose owner is no longer registered (owner_registered=no) is
#   an "orphaned ownership" — the registering identity has since left
#   the validator set, so no one can re-issue DAPP_REGISTER op=0/op=1
#   for it. That is an operator-actionable finding for an audit.
#
# Scope contrast with neighbouring DApp operator scripts (this session
# ships ~11 operator_dapp_*.sh; keep lanes distinct):
#   operator_dapp_inventory.sh   compact digest: service_pubkey +
#                                endpoint + registered_block + a
#                                RECENT-window message count (always
#                                counts over --message-window). Activity
#                                focus, not ownership.
#   operator_dapp_audit.sh       lifecycle status (ACTIVE / DEACTIVATING
#                                / INACTIVE vs DAPP_GRACE_BLOCKS) + topic
#                                count + endpoint. Lifecycle focus.
#   operator_dapp_health.sh      HEALTHY / STALE / ZOMBIE / ORPHAN
#                                classification over a window. Health
#                                focus.
#   operator_dapp_census.sh      THIS — OWNERSHIP roster. The "who owns
#                                each DApp + is the owner still a live
#                                member" table. Message count is OPT-IN
#                                (--with-message-counts; total over all
#                                history, not a recent window) precisely
#                                because the census is an ownership /
#                                inventory snapshot, not an activity
#                                digest. Single page per DApp.
#
# Read-only RPC; safe against any running daemon.
#
# Usage:
#   tools/operator_dapp_census.sh --rpc-port N
#                                 [--with-message-counts]
#                                 [--prefix STR]
#                                 [--json]
#
# Options:
#   --rpc-port N           RPC port to query (REQUIRED)
#   --with-message-counts  Add a per-DApp total DAPP_CALL count (whole
#                          chain history [0..head]). Slower — one extra
#                          dapp_messages scan per DApp. Best-effort: the
#                          per-page cap is 256 events, so counts that
#                          saturate are surfaced as ">=256" (human) /
#                          msg_count_truncated=true (JSON). Omit for a
#                          fast ownership-only roster.
#   --prefix STR           Pass-through server-side domain-prefix filter
#                          (only census DApps whose domain starts with
#                          STR). Empty matches all.
#   --json                 Emit a machine-readable JSON envelope
#   -h, --help             Show this help
#
# RPC dependencies (all read-only):
#   status        current chain height (head)
#   dapp_list     enumerate registered DApps (honours --prefix)
#   dapp_info     per-DApp full record (service_pubkey, endpoint_url,
#                 registered_at, inactive_from)
#   validators    owner cross-reference (domain -> registered/active)
#   dapp_messages OPT-IN total message count (--with-message-counts only)
#
# Exit codes:
#   0   census ran successfully (including zero DApps registered)
#   1   RPC error / daemon unreachable / malformed response / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_census.sh --rpc-port N
                               [--with-message-counts]
                               [--prefix STR]
                               [--json]

Enumerate every registered DApp on a running determ daemon and report
an ownership roster:

    domain | owner | service_pubkey(short) | endpoint_url | [msg_count]

The "owner" is the owning Determ domain (the registry key — a DApp has
no separate owner field; it is keyed by the domain that registered it).
Each owner is cross-referenced against the live validator set so the
roster flags owners that are no longer registered/active (orphaned
ownership). A trailing summary reports the DApp count.

Options:
  --rpc-port N           RPC port to query (REQUIRED)
  --with-message-counts  Add a per-DApp total DAPP_CALL count (whole
                         chain history). Slower; opt-in. Counts that hit
                         the 256-event page cap are shown as ">=256".
  --prefix STR           Server-side domain-prefix filter (empty = all)
  --json                 Emit machine-readable JSON envelope
  -h, --help             Show this help

Exit codes:
  0   census ran successfully (including zero DApps registered)
  1   RPC error / daemon unreachable / malformed response / bad args
EOF
}

PORT=""
WITH_MSG=0
PREFIX=""
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)              usage; exit 0 ;;
    --rpc-port)             PORT="${2:-}";   shift 2 ;;
    --with-message-counts)  WITH_MSG=1;      shift ;;
    --prefix)               PREFIX="${2:-}"; shift 2 ;;
    --json)                 JSON_OUT=1;      shift ;;
    *) echo "operator_dapp_census: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required. Operator scripts that default the port can
# silently target the wrong daemon on a multi-instance host; this script
# refuses to guess (mirrors operator_dapp_inventory.sh /
# operator_committee_snapshot.sh).
if [ -z "$PORT" ]; then
  echo "operator_dapp_census: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_census: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# common.sh sets $DETERM relative to the repo root. python's
# subprocess.run inherits the shell cwd (repo root) so the relative path
# usually resolves, but Windows CreateProcessW resolves relative paths
# differently from POSIX exec*(); promote to an absolute path so the
# per-DApp subprocess loop below behaves identically across platforms
# (same hardening as operator_dapp_inventory.sh / operator_dapp_health.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain height via status ──────────────────────────────────
STATUS_OUT=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_census: cannot reach daemon on rpc-port $PORT" >&2
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
  echo "operator_dapp_census: malformed status response (no .height field; port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: enumerate DApps via dapp-list (server-side --prefix) ─────────────
DAPP_LIST_ARGS=("dapp-list" "--rpc-port" "$PORT")
[ -n "$PREFIX" ] && DAPP_LIST_ARGS+=("--prefix" "$PREFIX")
LIST_OUT=$("$DETERM" "${DAPP_LIST_ARGS[@]}" 2>/dev/null) || {
  echo "operator_dapp_census: dapp-list RPC failed (port $PORT)" >&2
  exit 1
}

# ── Step 3: validator set for owner cross-reference ──────────────────────────
# `determ validators --json` returns an array of
# {domain, ed_pub, active_from, registered_at, stake, region}. We build
# two sets: every registered owner domain, and the subset whose
# active_from <= head (active). A DApp's owner == its registry key
# (domain). Failure here is non-fatal for the roster body — we degrade
# to "unknown" ownership flags rather than abort, because the census's
# primary payload (the roster) is still useful without the cross-ref.
VAL_OUT=$("$DETERM" validators --json --rpc-port "$PORT" 2>/dev/null) || VAL_OUT=""

# ── Step 4: per-DApp dapp-info (+ opt-in dapp-messages) pass ─────────────────
# The domain list is passed via a temp file (not stdin): the python
# heredoc that drives the per-DApp loop consumes stdin itself, so piping
# the list into `python - <<PY` would let the heredoc win and the loop
# would read nothing (same idiom as operator_dapp_inventory.sh).
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_census: cannot create temp file" >&2
  exit 1
}
TMP_LIST=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_census: cannot create temp file" >&2
  rm -f "$TMP_OUT" 2>/dev/null
  exit 1
}
TMP_VAL=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_census: cannot create temp file" >&2
  rm -f "$TMP_OUT" "$TMP_LIST" 2>/dev/null
  exit 1
}
trap 'rm -f "$TMP_OUT" "$TMP_LIST" "$TMP_VAL" 2>/dev/null' EXIT
printf '%s' "$LIST_OUT" > "$TMP_LIST"
printf '%s' "$VAL_OUT"  > "$TMP_VAL"

python - "$DETERM_ABS" "$PORT" "$HEIGHT" "$WITH_MSG" "$TMP_LIST" "$TMP_VAL" "$TMP_OUT" <<'PY'
import json, subprocess, sys, time

determ, port, height_s, with_msg_s, list_path, val_path, out_path = sys.argv[1:8]
height   = int(height_s)
with_msg = (with_msg_s == "1")

def run_rpc(args, what, retries=2):
    # Bounded retry on transient failures. A busy committee (multi-node
    # 3-of-3) can intermittently drop/refuse an RPC mid-finalize; a
    # persistent error still aborts (exit 1) after the retries are
    # exhausted, so this doesn't mask a genuinely-down daemon — it only
    # smooths over single-request blips. Each attempt re-runs the full
    # CLI subprocess (the determ CLI is a one-shot RPC client).
    last_err = ""
    for attempt in range(retries + 1):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except Exception as e:
            last_err = f"exception: {e}"
        else:
            if r.returncode != 0:
                last_err = f"rc={r.returncode}: {r.stderr.strip()}"
            else:
                try:
                    return json.loads(r.stdout)
                except Exception:
                    last_err = "non-JSON response"
        if attempt < retries:
            time.sleep(0.4)
    sys.stderr.write(f"operator_dapp_census: {what} {last_err}\n")
    sys.exit(1)

# Parse dapp-list (already fetched on the bash side).
with open(list_path, "r", encoding="utf-8") as f:
    list_raw = f.read()
try:
    listed = json.loads(list_raw)
except Exception:
    sys.stderr.write("operator_dapp_census: malformed dapp-list response\n")
    sys.exit(1)
if not isinstance(listed, dict):
    sys.stderr.write("operator_dapp_census: dapp-list not a JSON object\n")
    sys.exit(1)
dapps_raw = listed.get("dapps")
if not isinstance(dapps_raw, list):
    sys.stderr.write("operator_dapp_census: dapp-list missing .dapps array\n")
    sys.exit(1)

# Owner cross-reference from the validators snapshot. Degrade gracefully:
# if validators was unreachable / malformed, we leave the lookup sets
# empty and mark owner flags as None ("unknown") so the roster still
# renders.
val_ok = True
registered_owners = set()
active_owners = set()
with open(val_path, "r", encoding="utf-8") as f:
    val_raw = f.read()
if not val_raw.strip():
    val_ok = False
else:
    try:
        validators = json.loads(val_raw)
        if not isinstance(validators, list):
            raise ValueError("validators not an array")
        for v in validators:
            if not isinstance(v, dict):
                continue
            dom = v.get("domain")
            if not isinstance(dom, str) or not dom:
                continue
            registered_owners.add(dom)
            try:
                af = int(v.get("active_from", 0) or 0)
            except Exception:
                af = 0
            # active_from <= head means the validator is past its
            # activation delay and currently eligible.
            if af <= height:
                active_owners.add(dom)
    except Exception:
        val_ok = False

# Dedupe domains defensively (dapp_list returns unique domains by
# construction, but the registry can mutate between RPC calls).
seen = set()
domains = []
for d in dapps_raw:
    if isinstance(d, dict):
        dom = d.get("domain")
        if isinstance(dom, str) and dom and dom not in seen:
            seen.add(dom)
            domains.append(dom)

records = []
for domain in domains:
    info = run_rpc(
        [determ, "dapp-info", "--domain", domain, "--rpc-port", port],
        f"dapp-info {domain}")
    if isinstance(info, dict) and info.get("error"):
        # Race vs. deregister between dapp-list and dapp-info — skip
        # quietly (the registry can mutate between calls).
        continue

    svc = str(info.get("service_pubkey", "")) if isinstance(info, dict) else ""
    ep  = str(info.get("endpoint_url",   "")) if isinstance(info, dict) else ""
    try:
        reg_at = int(info.get("registered_at", 0) or 0) if isinstance(info, dict) else 0
    except Exception:
        reg_at = 0

    # owner == the owning Determ domain (registry key). Cross-reference
    # against the validator set. None == "unknown" (validators RPC
    # unavailable); True/False otherwise.
    if val_ok:
        owner_registered = domain in registered_owners
        owner_active     = domain in active_owners
    else:
        owner_registered = None
        owner_active     = None

    rec = {
        "domain":           domain,
        "owner":            domain,   # registry key IS the owner identity
        "service_pubkey":   svc,
        "endpoint_url":     ep,
        "registered_block": reg_at,
        "owner_registered": owner_registered,
        "owner_active":     owner_active,
    }

    if with_msg:
        # Total DAPP_CALL count over all history [0..head]. dapp_messages
        # uses [from_height, to_height) half-open; to_height = height + 1
        # makes the upper bound inclusive of the tip. Best-effort: a
        # single page caps at 256 events (truncated=true); we surface the
        # saturation rather than paginate (the census is an inventory
        # snapshot — operators needing exact high-volume counts run
        # operator_dapp_message_audit.sh).
        msg_count = 0
        msg_trunc = False
        if height > 0:
            msgs = run_rpc(
                [determ, "dapp-messages",
                 "--domain", domain,
                 "--from",   "0",
                 "--to",     str(height + 1),
                 "--rpc-port", port],
                f"dapp-messages {domain}")
            if isinstance(msgs, dict):
                try:
                    msg_count = int(msgs.get("count", 0) or 0)
                except Exception:
                    msg_count = 0
                msg_trunc = bool(msgs.get("truncated", False))
        rec["msg_count"] = msg_count
        rec["msg_count_truncated"] = msg_trunc

    records.append(rec)

# Stable ordering: ascending by registered_block, then by domain. (Oldest
# registrations first — natural reading order for an ownership roster.)
records.sort(key=lambda r: (r["registered_block"], r["domain"]))

payload = {
    "records":         records,
    "validators_seen": val_ok,
    "with_msg":        with_msg,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(payload, f)
PY
if [ "$?" -ne 0 ]; then
  exit 1
fi

# ── Step 5: render envelope (JSON or human table) ────────────────────────────
python - "$JSON_OUT" "$TMP_OUT" "$HEIGHT" "$WITH_MSG" "$PORT" "$PREFIX" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
out_path  = sys.argv[2]
height    = int(sys.argv[3])
with_msg  = sys.argv[4] == "1"
port      = int(sys.argv[5])
prefix    = sys.argv[6]

with open(out_path, "r", encoding="utf-8") as f:
    payload = json.load(f)
records  = payload["records"]
val_seen = payload["validators_seen"]

def short(pub):
    # First 12 hex chars — same short-hash convention as
    # operator_committee_snapshot.sh's pubkey_short column.
    if not pub:
        return "<none>"
    return pub[:12] if len(pub) > 12 else pub

if json_out:
    envelope = {
        "rpc_port":          port,
        "chain_height":      height,
        "prefix":            prefix,
        "with_message_counts": with_msg,
        "validators_seen":   val_seen,
        "dapp_count":        len(records),
        "dapps":             records,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable roster.
prefix_note = f", prefix='{prefix}'" if prefix else ""
print(f"DApp census (port {port}, chain height {height}{prefix_note})")
if not val_seen:
    print("(note: validators RPC unavailable — owner registered/active flags shown as '?')")

if not records:
    print("(no DApps registered)")
    print()
    print("0 DApps registered")
    sys.exit(0)

# Column widths. service_pubkey short is 12 chars; pad the variable
# columns to the widest observed value (capped so a pathological
# endpoint_url doesn't blow the table out — long URLs are simply not
# truncated, they just push the trailing columns, which is acceptable
# for an operator console roster).
dom_w = max(6, max(len(r["domain"]) for r in records))
ep_w  = max(12, max(len(r["endpoint_url"] or "") for r in records))

def owner_flag(r):
    # Compact ownership annotation appended to the owner column.
    reg = r["owner_registered"]
    act = r["owner_active"]
    if reg is None:
        return "?"
    if not reg:
        return "ORPHANED"   # owner no longer a registered validator
    return "active" if act else "registered"

header_cols = ["DOMAIN", "OWNER(status)", "SERVICE_PUBKEY", "ENDPOINT_URL"]
fmt = f"%-{dom_w}s  %-18s  %-14s  %-{ep_w}s"
if with_msg:
    header_cols.append("MSGS")
    fmt += "  %6s"

print(fmt % tuple(header_cols))
print("-" * (dom_w + 18 + 14 + ep_w + (8 if with_msg else 0) + 8))

orphan_count = 0
for r in records:
    flag = owner_flag(r)
    if flag == "ORPHANED":
        orphan_count += 1
    # owner == domain in every case (the registry key IS the owner
    # identity), so the OWNER column carries just the status annotation
    # rather than redundantly repeating the DOMAIN column.
    owner_cell = f"(self) {flag}"
    cols = [
        r["domain"],
        owner_cell,
        short(r["service_pubkey"]),
        r["endpoint_url"] or "<none>",
    ]
    if with_msg:
        c = r.get("msg_count", 0)
        disp = f">={c}" if r.get("msg_count_truncated") else str(c)
        cols.append(disp)
    print(fmt % tuple(cols))

print("-" * (dom_w + 18 + 14 + ep_w + (8 if with_msg else 0) + 8))
n = len(records)
summary = f"{n} DApp{'s' if n != 1 else ''} registered"
if val_seen and orphan_count > 0:
    summary += f" ({orphan_count} with ORPHANED ownership — owner no longer a registered validator)"
print(summary)
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_census: rendering failed" >&2
  exit 1
fi
exit 0
