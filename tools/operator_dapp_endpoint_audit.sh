#!/usr/bin/env bash
# operator_dapp_endpoint_audit.sh — Discovery-readiness audit of the
# on-chain DApp registry on a running determ daemon. For every
# registered DApp it inspects the two fields an off-chain client needs
# to actually REACH and SECURELY TALK TO the service — endpoint_url
# (discovery) and service_pubkey (E2E sealed-box encryption key) — and
# classifies each DApp as discoverable / degraded / unreachable.
#
# Why this is a distinct lane (the gap it fills):
#   The chain does NOT validate either field semantically. The
#   DAPP_REGISTER apply path (src/chain/chain.cpp, op=0 decode) copies
#   service_pubkey as a raw 32-byte blob and assigns endpoint_url from
#   the wire with the ONLY constraint being a length cap
#   (MAX_DAPP_ENDPOINT_LEN = 255, see include/determ/chain/block.hpp).
#   There is no scheme check, no non-empty check, and no rejection of
#   an all-zero service key. So a DApp can be perfectly valid on-chain
#   yet advertise an empty/garbage endpoint or a zero service_pubkey —
#   both of which silently break client discovery and payload
#   encryption (the libsodium sealed-box to a zero key is unusable).
#   No existing operator_dapp_*.sh tool audits this discovery surface:
#     operator_dapp_census.sh         OWNERSHIP roster (owner registered/active)
#     operator_dapp_audit.sh          LIFECYCLE (ACTIVE/DEACTIVATING/INACTIVE)
#     operator_dapp_health.sh         activity HEALTH over a message window
#     operator_dapp_topic_audit.sh    TOPIC registration patterns
#     operator_dapp_call_*_audit.sh   DAPP_CALL flow / volume
#     operator_dapp_message_audit.sh  message volume + topics
#     operator_dapp_balance_audit.sh  accrued balance / revenue
#     operator_dapp_registry_proof_audit.sh  d:-namespace state-proof
#     operator_dapp_endpoint_audit.sh THIS — endpoint_url + service_pubkey
#                                     DISCOVERY-READINESS. Distinct field
#                                     pair; distinct question.
#
# The defining question: "of the DApps registered on this chain, which
# ones can a client actually find and encrypt to?"
#
# Classification per DApp (only endpoint_url + service_pubkey examined;
# both come straight from dapp_info, see Node::rpc_dapp_info in
# src/node/node.cpp):
#   endpoint state:
#     ok       — non-empty, has an explicit scheme client tooling can
#                resolve: https:// / http:// / wss:// / ws:// or a
#                .onion host (with or without scheme), no embedded
#                whitespace/control chars
#     weak     — non-empty + scheme-bearing but http:// (cleartext) or
#                a bare host with a dot but no scheme (resolvable-ish
#                but ambiguous) — a soft finding, not a hard failure
#     missing  — empty string (no discovery URL at all)
#     malformed— non-empty but unusable: no scheme AND no dot, or
#                contains whitespace / control bytes
#   key state:
#     ok       — 64 lowercase-hex chars and NOT all-zero
#     zero     — 64 zero hex chars (placeholder; sealed-box unusable)
#     malformed— not exactly 64 hex chars (should not occur for a
#                fixed 32-byte PubKey, surfaced defensively)
#
#   Per-DApp verdict:
#     DISCOVERABLE — endpoint ok|weak AND key ok
#     DEGRADED     — endpoint weak, or any single soft issue, where the
#                    DApp is still theoretically reachable+encryptable
#     UNREACHABLE  — endpoint missing|malformed, OR key zero|malformed
#                    (a client cannot find it and/or cannot encrypt to
#                    it). This is the operator-actionable finding.
#
# Lifecycle awareness: inactive_from <= head means the DApp is no
# longer callable (DAPP_CALL is rejected at validate time — see the
# DAPP_CALL constraints in include/determ/chain/block.hpp). The audit
# reports lifecycle per row and, by default, only counts ACTIVE DApps
# toward the [ANOMALY] verdict (a deactivated DApp's broken endpoint is
# not actionable). --include-inactive folds inactive DApps into the
# verdict too.
#
# Read-only RPC; safe against any running daemon.
#
# Usage:
#   tools/operator_dapp_endpoint_audit.sh --rpc-port N
#                                         [--prefix STR]
#                                         [--include-inactive]
#                                         [--anomalies-only]
#                                         [--json]
#
# Options:
#   --rpc-port N        RPC port to query (REQUIRED)
#   --prefix STR        Server-side domain-prefix filter on dapp-list
#                       (empty matches all)
#   --include-inactive  Count INACTIVE (deactivated) DApps toward the
#                       UNREACHABLE/[ANOMALY] verdict too. Default:
#                       inactive DApps are reported but excluded from
#                       the verdict.
#   --anomalies-only    Suppress the full per-DApp table; print only the
#                       UNREACHABLE/DEGRADED rows + the verdict. Enables
#                       the exit-2 anomaly gate.
#   --json              Emit a machine-readable JSON envelope
#   -h, --help          Show this help
#
# RPC dependencies (all read-only; field sets verified against
# src/node/node.cpp):
#   status        current chain height (head) — for the active/inactive
#                 lifecycle predicate (inactive_from <= head)
#   dapp_list     enumerate registered DApps (honours --prefix)
#   dapp_info     per-DApp record; fields used: service_pubkey (hex),
#                 endpoint_url, inactive_from
#
# Exit codes:
#   0   audit ran; every in-scope ACTIVE DApp is DISCOVERABLE
#       (or DEGRADED), or no DApps registered, or daemon unreachable in
#       a clean SKIP. Also the default (non --anomalies-only) success.
#   2   --anomalies-only AND >= 1 in-scope DApp is UNREACHABLE
#   1   RPC error / malformed response / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_endpoint_audit.sh --rpc-port N
                                       [--prefix STR]
                                       [--include-inactive]
                                       [--anomalies-only]
                                       [--json]

Discovery-readiness audit of the on-chain DApp registry. For every
registered DApp, inspect the two fields a client needs to reach and
encrypt to the service:

    endpoint_url    — discovery URL (the chain does NOT validate it)
    service_pubkey  — libsodium sealed-box key (a zero key is unusable)

and classify each DApp as DISCOVERABLE / DEGRADED / UNREACHABLE.

Options:
  --rpc-port N        RPC port to query (REQUIRED)
  --prefix STR        Server-side domain-prefix filter (empty = all)
  --include-inactive  Fold deactivated DApps into the verdict too
                      (default: reported but excluded from the verdict)
  --anomalies-only    Print only the problem rows + verdict; enables the
                      exit-2 anomaly gate
  --json              Emit a machine-readable JSON envelope
  -h, --help          Show this help

Exit codes:
  0   audit ran; every in-scope ACTIVE DApp DISCOVERABLE/DEGRADED, or
      no DApps registered, or daemon unreachable (clean SKIP)
  2   --anomalies-only AND >= 1 in-scope DApp UNREACHABLE
  1   RPC error / malformed response / bad args
EOF
}

PORT=""
PREFIX=""
INCLUDE_INACTIVE=0
ANOM_ONLY=0
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)           usage; exit 0 ;;
    --rpc-port)          PORT="${2:-}";   shift 2 ;;
    --prefix)            PREFIX="${2:-}"; shift 2 ;;
    --include-inactive)  INCLUDE_INACTIVE=1; shift ;;
    --anomalies-only)    ANOM_ONLY=1;     shift ;;
    --json)              JSON_OUT=1;      shift ;;
    *) echo "operator_dapp_endpoint_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required: an operator script that defaults the port can
# silently target the wrong daemon on a multi-instance host (mirrors
# operator_dapp_census.sh / operator_dapp_inventory.sh).
if [ -z "$PORT" ]; then
  echo "operator_dapp_endpoint_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_endpoint_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote $DETERM to an absolute path for the python subprocess loop:
# python's subprocess.run inherits the shell cwd (repo root), but
# Windows CreateProcessW resolves relative paths differently from POSIX
# exec*(); the absolute form behaves identically across platforms (same
# hardening as operator_dapp_census.sh / operator_dapp_inventory.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain height via status (for the lifecycle predicate) ─────
# A clean SKIP (exit 0) when the daemon is unreachable: an unreachable
# daemon is an operational state, not an audit failure, so this script
# does not return non-zero merely because nothing is listening.
STATUS_OUT=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_endpoint_audit: [SKIP] cannot reach daemon on rpc-port $PORT (not an error)"
  exit 0
}
HEIGHT=$(printf '%s' "$STATUS_OUT" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('height', 0)))
except Exception:
    print('')")
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_dapp_endpoint_audit: malformed status response (no .height field; port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: enumerate DApps via dapp-list (server-side --prefix) ─────────────
DAPP_LIST_ARGS=("dapp-list" "--rpc-port" "$PORT")
[ -n "$PREFIX" ] && DAPP_LIST_ARGS+=("--prefix" "$PREFIX")
LIST_OUT=$("$DETERM" "${DAPP_LIST_ARGS[@]}" 2>/dev/null) || {
  echo "operator_dapp_endpoint_audit: dapp-list RPC failed (port $PORT)" >&2
  exit 1
}

# Pass the domain list through a temp file (not stdin): the python
# heredoc that drives the per-DApp loop consumes stdin itself, so piping
# the list into `python - <<PY` would let the heredoc win (same idiom as
# operator_dapp_census.sh).
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_endpoint_audit: cannot create temp file" >&2
  exit 1
}
TMP_LIST=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_endpoint_audit: cannot create temp file" >&2
  rm -f "$TMP_OUT" 2>/dev/null
  exit 1
}
trap 'rm -f "$TMP_OUT" "$TMP_LIST" 2>/dev/null' EXIT
printf '%s' "$LIST_OUT" > "$TMP_LIST"

# ── Step 3: per-DApp dapp-info pass + classification ─────────────────────────
python - "$DETERM_ABS" "$PORT" "$HEIGHT" "$TMP_LIST" "$TMP_OUT" <<'PY'
import json, subprocess, sys, time, re

determ, port, height_s, list_path, out_path = sys.argv[1:6]
height = int(height_s)

def run_rpc(args, what, retries=2):
    # Bounded retry on transient blips. A busy committee can
    # intermittently refuse an RPC mid-finalize; a persistent error
    # still aborts (exit 1) after retries, so this never masks a
    # genuinely-down daemon (same pattern as operator_dapp_census.sh).
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
    sys.stderr.write(f"operator_dapp_endpoint_audit: {what} {last_err}\n")
    sys.exit(1)

with open(list_path, "r", encoding="utf-8") as f:
    list_raw = f.read()
try:
    listed = json.loads(list_raw)
except Exception:
    sys.stderr.write("operator_dapp_endpoint_audit: malformed dapp-list response\n")
    sys.exit(1)
if not isinstance(listed, dict):
    sys.stderr.write("operator_dapp_endpoint_audit: dapp-list not a JSON object\n")
    sys.exit(1)
dapps_raw = listed.get("dapps")
if not isinstance(dapps_raw, list):
    sys.stderr.write("operator_dapp_endpoint_audit: dapp-list missing .dapps array\n")
    sys.exit(1)

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

HEX64 = re.compile(r'^[0-9a-f]{64}$')
ZERO64 = "0" * 64
# Schemes a client can resolve directly. http:// is intentionally NOT
# in the "ok" set — it is downgraded to "weak" (cleartext discovery).
SCHEME_OK   = ("https://", "wss://", "ws://")
SCHEME_WEAK = ("http://",)

def classify_endpoint(url):
    # Returns (state, reason). The chain validates none of this (only a
    # 255-byte length cap, see block.hpp MAX_DAPP_ENDPOINT_LEN), so all
    # checks here are client-discovery heuristics, not consensus rules.
    if url is None or url == "":
        return ("missing", "no endpoint_url advertised")
    # Whitespace / control bytes => unusable as a URL.
    if any((ord(c) < 0x20) or c in (" ", "\t") for c in url):
        return ("malformed", "embedded whitespace/control characters")
    low = url.lower()
    if low.startswith(SCHEME_OK):
        return ("ok", "")
    if low.startswith(SCHEME_WEAK):
        return ("weak", "cleartext http:// scheme")
    # .onion host (with or without scheme) is resolvable by Tor-aware
    # clients — treat as ok if it has the .onion suffix on the host.
    host = low.split("/", 1)[0]
    if host.endswith(".onion") or ".onion" in host:
        return ("ok", "")
    if "://" in low:
        # Some other explicit scheme (e.g. custom). Resolvable-ish but
        # not one the standard client stack handles — soft finding.
        return ("weak", "non-standard URL scheme")
    if "." in host:
        # Bare host with a dot, no scheme — ambiguous but plausibly
        # resolvable. Soft finding.
        return ("weak", "no URL scheme (bare host)")
    return ("malformed", "no scheme and no dotted host")

def classify_key(pub):
    if not isinstance(pub, str):
        return ("malformed", "non-string service_pubkey")
    p = pub.strip().lower()
    if not HEX64.match(p):
        return ("malformed", f"service_pubkey not 64 hex chars (len={len(p)})")
    if p == ZERO64:
        return ("zero", "all-zero service_pubkey (sealed-box unusable)")
    return ("ok", "")

UINT64_MAX = (1 << 64) - 1
records = []
for domain in domains:
    info = run_rpc(
        [determ, "dapp-info", "--domain", domain, "--rpc-port", port],
        f"dapp-info {domain}")
    if isinstance(info, dict) and info.get("error"):
        # Race vs. deregister between dapp-list and dapp-info — skip
        # quietly (the registry can mutate between calls).
        continue

    ep  = info.get("endpoint_url", "")   if isinstance(info, dict) else ""
    pub = info.get("service_pubkey", "") if isinstance(info, dict) else ""
    try:
        inactive_from = int(info.get("inactive_from", UINT64_MAX) or UINT64_MAX) \
            if isinstance(info, dict) else UINT64_MAX
    except Exception:
        inactive_from = UINT64_MAX

    # Lifecycle predicate mirrors the DAPP_CALL validate-time gate:
    # inactive_from <= head => no longer callable (deactivated/expired).
    active = inactive_from > height

    ep_state,  ep_reason  = classify_endpoint(ep if isinstance(ep, str) else "")
    key_state, key_reason = classify_key(pub)

    # Per-DApp verdict. A client cannot use a DApp it cannot find
    # (endpoint missing/malformed) OR cannot encrypt to (key
    # zero/malformed) => UNREACHABLE. Soft endpoint findings (weak)
    # with a good key => DEGRADED. Otherwise DISCOVERABLE.
    if ep_state in ("missing", "malformed") or key_state in ("zero", "malformed"):
        verdict = "UNREACHABLE"
    elif ep_state == "weak":
        verdict = "DEGRADED"
    else:
        verdict = "DISCOVERABLE"

    reasons = [r for r in (ep_reason, key_reason) if r]

    records.append({
        "domain":         domain,
        "active":         active,
        "endpoint_url":   ep if isinstance(ep, str) else "",
        "endpoint_state": ep_state,
        "service_pubkey": pub if isinstance(pub, str) else "",
        "key_state":      key_state,
        "verdict":        verdict,
        "reasons":        reasons,
    })

# Stable ordering: problem rows first (UNREACHABLE, then DEGRADED, then
# DISCOVERABLE), then by domain — operator reads the actionable ones at
# the top.
rank = {"UNREACHABLE": 0, "DEGRADED": 1, "DISCOVERABLE": 2}
records.sort(key=lambda r: (rank.get(r["verdict"], 3), r["domain"]))

with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"records": records}, f)
PY
if [ "$?" -ne 0 ]; then
  exit 1
fi

# ── Step 4: render envelope (JSON or human table) + verdict ──────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$INCLUDE_INACTIVE" "$TMP_OUT" \
            "$HEIGHT" "$PORT" "$PREFIX" <<'PY'
import json, sys

json_out         = sys.argv[1] == "1"
anom_only        = sys.argv[2] == "1"
include_inactive = sys.argv[3] == "1"
out_path         = sys.argv[4]
height           = int(sys.argv[5])
port             = int(sys.argv[6])
prefix           = sys.argv[7]

with open(out_path, "r", encoding="utf-8") as f:
    payload = json.load(f)
records = payload["records"]

def in_scope(r):
    # Inactive DApps count toward the verdict only with --include-inactive.
    return include_inactive or r["active"]

n_total   = len(records)
n_active  = sum(1 for r in records if r["active"])
scope     = [r for r in records if in_scope(r)]
n_unreach = sum(1 for r in scope if r["verdict"] == "UNREACHABLE")
n_degrade = sum(1 for r in scope if r["verdict"] == "DEGRADED")
n_discov  = sum(1 for r in scope if r["verdict"] == "DISCOVERABLE")

# Anomaly gate: any in-scope UNREACHABLE DApp.
anomaly_flag = n_unreach > 0
exit_code = 2 if (anom_only and anomaly_flag) else 0

def short(pub):
    if not pub:
        return "<none>"
    return pub[:12] if len(pub) > 12 else pub

if json_out:
    envelope = {
        "rpc_port":          port,
        "chain_height":      height,
        "prefix":            prefix,
        "include_inactive":  include_inactive,
        "dapp_count":        n_total,
        "active_count":      n_active,
        "in_scope_count":    len(scope),
        "discoverable":      n_discov,
        "degraded":          n_degrade,
        "unreachable":       n_unreach,
        "anomaly_flag":      anomaly_flag,
        "dapps":             records,
    }
    print(json.dumps(envelope, indent=2))
    sys.exit(exit_code)

# Human-readable.
prefix_note = f", prefix='{prefix}'" if prefix else ""
print(f"=== DApp endpoint/key discovery audit "
      f"(port {port}, chain height {height}{prefix_note}) ===")

if n_total == 0:
    print("(no DApps registered)")
    print()
    print("[OK] no DApps registered")
    sys.exit(0)

scope_note = "all DApps" if include_inactive else "ACTIVE DApps only"
print(f"DApps: {n_total} total, {n_active} active "
      f"(verdict scope: {scope_note}, {len(scope)} in scope)")
print(f"  DISCOVERABLE: {n_discov}   DEGRADED: {n_degrade}   "
      f"UNREACHABLE: {n_unreach}")
print()

# Which rows to print: in --anomalies-only mode, only the non-clean
# in-scope rows; otherwise the full roster.
def shown(r):
    if not anom_only:
        return True
    return in_scope(r) and r["verdict"] != "DISCOVERABLE"

rows = [r for r in records if shown(r)]

if not rows:
    if anom_only:
        print("(no problem rows)")
else:
    dom_w = max(6, max(len(r["domain"]) for r in rows))
    ep_w  = max(12, min(48, max(len(r["endpoint_url"] or "") for r in rows)))
    fmt = f"%-{dom_w}s  %-7s  %-12s  %-9s  %-9s  %-{ep_w}s"
    print(fmt % ("DOMAIN", "LIFECYC", "VERDICT", "ENDPOINT", "KEY", "ENDPOINT_URL"))
    print("-" * (dom_w + 7 + 12 + 9 + 9 + ep_w + 12))
    for r in rows:
        life = "active" if r["active"] else "inactive"
        ep_disp = r["endpoint_url"] or "<none>"
        if len(ep_disp) > ep_w:
            ep_disp = ep_disp[:ep_w - 1] + "…"
        print(fmt % (
            r["domain"],
            life,
            r["verdict"],
            r["endpoint_state"],
            r["key_state"],
            ep_disp,
        ))
        # Surface the reason(s) for the non-DISCOVERABLE rows.
        if r["verdict"] != "DISCOVERABLE" and r["reasons"]:
            print(f"    -> {'; '.join(r['reasons'])}")

print()
if anomaly_flag:
    suffix = "" if include_inactive else " (active only)"
    print(f"[ANOMALY] {n_unreach} in-scope DApp"
          f"{'s' if n_unreach != 1 else ''} UNREACHABLE{suffix} — "
          f"client cannot discover and/or encrypt to them")
else:
    if n_degrade > 0:
        print(f"[OK] no UNREACHABLE DApps "
              f"({n_degrade} DEGRADED — soft endpoint findings, still usable)")
    else:
        print("[OK] every in-scope DApp is DISCOVERABLE")

sys.exit(exit_code)
PY
RC=$?
if [ "$RC" -ne 0 ] && [ "$RC" -ne 2 ]; then
  echo "operator_dapp_endpoint_audit: rendering failed" >&2
  exit 1
fi
exit $RC
