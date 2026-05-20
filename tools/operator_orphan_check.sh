#!/usr/bin/env bash
# operator_orphan_check.sh — Audit chain state for orphaned references
# (anomalies where the three top-level state maps — accounts_, stakes_,
# and registrants_ — reference each other inconsistently).
#
# By construction the v1 apply pipeline keeps these three maps coupled
# tightly (V2 gate requires REGISTER before STAKE; UNSTAKE refund cascades
# via the chain code), but operators benefit from a defensive audit that
# would catch any drift introduced by:
#   - a future apply-rule change that desyncs the maps
#   - operators forgetting to call UNSTAKE after DEREGISTER + unstake_delay
#   - a corrupt or hand-edited chain.json
#   - tooling that hits the persistence layer directly
#
# All inspection is read-only via existing RPCs:
#   - `determ head --json`              — current chain height
#   - `determ snapshot create --out F`  — one-shot dump of accounts_,
#                                          stakes_, registrants_ in
#                                          internally-consistent form
#                                          (single shared_ptr load on
#                                          the daemon side)
#   - `determ snapshot inspect --in F --json` — sanity-check the dump
#                                          (round-trips through
#                                          restore_from_snapshot; S-033
#                                          + S-038 state-root gates)
#
# We snapshot rather than walking the chain because the snapshot RPC
# already gives us the full state in one O(1)-locking call; cross-
# referencing the three maps via per-domain RPCs would be O(N) round
# trips and could race the apply loop. The snapshot is taken at a single
# point in time so the cross-references are guaranteed to be coherent.
#
# Orphan patterns detected:
#   stake_without_registrant
#     domain D has stakes[D].locked > 0 but no registrants[D] entry.
#     SHOULD NEVER OCCUR by construction (REGISTER must precede STAKE
#     per V2 gate). Defensive check — fires => critical state drift.
#
#   registrant_without_stake_or_balance
#     domain D has registrants[D] but accounts[D].balance == 0 AND
#     no stakes[D] entry (or stakes[D].locked == 0). Informational:
#     usual cause is a freshly-REGISTER'd domain that hasn't yet
#     received its NEF/operator-funding STAKE, or a DEREGISTER'd one
#     whose stake refund landed and operator hasn't yet swept the
#     account.
#
#   deregistered_with_locked_stake
#     registrants[D].inactive_from != UINT64_MAX AND
#     registrants[D].inactive_from < current_height AND
#     stakes[D].locked > 0 AND stakes[D].unlock_height > current_height.
#     The DEREGISTER window between deregister and stake unlock — fully
#     normal during the unstake_delay countdown. Informational.
#
#   deregistered_past_unlock_height
#     registrants[D].inactive_from < current_height AND
#     stakes[D].unlock_height <= current_height (finite) AND
#     stakes[D].locked > 0. Operator forgot to call UNSTAKE; locked
#     funds are reclaimable but not yet reclaimed. CRITICAL — flag
#     for operator action.
#
#   account_with_zero_everything
#     accounts[D] entry exists with balance == 0 AND next_nonce == 0
#     AND no stakes[D] AND no registrants[D]. Most likely cause is
#     auto-creation from a zero-amount TRANSFER receipt that left a
#     residual entry. Informational (no harm — accounts map is monotone
#     in v1 so the entry simply lives on).
#
# Args:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human output
#   --anomalies-only    Suppress informational output; only list anomalies.
#                       Exit 2 if any CRITICAL orphan fired.
#   -h, --help          Show this help
#
# Exit codes:
#   0   audit ran successfully (or no CRITICAL orphans in --anomalies-only)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND at least one CRITICAL orphan fired
#       (deregistered_past_unlock_height, stake_without_registrant)
set -u

usage() {
  cat <<'EOF'
Usage: operator_orphan_check.sh [--rpc-port N] [--json] [--anomalies-only]

Audit chain state for orphaned cross-references between the accounts_,
stakes_, and registrants_ maps. Pulls a one-shot snapshot from a running
determ daemon (read-only), so the three maps are guaranteed coherent at
the moment of audit.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human output
  --anomalies-only    Suppress informational output; print only anomalies.
                      Exit 2 if any CRITICAL orphan fired.
  -h, --help          Show this help

Orphan patterns:
  stake_without_registrant            (CRITICAL — exit 2)
  registrant_without_stake_or_balance (informational)
  deregistered_with_locked_stake      (informational — normal in unstake_delay)
  deregistered_past_unlock_height     (CRITICAL — operator forgot UNSTAKE)
  account_with_zero_everything        (informational — auto-creation residue)

Exit codes:
  0   success (or --anomalies-only with no CRITICAL orphans)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >=1 CRITICAL orphan fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="$2";   shift 2 ;;
    --json)            JSON_OUT=1;  shift ;;
    --anomalies-only)  ANOM_ONLY=1; shift ;;
    *) echo "operator_orphan_check: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

case "$PORT" in *[!0-9]*|"")
  echo "operator_orphan_check: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# UINT64_MAX literal — the sentinel for "registrant is still active"
# (never deregistered). Stake refund path uses the same sentinel for
# "stake not unstaked".
UINT64_MAX=18446744073709551615

# ── Step 1: chain head ───────────────────────────────────────────────────────
HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_orphan_check: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
CURRENT_HEIGHT=$(python - "$HEAD_OUT" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print(""); sys.exit(0)
if not isinstance(d, dict):
    print(""); sys.exit(0)
print(d.get("height", ""))
PY
)
case "$CURRENT_HEIGHT" in *[!0-9]*|"")
  echo "operator_orphan_check: malformed head JSON (height not numeric: '$CURRENT_HEIGHT')" >&2
  exit 1 ;;
esac

# ── Step 2: snapshot dump ────────────────────────────────────────────────────
# Capture all three state maps in one coherent dump. Per the snapshot
# RPC contract, accounts/stakes/registrants are serialized from a single
# shared_ptr load, so their cross-references are guaranteed coherent at
# the snapshot height (which may be slightly behind CURRENT_HEIGHT if a
# block applied between the two RPCs; that's harmless for orphan
# detection since both maps would see the same delta).
TMP_SNAP=$(mktemp --suffix=.json 2>/dev/null || mktemp 2>/dev/null) || {
  echo "operator_orphan_check: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_SNAP"' EXIT

if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
  echo "operator_orphan_check: snapshot create failed (port $PORT)" >&2
  exit 1
fi

# ── Step 3: cross-reference analysis (Python driver) ─────────────────────────
# Python is the right tool here — we need set arithmetic across three
# associative arrays plus per-key conditional logic. Building this in
# pure bash would mean re-implementing assoc-array set ops via sorted-
# file comm/join chains, which is fragile with arbitrary domain strings.
# Python is also already a required dependency upstream (snapshot stats).
TMP_RESULT=$(mktemp 2>/dev/null) || {
  echo "operator_orphan_check: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_SNAP" "$TMP_RESULT"' EXIT

python - "$TMP_SNAP" "$CURRENT_HEIGHT" "$TMP_RESULT" <<'PY'
import json, sys

snap_path, current_height_s, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
current_height = int(current_height_s)
UINT64_MAX = (1 << 64) - 1

with open(snap_path, "r", encoding="utf-8") as f:
    snap = json.load(f)

# Build three lookup dicts. Snapshot serializes each as an array of
# objects keyed by "domain"; rebuild as map keyed by domain string.
accounts    = {}  # domain -> {balance, next_nonce}
stakes      = {}  # domain -> {locked, unlock_height}
registrants = {}  # domain -> {ed_pub, registered_at, active_from, inactive_from, region}

for a in snap.get("accounts", []) or []:
    if not isinstance(a, dict): continue
    d = a.get("domain")
    if isinstance(d, str) and d:
        accounts[d] = {
            "balance":    int(a.get("balance", 0)),
            "next_nonce": int(a.get("next_nonce", 0)),
        }
for s in snap.get("stakes", []) or []:
    if not isinstance(s, dict): continue
    d = s.get("domain")
    if isinstance(d, str) and d:
        stakes[d] = {
            "locked":        int(s.get("locked", 0)),
            "unlock_height": int(s.get("unlock_height", UINT64_MAX)),
        }
for r in snap.get("registrants", []) or []:
    if not isinstance(r, dict): continue
    d = r.get("domain")
    if isinstance(d, str) and d:
        registrants[d] = {
            "active_from":   int(r.get("active_from",   0)),
            "inactive_from": int(r.get("inactive_from", UINT64_MAX)),
        }

# Anomaly collection. Each entry is a dict {type, domain, detail}.
anomalies = []

# Pattern 1: stake_without_registrant (CRITICAL)
#   stakes[D].locked > 0 AND D not in registrants
for d, s in stakes.items():
    if s["locked"] > 0 and d not in registrants:
        anomalies.append({
            "type":     "stake_without_registrant",
            "domain":   d,
            "severity": "critical",
            "detail":   f"stake_locked={s['locked']} unlock_height={s['unlock_height']} but no registrants[{d}]",
        })

# Pattern 2: registrant_without_stake_or_balance (informational)
#   D in registrants but accounts[D].balance == 0 (or absent) AND
#   stakes[D].locked == 0 (or absent)
for d, r in registrants.items():
    bal = accounts.get(d, {}).get("balance", 0)
    locked = stakes.get(d, {}).get("locked", 0)
    if bal == 0 and locked == 0:
        anomalies.append({
            "type":     "registrant_without_stake_or_balance",
            "domain":   d,
            "severity": "info",
            "detail":   f"active_from={r['active_from']} inactive_from={r['inactive_from']} bal=0 locked=0",
        })

# Patterns 3 + 4: classify each DEREGISTER'd domain by whether its stake
# is still inside the unstake_delay window or has aged past it.
#   inactive_from != UINT64_MAX AND inactive_from < current_height
#   AND stakes[D].locked > 0
for d, r in registrants.items():
    inf = r["inactive_from"]
    if inf == UINT64_MAX or inf >= current_height:
        continue  # still active, or deregister hasn't taken effect yet
    s = stakes.get(d)
    if s is None or s["locked"] == 0:
        continue  # nothing locked; no orphan
    uh = s["unlock_height"]
    # Pattern 4: deregistered_past_unlock_height (CRITICAL)
    if uh != UINT64_MAX and uh <= current_height:
        anomalies.append({
            "type":     "deregistered_past_unlock_height",
            "domain":   d,
            "severity": "critical",
            "detail":   f"inactive_from={inf} unlock_height={uh} locked={s['locked']} — operator must call UNSTAKE",
        })
    else:
        # Pattern 3: deregistered_with_locked_stake (informational —
        # normal during the unstake_delay countdown).
        anomalies.append({
            "type":     "deregistered_with_locked_stake",
            "domain":   d,
            "severity": "info",
            "detail":   f"inactive_from={inf} unlock_height={uh} locked={s['locked']} (within unstake_delay window)",
        })

# Pattern 5: account_with_zero_everything (informational)
#   accounts[D] exists, balance == 0, next_nonce == 0, D not in stakes,
#   D not in registrants. Likely auto-creation residue from a zero-
#   amount TRANSFER receipt.
for d, a in accounts.items():
    if a["balance"] != 0 or a["next_nonce"] != 0:
        continue
    if d in stakes:
        continue
    if d in registrants:
        continue
    anomalies.append({
        "type":     "account_with_zero_everything",
        "domain":   d,
        "severity": "info",
        "detail":   "balance=0 next_nonce=0 no stakes no registrants (likely auto-creation residue)",
    })

# Per-type counts for the summary footer.
counts = {
    "stake_without_registrant":            0,
    "registrant_without_stake_or_balance": 0,
    "deregistered_with_locked_stake":      0,
    "deregistered_past_unlock_height":     0,
    "account_with_zero_everything":        0,
}
critical_count = 0
for a in anomalies:
    counts[a["type"]] = counts.get(a["type"], 0) + 1
    if a["severity"] == "critical":
        critical_count += 1

result = {
    "height":           current_height,
    "audited": {
        "accounts":     len(accounts),
        "stakes":       len(stakes),
        "registrants":  len(registrants),
    },
    "anomalies":        anomalies,
    "anomaly_counts":   counts,
    "critical_count":   critical_count,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_orphan_check: cross-reference analysis failed" >&2
  exit 1
fi

# ── Step 4: render output ────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Emit the Python-built result with rpc_port spliced in.
  python - "$TMP_RESULT" "$PORT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
r["rpc_port"] = int(sys.argv[2])
sys.stdout.write(json.dumps(r) + "\n")
PY
else
  # Human output. Print the audit header, per-type anomaly counts, then
  # in default mode list the offending domains under each non-zero count.
  python - "$TMP_RESULT" "$PORT" "$ANOM_ONLY" <<'PY'
import json, sys
from collections import defaultdict
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
port = sys.argv[2]
anom_only = sys.argv[3] == "1"
height       = r["height"]
audited      = r["audited"]
counts       = r["anomaly_counts"]
anomalies    = r["anomalies"]
crit         = r["critical_count"]

# Group anomalies by type for per-type printing.
by_type = defaultdict(list)
for a in anomalies:
    by_type[a["type"]].append(a)

print(f"=== Orphan reference check (port {port}, height {height}) ===")
print(f"Stakes audited:        {audited['stakes']}")
print(f"Registrants audited:   {audited['registrants']}")
print(f"Accounts audited:      {audited['accounts']}")
print("Anomaly counts:")

# Render order mirrors the spec: criticals first by descending severity-
# impact, then informationals. Annotated with severity hint to help
# operators triage at a glance.
order = [
    ("stake_without_registrant",            "critical"),
    ("registrant_without_stake_or_balance", "info"),
    ("deregistered_with_locked_stake",      "info"),
    ("deregistered_past_unlock_height",     "critical"),
    ("account_with_zero_everything",        "info"),
]
for typ, sev in order:
    n = counts.get(typ, 0)
    label = f"  {typ}:"
    # Compact-list mode: print first few domains inline when non-zero.
    extra = ""
    if n > 0:
        doms = [a["domain"] for a in by_type[typ]]
        if typ == "deregistered_with_locked_stake":
            extra = f" ({n} within unstake_delay — normal)"
        elif typ == "account_with_zero_everything":
            extra = f" (auto-creation residue)"
        else:
            head_doms = doms[:5]
            sample = ", ".join(head_doms)
            if len(doms) > 5:
                sample += f", ... +{len(doms) - 5} more"
            extra = f" ({sample})"
    # Align the count column at width 30 for readability.
    pad = max(2, 38 - len(label))
    print(f"{label}{' ' * pad}{n}{extra}")

# In default mode, after the count summary list every offending domain
# under its bucket. --anomalies-only mode skips zero-count buckets but
# still lists the offending domains; both modes always include any
# critical-severity detail rows.
def print_bucket(typ, sev_label):
    if anom_only and counts.get(typ, 0) == 0:
        return
    entries = by_type.get(typ, [])
    if not entries:
        return
    print()
    print(f"  [{sev_label}] {typ} ({len(entries)}):")
    for a in entries:
        print(f"    {a['domain']}: {a['detail']}")

if not anom_only or crit > 0 or any(counts.values()):
    # In default mode emit detail rows for every type with at least one
    # entry. In --anomalies-only mode emit only when something fired,
    # but skip the per-bucket details when no anomalies were found.
    for typ, sev in order:
        sev_label = "CRITICAL" if sev == "critical" else "INFO"
        print_bucket(typ, sev_label)

print()
if crit == 0:
    print("[OK] No critical orphans")
else:
    print(f"[CRITICAL] {crit} critical orphan(s) detected")
PY
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
# Per spec: exit 2 ONLY in --anomalies-only mode AND a CRITICAL orphan
# fired (deregistered_past_unlock_height, stake_without_registrant).
# Informational anomalies do NOT trip the alert gate — they're expected
# during normal validator-lifecycle flows (e.g. the unstake_delay
# window). Default mode is informational and always exits 0 on a
# successful audit.
CRIT_COUNT=$(python - "$TMP_RESULT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    r = json.load(f)
print(r.get("critical_count", 0))
PY
)
case "$CRIT_COUNT" in *[!0-9]*|"") CRIT_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$CRIT_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
