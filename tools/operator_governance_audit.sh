#!/usr/bin/env bash
# operator_governance_audit.sh — Audits the current governance POSTURE
# (state, not history) of a running determ daemon.
#
# State-focused complement to tools/operator_param_history.sh:
#   * operator_param_history.sh — chronological scan of every
#     PARAM_CHANGE tx that landed on-chain (historical activity log)
#   * operator_governance_audit.sh (this file) — current pending-change
#     state + governance config snapshot (now-state report)
#
# Composes:
#   * `determ head --field height --rpc-port P` -> current chain height
#   * `determ pending-params --json --rpc-port P` -> array of pending
#     PARAM_CHANGE entries: [{effective_height, name, value_hex,
#                             value_bytes}, ...]
#   * Optional: parse --genesis <file> directly off disk to extract
#     governance_mode + param_keyholders + param_threshold (none of
#     these are exposed via RPC today — verify-genesis --json omits
#     them, per src/main.cpp::cmd_verify_genesis)
#
# Per-pending classification:
#   blocks_until_activation = effective_height - current_head
#   soon   (<=100 blocks)       — operator must act / monitor closely
#   mid    (100 < n <= 1000)    — planned, scheduled
#   long   (>1000 blocks)       — far-future
#
# Anomaly flags:
#   conflicting_changes    — multiple pending entries share the same
#                            parameter name with DIFFERENT value_hex
#                            (operator must reconcile before the
#                            second one lands)
#   activation_cluster     — 3+ pending changes share a 10-block
#                            activation window (potential governance
#                            burst; coordinate apply order)
#
# Genesis governance fields are NOT exposed via the chain-id RPC. They
# live in the on-disk genesis.json and are mixed into compute_genesis_hash
# only when governance_mode != 0 (see src/chain/genesis.cpp). When the
# operator supplies --genesis, we parse those fields directly. Without
# --genesis, the audit still works against the running daemon (pending
# changes + timing classification + conflict detection) but can't report
# the keyholder set or threshold; --help documents this limitation.
#
# Decoding policy (matches activate_pending_params in src/chain/chain.cpp):
#   value_hex is decoded as u64 LE for entries with value_bytes == 8 AND
#   a recognized u64 parameter name (MIN_STAKE, SUSPENSION_SLASH,
#   UNSTAKE_DELAY, bft_escalation_threshold, param_threshold, tx_commit_ms,
#   block_sig_ms, abort_claim_ms, block_subsidy). Other names print
#   value_hex verbatim (truncated for readability in the human view).
#
# Args:
#   [--rpc-port N]      RPC port to query (default: 7778)
#   [--genesis <file>]  Path to the deployment's genesis.json on disk —
#                       enables reporting of governance_mode + N + M
#   [--json]            Emit single-line JSON envelope
#   [--anomalies-only]  Only print anomaly summary; in this mode exit 2
#                       if >=1 anomaly was detected
#   [-h|--help]         Show this help
#
# Exit codes:
#   0   success (no anomalies, or informational mode)
#   1   RPC error / daemon unreachable / pending-params not available /
#       malformed response / bad genesis file / bad args
#   2   --anomalies-only set AND >=1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_governance_audit.sh [--rpc-port N] [--genesis <file>]
                                    [--json] [--anomalies-only]

Audits the current A5 PARAM_CHANGE governance posture of a running
determ daemon — the now-state, not history. For the chronological
audit log, see operator_param_history.sh.

What it reports:
  * pending parameter changes (effective_height, name, decoded value,
    blocks-until-activation), classified by timing window:
      soon   <=100 blocks
      mid    100 < n <= 1000
      long   > 1000 blocks
  * with --genesis: governance_mode (uncontrolled vs governed) +
    keyholder set size N + threshold M (M-of-N multisig)
  * anomalies:
      conflicting_changes  multiple pending entries for the same
                           parameter name with different values
      activation_cluster   3+ changes activating within the same
                           10-block window

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --genesis <file>    Path to genesis.json on disk; without it the
                      script can't report N / M / governance_mode (they
                      are NOT exposed via RPC). Pending-change audit
                      still works.
  --json              Single-line JSON envelope instead of human report
  --anomalies-only    Suppress the per-change table; in this mode exit
                      2 if >=1 anomaly detected
  -h, --help          Show this help

Exit codes:
  0   success
  1   RPC error / pending-params unavailable / bad genesis / bad args
  2   --anomalies-only set AND >=1 anomaly detected

JSON shape (--json):
  {"mode":"uncontrolled"|"governed"|"unknown",
   "keyholders_n":  <N>|null,
   "threshold_m":   <M>|null,
   "current_height":<H>,
   "rpc_port":      <P>,
   "pending": [
     {"effective_height":<H>, "blocks_until":<n>, "name":"...",
      "value_hex":"...", "value_bytes":<b>, "decoded_value":"..."|null,
      "timing":"soon"|"mid"|"long"}, ...
   ],
   "by_timing":  {"soon":[...], "mid":[...], "long":[...]},
   "anomalies":  [{"kind":"conflicting_changes","name":"...",
                   "values":[...]},
                  {"kind":"activation_cluster",
                   "window_start":<H>,"window_end":<H>,
                   "entries":<n>}],
   "summary":    {"pending_count":<n>, "soon_count":<n>,
                  "mid_count":<n>,    "long_count":<n>,
                  "anomaly_count":<n>}}
EOF
}

PORT=7778
GENESIS=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="$2";    shift 2 ;;
    --genesis)        GENESIS="$2"; shift 2 ;;
    --json)           JSON_OUT=1;   shift ;;
    --anomalies-only) ANOM_ONLY=1;  shift ;;
    *) echo "operator_governance_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guard on the port.
case "$PORT" in
  *[!0-9]*|"")
    echo "operator_governance_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
    exit 1 ;;
esac

# Optional genesis-file existence + readability checks. Done up-front
# so the diagnostic mentions the operator-supplied path before any
# subprocess fires.
if [ -n "$GENESIS" ]; then
  if [ ! -f "$GENESIS" ]; then
    echo "operator_governance_audit: --genesis file not found: $GENESIS" >&2
    exit 1
  fi
  if [ ! -r "$GENESIS" ]; then
    echo "operator_governance_audit: --genesis file not readable: $GENESIS" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: current chain head height ────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_governance_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_governance_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: pending-params via RPC ───────────────────────────────────────────
# pending-params has shipped (round 3); operator_param_history.sh
# already depends on it via --include-pending. If it's missing on a
# very old daemon, the call returns non-zero and we surface that with
# a clear diagnostic.
TMP_PENDING=$(mktemp 2>/dev/null) || {
  echo "operator_governance_audit: cannot create temp file" >&2
  exit 1
}
trap 'rm -f "$TMP_PENDING"' EXIT

"$DETERM" pending-params --json --rpc-port "$PORT" >"$TMP_PENDING" 2>/dev/null || {
  echo "operator_governance_audit: pending-params RPC failed (port $PORT)" >&2
  echo "  (requires a daemon that exposes the pending_params RPC method;" >&2
  echo "   shipped in v1.x rev 3+ — upgrade if your daemon predates that)" >&2
  exit 1
}

# ── Step 3: aggregate + classify + format ─────────────────────────────────────
# Drive in Python so we get one parse pass for human + JSON output, can
# decode known u64-LE parameter names, and can compute anomaly groups
# (same-name-different-value + 10-block activation clusters) without
# the bash-array gymnastics that would make the script unreadable.
python - "$JSON_OUT" "$ANOM_ONLY" "$HEAD_H" "$PORT" "$TMP_PENDING" "$GENESIS" <<'PY'
import json, sys, os

json_out      = sys.argv[1] == "1"
anom_only     = sys.argv[2] == "1"
head_h        = int(sys.argv[3])
port          = int(sys.argv[4])
pending_path  = sys.argv[5]
genesis_path  = sys.argv[6]

# ── Load pending-params RPC array. ────────────────────────────────────────
try:
    with open(pending_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
except Exception as e:
    sys.stderr.write(f"operator_governance_audit: cannot parse pending-params JSON: {e}\n")
    sys.exit(1)
if not isinstance(raw, list):
    sys.stderr.write("operator_governance_audit: pending-params RPC did not return a JSON array\n")
    sys.exit(1)

# ── Parse genesis-on-disk for governance fields (best-effort). ───────────
# verify-genesis --json does NOT include governance_mode / param_keyholders /
# param_threshold (see cmd_verify_genesis in src/main.cpp); we parse the
# genesis file ourselves. Bad JSON / missing keys are FATAL when --genesis
# was supplied, since the operator explicitly asked for that view.
gov_mode  = "unknown"
N_holders = None
M_thresh  = None
if genesis_path:
    try:
        with open(genesis_path, "r", encoding="utf-8") as f:
            gen = json.load(f)
    except Exception as e:
        sys.stderr.write(f"operator_governance_audit: cannot parse --genesis {genesis_path}: {e}\n")
        sys.exit(1)
    if not isinstance(gen, dict):
        sys.stderr.write(f"operator_governance_audit: --genesis root is not a JSON object: {genesis_path}\n")
        sys.exit(1)
    gm = gen.get("governance_mode", 0)
    if isinstance(gm, bool):
        gm = 1 if gm else 0
    if not isinstance(gm, int) or gm not in (0, 1):
        sys.stderr.write(f"operator_governance_audit: --genesis governance_mode must be 0|1 (got {gm!r})\n")
        sys.exit(1)
    gov_mode = "governed" if gm == 1 else "uncontrolled"
    khs = gen.get("param_keyholders", [])
    if not isinstance(khs, list):
        sys.stderr.write("operator_governance_audit: --genesis param_keyholders must be an array\n")
        sys.exit(1)
    N_holders = len(khs)
    M_thresh  = int(gen.get("param_threshold", 0) or 0)
    # In governed mode with absent/zero threshold, src/chain/genesis.cpp
    # defaults to N-of-N — mirror that semantics here.
    if gov_mode == "governed" and M_thresh == 0:
        M_thresh = N_holders

# ── Known u64-LE parameter names (decoding hint set). ─────────────────────
# Anything else stays opaque (value_hex truncated for display). The full
# list comes from src/chain/chain.cpp::activate_pending_params + the
# Node-side hook in src/node/node.cpp + the validator timing knobs.
U64_NAMES = {
    "MIN_STAKE", "SUSPENSION_SLASH", "UNSTAKE_DELAY",
    "bft_escalation_threshold", "param_threshold",
    "tx_commit_ms", "block_sig_ms", "abort_claim_ms",
    "block_subsidy",
}

def decode_value(name, hex_str, n_bytes):
    """Return decoded human form or None if unknown / not u64-shaped."""
    if name in U64_NAMES and n_bytes == 8:
        try:
            b = bytes.fromhex(hex_str)
            if len(b) == 8:
                return str(int.from_bytes(b, "little"))
        except Exception:
            return None
    return None

# ── Build per-entry records. ──────────────────────────────────────────────
pending = []
for e in raw:
    if not isinstance(e, dict):
        continue
    try:
        eff   = int(e.get("effective_height", 0))
        name  = str(e.get("name", ""))
        vhex  = str(e.get("value_hex", ""))
        vbytes = int(e.get("value_bytes", 0))
    except Exception:
        sys.stderr.write("operator_governance_audit: malformed pending entry, skipping\n")
        continue
    bu = eff - head_h
    if bu <= 100:
        timing = "soon"
    elif bu <= 1000:
        timing = "mid"
    else:
        timing = "long"
    pending.append({
        "effective_height": eff,
        "blocks_until":     bu,
        "name":             name,
        "value_hex":        vhex,
        "value_bytes":      vbytes,
        "decoded_value":    decode_value(name, vhex, vbytes),
        "timing":           timing,
    })

# Stable sort: by effective_height asc, then name asc (deterministic
# output across runs; RPC insertion order is documented but pairing
# blocks of changes at the same effective_height by name aids
# readability).
pending.sort(key=lambda p: (p["effective_height"], p["name"]))

by_timing = {"soon": [], "mid": [], "long": []}
for p in pending:
    by_timing[p["timing"]].append(p)

# ── Anomaly detection. ────────────────────────────────────────────────────
anomalies = []

# (1) Conflicting changes: same name, different value_hex across pending
# entries. (Same name + same value across multiple effective_heights is
# not a conflict — it's just deduplication-worthy.)
by_name_vals = {}
for p in pending:
    by_name_vals.setdefault(p["name"], []).append(
        (p["effective_height"], p["value_hex"], p["decoded_value"]))
for name, lst in by_name_vals.items():
    distinct_vals = {v for (_h, v, _d) in lst}
    if len(distinct_vals) > 1:
        # Materialize value descriptors (decoded where possible) for
        # operator readability.
        val_descs = []
        seen = set()
        for h, vhex, dv in lst:
            if vhex in seen:
                continue
            seen.add(vhex)
            val_descs.append({
                "value_hex":     vhex,
                "decoded_value": dv,
                "effective_height": h,
            })
        anomalies.append({
            "kind":   "conflicting_changes",
            "name":   name,
            "values": val_descs,
        })

# (2) Activation cluster: any 10-block window containing >=3 distinct
# pending entries. Walk the sorted effective_heights and find clusters.
heights = [p["effective_height"] for p in pending]
if len(heights) >= 3:
    i = 0
    n = len(heights)
    while i < n:
        # Greedy window: how many entries fit in [heights[i], heights[i]+9]?
        j = i
        while j < n and heights[j] - heights[i] <= 9:
            j += 1
        count = j - i
        if count >= 3:
            anomalies.append({
                "kind":         "activation_cluster",
                "window_start": heights[i],
                "window_end":   heights[j - 1],
                "entries":      count,
            })
            # Skip past this window so we don't double-report overlapping
            # clusters; advance to the entry past the window end.
            i = j
        else:
            i += 1

# ── Summary. ──────────────────────────────────────────────────────────────
summary = {
    "pending_count": len(pending),
    "soon_count":    len(by_timing["soon"]),
    "mid_count":     len(by_timing["mid"]),
    "long_count":    len(by_timing["long"]),
    "anomaly_count": len(anomalies),
}

# ── Emit. ─────────────────────────────────────────────────────────────────
exit_code = 2 if (anom_only and summary["anomaly_count"] > 0) else 0

if json_out:
    envelope = {
        "mode":           gov_mode,
        "keyholders_n":   N_holders,
        "threshold_m":    M_thresh,
        "current_height": head_h,
        "rpc_port":       port,
        "pending":        pending,
        "by_timing":      by_timing,
        "anomalies":      anomalies,
        "summary":        summary,
    }
    print(json.dumps(envelope))
    sys.exit(exit_code)

# Human-readable report.
print(f"=== Governance audit (port {port}, height {head_h}) ===")
if genesis_path:
    print(f"Governance mode: {gov_mode}")
    if gov_mode == "governed":
        print(f"Keyholders: {N_holders} (threshold M={M_thresh} of N={N_holders})")
    elif gov_mode == "uncontrolled":
        print("Keyholders: n/a (uncontrolled mode — no PARAM_CHANGE accepted)")
else:
    print("Governance mode: unknown (pass --genesis <file> to report mode/N/M)")

print(f"Pending parameter changes: {summary['pending_count']}")

def fmt_change(p):
    """One-line per-entry render for the human view."""
    if p["decoded_value"] is not None:
        val = p["decoded_value"]
    else:
        # Long hex — truncate for readability.
        v = p["value_hex"]
        val = v if len(v) <= 32 else v[:32] + "..."
    return (f"- {p['name']}: {val} -> activates at {p['effective_height']} "
            f"({p['blocks_until']} blocks)")

if not anom_only:
    if summary["pending_count"] == 0:
        print("(no pending parameter changes)")
    else:
        print("By timing:")
        for bucket_key, bucket_label in (
                ("soon", "Soon (<=100 blocks):     "),
                ("mid",  "Mid-term (100-1000):    "),
                ("long", "Long-term (>1000):      ")):
            entries = by_timing[bucket_key]
            cnt = len(entries)
            noun = "change" if cnt == 1 else "changes"
            print(f"  {bucket_label}{cnt} {noun}")
            for p in entries:
                print(f"    {fmt_change(p)}")

# Anomaly section (printed in both modes; in --anomalies-only this is
# the only per-entry detail surfaced).
if not anomalies:
    print("[OK] No conflicting pending changes")
    print("[OK] No activation cluster")
else:
    for a in anomalies:
        if a["kind"] == "conflicting_changes":
            print(f"[ANOMALY] conflicting_changes: parameter '{a['name']}' "
                  f"has {len(a['values'])} distinct pending values:")
            for v in a["values"]:
                if v["decoded_value"] is not None:
                    val = v["decoded_value"]
                else:
                    vh = v["value_hex"]
                    val = vh if len(vh) <= 32 else vh[:32] + "..."
                print(f"    - {val} (activates at {v['effective_height']})")
        elif a["kind"] == "activation_cluster":
            print(f"[ANOMALY] activation_cluster: {a['entries']} changes "
                  f"in window [{a['window_start']}..{a['window_end']}] "
                  f"(10-block governance burst)")

sys.exit(exit_code)
PY
PY_RC=$?
# Python emits the final exit code (0, 2, or 1 on its own internal
# error). Forward verbatim so --anomalies-only's exit-2 gate survives.
exit "$PY_RC"
