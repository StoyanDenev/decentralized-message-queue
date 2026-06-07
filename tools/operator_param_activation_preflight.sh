#!/usr/bin/env bash
# operator_param_activation_preflight.sh — Read-only ACTIVATION-CONFORMANCE
# pre-flight for STAGED A5 governance PARAM_CHANGEs. For every change the
# daemon currently reports as pending, it predicts whether the change will
# actually TAKE EFFECT when its effective_height arrives — or be silently
# INERT — by classifying it against the authoritative validator whitelist
# (src/node/validator.cpp::kWhitelist) AND the activation semantics in
# src/chain/chain.cpp::activate_pending_params.
#
# THE OPERATOR QUESTION
#   "Of the parameter changes I have STAGED, which ones will mutate the
#    consensus scalar I intended when they activate, and which are
#    mis-staged so that activation will SILENTLY NO-OP?"
#
#   This is a pre-activation safety check. A keyholder multisig can stage a
#   PARAM_CHANGE that the validator accepts (whitelisted name, valid sigs,
#   well-formed payload) yet which DOES NOTHING at activation — because the
#   value width is wrong for a numeric scalar. The operator only finds out
#   after the activation height passes and the parameter didn't move. This
#   tool catches that BEFORE the window.
#
# WHY THE GAP IS REAL (activation drops mis-typed values on the floor)
#   src/chain/chain.cpp::activate_pending_params decodes numeric scalars via
#   a parse_u64 lambda that REQUIRES exactly 8 bytes:
#       auto parse_u64 = [&](uint64_t& dst) {
#           if (value.size() != 8) return false;   // <-- silent reject
#           ...
#       };
#       if (name == "MIN_STAKE")            { parse_u64(min_stake_); }
#       else if (name == "SUSPENSION_SLASH") { parse_u64(suspension_slash_); }
#       else if (name == "UNSTAKE_DELAY")    { parse_u64(unstake_delay_); }
#   The validator (src/node/validator.cpp, TxType::PARAM_CHANGE) checks the
#   NAME against kWhitelist but does NOT check the value WIDTH. So a
#   MIN_STAKE staged with a 4-byte value passes validation, lands on-chain,
#   surfaces in pending_params — and at activation parse_u64 returns false,
#   min_stake_ is never written, and the change is inert. The hook still
#   fires with the wrong-width value, but the per-Chain scalar that governs
#   consensus stays put. No existing tool flags this.
#
# CLASSIFICATION (predicts the activation outcome for each staged entry)
#   EFFECTIVE        Chain-scalar name (MIN_STAKE / SUSPENSION_SLASH /
#                    UNSTAKE_DELAY) with value_bytes == 8. parse_u64 will
#                    succeed; the scalar updates and is committed to the
#                    k: state_root namespace.
#   INERT_BAD_WIDTH  Chain-scalar name but value_bytes != 8. parse_u64 will
#                    return false; the scalar is NEVER updated — a silent
#                    no-op. ANOMALY (this is the trap the tool exists for).
#   HOOK_ONLY        Whitelisted hook-forwarded name (bft_escalation_threshold
#                    / param_keyholders / param_threshold / tx_commit_ms /
#                    block_sig_ms / abort_claim_ms). activate_pending_params
#                    forwards these to the Node hook; they have NO per-Chain
#                    scalar (the timing fields remain params.hpp constants),
#                    so there is no k: state-root commitment of their
#                    effective value. Informational, not an anomaly.
#   UNKNOWN_NAME     Name NOT on the validator whitelist. The validator
#                    rejects such a tx, so a staged entry with this name is a
#                    node/state divergence and must not exist. ANOMALY.
#
#   Orthogonal annotation (can co-occur with any class):
#   OVERDUE          effective_height <= current head. The change will
#                    activate on the very next applied block (its activation
#                    window is already reached/passed). Surfaced as a flag,
#                    not a separate class; an EFFECTIVE+OVERDUE change is
#                    fine — an INERT_BAD_WIDTH+OVERDUE change will silently
#                    no-op imminently.
#
# SCOPE CONTRAST WITH THE NEIGHBOURING GOVERNANCE TOOLS (keep lanes distinct)
#   operator_param_change_watch.sh         counts blocks_until_active for the
#                                          staged set (timing only; never asks
#                                          whether the change will WORK).
#   operator_pending_param_proof_audit.sh  proves each staged entry is in the
#                                          p: state tree (Merkle provability of
#                                          the ENCODING; never the semantic
#                                          activation outcome).
#   operator_effective_param_audit.sh      proves the CURRENTLY-EFFECTIVE k:
#                                          scalar (the other end of the
#                                          lifecycle — already activated).
#   operator_governance_audit.sh           pending posture + conflict/cluster
#                                          detection (no per-entry effective-
#                                          ness prediction).
#   operator_param_history.sh /            past PARAM_CHANGE audit logs.
#   operator_param_change_history.sh
#
#   operator_param_activation_preflight.sh (THIS) is the only tool that
#   predicts, per staged entry, whether activation will MUTATE THE INTENDED
#   SCALAR or silently no-op. It reads only pending_params + head; no block
#   scan, no state-proof fan-out.
#
# RPC dependencies (all read-only):
#   - head           (current chain height; via `determ head --field height`)
#   - pending_params (staged-change list; `determ pending-params --json`)
#
# Usage:
#   tools/operator_param_activation_preflight.sh [--rpc-port N] [--json]
#                                                [--anomalies-only]
#
# Options:
#   --rpc-port N      RPC port to query (default: 7778)
#   --json            Emit a structured JSON envelope instead of a table
#   --anomalies-only  Print only mis-staged (anomalous) entries; in this
#                     mode exit 2 if >=1 anomaly fired (operator alert gate)
#   -h, --help        Show this help
#
# Exit codes:
#   0   success / informational (no staged changes also exits 0; an
#       unreachable daemon prints an INFO+SKIP line and exits 0)
#   1   bad args / malformed pending_params response
#   2   --anomalies-only AND >=1 anomaly fired (INERT_BAD_WIDTH or
#       UNKNOWN_NAME present)
set -u

usage() {
  cat <<'EOF'
Usage: operator_param_activation_preflight.sh [--rpc-port N] [--json]
                                              [--anomalies-only]

Read-only ACTIVATION-CONFORMANCE pre-flight for STAGED A5 PARAM_CHANGEs.
For each change the daemon reports as pending, predicts whether it will
take effect when its effective_height arrives, by classifying it against
the validator whitelist + chain.cpp::activate_pending_params semantics:

  EFFECTIVE        chain-scalar name (MIN_STAKE / SUSPENSION_SLASH /
                   UNSTAKE_DELAY) with value_bytes == 8 — scalar updates
  INERT_BAD_WIDTH  chain-scalar name but value_bytes != 8 — parse_u64
                   rejects it; scalar silently never updated  (ANOMALY)
  HOOK_ONLY        whitelisted hook-forwarded name (no per-Chain scalar;
                   timing fields stay params.hpp constants)  (info)
  UNKNOWN_NAME     name not on the validator whitelist — should not be
                   staged at all; a node/state divergence  (ANOMALY)

OVERDUE (flag, can co-occur): effective_height <= head — activates on the
next applied block.

Reads only head + pending_params. No block scan, no state-proof fan-out.

Options:
  --rpc-port N      RPC port to query (default: 7778)
  --json            Emit a structured JSON envelope instead of a table
  --anomalies-only  Print only mis-staged entries; exit 2 if any fired
  -h, --help        Show this help

Exit codes:
  0   success / informational (no staged changes; daemon unreachable -> SKIP)
  1   bad args / malformed pending_params response
  2   --anomalies-only AND >=1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";  shift 2 ;;
    --json)           JSON_OUT=1;     shift ;;
    --anomalies-only) ANOM_ONLY=1;    shift ;;
    *) echo "operator_param_activation_preflight: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guard on the port.
case "$PORT" in *[!0-9]*|"")
  echo "operator_param_activation_preflight: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Resolve current head height. `determ head --field height` returns a bare
# integer on stdout. An unreachable daemon is treated as INFO+SKIP (exit 0):
# this is a pre-flight aid, not a liveness probe, so a down daemon is not an
# error condition for the operator running it ad hoc.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"skipped":true,"reason":"daemon_unreachable","rpc_port":%s}\n' "$PORT"
  else
    echo "INFO: cannot reach daemon on rpc-port $PORT — SKIP (nothing to pre-flight)"
  fi
  exit 0
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_param_activation_preflight: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Pull the staged-change list. Empty list (governance disabled or nothing
# staged) is success, not an error.
PENDING_JSON=$("$DETERM" pending-params --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_param_activation_preflight: pending-params RPC failed (port $PORT)" >&2
  exit 1
}
[ -z "$PENDING_JSON" ] && PENDING_JSON="[]"

# Classify each staged entry in Python (no jq dependency — mirrors the
# python-heredoc parser convention of the sibling governance tools). The
# whitelist + width rules below are transcribed directly from:
#   src/node/validator.cpp::kWhitelist          (the 9 admitted names)
#   src/chain/chain.cpp::activate_pending_params (parse_u64 width==8 +
#                                                 which names own a scalar)
python - "$PENDING_JSON" "$HEAD_H" "$JSON_OUT" "$ANOM_ONLY" "$PORT" <<'PY' || exit 1
import json, sys

pending_raw, head_s, json_out_s, anom_only_s, port_s = sys.argv[1:6]
head      = int(head_s)
json_out  = (json_out_s == "1")
anom_only = (anom_only_s == "1")
port      = int(port_s)

def die(msg):
    sys.stderr.write(f"operator_param_activation_preflight: {msg}\n")
    sys.exit(1)

try:
    entries = json.loads(pending_raw)
except Exception as e:
    die(f"malformed pending-params JSON ({e}) (port {port})")
if not isinstance(entries, list):
    die(f"pending-params did not return a JSON array (port {port})")

# Names whose activation writes a per-Chain numeric scalar via parse_u64
# (value MUST be exactly 8 bytes / u64 LE, else parse_u64 returns false and
# the scalar is never updated). Source: chain.cpp::activate_pending_params.
CHAIN_SCALAR_NAMES = {"MIN_STAKE", "SUSPENSION_SLASH", "UNSTAKE_DELAY"}

# Whitelisted names that activation only forwards to the Node hook — no
# per-Chain scalar; the timing fields remain params.hpp constants. Source:
# validator.cpp::kWhitelist minus the chain-scalar names above.
HOOK_NAMES = {
    "bft_escalation_threshold", "param_keyholders", "param_threshold",
    "tx_commit_ms", "block_sig_ms", "abort_claim_ms",
}

WHITELIST = CHAIN_SCALAR_NAMES | HOOK_NAMES  # validator.cpp::kWhitelist

def decode_u64_le(value_hex):
    try:
        b = bytes.fromhex(value_hex)
    except Exception:
        return None
    if len(b) == 8:
        return int.from_bytes(b, "little")
    return None

rows = []
for e in entries:
    if not isinstance(e, dict):
        continue
    name = e.get("name", "")
    if not isinstance(name, str):
        name = str(name)
    try:
        eff = int(e.get("effective_height", 0) or 0)
    except Exception:
        eff = 0
    vhex = e.get("value_hex", "")
    if not isinstance(vhex, str):
        vhex = ""
    try:
        vbytes = int(e.get("value_bytes", 0) or 0)
    except Exception:
        vbytes = 0

    # Classify activation outcome.
    if name in CHAIN_SCALAR_NAMES:
        if vbytes == 8:
            verdict = "EFFECTIVE"
        else:
            verdict = "INERT_BAD_WIDTH"
    elif name in HOOK_NAMES:
        verdict = "HOOK_ONLY"
    else:
        verdict = "UNKNOWN_NAME"

    overdue = eff <= head
    # Best-effort decoded value for the human/JSON view (only meaningful
    # when width is the expected 8 bytes; otherwise None).
    decoded = decode_u64_le(vhex) if vbytes == 8 else None

    rows.append({
        "name":              name,
        "effective_height":  eff,
        "blocks_until":      eff - head,   # signed; <=0 means OVERDUE
        "value_bytes":       vbytes,
        "value_hex":         vhex,
        "decoded_value":     decoded,
        "verdict":           verdict,
        "overdue":           overdue,
        "anomaly":           verdict in ("INERT_BAD_WIDTH", "UNKNOWN_NAME"),
    })

# Stable ordering: soonest activation first, tie-break by name.
rows.sort(key=lambda r: (r["effective_height"], r["name"]))

counts = {"EFFECTIVE": 0, "INERT_BAD_WIDTH": 0, "HOOK_ONLY": 0, "UNKNOWN_NAME": 0}
for r in rows:
    counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
overdue_n = sum(1 for r in rows if r["overdue"])
anomaly_n = sum(1 for r in rows if r["anomaly"])

anomalies = []
if counts["INERT_BAD_WIDTH"] > 0:
    anomalies.append("inert_bad_width")
if counts["UNKNOWN_NAME"] > 0:
    anomalies.append("unknown_name")

# ── JSON envelope ─────────────────────────────────────────────────────────────
if json_out:
    out_rows = rows
    if anom_only:
        out_rows = [r for r in rows if r["anomaly"]]
    envelope = {
        "rpc_port":        port,
        "current_height":  head,
        "total_staged":    len(rows),
        "counts":          counts,
        "overdue":         overdue_n,
        "anomaly_count":   anomaly_n,
        "anomalies":       anomalies,
        "entries":         out_rows,
    }
    print(json.dumps(envelope))
    sys.exit(2 if (anom_only and anomaly_n > 0) else 0)

# ── Human table ───────────────────────────────────────────────────────────────
def value_cell(r):
    if r["decoded_value"] is not None:
        return str(r["decoded_value"])
    vh = r["value_hex"]
    head_hex = vh[:16] + (".." if len(vh) > 16 else "")
    return f"hex:{head_hex}({r['value_bytes']}B)"

if anom_only:
    shown = [r for r in rows if r["anomaly"]]
    if not shown:
        print(f"operator_param_activation_preflight: all {len(rows)} staged "
              f"change(s) will activate as intended (port {port}, head {head})")
        print("[OK] no mis-staged (inert / unknown) entries")
        sys.exit(0)
    print(f"=== Mis-staged PARAM_CHANGEs (port {port}, head {head}) ===")
    for r in shown:
        flag = " OVERDUE" if r["overdue"] else ""
        print(f"  [{r['verdict']}]{flag} name={r['name']} "
              f"effective_height={r['effective_height']} "
              f"value_bytes={r['value_bytes']} value={value_cell(r)}")
        if r["verdict"] == "INERT_BAD_WIDTH":
            print(f"       -> numeric scalar '{r['name']}' needs an 8-byte u64 "
                  f"value; activation parse_u64 will reject {r['value_bytes']} "
                  f"bytes and SILENTLY NO-OP")
        elif r["verdict"] == "UNKNOWN_NAME":
            print(f"       -> '{r['name']}' is not on the validator whitelist; "
                  f"a staged entry with this name should not exist")
    print(f"[ANOMALY] {anomaly_n} mis-staged entr"
          f"{'y' if anomaly_n == 1 else 'ies'}: {','.join(anomalies)}")
    sys.exit(2)

# Full report.
print(f"Activation pre-flight (port {port}, current height {head})")
if not rows:
    print("(no pending PARAM_CHANGE entries — nothing to pre-flight)")
    print()
    print("[OK] 0 staged changes")
    sys.exit(0)

name_w = max(4, max(len(r["name"]) for r in rows))
val_cells = [value_cell(r) for r in rows]
val_w = max(5, max(len(v) for v in val_cells))
verdict_w = max(len(r["verdict"]) for r in rows)

header = (f"{'NAME':<{name_w}}  {'VERDICT':<{verdict_w}}  "
          f"{'VALUE':<{val_w}}  {'EFFECTIVE':>10}  {'BLOCKS':>7}  FLAGS")
print(header)
print("-" * (name_w + 2 + verdict_w + 2 + val_w + 2 + 10 + 2 + 7 + 7))
for r, vcell in zip(rows, val_cells):
    flags = "OVERDUE" if r["overdue"] else ""
    bl = r["blocks_until"]
    bl_disp = str(bl) if bl > 0 else "0"
    print(f"{r['name']:<{name_w}}  {r['verdict']:<{verdict_w}}  "
          f"{vcell:<{val_w}}  {r['effective_height']:>10}  "
          f"{bl_disp:>7}  {flags}")
print("-" * (name_w + 2 + verdict_w + 2 + val_w + 2 + 10 + 2 + 7 + 7))

print(f"{len(rows)} staged  |  "
      f"{counts['EFFECTIVE']} EFFECTIVE  "
      f"{counts['INERT_BAD_WIDTH']} INERT_BAD_WIDTH  "
      f"{counts['HOOK_ONLY']} HOOK_ONLY  "
      f"{counts['UNKNOWN_NAME']} UNKNOWN_NAME  |  "
      f"{overdue_n} OVERDUE")

if anomaly_n == 0:
    print("[OK] every staged change will mutate its intended scalar (or is "
          "hook-forwarded) at activation")
    sys.exit(0)
else:
    print(f"[ANOMALY] {anomaly_n} mis-staged entr"
          f"{'y' if anomaly_n == 1 else 'ies'} will silently no-op at "
          f"activation: {','.join(anomalies)}")
    # Non-anomalies-only mode does not gate the exit code on anomalies; the
    # operator asked for the full report. Exit 0 so the report renders in
    # pipelines; --anomalies-only is the alerting gate.
    sys.exit(0)
PY
EXIT=$?
exit "$EXIT"
