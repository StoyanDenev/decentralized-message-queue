#!/usr/bin/env bash
# operator_dapp_lifecycle_audit.sh — Per-DApp lifecycle-transition
# timeline audit over a chain window. For every DApp seen in the
# window, derive the tuple
#
#     (register_block, first_call_block, last_call_block, deregister_block)
#
# plus a derived `state` ∈ {ACTIVE, DORMANT, DEREGISTERED,
# REGISTERED_NEVER_CALLED}, then flag abandoned registrations,
# high-volume DApps that have gone silent, and the rare
# call-after-deregister anomaly.
#
# Scope contrast with neighbouring DApp operator scripts:
#   operator_dapp_inventory.sh        compact registry digest +
#                                     recent-message count (no per-
#                                     transition aggregation; doesn't
#                                     answer "when did each DApp first
#                                     register / first call / go silent
#                                     / get torn down?").
#   operator_dapp_health.sh           registry + recent-message liveness
#                                     join (no historical first/last
#                                     call-block tracking; no
#                                     abandoned-registration detection).
#   operator_dapp_call_volume_audit.sh per-DApp + per-sender call
#                                     concentration + spam-burst
#                                     detection (orthogonal: about
#                                     in-window call HOT-SPOTS, not
#                                     about lifecycle transitions).
#   operator_dapp_balance_audit.sh    accrued-balance + DAPP_CALL
#                                     revenue (about FUNDS, not about
#                                     transition timestamps).
#   operator_dapp_registration_audit.sh DAPP_REGISTER op=0/op=1 flow
#                                     classification + Sybil / mass-
#                                     deactivation flags (focuses on
#                                     the REGISTER stream only; doesn't
#                                     join against the DAPP_CALL stream
#                                     to derive per-DApp first/last-call
#                                     timestamps).
#   operator_dapp_lifecycle_audit.sh  THIS — per-DApp lifecycle TIMELINE
#                                     across all three streams
#                                     (REGISTER, CALL, DEREGISTER)
#                                     joined by DApp domain. Asks:
#                                     "for each DApp, when did it
#                                     register / first see traffic /
#                                     last see traffic / get torn down,
#                                     and what's its current lifecycle
#                                     state right now?"
#
# Wire-format note (important):
#
#   DApp deregistration is NOT a separate TxType in v2.18+ — it is
#   DAPP_REGISTER (TxType=9) with payload[0] == 1 ("op=1 deactivate"
#   per include/determ/chain/block.hpp lines 130-131). There is no
#   distinct TxType::DAPP_DEREGISTER on the wire. This script treats
#   DAPP_REGISTER op=0 as the register transition and DAPP_REGISTER
#   op=1 as the deregister transition, consistent with the sibling
#   operator_dapp_registration_audit.sh classifier and the apply-side
#   rules in Chain::apply (inactive_from = height + DAPP_GRACE_BLOCKS
#   on op=1).
#
# Pipeline (read-only RPC):
#   1.  Resolve current chain head via `determ head --field height`.
#   2.  Walk the requested window [FROM..TO] via `determ block-info
#       <h> --json` (one round-trip per block; matches the per-block
#       pattern in operator_dapp_call_volume_audit.sh /
#       operator_dapp_balance_audit.sh / operator_dapp_call_audit.sh).
#       For each transaction:
#         - tx.type == 9 (DAPP_REGISTER) AND payload[0] == 0
#           -> per-DApp register-event (key by tx.from since the
#              DApp's owning domain IS the registrant identity)
#         - tx.type == 9 (DAPP_REGISTER) AND payload[0] == 1
#           -> per-DApp deregister-event (same keying)
#         - tx.type == 10 (DAPP_CALL)
#           -> per-DApp call-event (key by tx.to since DAPP_CALL
#              targets the DApp's domain)
#   3.  For each DApp domain that appears in any stream:
#         register_block          = first block where we saw a
#                                   DAPP_REGISTER op=0 from that
#                                   domain (None if never seen in
#                                   window — the DApp may have
#                                   pre-registered before --from).
#         first_call_block        = first block where any DAPP_CALL
#                                   targeted that domain (None if no
#                                   calls in window).
#         last_call_block         = last block where any DAPP_CALL
#                                   targeted that domain (None if no
#                                   calls in window).
#         total_calls             = count of DAPP_CALL where tx.to ==
#                                   that domain.
#         deregister_block        = first block where we saw a
#                                   DAPP_REGISTER op=1 from that
#                                   domain (None if not deregistered
#                                   in window).
#         dormant_blocks          = (head - last_call_block) when state
#                                   is DORMANT; null otherwise.
#         state                   = derived per the rules in the
#                                   classification block below.
#   4.  Classify each DApp's state:
#         DEREGISTERED              deregister_block is non-null.
#         REGISTERED_NEVER_CALLED   register_block non-null AND
#                                   total_calls == 0 AND not deregistered.
#         DORMANT                   total_calls > 0 AND not deregistered
#                                   AND (head - last_call_block) > 1000.
#         ACTIVE                    total_calls > 0 AND not deregistered
#                                   AND (head - last_call_block) <= 1000.
#         (If register_block is null AND total_calls == 0 AND
#         deregister_block is null we don't surface the DApp at all —
#         no event in window means nothing to report; the DApp may
#         exist in the registry but the inventory script is the right
#         tool for that view.)
#
# Per-DApp report fields (sorted by total_calls desc, then domain asc):
#   - domain                 DApp address
#   - state                  one of {ACTIVE, DORMANT, DEREGISTERED,
#                                    REGISTERED_NEVER_CALLED}
#   - register_block         block height of first observed register
#                            (null if pre-window or never)
#   - first_call_block       block height of first observed call
#                            (null if no calls in window)
#   - last_call_block        block height of last observed call
#                            (null if no calls in window)
#   - total_calls            count of DAPP_CALLs in window
#   - deregister_block       block height of deregister event
#                            (null if not deregistered in window)
#   - dormant_blocks         head - last_call_block when state is
#                            DORMANT; null otherwise
#
# Aggregates / summary:
#   - total_dapps            count of distinct DApp domains surfaced
#   - active                 count of DApps in state ACTIVE
#   - dormant                count of DApps in state DORMANT
#   - deregistered           count of DApps in state DEREGISTERED
#   - never_called           count of DApps in state REGISTERED_NEVER_CALLED
#
# Anomaly flags (printed in human mode + present in JSON):
#   - registered_never_called   WARN — > 0 DApps registered in-window
#                               with zero calls observed (potentially
#                               abandoned registrations; squatting /
#                               dropped-rollout signal).
#   - dormant_high_call_count   WARN — any DApp with > 100 total
#                               historical calls AND no calls in the
#                               last 1000 blocks (regression-of-traffic
#                               signal — formerly-popular DApp has gone
#                               silent and operator likely wants to
#                               know).
#   - deregister_then_recall    WARN — DAPP_CALL targeting a DApp at a
#                               height GREATER than its deregister
#                               block. The validator + apply layer
#                               should reject this past DAPP_GRACE_BLOCKS
#                               (Chain::apply drops new DAPP_CALL
#                               credits when inactive_from <= height);
#                               so a hit indicates either a grace-
#                               boundary race or a stale-client call
#                               that slipped through within the
#                               DAPP_GRACE_BLOCKS = 100 grace window.
#                               Flagged for operator review; not
#                               necessarily a correctness violation
#                               but worth surfacing.
#
# RPC dependencies (all read-only):
#   - head                   current chain height
#   - block                  per-block walk (via block-info)
#
# Usage:
#   tools/operator_dapp_lifecycle_audit.sh --rpc-port N
#                                          [--from H] [--to H]
#                                          [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port (REQUIRED)
#   --from H            Start block of audit window (default: 0).
#                       Note that pre-window registration events are
#                       invisible — DApps that registered before
#                       --from will have register_block = null.
#   --to H              End block of audit window (default: head).
#   --json              Emit machine-readable JSON envelope.
#   --anomalies-only    Print only anomaly lines; suppress healthy rows;
#                       exit 2 if any anomaly fires.
#   -h, --help          Show this help.
#
# Exit codes:
#   0   audit ran successfully (no anomalies OR anomalies in default mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_lifecycle_audit.sh --rpc-port N
         [--from H] [--to H]
         [--json] [--anomalies-only]

Per-DApp lifecycle-transition timeline audit. Walks the requested
window via block-info, joins DAPP_REGISTER (op=0 register, op=1
deregister) and DAPP_CALL streams per DApp domain, and reports
(register_block, first_call_block, last_call_block, deregister_block,
total_calls, state) for each DApp seen.

State classification:
  ACTIVE                    calls > 0, not deregistered, last call within 1000 blocks
  DORMANT                   calls > 0, not deregistered, last call > 1000 blocks ago
  DEREGISTERED              deregister event observed in window
  REGISTERED_NEVER_CALLED   register event observed, zero calls, not deregistered

Options:
  --rpc-port N        RPC port (REQUIRED)
  --from H            Window start (default: 0)
  --to H              Window end   (default: head)
  --json              Emit machine-readable JSON envelope
  --anomalies-only    Print only anomaly lines; suppress healthy rows;
                      exit 2 if any anomaly fires
  -h, --help          Show this help

Anomaly flags:
  registered_never_called   WARN — > 0 DApps registered in-window with zero calls
                            (potentially abandoned registrations)
  dormant_high_call_count   WARN — DApp with > 100 historical calls AND no calls
                            in last 1000 blocks (regression-of-traffic signal)
  deregister_then_recall    WARN — DAPP_CALL after this DApp's deregister height
                            (grace-boundary race / stale-client review item)

Exit codes:
  0   success (no anomalies OR anomalies in default mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >=1 anomaly fired

Wire-format note:
  DApp deregistration is encoded as DAPP_REGISTER (TxType=9) with
  payload[0]==1 ("op=1 deactivate"); there is no separate DAPP_DEREGISTER
  TxType in v2.18+. This script treats DAPP_REGISTER op=0 as register
  and DAPP_REGISTER op=1 as deregister, matching the apply-side rules
  in Chain::apply and the sibling operator_dapp_registration_audit.sh.
EOF
}

PORT=""
FROM_H=""
TO_H=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)          usage; exit 0 ;;
    --rpc-port)         PORT="${2:-}";    shift 2 ;;
    --from)             FROM_H="${2:-}";  shift 2 ;;
    --to)               TO_H="${2:-}";    shift 2 ;;
    --json)             JSON_OUT=1;       shift ;;
    --anomalies-only)   ANOM_ONLY=1;      shift ;;
    *) echo "operator_dapp_lifecycle_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port required (per sibling operator script convention; refuses
# to silently guess on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_dapp_lifecycle_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards on user-supplied integer values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_lifecycle_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_dapp_lifecycle_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to absolute path (some Windows shells trip on relative
# paths inside subprocess.run — mirror operator_dapp_call_volume_audit.sh
# / operator_dapp_message_audit.sh).
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
  echo "operator_dapp_lifecycle_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_dapp_lifecycle_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: whole chain [0..head] per the task. Clamp --to to head.
if [ -z "$FROM_H" ]; then FROM=0;       else FROM=$FROM_H; fi
if [ -z "$TO_H" ];   then TO=$HEAD_H;   else TO=$TO_H;     fi
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_dapp_lifecycle_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk window in Python (block-info per block; aggregate) ──────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_lifecycle_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$HEAD_H" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port, from_s, to_s, head_s, out_path) = sys.argv[1:7]
from_h = int(from_s)
to_h   = int(to_s)
head_h = int(head_s)

# Dormant cutoff per the task: a DApp with calls is DORMANT when its
# last call was > DORMANT_THRESHOLD blocks ago. Hard-coded to match the
# anomaly threshold below; if these ever need to be operator-tunable,
# wire them through as separate flags rather than coupling them.
DORMANT_THRESHOLD       = 1000

# dormant_high_call_count anomaly thresholds.
HIGH_CALL_COUNT         = 100
HIGH_CALL_DORMANT_BLOCKS = 1000

def is_dapp_register(tx_type):
    # TxType::DAPP_REGISTER = 9 per include/determ/chain/block.hpp.
    # Accept int / string forms (forward-compat with future RPC
    # renderers; matches operator_dapp_registration_audit.sh's helper).
    if isinstance(tx_type, int):  return tx_type == 9
    if isinstance(tx_type, str):  return tx_type in ("9", "DAPP_REGISTER")
    return False

def is_dapp_call(tx_type):
    # TxType::DAPP_CALL = 10. Accept int / string forms — same
    # contract as operator_dapp_call_volume_audit.sh's helper.
    if isinstance(tx_type, int):  return tx_type == 10
    if isinstance(tx_type, str):  return tx_type in ("10", "DAPP_CALL")
    return False

def decode_register_op(hex_str):
    # DAPP_REGISTER payload[0] is the op byte: 0 = register/update,
    # 1 = deactivate. Return None if the payload is empty / non-hex
    # (treated as a decode error; the script doesn't classify the tx
    # as either register or deregister in that case).
    if not hex_str:
        return None
    try:
        p = bytes.fromhex(hex_str)
    except Exception:
        return None
    if len(p) < 1:
        return None
    return p[0]

# Per-DApp aggregators.
register_block      = {}            # domain -> first observed op=0 height
deregister_block    = {}            # domain -> first observed op=1 height
first_call_block    = {}            # domain -> earliest DAPP_CALL height
last_call_block     = {}            # domain -> latest DAPP_CALL height
total_calls         = defaultdict(int)  # domain -> count of DAPP_CALLs
# Per-DApp post-deregister call list (for deregister_then_recall flag).
post_dereg_calls    = defaultdict(list)  # domain -> [heights]

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(
            f"operator_dapp_lifecycle_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(
            f"operator_dapp_lifecycle_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(
            f"operator_dapp_lifecycle_audit: block-info {h} non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list): continue

    for tx in txs:
        if not isinstance(tx, dict): continue
        tx_type = tx.get("type")
        tx_from = str(tx.get("from", "") or "")
        tx_to   = str(tx.get("to",   "") or "")

        if is_dapp_register(tx_type):
            # Identify the DApp by tx.from — the registrant's address
            # IS the DApp's owning domain (apply-side: dapp_registry_[tx.from]
            # per Chain::apply, src/chain/chain.cpp; same convention used
            # by operator_dapp_registration_audit.sh).
            if not tx_from: continue
            op = decode_register_op(tx.get("payload", ""))
            if op == 0:
                # First-time register (earliest wins; later op=0 events
                # are updates to an already-registered DApp and don't
                # reset the timeline).
                if tx_from not in register_block:
                    register_block[tx_from] = h
            elif op == 1:
                # Deregister; earliest wins (multiple deregisters from
                # the same DApp shouldn't happen but if they do the
                # timeline anchors on the first).
                if tx_from not in deregister_block:
                    deregister_block[tx_from] = h
            # op != 0/1 (or undecoded): skip silently — matches
            # operator_dapp_registration_audit.sh's decode_error class
            # which is reported separately there but not relevant to
            # the lifecycle-transition timeline this script builds.

        elif is_dapp_call(tx_type):
            # Identify the DApp by tx.to — DAPP_CALL targets the DApp's
            # domain (apply-side: credits accounts_[tx.to]).
            if not tx_to: continue
            if tx_to not in first_call_block:
                first_call_block[tx_to] = h
            last_call_block[tx_to] = h
            total_calls[tx_to] += 1
            # If this DApp has already deregistered, this is a
            # deregister_then_recall candidate. Compare against the
            # FIRST deregister we've seen so far; subsequent op=1
            # events are unusual but don't change the rule.
            dereg_h = deregister_block.get(tx_to)
            if dereg_h is not None and h > dereg_h:
                post_dereg_calls[tx_to].append(h)

# All DApps surfaced: anything observed in any of the four streams.
all_domains = set()
all_domains.update(register_block.keys())
all_domains.update(deregister_block.keys())
all_domains.update(first_call_block.keys())
# total_calls keys are a subset of first_call_block keys but be defensive.
all_domains.update(total_calls.keys())

# ── Compose per-DApp records + classify state ───────────────────────────────
def classify(domain):
    has_dereg  = domain in deregister_block
    n_calls    = total_calls.get(domain, 0)
    has_reg    = domain in register_block
    if has_dereg:
        return "DEREGISTERED"
    if n_calls == 0:
        # No calls observed in window. If we saw a register event in
        # window the DApp is REGISTERED_NEVER_CALLED; otherwise we
        # don't surface it (no event in window — nothing to report).
        return "REGISTERED_NEVER_CALLED" if has_reg else None
    # Has calls, not deregistered.
    blocks_since_last = head_h - last_call_block[domain]
    return "DORMANT" if blocks_since_last > DORMANT_THRESHOLD else "ACTIVE"

per_dapp = []
for d in all_domains:
    state = classify(d)
    if state is None:
        # Edge case: no register, no call, no deregister — shouldn't
        # happen because we only add domains that appeared in at least
        # one stream, but be defensive.
        continue
    n_calls = total_calls.get(d, 0)
    last_h  = last_call_block.get(d)
    dormant_blocks = None
    if state == "DORMANT" and last_h is not None:
        dormant_blocks = head_h - last_h
    per_dapp.append({
        "domain":              d,
        "state":               state,
        "register_block":      register_block.get(d),
        "first_call_block":    first_call_block.get(d),
        "last_call_block":     last_h,
        "total_calls":         n_calls,
        "deregister_block":    deregister_block.get(d),
        "dormant_blocks":      dormant_blocks,
    })

# Sort by total_calls desc, then domain asc (deterministic).
per_dapp.sort(key=lambda d: (-d["total_calls"], d["domain"]))

# ── Anomaly classification ──────────────────────────────────────────────────
anomalies = []

# registered_never_called: any DApp surfaced in REGISTERED_NEVER_CALLED.
never_called_offenders = [
    d["domain"] for d in per_dapp if d["state"] == "REGISTERED_NEVER_CALLED"
]
if never_called_offenders:
    anomalies.append("registered_never_called")

# dormant_high_call_count: DApp with > HIGH_CALL_COUNT historical calls
# AND last call > HIGH_CALL_DORMANT_BLOCKS ago (== state DORMANT given
# the constants align; check the data fields directly so the threshold
# is explicit and decoupled from the state label).
high_call_dormant_offenders = []
for d in per_dapp:
    if d["last_call_block"] is None: continue
    if d["total_calls"] <= HIGH_CALL_COUNT: continue
    if d["deregister_block"] is not None: continue  # DEREGISTERED takes precedence
    if (head_h - d["last_call_block"]) > HIGH_CALL_DORMANT_BLOCKS:
        high_call_dormant_offenders.append(d["domain"])
if high_call_dormant_offenders:
    anomalies.append("dormant_high_call_count")

# deregister_then_recall: any DApp with a post-deregister call observed.
# Capture per-DApp the FIRST offending recall height (the rest are
# implied; one example is enough for operator review).
recall_offenders = []
recall_detail    = {}     # domain -> {deregister_block, recall_block, recall_count}
for d in per_dapp:
    dom = d["domain"]
    if dom in post_dereg_calls and post_dereg_calls[dom]:
        recall_offenders.append(dom)
        recall_detail[dom] = {
            "deregister_block": deregister_block[dom],
            "recall_block":     min(post_dereg_calls[dom]),
            "recall_count":     len(post_dereg_calls[dom]),
        }
if recall_offenders:
    anomalies.append("deregister_then_recall")

# ── Summary ────────────────────────────────────────────────────────────────
n_active           = sum(1 for d in per_dapp if d["state"] == "ACTIVE")
n_dormant          = sum(1 for d in per_dapp if d["state"] == "DORMANT")
n_deregistered     = sum(1 for d in per_dapp if d["state"] == "DEREGISTERED")
n_never_called     = sum(1 for d in per_dapp if d["state"] == "REGISTERED_NEVER_CALLED")

result = {
    "window": {"from": from_h, "to": to_h, "blocks": to_h - from_h + 1},
    "head":   head_h,
    "dapps":  per_dapp,
    "summary": {
        "total_dapps":                len(per_dapp),
        "active":                     n_active,
        "dormant":                    n_dormant,
        "deregistered":               n_deregistered,
        "never_called":               n_never_called,
        "dormant_threshold_blocks":   DORMANT_THRESHOLD,
        "high_call_count_threshold":  HIGH_CALL_COUNT,
        "never_called_offenders":     never_called_offenders,
        "high_call_dormant_offenders": high_call_dormant_offenders,
        "recall_offenders":           recall_offenders,
        "recall_detail":              recall_detail,
        "anomalies":                  anomalies,
    },
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_dapp_lifecycle_audit: aggregation pass failed" >&2
  exit 1
fi

# ── Step 3: render envelope (JSON or human) ───────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" \
         "$WIN_BLOCKS" "$HEAD_H" <<'PY'
import json, sys

json_out   = sys.argv[1] == "1"
anom_only  = sys.argv[2] == "1"
out_path   = sys.argv[3]
port       = int(sys.argv[4])
from_h     = int(sys.argv[5])
to_h       = int(sys.argv[6])
win_blocks = int(sys.argv[7])
head_h     = int(sys.argv[8])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

summary    = r["summary"]
anomalies  = summary["anomalies"]
anom_count = len(anomalies)

def fmt_opt(v):
    """Render None as '-' for human-readable columns."""
    return "-" if v is None else str(v)

if json_out:
    # Pass through the full envelope verbatim; the aggregation pass
    # already shaped the per-DApp records to the schema spec'd in the
    # task. Echo the rpc_port alongside so external consumers can
    # correlate runs.
    envelope = {
        "window":     r["window"],
        "head":       r["head"],
        "dapps":      r["dapps"],
        "anomalies":  anomalies,
        "summary":    {
            "total_dapps":   summary["total_dapps"],
            "active":        summary["active"],
            "dormant":       summary["dormant"],
            "deregistered":  summary["deregistered"],
            "never_called":  summary["never_called"],
        },
        "rpc_port":   port,
    }
    print(json.dumps(envelope))
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    print(f"operator_dapp_lifecycle_audit: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], "
          f"{win_blocks} blocks, head {head_h})")
    sys.exit(0)

print(f"=== DApp lifecycle audit (port {port}, window [{from_h}..{to_h}], "
      f"{win_blocks} blocks, head {head_h}) ===")
print(f"Total DApps surfaced: {summary['total_dapps']}  "
      f"(active={summary['active']}, dormant={summary['dormant']}, "
      f"deregistered={summary['deregistered']}, "
      f"never_called={summary['never_called']})")

if not anom_only:
    print()
    if not r["dapps"]:
        print("(no DApp lifecycle events in window)")
    else:
        # Per-DApp timeline table.
        print("Per-DApp lifecycle timeline:")
        for d in r["dapps"]:
            print(f"  {d['domain']:32s}  state={d['state']:<26s}  "
                  f"calls={d['total_calls']:>7}")
            print(f"      register={fmt_opt(d['register_block']):>10s}  "
                  f"first_call={fmt_opt(d['first_call_block']):>10s}  "
                  f"last_call={fmt_opt(d['last_call_block']):>10s}  "
                  f"deregister={fmt_opt(d['deregister_block']):>10s}")
            if d["dormant_blocks"] is not None:
                print(f"      dormant_blocks={d['dormant_blocks']} "
                      f"(threshold={summary['dormant_threshold_blocks']})")

# Anomaly lines.
print()
if anom_count == 0:
    print("[OK] No anomalies")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "registered_never_called" in anomalies:
        offenders = summary["never_called_offenders"]
        print(f"  - registered_never_called: {len(offenders)} DApp(s) "
              f"registered in-window but never called (WARN — potentially "
              f"abandoned registrations)")
        for dom in offenders:
            for d in r["dapps"]:
                if d["domain"] != dom: continue
                print(f"      {dom}: register={fmt_opt(d['register_block'])}")
                break
    if "dormant_high_call_count" in anomalies:
        offenders = summary["high_call_dormant_offenders"]
        thresh    = summary["high_call_count_threshold"]
        print(f"  - dormant_high_call_count: {len(offenders)} DApp(s) "
              f"with > {thresh} historical calls but no calls in last "
              f"{summary['dormant_threshold_blocks']} blocks (WARN — "
              f"regression-of-traffic signal)")
        for dom in offenders:
            for d in r["dapps"]:
                if d["domain"] != dom: continue
                dormant_blocks = (head_h - d["last_call_block"]
                                  if d["last_call_block"] is not None else None)
                print(f"      {dom}: total_calls={d['total_calls']} "
                      f"last_call={fmt_opt(d['last_call_block'])} "
                      f"dormant_blocks={fmt_opt(dormant_blocks)}")
                break
    if "deregister_then_recall" in anomalies:
        offenders = summary["recall_offenders"]
        detail    = summary["recall_detail"]
        print(f"  - deregister_then_recall: {len(offenders)} DApp(s) "
              f"received DAPP_CALLs after their deregister block (WARN — "
              f"grace-boundary race / stale-client review item)")
        for dom in offenders:
            dt = detail.get(dom, {})
            print(f"      {dom}: deregister={fmt_opt(dt.get('deregister_block'))} "
                  f"first_recall={fmt_opt(dt.get('recall_block'))} "
                  f"recall_count={dt.get('recall_count', 0)}")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_dapp_lifecycle_audit: rendering failed" >&2
  exit 1
fi

# ── Step 4: exit-code policy ──────────────────────────────────────────────────
TMP_ANOM=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_lifecycle_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" "$TMP_ANOM" 2>/dev/null' EXIT
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
