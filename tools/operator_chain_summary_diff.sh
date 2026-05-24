#!/usr/bin/env bash
# operator_chain_summary_diff.sh — Chain-summary scalar-field divergence
# detector between two running RPC daemons. ONE RPC fetch per port,
# compares the scalar fields (head_hash, head_state_root, chain_id,
# genesis_hash, accumulated_*, total_supply, chain_height, peers_count,
# mempool_depth) and classifies each row by impact tier.
#
# Sibling positioning:
#   * operator_chain_diff.sh           — PAIRWISE BLOCK-LEVEL diff
#     across two daemons at every (or strided) shared height. Walks the
#     full chain; cost grows with window size. Right tool for "is there
#     a historical divergence at some specific height?".
#   * operator_consensus_lag.sh        — N-way HEIGHT-only lag check
#     across a fleet. Stragglers vs. tip. Right tool for "who is behind?".
#   * operator_chain_summary_diff.sh   — TWO-DAEMON SCALAR-FIELD diff.
#     One round-trip per daemon, no per-block walk. Right tool for the
#     fast "do these two daemons currently agree on the chain identity
#     and supply envelope?" probe — cheap enough to run every few
#     seconds from a monitoring loop. Catches:
#       (a) head_hash / state_root divergence at the tip — silent fork.
#       (b) chain_id / genesis_hash divergence — wrong-chain misconfig.
#       (c) accumulated_* / total_supply divergence at matching heights
#           — A1 unitary-supply invariant break (one daemon's apply
#           path is diverging from the other's).
#       (d) excessive height drift — one daemon is far behind.
#
# Read-only RPC; safe against any running daemons. Both ports must be
# listening on 127.0.0.1.
#
# Field tiers + status semantics:
#
#   CRITICAL (exit 2 on mismatch)
#     head_hash         — tip block hash. Honest nodes at the same
#                         finalized height MUST produce identical hashes
#                         (FA1 + S-033 + S-038). Divergence = fork.
#     head_state_root   — tip block's body.state_root. Same nodes at the
#                         same height MUST agree (S-033 apply-time gate).
#                         Divergence = apply-determinism break OR fork.
#     chain_id          — chain identity tag. Divergence = the two
#                         daemons are configured for different chains
#                         entirely (operator misconfiguration; comparison
#                         is meaningless).
#     genesis_hash      — genesis block hash. Same role as chain_id.
#                         Divergence = different deployments.
#
#   HEIGHT-SENSITIVE (status MATCH / DRIFT_OK / DIVERGENT)
#     accumulated_subsidy  ┐
#     accumulated_inbound  │ Cumulative A1 counters at chain head.
#     accumulated_outbound │ MUST match across honest daemons IFF the
#     accumulated_slashed  │ daemons are at the same height. If heights
#     total_supply         ┘ differ, mismatch is expected (each daemon
#                            credited a different number of subsidies);
#                            tolerated as DRIFT_OK. At matching heights,
#                            mismatch = A1 invariant violation.
#     genesis_total        — should NEVER drift across honest daemons
#                            regardless of height (genesis is shared).
#                            Effectively identity-tier; status flips to
#                            CRITICAL if it diverges.
#
#   METADATA (info only; DRIFT_OK tolerated up to --ignore-height-drift)
#     chain_height      — drift > --ignore-height-drift threshold gets
#                         flagged as anomaly (height_drift_high).
#     peers_count       — peer fanout count from each daemon's local
#                         view; expected to vary across daemons.
#     mempool_depth     — pending tx count per daemon; expected to vary.
#
# Anomalies:
#   critical_field_divergence  — any CRITICAL-tier field diverges (or
#                                 genesis_total divergence). FATAL.
#   height_drift_high          — |height_a - height_b| > --ignore-height-drift.
#   supply_drift               — any HEIGHT-SENSITIVE field diverges at
#                                 matching heights. A1 invariant break.
#
# Exit codes:
#   0   all fields match (modulo allowed metadata drift)
#   2   any anomaly fired (critical / height / supply)
#   1   RPC error / args error / malformed response
#
# Usage:
#   tools/operator_chain_summary_diff.sh --rpc-port-a N --rpc-port-b N
#                                        [--ignore-height-drift N]
#                                        [--json] [--anomalies-only]
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_summary_diff.sh --rpc-port-a N --rpc-port-b N
                                      [--ignore-height-drift N]
                                      [--json] [--anomalies-only]

Compares chain-summary scalar fields between two running RPC daemons.
ONE RPC fetch per port (cheap). Reports per-field MATCH / DRIFT_OK /
DIVERGENT / CRITICAL and raises anomalies on critical-tier mismatch,
excessive height drift, or supply drift at matching heights.

Required:
  --rpc-port-a N            First daemon RPC port (127.0.0.1)
  --rpc-port-b N            Second daemon RPC port (127.0.0.1)

Options:
  --ignore-height-drift N   Tolerate up to N blocks of height drift.
                            Drift > N raises the height_drift_high
                            anomaly. Default 3.
  --json                    Emit single-line JSON envelope (see below)
  --anomalies-only          Suppress healthy (MATCH / DRIFT_OK) rows
                            in human output; only print non-OK rows
                            + summary.
  -h, --help                Show this help

Exit codes:
  0   all fields healthy
  2   any anomaly (critical / height / supply) detected
  1   RPC error / args / malformed response

Field tiers:
  CRITICAL          head_hash, head_state_root, chain_id, genesis_hash
                    (mismatch is always an alert regardless of height)
  HEIGHT-SENSITIVE  accumulated_subsidy, accumulated_inbound,
                    accumulated_outbound, accumulated_slashed,
                    total_supply, genesis_total
                    (must match at same height; tolerated otherwise)
  METADATA          chain_height (drift > threshold = anomaly),
                    peers_count, mempool_depth (info-only)

JSON envelope (--json):
  {"port_a": N, "port_b": N,
   "height_a": N, "height_b": N, "height_delta": N,
   "ignore_height_drift": N,
   "fields": [
     {"name": "<field>", "tier": "CRITICAL|HEIGHT_SENSITIVE|METADATA",
      "a": <value>, "b": <value>,
      "status": "MATCH|DRIFT_OK|DIVERGENT|CRITICAL",
      "delta": <signed-int-or-null>}, ...
   ],
   "anomalies": ["critical_field_divergence", "height_drift_high",
                 "supply_drift", ...],
   "summary": {"n_fields": N, "n_match": N, "n_drift_ok": N,
               "n_divergent": N, "n_critical": N}}

Examples:
  # Quick health probe between two regional daemons.
  tools/operator_chain_summary_diff.sh --rpc-port-a 7778 --rpc-port-b 7779

  # Tighter drift threshold for a hot/standby pair.
  tools/operator_chain_summary_diff.sh --rpc-port-a 7778 --rpc-port-b 7779 \
      --ignore-height-drift 1

  # Monitoring loop: only print anomalies, machine-readable.
  while true; do
    tools/operator_chain_summary_diff.sh --rpc-port-a 7778 --rpc-port-b 7779 \
        --json --anomalies-only || alert "chain diff"
    sleep 5
  done
EOF
}

PORT_A=""
PORT_B=""
IGNORE_DRIFT="3"
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                usage; exit 0 ;;
    --rpc-port-a)             PORT_A="${2:-}"; shift 2 ;;
    --rpc-port-b)             PORT_B="${2:-}"; shift 2 ;;
    --ignore-height-drift)    IGNORE_DRIFT="${2:-}"; shift 2 ;;
    --json)                   JSON_OUT=1; shift ;;
    --anomalies-only)         ANOM_ONLY=1; shift ;;
    *) echo "operator_chain_summary_diff: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORT_A" ] || [ -z "$PORT_B" ]; then
  echo "operator_chain_summary_diff: --rpc-port-a and --rpc-port-b are required" >&2
  usage >&2
  exit 1
fi
for label_val in "rpc-port-a:$PORT_A" "rpc-port-b:$PORT_B"; do
  label=${label_val%%:*}
  v=${label_val#*:}
  case "$v" in *[!0-9]*|"")
    echo "operator_chain_summary_diff: --$label must be a positive integer (got '$v')" >&2
    exit 1 ;;
  esac
  if [ "$v" -lt 1 ] || [ "$v" -gt 65535 ]; then
    echo "operator_chain_summary_diff: --$label must be 1..65535 (got '$v')" >&2
    exit 1
  fi
done
if [ "$PORT_A" = "$PORT_B" ]; then
  echo "operator_chain_summary_diff: --rpc-port-a and --rpc-port-b must differ (both = $PORT_A); the diff is trivially empty" >&2
  exit 1
fi
case "$IGNORE_DRIFT" in *[!0-9]*|"")
  echo "operator_chain_summary_diff: --ignore-height-drift must be a non-negative integer (got '$IGNORE_DRIFT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Resolve python for JSON parsing / emission. The chain_summary +
# status RPC results carry types richer than what bash can safely
# string-handle (large u64 counters, optional fields, mixed types).
PYEXE=""
if   command -v python3 >/dev/null 2>&1; then PYEXE=python3
elif command -v python  >/dev/null 2>&1; then PYEXE=python
else
  echo "operator_chain_summary_diff: python (python3 or python) is required for JSON parsing" >&2
  exit 1
fi

# ── Fetch all three RPC views from each daemon ──────────────────────────────
# Triple-fetch per port:
#   1. chain_summary --last 1 --json  → accumulated_*, total_supply,
#                                       genesis_total, height (chain tip).
#   2. status RPC (via raw rpc_call equivalent — `head --json` returns
#      only height + head_hash, but we need genesis hash + peer_count +
#      mempool_size + chain_role + shard_id too, so we walk status
#      directly via a dedicated invocation).
#   3. block-info <head-1> --field state_root → head_state_root.
#
# All three fetches must succeed on each port; partial failures are
# treated as RPC errors (exit 1) because the field set is the contract.
fetch_chain_summary() {
  # fetch_chain_summary <port> → JSON object string on stdout, rc 0 on success.
  local port="$1"
  local out
  out=$("$DETERM" chain-summary --last 1 --json --rpc-port "$port" 2>/dev/null)
  local rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$out" ]; then
    return 1
  fi
  printf '%s' "$out"
}

# `determ` exposes `head --json` which sources status. We need a few more
# fields than `head` carries, so a tiny inline helper that re-invokes
# `determ` per-field is the right shape — keeps this script in pure CLI
# territory (no direct RPC packet construction).
fetch_head_height() {
  # → bare integer; rc 0 on success.
  local port="$1"
  local out
  out=$("$DETERM" head --field height --rpc-port "$port" 2>/dev/null)
  local rc=$?
  if [ "$rc" -ne 0 ]; then return 1; fi
  printf '%s' "$out" | tr -d '[:space:]'
}
fetch_head_hash() {
  local port="$1"
  local out
  out=$("$DETERM" head --field hash --rpc-port "$port" 2>/dev/null)
  local rc=$?
  if [ "$rc" -ne 0 ]; then return 1; fi
  printf '%s' "$out" | tr -d '[:space:]'
}
fetch_state_root_at() {
  # fetch_state_root_at <port> <height> → bare hex on stdout.
  # height==0 ⇒ empty chain; return empty string.
  local port="$1"
  local h="$2"
  if [ "$h" = "0" ]; then
    printf '%s' ""
    return 0
  fi
  # Last finalized index = height - 1.
  local idx=$(( h - 1 ))
  local out
  out=$("$DETERM" block-info "$idx" --field state_root --rpc-port "$port" 2>/dev/null)
  local rc=$?
  if [ "$rc" -ne 0 ]; then return 1; fi
  printf '%s' "$out" | tr -d '[:space:]'
}

# Probe each daemon. Fail loud on RPC error with port-tagged diagnostic.
CS_A=$(fetch_chain_summary "$PORT_A") || {
  echo "operator_chain_summary_diff: RPC error querying chain-summary on port $PORT_A (is daemon running on 127.0.0.1:$PORT_A?)" >&2
  exit 1
}
CS_B=$(fetch_chain_summary "$PORT_B") || {
  echo "operator_chain_summary_diff: RPC error querying chain-summary on port $PORT_B (is daemon running on 127.0.0.1:$PORT_B?)" >&2
  exit 1
}

HEIGHT_A=$(fetch_head_height "$PORT_A") || {
  echo "operator_chain_summary_diff: RPC error querying head height on port $PORT_A" >&2
  exit 1
}
HEIGHT_B=$(fetch_head_height "$PORT_B") || {
  echo "operator_chain_summary_diff: RPC error querying head height on port $PORT_B" >&2
  exit 1
}
case "$HEIGHT_A" in *[!0-9]*|"")
  echo "operator_chain_summary_diff: head height from port $PORT_A not numeric (got '$HEIGHT_A')" >&2
  exit 1 ;;
esac
case "$HEIGHT_B" in *[!0-9]*|"")
  echo "operator_chain_summary_diff: head height from port $PORT_B not numeric (got '$HEIGHT_B')" >&2
  exit 1 ;;
esac

# Empty-chain head_hash is legitimately "" — fetch_head_hash returns
# that. Only error out if the underlying RPC call itself fails.
HEAD_HASH_A=""
if [ "$HEIGHT_A" != "0" ]; then
  HEAD_HASH_A=$(fetch_head_hash "$PORT_A") || {
    echo "operator_chain_summary_diff: RPC error querying head hash on port $PORT_A" >&2
    exit 1
  }
fi
HEAD_HASH_B=""
if [ "$HEIGHT_B" != "0" ]; then
  HEAD_HASH_B=$(fetch_head_hash "$PORT_B") || {
    echo "operator_chain_summary_diff: RPC error querying head hash on port $PORT_B" >&2
    exit 1
  }
fi

# head_state_root is sourced from the last finalized block. block-info
# may legitimately return empty when state_root is the zero hash (older
# blocks before S-038 wiring populated body.state_root); that's not an
# RPC error.
HEAD_STATE_ROOT_A=$(fetch_state_root_at "$PORT_A" "$HEIGHT_A") || {
  echo "operator_chain_summary_diff: RPC error querying state_root for block $(( HEIGHT_A - 1 )) on port $PORT_A" >&2
  exit 1
}
HEAD_STATE_ROOT_B=$(fetch_state_root_at "$PORT_B" "$HEIGHT_B") || {
  echo "operator_chain_summary_diff: RPC error querying state_root for block $(( HEIGHT_B - 1 )) on port $PORT_B" >&2
  exit 1
}

# chain_id / genesis_hash come from a third RPC fetch — `verify-genesis-live`-
# style. The status RPC carries the genesis hash inline; we walk it
# through a tiny python-side parse below alongside chain_summary so we
# only need to spawn python once.
fetch_status_field() {
  # fetch_status_field <port> <field> → bare value on stdout; "" if absent.
  # `determ status --field NAME --rpc-port P` extracts one field of the
  # status RPC (defined in src/main.cpp:cmd_status). Returns rc 1 only on
  # RPC error; missing/null fields render as empty stdout with rc 0.
  local port="$1"
  local field="$2"
  local out
  out=$("$DETERM" status --field "$field" --rpc-port "$port" 2>/dev/null)
  local rc=$?
  if [ "$rc" -ne 0 ]; then return 1; fi
  printf '%s' "$out" | tr -d '[:space:]'
}

# chain_id vs genesis_hash sourcing:
#
#   chain_id      — config-pinned identifier from genesis.json. Folded
#                   INTO compute_genesis_hash so any chain_id drift
#                   produces a genesis_hash mismatch by construction.
#                   The live RPC `chain-id` (cmd_chain_id) emits the
#                   genesis hash for legacy reasons — it's a stable
#                   per-deployment fingerprint operators recognize. We
#                   keep it as a distinct CRITICAL row here for
#                   forward-compat (a future RPC may surface
#                   cfg_.chain_id as a separate field).
#
#   genesis_hash  — compute_hash(block[0]). Surfaced as status.genesis.
#                   Same wire value as `determ chain-id` today; kept as
#                   its own row so operators can see both labels.
#
# In practice both rows will MATCH or both will MISMATCH on today's
# server; the distinction matters for future-proof reporting.
CHAIN_ID_A=$("$DETERM" chain-id --rpc-port "$PORT_A" 2>/dev/null) || {
  echo "operator_chain_summary_diff: RPC error querying chain-id on port $PORT_A" >&2
  exit 1
}
CHAIN_ID_B=$("$DETERM" chain-id --rpc-port "$PORT_B" 2>/dev/null) || {
  echo "operator_chain_summary_diff: RPC error querying chain-id on port $PORT_B" >&2
  exit 1
}
CHAIN_ID_A=$(printf '%s' "$CHAIN_ID_A" | tr -d '[:space:]')
CHAIN_ID_B=$(printf '%s' "$CHAIN_ID_B" | tr -d '[:space:]')

# genesis_hash from status.genesis (same wire value chain-id emits;
# kept distinct in case the surfaces diverge in a future RPC version).
GENESIS_A=$(fetch_status_field "$PORT_A" genesis) || {
  echo "operator_chain_summary_diff: RPC error querying status.genesis on port $PORT_A" >&2
  exit 1
}
GENESIS_B=$(fetch_status_field "$PORT_B" genesis) || {
  echo "operator_chain_summary_diff: RPC error querying status.genesis on port $PORT_B" >&2
  exit 1
}

# peers_count + mempool_depth come from status.peer_count + status.mempool_size
# (canonical server-side field names; the operator-facing aliases in this
# script are "peers_count" and "mempool_depth"). Missing/null → empty
# string; we treat empty as "field not surfaced by this daemon build"
# rather than an RPC error.
PEERS_A=$(fetch_status_field "$PORT_A" peer_count) || PEERS_A=""
PEERS_B=$(fetch_status_field "$PORT_B" peer_count) || PEERS_B=""
MEMPOOL_A=$(fetch_status_field "$PORT_A" mempool_size) || MEMPOOL_A=""
MEMPOOL_B=$(fetch_status_field "$PORT_B" mempool_size) || MEMPOOL_B=""

# Pack the per-daemon status view as a single-line JSON object so the
# python driver only needs one positional arg slot per side.
mk_status_json() {
  # mk_status_json <chain_id> <genesis_hash> <peers> <mempool>
  local cid="$1" gh="$2" peers="$3" mempool="$4"
  # Quote string fields; integer fields render bare (empty → "null").
  local peers_repr="null"
  case "$peers" in ''|*[!0-9]*) peers_repr="null" ;; *) peers_repr="$peers" ;; esac
  local mempool_repr="null"
  case "$mempool" in ''|*[!0-9]*) mempool_repr="null" ;; *) mempool_repr="$mempool" ;; esac
  printf '{"chain_id":"%s","genesis_hash":"%s","peer_count":%s,"mempool_size":%s}' \
    "$cid" "$gh" "$peers_repr" "$mempool_repr"
}
ST_A=$(mk_status_json "$CHAIN_ID_A" "$GENESIS_A" "$PEERS_A" "$MEMPOOL_A")
ST_B=$(mk_status_json "$CHAIN_ID_B" "$GENESIS_B" "$PEERS_B" "$MEMPOOL_B")

# ── Drive comparison + emit in python ───────────────────────────────────────
"$PYEXE" - "$PORT_A" "$PORT_B" "$IGNORE_DRIFT" "$JSON_OUT" "$ANOM_ONLY" \
         "$CS_A" "$CS_B" "$ST_A" "$ST_B" \
         "$HEIGHT_A" "$HEIGHT_B" \
         "$HEAD_HASH_A" "$HEAD_HASH_B" \
         "$HEAD_STATE_ROOT_A" "$HEAD_STATE_ROOT_B" <<'PY'
import json, sys

(port_a, port_b, ignore_drift,
 json_out, anom_only,
 cs_a_raw, cs_b_raw,
 st_a_raw, st_b_raw,
 height_a_s, height_b_s,
 head_hash_a, head_hash_b,
 head_state_root_a, head_state_root_b) = sys.argv[1:16]

port_a       = int(port_a)
port_b       = int(port_b)
ignore_drift = int(ignore_drift)
json_out     = (json_out == "1")
anom_only    = (anom_only == "1")
height_a     = int(height_a_s)
height_b     = int(height_b_s)

def die(msg):
    sys.stderr.write(f"operator_chain_summary_diff: {msg}\n")
    sys.exit(1)

# Parse chain_summary results.
try:
    cs_a = json.loads(cs_a_raw)
except Exception as e:
    die(f"chain-summary(a) JSON not parseable: {e}")
try:
    cs_b = json.loads(cs_b_raw)
except Exception as e:
    die(f"chain-summary(b) JSON not parseable: {e}")
if not isinstance(cs_a, dict):
    die(f"chain-summary(a) root not an object: {type(cs_a).__name__}")
if not isinstance(cs_b, dict):
    die(f"chain-summary(b) root not an object: {type(cs_b).__name__}")

try:
    st_a = json.loads(st_a_raw)
except Exception as e:
    die(f"status(a) JSON not parseable: {e}")
try:
    st_b = json.loads(st_b_raw)
except Exception as e:
    die(f"status(b) JSON not parseable: {e}")

def gint(obj, key, default=0):
    v = obj.get(key, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

def gstr(obj, key, default=""):
    v = obj.get(key, default)
    if v is None:
        return default
    return str(v)

# chain_summary scalar set (server-canonical names).
acc_subsidy_a  = gint(cs_a, "accumulated_subsidy")
acc_subsidy_b  = gint(cs_b, "accumulated_subsidy")
acc_inbound_a  = gint(cs_a, "accumulated_inbound")
acc_inbound_b  = gint(cs_b, "accumulated_inbound")
acc_outbound_a = gint(cs_a, "accumulated_outbound")
acc_outbound_b = gint(cs_b, "accumulated_outbound")
acc_slashed_a  = gint(cs_a, "accumulated_slashed")
acc_slashed_b  = gint(cs_b, "accumulated_slashed")
total_supply_a = gint(cs_a, "total_supply")
total_supply_b = gint(cs_b, "total_supply")
genesis_total_a = gint(cs_a, "genesis_total")
genesis_total_b = gint(cs_b, "genesis_total")
# Both chain_summary's `height` field AND the head RPC height should
# agree on a given daemon. Use chain_summary's height as the canonical
# value (matches the row of accumulated_* it's reporting) and reconcile
# against head as a sanity check.
cs_height_a = gint(cs_a, "height", height_a)
cs_height_b = gint(cs_b, "height", height_b)
# Surface a diagnostic if chain_summary's height disagrees with `head`
# height on the same daemon — that would mean the daemon's RPC layer
# is in an inconsistent state between two consecutive calls. Treat as
# an RPC anomaly (exit 1) since the comparison framework relies on
# both views being self-consistent on each side.
if cs_height_a != height_a:
    die(f"port {port_a}: chain-summary.height ({cs_height_a}) != head.height "
        f"({height_a}) — inconsistent RPC views; retry")
if cs_height_b != height_b:
    die(f"port {port_b}: chain-summary.height ({cs_height_b}) != head.height "
        f"({height_b}) — inconsistent RPC views; retry")

# status scalar set.
chain_id_a     = gstr(st_a, "chain_id")
chain_id_b     = gstr(st_b, "chain_id")
genesis_hash_a = gstr(st_a, "genesis_hash")
genesis_hash_b = gstr(st_b, "genesis_hash")

# peers_count / mempool_depth source mapping:
#
#   peers_count   ← status.peer_count   (local peer-fanout count)
#   mempool_depth ← status.mempool_size (pending tx count)
#
# Both come from the per-daemon status RPC; the wrapper builds the
# {peer_count, mempool_size} object via `determ status --field NAME`.
# A daemon build that doesn't surface either field will emit JSON
# null → -1 sentinel here. METADATA tier (info only) so missing-on-
# one-side does NOT trigger an anomaly; the row simply renders "n/a".
def gint_optional(obj, key):
    v = obj.get(key)
    if v is None:
        return -1
    try:
        return int(v)
    except (TypeError, ValueError):
        return -1
peers_a    = gint_optional(st_a, "peer_count")
peers_b    = gint_optional(st_b, "peer_count")
mempool_a  = gint_optional(st_a, "mempool_size")
mempool_b  = gint_optional(st_b, "mempool_size")

# Reconcile drift / matching-height boolean once.
heights_match = (height_a == height_b)
height_delta  = height_a - height_b   # signed; A - B (positive ⇒ A ahead)
height_drift_abs = abs(height_delta)

# Field tier enumeration. Order in this list = render order.
# Each row: (name, tier, a_value, b_value)
#   tier ∈ {"CRITICAL", "HEIGHT_SENSITIVE", "METADATA"}
FIELDS = [
    # CRITICAL tier (must always match across honest daemons on same chain)
    ("chain_id",         "CRITICAL",         chain_id_a,         chain_id_b),
    ("genesis_hash",     "CRITICAL",         genesis_hash_a,     genesis_hash_b),
    ("head_hash",        "CRITICAL",         head_hash_a,        head_hash_b),
    ("head_state_root",  "CRITICAL",         head_state_root_a,  head_state_root_b),
    # HEIGHT_SENSITIVE tier (must match at matching heights)
    ("genesis_total",      "HEIGHT_SENSITIVE", genesis_total_a,  genesis_total_b),
    ("total_supply",       "HEIGHT_SENSITIVE", total_supply_a,   total_supply_b),
    ("accumulated_subsidy","HEIGHT_SENSITIVE", acc_subsidy_a,    acc_subsidy_b),
    ("accumulated_inbound","HEIGHT_SENSITIVE", acc_inbound_a,    acc_inbound_b),
    ("accumulated_outbound","HEIGHT_SENSITIVE",acc_outbound_a,   acc_outbound_b),
    ("accumulated_slashed","HEIGHT_SENSITIVE", acc_slashed_a,    acc_slashed_b),
    # METADATA tier (info only)
    ("chain_height",  "METADATA", height_a,  height_b),
    ("peers_count",   "METADATA", peers_a,   peers_b),
    ("mempool_depth", "METADATA", mempool_a, mempool_b),
]

# Per-row status classification:
#   MATCH       — values equal
#   DRIFT_OK    — values differ but the difference is expected for this
#                 tier (HEIGHT_SENSITIVE @ differing heights;
#                 METADATA peers_count / mempool_depth always;
#                 chain_height @ |Δ| <= --ignore-height-drift)
#   DIVERGENT   — HEIGHT_SENSITIVE values differ at matching heights;
#                 chain_height drift exceeds threshold
#   CRITICAL    — CRITICAL-tier values differ (or genesis_total drift
#                 which is effectively identity)

def classify(name, tier, a, b):
    if a == b:
        return "MATCH"
    if tier == "CRITICAL":
        return "CRITICAL"
    if tier == "HEIGHT_SENSITIVE":
        # genesis_total is identity-grade — diverging here is CRITICAL
        # regardless of height. The remaining height-sensitive fields
        # tolerate drift iff heights differ.
        if name == "genesis_total":
            return "CRITICAL"
        if heights_match:
            return "DIVERGENT"
        return "DRIFT_OK"
    # METADATA
    if name == "chain_height":
        if height_drift_abs <= ignore_drift:
            return "DRIFT_OK"
        return "DIVERGENT"
    # peers_count / mempool_depth: local-view fields, diff expected.
    return "DRIFT_OK"

def compute_delta(name, a, b):
    # Signed integer delta (a - b) where both sides are integers.
    # Returns None for string-valued rows or when either side is the
    # sentinel "field not present" (-1 for peers_count / mempool_depth
    # when the daemon build doesn't surface them).
    if isinstance(a, str) or isinstance(b, str):
        return None
    if name in ("peers_count", "mempool_depth"):
        if a < 0 or b < 0:
            return None
    try:
        return int(a) - int(b)
    except (TypeError, ValueError):
        return None

rows = []
for (name, tier, a, b) in FIELDS:
    status = classify(name, tier, a, b)
    delta  = compute_delta(name, a, b)
    rows.append({
        "name":   name,
        "tier":   tier,
        "a":      a,
        "b":      b,
        "status": status,
        "delta":  delta,
    })

# Anomaly detection.
anomalies = []
if any(r["status"] == "CRITICAL" for r in rows):
    anomalies.append("critical_field_divergence")
if height_drift_abs > ignore_drift:
    anomalies.append("height_drift_high")
# supply_drift = any HEIGHT_SENSITIVE field DIVERGENT (i.e., drift at
# matching heights). Excludes genesis_total because that's already
# bucketed into critical_field_divergence above.
if any(r["status"] == "DIVERGENT" and r["tier"] == "HEIGHT_SENSITIVE"
       for r in rows):
    anomalies.append("supply_drift")

# Summary counters.
n_match    = sum(1 for r in rows if r["status"] == "MATCH")
n_drift_ok = sum(1 for r in rows if r["status"] == "DRIFT_OK")
n_div      = sum(1 for r in rows if r["status"] == "DIVERGENT")
n_crit     = sum(1 for r in rows if r["status"] == "CRITICAL")
summary = {
    "n_fields":    len(rows),
    "n_match":     n_match,
    "n_drift_ok":  n_drift_ok,
    "n_divergent": n_div,
    "n_critical":  n_crit,
}

# Exit code:
#   0   no anomalies
#   2   any anomaly fired
exit_rc = 2 if anomalies else 0

# ── Render ──────────────────────────────────────────────────────────────────
if json_out:
    # Anomalies-only suppression in JSON mode trims the fields[] list to
    # non-OK rows but keeps the summary + anomalies envelope intact, so
    # a monitoring loop can still see the verdict in one parse.
    rendered_rows = rows
    if anom_only:
        rendered_rows = [r for r in rows
                         if r["status"] not in ("MATCH", "DRIFT_OK")]
    out = {
        "port_a":              port_a,
        "port_b":              port_b,
        "height_a":            height_a,
        "height_b":            height_b,
        "height_delta":        height_delta,
        "ignore_height_drift": ignore_drift,
        "fields":              rendered_rows,
        "anomalies":           anomalies,
        "summary":             summary,
    }
    print(json.dumps(out, separators=(",", ":")))
    sys.exit(exit_rc)

# Human render.
def fmt_val(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        if v == "":
            return '""'
        # Hash-style values shorten for tabular readability; chain_id
        # is typically already short so we don't truncate it.
        if len(v) >= 40 and all(c in "0123456789abcdefABCDEF" for c in v):
            return v[:12] + "..." + v[-6:]
        return v
    if isinstance(v, int):
        if v < 0:
            return "n/a"   # sentinel for missing peers_count / mempool_depth
        return str(v)
    return str(v)

def fmt_delta(d):
    if d is None:
        return ""
    sign = "+" if d >= 0 else ""
    return f"{sign}{d}"

print(f"=== Chain summary diff (port_a={port_a} vs port_b={port_b}) ===")
print(f"Heights:           a={height_a}  b={height_b}  delta={height_delta}  "
      f"(tolerance ±{ignore_drift})")
print(f"Identity probe:    chain_id_a='{chain_id_a}'  chain_id_b='{chain_id_b}'")
print(f"                   genesis_a={fmt_val(genesis_hash_a)}  "
      f"genesis_b={fmt_val(genesis_hash_b)}")
print("")

# Compute column widths from the widest formatted value across all rows
# (so the table stays aligned even when one side has a long hex hash).
def width_of(rows, key):
    return max((len(fmt_val(r[key])) for r in rows), default=4)

# Filter rows for anomalies-only mode. Always keep the field-row table
# header but trim healthy rows.
visible_rows = rows
if anom_only:
    visible_rows = [r for r in rows if r["status"] not in ("MATCH", "DRIFT_OK")]

if visible_rows:
    name_w  = max(width_of(visible_rows, "name"), len("field"))
    tier_w  = max(width_of(visible_rows, "tier"), len("tier"))
    a_w     = max(width_of(visible_rows, "a"),    len("a"))
    b_w     = max(width_of(visible_rows, "b"),    len("b"))
    a_label = f"a (port {port_a})"
    b_label = f"b (port {port_b})"
    if len(a_label) > a_w: a_w = len(a_label)
    if len(b_label) > b_w: b_w = len(b_label)

    print(f"  {'field':<{name_w}}  {'tier':<{tier_w}}  "
          f"{a_label:<{a_w}}  {b_label:<{b_w}}  "
          f"{'delta':>12}  status")
    print(f"  {'-'*name_w}  {'-'*tier_w}  {'-'*a_w}  {'-'*b_w}  "
          f"{'-'*12}  ----------")
    for r in visible_rows:
        print(f"  {r['name']:<{name_w}}  {r['tier']:<{tier_w}}  "
              f"{fmt_val(r['a']):<{a_w}}  {fmt_val(r['b']):<{b_w}}  "
              f"{fmt_delta(r['delta']):>12}  {r['status']}")
else:
    print("  (no rows to display under --anomalies-only)")

print("")
print(f"Summary: n_fields={summary['n_fields']}  "
      f"match={n_match}  drift_ok={n_drift_ok}  "
      f"divergent={n_div}  critical={n_crit}")
if anomalies:
    print("")
    print(f"Anomalies ({len(anomalies)}):")
    for a in anomalies:
        print(f"  [!] {a}")

print("")
if exit_rc == 0:
    print(f"[OK] port_a={port_a} and port_b={port_b} agree on chain-summary "
          f"scalars (height drift {height_drift_abs} <= tolerance {ignore_drift}).")
else:
    bits = []
    if "critical_field_divergence" in anomalies:
        bits.append("CRITICAL-tier mismatch (head/state/identity)")
    if "supply_drift" in anomalies:
        bits.append("supply drift at matching heights (A1 break)")
    if "height_drift_high" in anomalies:
        bits.append(f"height drift {height_drift_abs} > tolerance {ignore_drift}")
    detail = "; ".join(bits) if bits else "see anomalies above"
    print(f"[X]  Divergence detected — {detail}.")

sys.exit(exit_rc)
PY
PY_RC=$?
exit "$PY_RC"
