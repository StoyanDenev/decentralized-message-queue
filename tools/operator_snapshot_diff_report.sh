#!/usr/bin/env bash
# operator_snapshot_diff_report.sh — Multi-domain field-level diff report
# between two snapshot files, layered on top of `determ snapshot diff`.
#
# `determ snapshot diff` (built-in) returns a flat differences[] array:
# one entry per top-level scalar that disagrees (block_index, head_hash,
# state_root, accounts size, balance_sum, registrants size, stakes size,
# stake_sum, the 5 A1 counters, live_total_supply, block_subsidy,
# min_stake). That's adequate for incident triage on a single mismatch
# but leaves three operator workflows under-served:
#
#   1. Grouped reporting — operators triaging across many snapshots want
#      "what changed in counters between epoch N and N+1?" answered as a
#      single line, not threaded through 14 differences[] entries.
#   2. Per-set deltas — `snapshot diff` reports `accounts: 100 != 105`
#      (sizes only). It does not say *which* 5 domains were added,
#      removed, or had their balance modified. That detail is fully
#      recoverable from the snapshot JSON files themselves; this script
#      mines them.
#   3. Anomaly flags — sanity checks like "supply moved but balances
#      didn't" or "snapshot B is OLDER than A (operator probably swapped
#      --from/--to)" need a structured envelope the operator can gate on.
#
# Sibling positioning:
#   * operator_snapshot_check.sh — single snapshot vs daemon (live).
#   * operator_genesis_diff.sh   — two genesis configs (deployment-time).
#   * operator_snapshot_diff_report.sh (this) — two snapshots, grouped
#     field-level + account-set diff (incident / post-mortem).
#
# Pipeline:
#   1. `determ snapshot diff --from --to --json` validates both files
#      via Chain::restore_from_snapshot (S-033 / S-038 state_root gate)
#      and gives the scalar-level differences[] array. A non-zero exit
#      here is fatal — either snapshot is structurally broken.
#   2. Raw JSON parse of both snapshot files yields the full
#      accounts[] / stakes[] / registrants[] arrays for set-level diff
#      (added / removed / modified).
#   3. Python groups everything by domain (state / counters / accounts /
#      stakes / registrants / params), applies anomaly rules, and emits
#      either grouped human text or a JSON envelope.
#
# Why parse the snapshot JSON directly (vs. extending `snapshot diff`)?
# The snapshot wire format already serializes the full set explicitly
# (accounts[], stakes[], registrants[] with per-entry domain + scalar
# fields — see Chain::serialize_state). Walking that in Python is ~10
# lines per domain and adds no new C++ surface to maintain. The binary
# already verified structural integrity in step 1.
#
# Usage:
#   tools/operator_snapshot_diff_report.sh --from <file-a> --to <file-b>
#                                          [--group all|counters|state|
#                                                   accounts|stakes|
#                                                   registrants|params]
#                                          [--json] [--account-detail]
#
# Anomaly rules (flagged in JSON envelope + human verdict):
#   supply_drift_during_diff
#     accumulated_inbound OR accumulated_outbound changed but no account
#     balance was modified. Diagnostic: counters moved but the ledger
#     they reconcile against did not — points at A1-counter bookkeeping
#     drift OR a deliberate counter-reset without ledger changes.
#   negative_block_index_delta
#     to.block_index < from.block_index. Operator likely swapped --from
#     and --to; the diff is semantically backward.
#   state_root_unchanged_but_accounts_changed
#     state_root identical between the two snapshots but at least one
#     account/stake/registrant was added, removed, or modified. This
#     would indicate the S-033 state_root binding is broken (legitimate
#     state changes failed to propagate into the root). Either snapshot
#     is fabricated OR a serializer regression dropped a namespace.
#   identical_snapshots
#     not an anomaly per se — emitted when from == to in every group, so
#     operators can distinguish "ran the tool against the same file"
#     from "actually diff'd two snapshots and they happen to agree".
#
# Exit codes:
#   0   success (diff completed, including identical snapshots)
#   1   file error / binary error / malformed snapshot / bad args
#   2   anomaly detected (any of the above except identical_snapshots)
set -u

usage() {
  cat <<'EOF'
Usage: operator_snapshot_diff_report.sh --from <file-a> --to <file-b>
                                        [--group GROUP] [--json]
                                        [--account-detail]

Grouped field-level snapshot diff layered on `determ snapshot diff`.

Required:
  --from <file-a>    First snapshot (the "before" reference)
  --to   <file-b>    Second snapshot (the "after" reference)

Options:
  --group GROUP      Restrict report to one domain. One of:
                       all          — every group (default)
                       state        — head_hash / state_root / block_index
                       counters     — A1 counters + live_total_supply
                                      + balance_sum + stake_sum
                       accounts     — per-account add/remove/modify
                       stakes       — per-stake add/remove/modify
                       registrants  — per-registrant add/remove/modify
                       params       — block_subsidy, min_stake
  --json             Emit structured JSON envelope (single line)
  --account-detail   When accounts/stakes/registrants are reported, also
                     emit per-domain balance/stake/registry deltas. Off
                     by default to keep output compact on large state.
  -h, --help         Show this help

Exit codes:
  0   diff completed (including identical snapshots)
  1   file error / binary error / malformed snapshot / bad args
  2   anomaly detected — see the JSON envelope's "anomalies" array

JSON envelope (--json):
  {"from":              "<path>",
   "to":                "<path>",
   "identical":         <bool>,
   "block_index_delta": <signed int>,
   "state": {
     "head_hash_changed":  <bool>,
     "state_root_changed": <bool>,
     "block_index_delta":  <signed int>,
     "from_head_hash":     "<hex>",
     "to_head_hash":       "<hex>",
     "from_state_root":    "<hex>",
     "to_state_root":      "<hex>",
     "from_block_index":   <int>,
     "to_block_index":     <int>
   },
   "counters": {
     "accumulated_subsidy_delta":   <signed int>,
     "accumulated_inbound_delta":   <signed int>,
     "accumulated_outbound_delta":  <signed int>,
     "accumulated_slashed_delta":   <signed int>,
     "live_total_supply_delta":     <signed int>,
     "genesis_total_delta":         <signed int>,
     "balance_sum_delta":           <signed int>,
     "stake_sum_delta":             <signed int>
   },
   "accounts":    {"added": N, "removed": N, "modified": N,
                   "detail": [{"domain":"...","change":"added|removed|modified",
                               "from_balance":N,"to_balance":N,
                               "balance_delta":N,
                               "from_next_nonce":N,"to_next_nonce":N}, ...]?},
   "stakes":      {"added": N, "removed": N, "modified": N,
                   "detail": [{"domain":"...","change":"...",
                               "from_locked":N,"to_locked":N,
                               "locked_delta":N,
                               "from_unlock_height":N,"to_unlock_height":N}, ...]?},
   "registrants": {"added": N, "removed": N, "modified": N,
                   "detail": [{"domain":"...","change":"...",
                               "from_active_from":N,"to_active_from":N,
                               "from_inactive_from":N,"to_inactive_from":N,
                               "from_region":"...","to_region":"..."}, ...]?},
   "params":      {"block_subsidy_changed": <bool>, "min_stake_changed": <bool>,
                   "from_block_subsidy":N,"to_block_subsidy":N,
                   "from_min_stake":N,"to_min_stake":N},
   "anomalies":   ["..."]}
EOF
}

FROM_PATH=""
TO_PATH=""
GROUP="all"
JSON_OUT=0
ACCOUNT_DETAIL=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --from)           FROM_PATH="$2"; shift 2 ;;
    --to)             TO_PATH="$2";   shift 2 ;;
    --group)          GROUP="$2";     shift 2 ;;
    --json)           JSON_OUT=1;     shift ;;
    --account-detail) ACCOUNT_DETAIL=1; shift ;;
    *) echo "operator_snapshot_diff_report: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$FROM_PATH" ] || [ -z "$TO_PATH" ]; then
  echo "operator_snapshot_diff_report: --from <file-a> and --to <file-b> are required" >&2
  usage >&2
  exit 1
fi

case "$GROUP" in
  all|counters|state|accounts|stakes|registrants|params) ;;
  *)
    echo "operator_snapshot_diff_report: --group must be one of all|counters|state|accounts|stakes|registrants|params (got '$GROUP')" >&2
    exit 1 ;;
esac

# Existence + readability checks up front so the operator gets a
# path-specific diagnostic before any subprocess output.
for label_path in "from:$FROM_PATH" "to:$TO_PATH"; do
  label=${label_path%%:*}
  path=${label_path#*:}
  if [ ! -f "$path" ]; then
    echo "operator_snapshot_diff_report: --$label file not found: $path" >&2
    exit 1
  fi
  if [ ! -r "$path" ]; then
    echo "operator_snapshot_diff_report: --$label file not readable: $path" >&2
    exit 1
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── 1. Run `determ snapshot diff --json` (validate + canonical scalars) ────
# This validates both snapshots through Chain::restore_from_snapshot
# (S-033 / S-038 state_root gate) and emits the canonical scalar-level
# differences[] array. Either file being structurally broken short-
# circuits the whole pipeline here. The differences[] array is also
# what we surface back to operators in the JSON envelope under
# `binary_diffs` — it's the same view incident-response runbooks
# already cite.
DIFF_OUT=$("$DETERM" snapshot diff "$FROM_PATH" "$TO_PATH" --json 2>&1)
DIFF_RC=$?
if [ "$DIFF_RC" -ne 0 ]; then
  echo "operator_snapshot_diff_report: 'determ snapshot diff' failed (rc=$DIFF_RC)" >&2
  echo "$DIFF_OUT" >&2
  exit 1
fi

# ── 2. Pull state_root + head_hash + block_index via `snapshot inspect` ─────
# Snapshot files do NOT store top-level state_root / head_hash directly —
# state_root is recomputed from the restored state and head_hash is read
# off the (optional) embedded tail-headers array. `snapshot diff` only
# emits these fields when they DIFFER, so to populate the `state` group
# unconditionally (operators want the from/to values even when they
# agree) we need a separate `snapshot inspect` pass on each file.
INSPECT_FROM=$("$DETERM" snapshot inspect --in "$FROM_PATH" --json 2>&1)
INSPECT_FROM_RC=$?
if [ "$INSPECT_FROM_RC" -ne 0 ]; then
  echo "operator_snapshot_diff_report: 'determ snapshot inspect' on --from failed (rc=$INSPECT_FROM_RC)" >&2
  echo "$INSPECT_FROM" >&2
  exit 1
fi
INSPECT_TO=$("$DETERM" snapshot inspect --in "$TO_PATH" --json 2>&1)
INSPECT_TO_RC=$?
if [ "$INSPECT_TO_RC" -ne 0 ]; then
  echo "operator_snapshot_diff_report: 'determ snapshot inspect' on --to failed (rc=$INSPECT_TO_RC)" >&2
  echo "$INSPECT_TO" >&2
  exit 1
fi

# ── 3. Drive grouping + set-level diff + anomaly detection in Python ────────
# Python is the right tool here because:
#   - we need to walk three arrays (accounts[], stakes[], registrants[])
#     in both files and compute symmetric differences keyed on .domain;
#   - we need to keep two output paths (human grouped table vs JSON
#     envelope) feeding off the same data structure;
#   - the anomaly rules need cross-group state (e.g.,
#     "state_root_unchanged AND accounts_changed").
python - "$FROM_PATH" "$TO_PATH" "$GROUP" "$JSON_OUT" "$ACCOUNT_DETAIL" "$DIFF_OUT" "$INSPECT_FROM" "$INSPECT_TO" <<'PY'
import json, sys

from_path, to_path = sys.argv[1], sys.argv[2]
group              = sys.argv[3]
json_out           = sys.argv[4] == "1"
account_detail     = sys.argv[5] == "1"
diff_raw           = sys.argv[6]
inspect_from_raw   = sys.argv[7]
inspect_to_raw     = sys.argv[8]

def die(msg, rc=1):
    sys.stderr.write(f"operator_snapshot_diff_report: {msg}\n")
    sys.exit(rc)

# ── Parse the binary's diff envelope ────────────────────────────────────────
# Shape: {"a":<path>,"b":<path>,"identical":<bool>,
#         "differences":[{"field":<name>,"a":<v>,"b":<v>}, ...]}
try:
    diff_env = json.loads(diff_raw)
except Exception as e:
    die(f"'determ snapshot diff --json' output not parseable: {e}")

if "error" in diff_env:
    die(f"'determ snapshot diff' returned error: {diff_env}")

# The differences[] list is the same scalar diff our richer envelope
# already encodes — we don't surface it again. We do keep the
# `identical` flag for the verdict line so the binary's own view shows
# up alongside ours (mainly so any future divergence between the two
# views fails loudly instead of silently).
binary_identical = bool(diff_env.get("identical", False))

# ── Parse the two `snapshot inspect` envelopes ─────────────────────────────
# Shape (one per file):
#   {"status":"ok","path":<p>,"block_index":N,"head_hash":<hex>,
#    "state_root":<hex>,"accounts":N,"stakes":N,"registrants":N,
#    "block_subsidy":N,"min_stake":N,"shard_count":N,"shard_id":N,
#    "tail_headers":N}
try:
    insp_a = json.loads(inspect_from_raw)
except Exception as e:
    die(f"'determ snapshot inspect' on --from output not parseable: {e}")
try:
    insp_b = json.loads(inspect_to_raw)
except Exception as e:
    die(f"'determ snapshot inspect' on --to output not parseable: {e}")
if insp_a.get("status") != "ok":
    die(f"'determ snapshot inspect' on --from did not return status=ok: {inspect_from_raw}")
if insp_b.get("status") != "ok":
    die(f"'determ snapshot inspect' on --to did not return status=ok: {inspect_to_raw}")

# ── Parse both snapshot files ───────────────────────────────────────────────
def load_raw(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        die(f"cannot parse snapshot {path}: {e}")

snap_a = load_raw(from_path)
snap_b = load_raw(to_path)
if not isinstance(snap_a, dict):
    die(f"snapshot root not a JSON object: {from_path}")
if not isinstance(snap_b, dict):
    die(f"snapshot root not a JSON object: {to_path}")

# Soft scalar accessor: returns 0 / "" when missing OR null, so a
# field-stripped legacy snapshot still produces a sensible delta.
def gi(snap, key):
    v = snap.get(key)
    try:
        return int(v) if v is not None else 0
    except (TypeError, ValueError):
        return 0
def gs(snap, key):
    v = snap.get(key)
    return v if isinstance(v, str) else ""

# ── State (block_index + head_hash + state_root) ───────────────────────────
# Sourced from `snapshot inspect` rather than the raw snapshot JSON
# because head_hash is read off the embedded tail_headers[] array
# (last-header dependent, not a top-level field) and state_root is
# RECOMPUTED on restore (not stored — see Chain::serialize_state +
# Chain::restore_from_snapshot). The inspect envelope gives us the
# canonical values post-restore.
def gi_insp(insp, key):
    v = insp.get(key)
    try:
        return int(v) if v is not None else 0
    except (TypeError, ValueError):
        return 0
def gs_insp(insp, key):
    v = insp.get(key)
    return v if isinstance(v, str) else ""

state = {
    "from_block_index":   gi_insp(insp_a, "block_index"),
    "to_block_index":     gi_insp(insp_b, "block_index"),
    "from_head_hash":     gs_insp(insp_a, "head_hash"),
    "to_head_hash":       gs_insp(insp_b, "head_hash"),
    "from_state_root":    gs_insp(insp_a, "state_root"),
    "to_state_root":      gs_insp(insp_b, "state_root"),
}
state["block_index_delta"]   = state["to_block_index"] - state["from_block_index"]
state["head_hash_changed"]   = state["from_head_hash"]  != state["to_head_hash"]
state["state_root_changed"]  = state["from_state_root"] != state["to_state_root"]

# A1 counters + supply aggregates.
COUNTER_FIELDS = [
    "accumulated_subsidy",
    "accumulated_inbound",
    "accumulated_outbound",
    "accumulated_slashed",
    "genesis_total",
]
counters = {}
for f in COUNTER_FIELDS:
    counters[f"from_{f}"]  = gi(snap_a, f)
    counters[f"to_{f}"]    = gi(snap_b, f)
    counters[f"{f}_delta"] = counters[f"to_{f}"] - counters[f"from_{f}"]

# live_total_supply isn't stored in the snapshot JSON top-level (it's
# computed from genesis_total + accumulated_subsidy + accumulated_inbound
# − accumulated_outbound − accumulated_slashed inside the chain). Compute
# it here so the report stays consistent with `determ snapshot diff`,
# which DOES surface live_total_supply via Chain::live_total_supply.
def compute_live_total(snap):
    g  = gi(snap, "genesis_total")
    s  = gi(snap, "accumulated_subsidy")
    ib = gi(snap, "accumulated_inbound")
    ob = gi(snap, "accumulated_outbound")
    sl = gi(snap, "accumulated_slashed")
    return g + s + ib - ob - sl
counters["from_live_total_supply"]  = compute_live_total(snap_a)
counters["to_live_total_supply"]    = compute_live_total(snap_b)
counters["live_total_supply_delta"] = counters["to_live_total_supply"] - counters["from_live_total_supply"]

# Params (chain constants).
params = {
    "from_block_subsidy":     gi(snap_a, "block_subsidy"),
    "to_block_subsidy":       gi(snap_b, "block_subsidy"),
    "from_min_stake":         gi(snap_a, "min_stake"),
    "to_min_stake":           gi(snap_b, "min_stake"),
}
params["block_subsidy_changed"] = params["from_block_subsidy"] != params["to_block_subsidy"]
params["min_stake_changed"]     = params["from_min_stake"]     != params["to_min_stake"]

# ── Per-set diffs (accounts / stakes / registrants) ─────────────────────────
# Each snapshot serializes the set as a JSON array of {domain, ...} dicts
# (see Chain::serialize_state). Build keyed lookups, then compute the
# 3-way partition: added (in B not A), removed (in A not B),
# modified (in both but at least one scalar field differs).
def build_set(arr, scalar_fields):
    # scalar_fields: list of (key, type_coercer) tuples.
    by_domain = {}
    if not isinstance(arr, list):
        return by_domain
    for entry in arr:
        if not isinstance(entry, dict):
            continue
        d = entry.get("domain", "")
        if not isinstance(d, str) or not d:
            continue
        rec = {}
        for fname, coerce in scalar_fields:
            v = entry.get(fname)
            try:
                rec[fname] = coerce(v) if v is not None else coerce(0) if coerce is int else (coerce("") if coerce is str else None)
            except (TypeError, ValueError):
                rec[fname] = coerce(0) if coerce is int else ""
        by_domain[d] = rec
    return by_domain

ACCOUNT_FIELDS    = [("balance", int), ("next_nonce", int)]
STAKE_FIELDS      = [("locked", int), ("unlock_height", int)]
REGISTRANT_FIELDS = [("ed_pub", str), ("registered_at", int),
                     ("active_from", int), ("inactive_from", int),
                     ("region", str)]

a_accounts    = build_set(snap_a.get("accounts"),    ACCOUNT_FIELDS)
b_accounts    = build_set(snap_b.get("accounts"),    ACCOUNT_FIELDS)
a_stakes      = build_set(snap_a.get("stakes"),      STAKE_FIELDS)
b_stakes      = build_set(snap_b.get("stakes"),      STAKE_FIELDS)
a_registrants = build_set(snap_a.get("registrants"), REGISTRANT_FIELDS)
b_registrants = build_set(snap_b.get("registrants"), REGISTRANT_FIELDS)

def partition(a_set, b_set, scalar_fields, primary_delta_field=None):
    """3-way set partition.
    Returns (added_list, removed_list, modified_list).
    Each list element is a dict ready for the --account-detail output;
    primary_delta_field is the scalar that gets a balance_delta /
    locked_delta entry computed (modified rows only).
    """
    a_keys = set(a_set.keys())
    b_keys = set(b_set.keys())
    added_keys    = sorted(b_keys - a_keys)
    removed_keys  = sorted(a_keys - b_keys)
    common_keys   = sorted(a_keys & b_keys)
    modified_keys = []
    for k in common_keys:
        for fname, _ in scalar_fields:
            if a_set[k].get(fname) != b_set[k].get(fname):
                modified_keys.append(k)
                break

    def detail_rec(domain, change, a_rec, b_rec):
        rec = {"domain": domain, "change": change}
        for fname, _ in scalar_fields:
            rec[f"from_{fname}"] = a_rec.get(fname) if a_rec is not None else None
            rec[f"to_{fname}"]   = b_rec.get(fname) if b_rec is not None else None
        if primary_delta_field is not None:
            # Compute signed delta for the chosen primary scalar.
            fv = (a_rec or {}).get(primary_delta_field, 0)
            tv = (b_rec or {}).get(primary_delta_field, 0)
            try:
                rec[f"{primary_delta_field}_delta"] = int(tv) - int(fv)
            except (TypeError, ValueError):
                rec[f"{primary_delta_field}_delta"] = 0
        return rec

    added    = [detail_rec(k, "added",    None,     b_set[k]) for k in added_keys]
    removed  = [detail_rec(k, "removed",  a_set[k], None)     for k in removed_keys]
    modified = [detail_rec(k, "modified", a_set[k], b_set[k]) for k in modified_keys]
    return added, removed, modified

acct_added, acct_removed, acct_modified = partition(a_accounts,    b_accounts,    ACCOUNT_FIELDS,    "balance")
stk_added,  stk_removed,  stk_modified  = partition(a_stakes,      b_stakes,      STAKE_FIELDS,      "locked")
reg_added,  reg_removed,  reg_modified  = partition(a_registrants, b_registrants, REGISTRANT_FIELDS, None)

accounts = {
    "added":    len(acct_added),
    "removed":  len(acct_removed),
    "modified": len(acct_modified),
}
stakes_set = {
    "added":    len(stk_added),
    "removed":  len(stk_removed),
    "modified": len(stk_modified),
}
registrants = {
    "added":    len(reg_added),
    "removed":  len(reg_removed),
    "modified": len(reg_modified),
}

if account_detail:
    accounts["detail"]    = acct_added    + acct_removed    + acct_modified
    stakes_set["detail"]  = stk_added     + stk_removed     + stk_modified
    registrants["detail"] = reg_added     + reg_removed     + reg_modified

balance_sum_from = sum(a_accounts[k].get("balance", 0) for k in a_accounts)
balance_sum_to   = sum(b_accounts[k].get("balance", 0) for k in b_accounts)
stake_sum_from   = sum(a_stakes[k].get("locked", 0)    for k in a_stakes)
stake_sum_to     = sum(b_stakes[k].get("locked", 0)    for k in b_stakes)
counters["from_balance_sum"]  = balance_sum_from
counters["to_balance_sum"]    = balance_sum_to
counters["balance_sum_delta"] = balance_sum_to - balance_sum_from
counters["from_stake_sum"]    = stake_sum_from
counters["to_stake_sum"]      = stake_sum_to
counters["stake_sum_delta"]   = stake_sum_to - stake_sum_from

# ── Anomaly detection ───────────────────────────────────────────────────────
# These fire on cross-group conditions the operator should see at a
# glance before drilling into individual fields.
anomalies = []

# (1) Operator likely swapped --from and --to.
if state["block_index_delta"] < 0:
    anomalies.append("negative_block_index_delta")

# (2) A1 counters moved but the ledger they reconcile against did not.
# A pure subsidy block (no inbound / outbound tx) increments
# accumulated_subsidy AND the recipient's account balance, so a
# subsidy-only chain advance would NOT trigger this. The rule only
# fires when accumulated_inbound or accumulated_outbound moved with
# zero modifications/adds/removes in the accounts set.
ledger_changed = (accounts["added"] + accounts["removed"] + accounts["modified"]) > 0
inbound_moved  = counters["accumulated_inbound_delta"]  != 0
outbound_moved = counters["accumulated_outbound_delta"] != 0
if (inbound_moved or outbound_moved) and not ledger_changed:
    anomalies.append("supply_drift_during_diff")

# (3) state_root unchanged but the set changed — S-033 binding broken.
# Only fires when at least one of accounts / stakes / registrants
# changed (any of added / removed / modified > 0) while state_root
# stayed identical. This is the canonical "fabricated snapshot" /
# "serializer regression" signature.
set_changed = ledger_changed or (
    stakes_set["added"] + stakes_set["removed"] + stakes_set["modified"]
    + registrants["added"] + registrants["removed"] + registrants["modified"]
) > 0
if set_changed and not state["state_root_changed"]:
    anomalies.append("state_root_unchanged_but_accounts_changed")

# Identical-snapshots flag — not an alert, just a clarifying marker so
# the operator distinguishes "I ran this against the same file twice"
# from "I diff'd two snapshots and they happen to agree exactly".
all_identical = (
    not state["head_hash_changed"]
    and not state["state_root_changed"]
    and state["block_index_delta"] == 0
    and all(counters[f"{f}_delta"] == 0 for f in COUNTER_FIELDS)
    and counters["live_total_supply_delta"] == 0
    and counters["balance_sum_delta"] == 0
    and counters["stake_sum_delta"] == 0
    and not set_changed
    and not params["block_subsidy_changed"]
    and not params["min_stake_changed"]
)
if all_identical:
    anomalies.append("identical_snapshots")

# Exit code: 2 if any "real" anomaly fired. identical_snapshots is
# informational only — it does NOT escalate to exit 2.
real_anomalies = [a for a in anomalies if a != "identical_snapshots"]
exit_code = 2 if real_anomalies else 0

# ── Helpers for human render ────────────────────────────────────────────────
def short_hash(h, n=16):
    if not isinstance(h, str):
        return ""
    if len(h) <= n:
        return h
    return h[:n] + "..."

def signed(n):
    if n is None:
        return "n/a"
    return f"+{n}" if n > 0 else f"{n}"

# ── JSON emit ───────────────────────────────────────────────────────────────
def filter_groups(env):
    if group == "all":
        return env
    # Keep top-level identification fields always (so the envelope is
    # still self-describing) but drop unused group keys.
    keep_top = {"from", "to", "identical", "block_index_delta", "anomalies", "group"}
    group_key_map = {
        "state":       "state",
        "counters":    "counters",
        "accounts":    "accounts",
        "stakes":      "stakes",
        "registrants": "registrants",
        "params":      "params",
    }
    sel = group_key_map.get(group)
    out = {k: v for k, v in env.items() if k in keep_top or k == sel}
    return out

if json_out:
    env = {
        "from":              from_path,
        "to":                to_path,
        "identical":         all_identical,
        "block_index_delta": state["block_index_delta"],
        "group":             group,
        "state":             state,
        "counters":          counters,
        "accounts":          accounts,
        "stakes":            stakes_set,
        "registrants":       registrants,
        "params":            params,
        "anomalies":         anomalies,
    }
    print(json.dumps(filter_groups(env)))
    sys.exit(exit_code)

# ── Human render ────────────────────────────────────────────────────────────
def header():
    print(f"Snapshot diff report: {from_path} -> {to_path}")
    print("=" * 70)

def render_state():
    print()
    print("State roots:")
    print(f"  head_hash:   {short_hash(state['from_head_hash'])} -> {short_hash(state['to_head_hash'])}"
          f"   ({'changed' if state['head_hash_changed'] else 'same'})")
    print(f"  state_root:  {short_hash(state['from_state_root'])} -> {short_hash(state['to_state_root'])}"
          f"   ({'changed' if state['state_root_changed'] else 'same'})")
    print(f"  block_index: {state['from_block_index']} -> {state['to_block_index']}"
          f"   (delta = {signed(state['block_index_delta'])})")

def render_counters():
    print()
    print("Counters (A1 supply + aggregates):")
    rows = [
        ("accumulated_subsidy",  counters["from_accumulated_subsidy"],  counters["to_accumulated_subsidy"],  counters["accumulated_subsidy_delta"]),
        ("accumulated_inbound",  counters["from_accumulated_inbound"],  counters["to_accumulated_inbound"],  counters["accumulated_inbound_delta"]),
        ("accumulated_outbound", counters["from_accumulated_outbound"], counters["to_accumulated_outbound"], counters["accumulated_outbound_delta"]),
        ("accumulated_slashed",  counters["from_accumulated_slashed"],  counters["to_accumulated_slashed"],  counters["accumulated_slashed_delta"]),
        ("genesis_total",        counters["from_genesis_total"],        counters["to_genesis_total"],        counters["genesis_total_delta"]),
        ("live_total_supply",    counters["from_live_total_supply"],    counters["to_live_total_supply"],    counters["live_total_supply_delta"]),
        ("balance_sum",          counters["from_balance_sum"],          counters["to_balance_sum"],          counters["balance_sum_delta"]),
        ("stake_sum",            counters["from_stake_sum"],            counters["to_stake_sum"],            counters["stake_sum_delta"]),
    ]
    width = max(len(r[0]) for r in rows)
    for name, a, b, d in rows:
        marker = "" if a == b else "  <-- changed"
        print(f"  {name:<{width}}  {a} -> {b}   (delta = {signed(d)}){marker}")

def render_set(label, summary, added, removed, modified, primary_delta_field):
    print()
    print(f"{label.capitalize()}:")
    print(f"  +{summary['added']} added, -{summary['removed']} removed, ~{summary['modified']} modified")
    if account_detail and (added or removed or modified):
        # Compact per-domain listing. Cap each section at 50 entries to
        # avoid runaway output on large state — operators wanting the
        # full list should run with --json.
        CAP = 50
        def show(prefix, rows):
            for r in rows[:CAP]:
                d = r["domain"]
                if primary_delta_field is not None:
                    fv = r.get(f"from_{primary_delta_field}")
                    tv = r.get(f"to_{primary_delta_field}")
                    delta = r.get(f"{primary_delta_field}_delta")
                    print(f"    {prefix} {d}: {primary_delta_field} {fv} -> {tv} (delta = {signed(delta)})")
                else:
                    print(f"    {prefix} {d}")
            if len(rows) > CAP:
                print(f"    ... {len(rows) - CAP} more (use --json for full listing)")
        if added:    show("[+]", added)
        if removed:  show("[-]", removed)
        if modified: show("[~]", modified)

def render_params():
    print()
    print("Params (chain constants):")
    print(f"  block_subsidy:  {params['from_block_subsidy']} -> {params['to_block_subsidy']}"
          f"   ({'changed' if params['block_subsidy_changed'] else 'same'})")
    print(f"  min_stake:      {params['from_min_stake']} -> {params['to_min_stake']}"
          f"   ({'changed' if params['min_stake_changed'] else 'same'})")

def render_anomalies():
    print()
    if not anomalies:
        print("Anomalies: (none)")
        return
    print("Anomalies:")
    for a in anomalies:
        if a == "identical_snapshots":
            print(f"  [i] {a} (informational — both snapshots are byte-equivalent in state)")
        else:
            print(f"  [!] {a}")

def render_verdict():
    print()
    if all_identical:
        print("[OK] Snapshots are identical across every group.")
    elif real_anomalies:
        print(f"[X]  {len(real_anomalies)} anomaly(ies) detected — see anomalies block above.")
    else:
        print("[OK] Diff completed; no anomalies.")

header()
if group == "all" or group == "state":       render_state()
if group == "all" or group == "counters":    render_counters()
if group == "all" or group == "accounts":    render_set("accounts",    accounts,    acct_added, acct_removed, acct_modified, "balance")
if group == "all" or group == "stakes":      render_set("stakes",      stakes_set,  stk_added,  stk_removed,  stk_modified,  "locked")
if group == "all" or group == "registrants": render_set("registrants", registrants, reg_added,  reg_removed,  reg_modified,  None)
if group == "all" or group == "params":      render_params()
render_anomalies()
render_verdict()

sys.exit(exit_code)
PY
PY_RC=$?
exit "$PY_RC"
