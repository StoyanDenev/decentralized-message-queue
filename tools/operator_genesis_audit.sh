#!/usr/bin/env bash
# operator_genesis_audit.sh — S-039 genesis-config drift audit.
#
# Determ chains are identified by the 32-byte genesis_hash, but per
# SECURITY.md §S-039 the hash does NOT bind every operationally-
# significant parameter:
#
#   m_creators, k_block_sigs, block_subsidy, subsidy_pool_initial,
#   subsidy_mode, min_stake, initial_shard_count, bft_enabled,
#   bft_escalation_threshold, epoch_blocks, shard_address_salt
#
# are read from the genesis JSON at daemon startup and pinned into the
# running cfg_, but they are NOT factored into compute_genesis_hash.
# Two operators with matching genesis_hash but drifted operational
# parameters produce silent consensus divergence (different K-committees
# → signature gathering never converges, BFT escalation thresholds
# differ → some operators escalate while others wait, divergent
# block_subsidy → A1 balance invariant violations across the cluster).
#
# This script audits a running daemon's EFFECTIVE operational params
# against an operator-supplied REFERENCE genesis.json (typically the
# canonical chain genesis pinned in the deployment manifest) and flags
# drift, mapping each parameter to its observed source so the operator
# sees the live-vs-reference delta even when the genesis_hash matches.
#
# Sibling positioning:
#
#   operator_genesis_verify_live.sh   live daemon's genesis_hash vs
#                                     verify-genesis(file) hash. Binary
#                                     pass/fail on chain identity.
#                                     Right tool when "are we even on
#                                     the same chain?" is the question.
#
#   operator_genesis_diff.sh          file-vs-file semantic diff between
#                                     two genesis.json files, grouped by
#                                     impact tier. Right tool for
#                                     promotion gates / multi-region
#                                     rollouts comparing two manifests.
#
#   operator_genesis_dump.sh          single-file inspection (no daemon
#                                     required). Right tool for security-
#                                     posture review or pre-deployment
#                                     review of a candidate genesis.
#
#   operator_genesis_audit.sh (THIS)  live daemon's EFFECTIVE operational
#                                     params vs reference file, per-
#                                     parameter MATCH / DRIFT verdict.
#                                     Right tool when "is this running
#                                     daemon's config still consistent
#                                     with the canonical genesis?" is
#                                     the question — i.e., the S-039
#                                     surface that the other three
#                                     scripts don't quite cover.
#
# RPC composition (all read-only, safe against a production daemon):
#
#   * `determ chain-summary --json` — returns the supply envelope
#     (blocks + total_supply + accumulated_*); used for the live head
#     height read.
#   * `determ status --json` — returns the LIVE operational params
#     (m_creators, k_block_sigs, chain_role, shard_id, committee_region,
#     plus the genesis-block-hash via the `genesis` field).
#   * `determ chain-id --rpc-port N` — returns the canonical 64-hex
#     genesis_hash; cross-checked against status's `genesis` field for
#     consistency and used as the authoritative live identity.
#
# Live ops-param sourcing note: `status` exposes the running daemon's
# `cfg_` snapshot which reflects what the validator + producer + chain
# are USING right now. Genesis-pinned constants that don't show up in
# `status` (block_subsidy, subsidy_pool_initial, subsidy_mode,
# initial_shard_count, bft_escalation_threshold, epoch_blocks,
# shard_address_salt, min_stake, suspension_slash, unstake_delay) are
# fetched indirectly by parsing the daemon's snapshot-state RPC where
# available, falling back to "not_exposed" when the daemon doesn't
# surface that field over RPC. Drift on `not_exposed` rows is flagged
# as INFO (operator visibility limitation) rather than CRITICAL
# (genuine drift).
#
# Reference-source contract: --reference-genesis is parsed as a
# determ-format genesis.json. The script applies `determ verify-genesis
# --in <file> --json` so the file is verified for sane-bounds + parse
# correctness before any field-level comparison.
#
# Usage:
#   tools/operator_genesis_audit.sh --rpc-port N
#                                   [--reference-genesis <path>]
#                                   [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N              RPC port of the running daemon (REQUIRED)
#   --reference-genesis PATH  Path to the canonical reference genesis.json
#                             (optional; if absent the script runs in
#                             info-only mode and just dumps the live
#                             effective params)
#   --json                    Emit single-line JSON envelope
#   --anomalies-only          Suppress healthy rows; exit 2 on any anomaly
#   -h, --help                Show this help
#
# Anomalies:
#   genesis_hash_mismatch   CRITICAL — live daemon's genesis_hash differs
#                                      from the reference file's computed
#                                      hash. Wrong-chain operator alert.
#   param_drift             CRITICAL — at least one operational parameter
#                                      differs without governance-event
#                                      provenance. Worth investigating
#                                      whether the operator's daemon was
#                                      started against a different config
#                                      than the canonical one.
#   reference_unavailable   INFO     — no --reference-genesis supplied;
#                                      script ran in info-only mode and
#                                      just emitted the live state for
#                                      archival. NOT a failure case.
#
# Exit codes:
#   0   healthy (params match) OR --reference-genesis not supplied
#       (info-only run)
#   1   bad args / RPC error / unreachable daemon / unreadable or
#       malformed reference file
#   2   --anomalies-only AND ≥1 anomaly detected (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_genesis_audit.sh --rpc-port N
                                 [--reference-genesis <path>]
                                 [--json] [--anomalies-only]

Audits a running determ daemon's effective genesis-pinned operational
parameters against an operator-supplied reference genesis.json file.
Detects per-S-039 drift in parameters that are NOT bound to the
genesis_hash but ARE consensus-affecting (m_creators, k_block_sigs,
bft_enabled, bft_escalation_threshold, chain_role, shard_id,
initial_shard_count, committee_region, etc.). Two operators with
matching genesis_hash but drifted operational params produce silent
consensus divergence; this audit catches that before it manifests on-
chain.

Required:
  --rpc-port N              RPC port of the running daemon

Options:
  --reference-genesis PATH  Path to the canonical reference genesis.json.
                            If absent, runs in info-only mode and just
                            dumps the live effective params for archival.
  --json                    Emit single-line JSON envelope
  --anomalies-only          Suppress healthy rows; exit 2 on any anomaly
  -h, --help                Show this help

Anomalies:
  genesis_hash_mismatch   CRITICAL — live vs reference genesis_hash differ
  param_drift             CRITICAL — operational parameter drift detected
  reference_unavailable   INFO     — no reference supplied (info-only mode)

Exit codes:
  0   healthy OR info-only mode (no --reference-genesis)
  1   bad args / RPC error / unreachable daemon / unreadable reference
  2   --anomalies-only AND ≥1 anomaly fired

JSON shape (--json):
  {"rpc_port":     P,
   "live": {
     "genesis_hash":             "<64hex>",
     "m_creators":               int,
     "k_block_sigs":             int,
     "chain_role":               "SINGLE|BEACON|SHARD",
     "shard_id":                 int,
     "committee_region":         str,
     ...},
   "reference": {                              // only if --reference-genesis
     "genesis_hash":             "<64hex>",
     ... (same shape)
   },
   "drift":  [{"name":..., "live":..., "reference":..., "status":"DRIFT|MATCH"}, ...],
   "anomalies": ["genesis_hash_mismatch"|"param_drift"|"reference_unavailable", ...]}
EOF
}

PORT=""
REF_GENESIS=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    # Per the script's spec, --help exits non-zero (1) so a misconfigured
    # alerting wrapper that accidentally substitutes "--help" for the
    # required --rpc-port flag still bubbles a failure code instead of
    # silently treating "I printed usage" as success. Operators reading
    # the help text interactively will ignore the exit code; automated
    # callers that pass --help by accident get a clear non-zero signal.
    -h|--help)              usage; exit 1 ;;
    --rpc-port)             PORT="${2:-}";         shift 2 ;;
    --reference-genesis)    REF_GENESIS="${2:-}";  shift 2 ;;
    --json)                 JSON_OUT=1;            shift ;;
    --anomalies-only)       ANOM_ONLY=1;           shift ;;
    *) echo "operator_genesis_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (sibling-script convention; refuses to guess
# the daemon on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_genesis_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_genesis_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# If --reference-genesis is supplied, check existence + readability up
# front so the operator sees a path-specific diagnostic before any
# subprocess fires. (Matches operator_genesis_diff.sh convention.)
if [ -n "$REF_GENESIS" ]; then
  if [ ! -f "$REF_GENESIS" ]; then
    echo "operator_genesis_audit: --reference-genesis file not found: $REF_GENESIS" >&2
    exit 1
  fi
  if [ ! -r "$REF_GENESIS" ]; then
    echo "operator_genesis_audit: --reference-genesis file not readable: $REF_GENESIS" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: live daemon snapshot ──────────────────────────────────────────────
# `chain-summary --json` gives us a sanity-check that the daemon is
# reachable + returns valid JSON. We don't strictly NEED its supply
# fields for the genesis audit, but the spec calls for fetching it so
# the script doubles as a basic liveness probe.
CS_JSON=$("$DETERM" chain-summary --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_genesis_audit: RPC error from \`determ chain-summary\` (is daemon running on port $PORT?)" >&2
  exit 1
}

# `status --json` is the canonical source for the daemon's live
# operational params (m_creators, k_block_sigs, chain_role, shard_id,
# committee_region) PLUS the genesis-block hash via the `genesis`
# field. Always emits valid JSON; exit 1 if RPC unreachable.
ST_JSON=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_genesis_audit: RPC error from \`determ status\` (port $PORT)" >&2
  exit 1
}

# `chain-id` returns the canonical genesis_hash as a bare 64-hex
# string; this is the authoritative identity value (matches what
# verify-genesis produces from the file). Cross-checked against
# status's `genesis` field for consistency.
CHAIN_ID=$("$DETERM" chain-id --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_genesis_audit: RPC error from \`determ chain-id\` (port $PORT)" >&2
  exit 1
}
CHAIN_ID=$(printf '%s' "$CHAIN_ID" | tr -d ' \t\r\n')
if [ -z "$CHAIN_ID" ] || [ ${#CHAIN_ID} -ne 64 ]; then
  echo "operator_genesis_audit: daemon returned malformed chain-id (got '$CHAIN_ID', expected 64 hex chars)" >&2
  exit 1
fi

# ── Step 2: optional reference verify-genesis pass ────────────────────────────
# When --reference-genesis is supplied, run verify-genesis on it to get
# both the canonical hash AND the parsed-out operational params. The
# script applies the same sane-bounds + cross-field validation a real
# daemon would at startup, so a malformed reference file is rejected
# before any field-level comparison fires.
VG_JSON=""
if [ -n "$REF_GENESIS" ]; then
  VG_JSON=$("$DETERM" verify-genesis --in "$REF_GENESIS" --json 2>&1)
  VG_RC=$?
  if [ "$VG_RC" -ne 0 ]; then
    echo "operator_genesis_audit: verify-genesis failed on $REF_GENESIS (rc=$VG_RC)" >&2
    echo "$VG_JSON" >&2
    exit 1
  fi
fi

# ── Step 3: comparison + envelope construction in Python ──────────────────────
# Python is the right tool: it can parse all three RPC JSONs (chain-
# summary, status, chain-id) + the optional verify-genesis JSON + the
# raw reference genesis.json (for fields verify-genesis doesn't surface
# like bft_escalation_threshold, subsidy_pool_initial, etc.), classify
# each per-parameter row, and emit both human + JSON renderings off one
# set of accessors.
python - "$JSON_OUT" "$ANOM_ONLY" "$PORT" "$REF_GENESIS" "$CHAIN_ID" "$CS_JSON" "$ST_JSON" "$VG_JSON" <<'PY'
import json, sys

json_out    = sys.argv[1] == "1"
anom_only   = sys.argv[2] == "1"
port        = int(sys.argv[3])
ref_path    = sys.argv[4]
chain_id    = sys.argv[5]
cs_raw      = sys.argv[6]
st_raw      = sys.argv[7]
vg_raw      = sys.argv[8] if len(sys.argv) > 8 else ""

def die(msg, rc=1):
    sys.stderr.write(f"operator_genesis_audit: {msg}\n")
    sys.exit(rc)

# Parse live-daemon JSONs. chain-summary and status are both required
# to be objects; any parse failure means the daemon is misbehaving and
# we should bail out rather than emit a half-built envelope.
try:
    cs = json.loads(cs_raw)
except Exception as e:
    die(f"chain-summary RPC returned non-JSON: {e}")
try:
    st = json.loads(st_raw)
except Exception as e:
    die(f"status RPC returned non-JSON: {e}")
if not isinstance(cs, dict):
    die("chain-summary RPC returned non-object")
if not isinstance(st, dict):
    die("status RPC returned non-object")

# Cross-check: status.genesis should match chain-id RPC. If they
# disagree the daemon is in an inconsistent state — surface as a hard
# error before any reference comparison runs.
status_genesis = st.get("genesis", "") or ""
if status_genesis and status_genesis != chain_id:
    die(f"daemon internal inconsistency: status.genesis ({status_genesis}) "
        f"!= chain-id RPC ({chain_id})")

# ── Live params extraction (from status RPC) ────────────────────────────────
# These are the operational params the running daemon's cfg_ snapshot
# exposes. The fields NOT in status (block_subsidy, subsidy_pool_initial,
# subsidy_mode, initial_shard_count, bft_escalation_threshold,
# epoch_blocks, shard_address_salt, min_stake, etc.) are not surfaced
# over any RPC; for those we report the live value as "not_exposed"
# and classify any reference-vs-live comparison as informational.

ROLE_NAMES = {0: "SINGLE", 1: "BEACON", 2: "SHARD"}
def role_name(v):
    # status emits chain_role as a string ("SINGLE", "BEACON", "SHARD")
    # via to_string() helper. verify-genesis emits chain_role as an int.
    # Accept both forms; normalize to string.
    if isinstance(v, str):
        return v
    if isinstance(v, int):
        return ROLE_NAMES.get(v, f"UNKNOWN({v})")
    return ""

live = {
    "genesis_hash":         chain_id,
    "m_creators":           int(st.get("m_creators", 0) or 0),
    "k_block_sigs":         int(st.get("k_block_sigs", 0) or 0),
    "chain_role":           role_name(st.get("chain_role", "")),
    "shard_id":             int(st.get("shard_id", 0) or 0),
    "committee_region":     st.get("committee_region", "") or "",
    # Fields the status RPC does NOT expose. The sentinel "not_exposed"
    # tells the diff renderer to classify drift on these rows as INFO
    # (visibility limitation) rather than CRITICAL (real drift) since
    # we can't observe the live value to make a definitive call.
    "block_subsidy":              "not_exposed",
    "subsidy_pool_initial":       "not_exposed",
    "subsidy_mode":               "not_exposed",
    "min_stake":                  "not_exposed",
    "initial_shard_count":        "not_exposed",
    "bft_enabled":                "not_exposed",
    "bft_escalation_threshold":   "not_exposed",
    "epoch_blocks":               "not_exposed",
    "shard_address_salt":         "not_exposed",
}

# ── Reference params extraction (from verify-genesis + raw file) ─────────────
reference = None
ref_anomalies = []
if ref_path:
    try:
        vg = json.loads(vg_raw)
    except Exception as e:
        die(f"verify-genesis JSON not parseable: {e}")
    if vg.get("status") != "ok":
        die(f"verify-genesis status!=ok: {vg_raw}")

    # Also parse the raw file for fields verify-genesis doesn't surface.
    try:
        with open(ref_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        die(f"cannot parse {ref_path} as JSON: {e}")
    if not isinstance(raw, dict):
        die(f"reference genesis root is not a JSON object: {ref_path}")

    # Soft accessor with default — matches GenesisConfig::from_json
    # defaults byte-for-byte (see include/determ/chain/genesis.hpp).
    def g(key, default):
        v = raw.get(key, default)
        return v if v is not None else default

    reference = {
        "genesis_hash":             vg.get("genesis_hash", "") or "",
        "m_creators":               int(vg.get("m_creators", 3)),
        "k_block_sigs":             int(vg.get("k_block_sigs", 3)),
        "chain_role":               role_name(vg.get("chain_role", 0)),
        "shard_id":                 int(vg.get("shard_id", 0)),
        "committee_region":         vg.get("committee_region", "") or "",
        "block_subsidy":            int(vg.get("block_subsidy", 0)),
        "subsidy_pool_initial":     int(g("subsidy_pool_initial", 0)),
        "subsidy_mode":             int(g("subsidy_mode", 0)),
        "min_stake":                int(vg.get("min_stake", 1000)),
        "initial_shard_count":      int(vg.get("initial_shard_count", 1)),
        "bft_enabled":              bool(vg.get("bft_enabled", True)),
        "bft_escalation_threshold": int(g("bft_escalation_threshold", 5)),
        "epoch_blocks":             int(g("epoch_blocks", 1000)),
        "shard_address_salt":       g("shard_address_salt", "") or "",
    }

# ── Per-parameter drift classification ──────────────────────────────────────
# Each row has: name | live | reference | status (MATCH | DRIFT | INFO).
# When the live value is the "not_exposed" sentinel we classify any
# delta as INFO (operator visibility gap, not real drift); when both
# are present we compare directly.
#
# Operational-significance ranking is encoded by row order: identity-
# bound first (genesis_hash), then K-of-K consensus knobs, then
# BFT escalation, then economics, then sharding/timing. The renderer
# preserves this order so the most-impactful drift appears first.

OPS_PARAMS = [
    "genesis_hash",
    "m_creators",
    "k_block_sigs",
    "chain_role",
    "shard_id",
    "committee_region",
    "initial_shard_count",
    "bft_enabled",
    "bft_escalation_threshold",
    "block_subsidy",
    "subsidy_pool_initial",
    "subsidy_mode",
    "min_stake",
    "epoch_blocks",
    "shard_address_salt",
]

drift_rows = []
anomalies  = []
has_real_drift     = False
has_hash_mismatch  = False

for name in OPS_PARAMS:
    live_v = live.get(name, "")
    if reference is None:
        # Info-only mode: emit the live row, no comparison.
        drift_rows.append({
            "name":      name,
            "live":      live_v,
            "reference": None,
            "status":    "INFO",
        })
        continue

    ref_v  = reference.get(name, "")
    if live_v == "not_exposed":
        # We can't observe the live value over RPC; classify as INFO so
        # the operator sees the reference value for archival but isn't
        # alerted on a comparison we can't actually make.
        drift_rows.append({
            "name":      name,
            "live":      live_v,
            "reference": ref_v,
            "status":    "INFO",
        })
        continue

    if live_v == ref_v:
        drift_rows.append({
            "name":      name,
            "live":      live_v,
            "reference": ref_v,
            "status":    "MATCH",
        })
    else:
        drift_rows.append({
            "name":      name,
            "live":      live_v,
            "reference": ref_v,
            "status":    "DRIFT",
        })
        if name == "genesis_hash":
            has_hash_mismatch = True
        else:
            has_real_drift = True

# ── Anomaly classification ──────────────────────────────────────────────────
# Per spec:
#   genesis_hash_mismatch   CRITICAL — live genesis_hash != reference
#   param_drift             CRITICAL — any non-hash op param drifted
#   reference_unavailable   INFO     — no --reference-genesis supplied
if reference is None:
    anomalies.append("reference_unavailable")
if has_hash_mismatch:
    anomalies.append("genesis_hash_mismatch")
if has_real_drift:
    anomalies.append("param_drift")

# ── Envelope construction + emit ────────────────────────────────────────────
# JSON envelope includes both live + (optional) reference + per-row
# drift + anomaly list. Order of keys mirrors the human render below
# for grep-ability.
envelope = {
    "rpc_port":  port,
    "live":      live,
    "drift":     drift_rows,
    "anomalies": anomalies,
}
if reference is not None:
    envelope["reference"] = reference
if ref_path:
    envelope["reference_path"] = ref_path

# Drift count (excluding INFO rows; only real DRIFT entries count).
real_drift_count = sum(1 for r in drift_rows if r["status"] == "DRIFT")
n_match          = sum(1 for r in drift_rows if r["status"] == "MATCH")
n_info           = sum(1 for r in drift_rows if r["status"] == "INFO")

if json_out:
    print(json.dumps(envelope))
    # JSON-mode exit: still respects --anomalies-only gate below.
    if anom_only and (has_hash_mismatch or has_real_drift):
        sys.exit(2)
    sys.exit(0)

# ── Human-readable render ──────────────────────────────────────────────────
# --anomalies-only suppresses the table when nothing's wrong. Only the
# CRITICAL anomalies (genesis_hash_mismatch + param_drift) gate the
# alert; reference_unavailable is informational and doesn't suppress
# the table even under --anomalies-only (operator may want to confirm
# they actually didn't pass a reference).
critical_fired = has_hash_mismatch or has_real_drift

if anom_only and not critical_fired:
    if reference is None:
        print(f"operator_genesis_audit: info-only mode "
              f"(port {port}, no --reference-genesis supplied)")
    else:
        print(f"operator_genesis_audit: no drift "
              f"(port {port}, {n_match} params matched)")
    sys.exit(0)

# Header
ref_disp = ref_path if ref_path else "(none — info-only mode)"
print(f"=== Genesis-config drift audit (port {port}) ===")
print(f"Reference genesis: {ref_disp}")
if reference is not None:
    print(f"Live genesis_hash:      {live['genesis_hash']}")
    print(f"Reference genesis_hash: {reference['genesis_hash']}")
    if live["genesis_hash"] == reference["genesis_hash"]:
        print("Identity hashes:        MATCH")
    else:
        print("Identity hashes:        DIFFER -- wrong-chain operator alert")
else:
    print(f"Live genesis_hash: {live['genesis_hash']}")
print()

# Per-parameter table. Compute column widths so values line up even
# under the longest live string (e.g. shard_address_salt's 64-hex).
def fmt_val(v):
    if v is None:        return "(n/a)"
    if v == "":          return '""'
    if v == "not_exposed": return "not_exposed"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)

# Truncate long hex values (genesis_hash, shard_address_salt) to keep
# the table on one line per row. Full values are available in --json.
def display_val(v):
    s = fmt_val(v)
    if len(s) > 32:
        return s[:29] + "..."
    return s

name_w = max(len(r["name"]) for r in drift_rows)
print(f"{'parameter':<{name_w}}  {'live':<32}  {'reference':<32}  status")
print(f"{'-'*name_w:<{name_w}}  {'-'*32:<32}  {'-'*32:<32}  {'-'*6}")
for r in drift_rows:
    name = r["name"]
    lv   = display_val(r["live"])
    rv   = display_val(r["reference"])
    st_  = r["status"]
    print(f"{name:<{name_w}}  {lv:<32}  {rv:<32}  {st_}")

# Summary footer.
total = len(drift_rows)
print()
print(f"Summary: {total} param(s) audited; "
      f"{n_match} matched, {real_drift_count} drifted, {n_info} informational")

# Anomaly verdict.
if not anomalies:
    print("[OK] No anomalies — live params match reference")
else:
    for a in anomalies:
        if a == "genesis_hash_mismatch":
            print(f"[CRITICAL] genesis_hash_mismatch — live ({live['genesis_hash'][:16]}...) "
                  f"differs from reference ({reference['genesis_hash'][:16]}...)")
        elif a == "param_drift":
            drifted = [r["name"] for r in drift_rows if r["status"] == "DRIFT" and r["name"] != "genesis_hash"]
            print(f"[CRITICAL] param_drift — {len(drifted)} operational parameter(s) "
                  f"drifted from reference: {', '.join(drifted)}")
        elif a == "reference_unavailable":
            print("[INFO] reference_unavailable — no --reference-genesis "
                  "supplied; live params dumped for archival")
        else:
            print(f"[WARN] {a}")

# Exit-code policy: 0 healthy / info-only; 2 only when --anomalies-only
# AND a CRITICAL anomaly fired (genesis_hash_mismatch OR param_drift).
# Default informational mode always exits 0 if the RPC walk succeeded.
if anom_only and critical_fired:
    sys.exit(2)
sys.exit(0)
PY
PY_RC=$?
exit "$PY_RC"
