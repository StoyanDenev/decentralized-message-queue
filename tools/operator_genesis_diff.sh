#!/usr/bin/env bash
# operator_genesis_diff.sh — Semantic diff between two genesis.json files.
#
# Compares two local genesis configs field-by-field and classifies the
# differences by impact tier:
#
#   * Identity-affecting — fields bound to compute_genesis_hash (chain_id,
#     chain_role, shard_id, initial_creators, initial_balances,
#     committee_region, genesis_message, etc.). Any diff here means the
#     two configs describe distinct chains; nodes started from one cannot
#     federate with nodes started from the other.
#
#   * Consensus-affecting — operational params that drive block-
#     production semantics (m_creators, k_block_sigs, bft_enabled,
#     bft_escalation_threshold, governance_mode + param_threshold +
#     param_keyholders). Per S-039 these do NOT contribute to the
#     identity hash but they DO change how a node behaves; mismatched
#     consensus params across operators leads to silent forks even when
#     both nodes "agree" on the genesis hash.
#
#   * Economic — block_subsidy, suspension_slash, min_stake,
#     unstake_delay, subsidy_pool_initial, subsidy_mode + lottery
#     multiplier, zeroth_pool_initial, inclusion_model. Changing any
#     between deployments rewrites the economic contract.
#
#   * Operational — epoch_blocks, merge_threshold_blocks,
#     revert_threshold_blocks, merge_grace_blocks, shard_address_salt.
#     Diffs here typically signal a deployment-template drift rather
#     than a real economic / consensus change.
#
# Why not just `diff a.json b.json`? Byte-for-byte diff is noisy:
#   * Key-order is incidental (JSON object members are unordered).
#   * Whitespace / trailing newlines / quoting style vary across
#     editors.
#   * A renamed `param_threshold` from 2 → 3 looks identical (visually)
#     to a renamed `block_subsidy` from 50 → 51, but operationally one
#     is a governance change while the other is an economic change.
# This script normalizes both files through verify-genesis and JSON
# parsing, then renders the diff grouped by impact tier with explicit
# severity classification.
#
# Sibling positioning:
#   * operator_genesis_verify_live.sh — daemon vs file (chain-id RPC).
#   * operator_genesis_dump.sh        — single-file inspection.
#   * operator_genesis_diff.sh (this) — two-file semantic comparison.
#
# Use cases:
#   1. Promotion gate — diff staging vs prod genesis before promoting
#      a release. Identity-affecting diffs MUST be intentional; the
#      script's --strict flag turns identity divergence into an
#      operator alert (exit 2).
#   2. Multi-region rollout — compare per-region genesis templates to
#      confirm only the region-specific fields (committee_region,
#      shard_id) differ; everything else should be identical.
#   3. Post-incident forensics — diff the genesis a node actually
#      shipped against the canonical deployment manifest to spot
#      configuration drift.
#   4. Governance review — confirm a proposed genesis change touches
#      only the intended fields (e.g., a min_stake bump should NOT
#      also flip bft_enabled).
#
# Exit codes:
#   0   identical genesis_hash AND no differences in any tier
#   2   any diff detected (or hash mismatch with --strict)
#   1   file missing / unreadable / verify-genesis error / bad args
#
# Output formats:
#   default — human-readable, grouped by tier
#   --json  — single-line JSON envelope with all detected diffs and
#             computed identity hashes
set -u

usage() {
  cat <<'EOF'
Usage: operator_genesis_diff.sh --in-a <file> --in-b <file>
                                [--json] [--strict]

Semantically diffs two local genesis.json files. Differences are
grouped by impact tier:
  * Identity-affecting   (chain_id, chain_role, initial_creators, ...)
  * Consensus-affecting  (m_creators, k_block_sigs, bft_enabled, ...)
  * Economic            (block_subsidy, min_stake, unstake_delay, ...)
  * Operational         (epoch_blocks, merge_threshold_blocks, ...)

Required:
  --in-a <file>     First genesis.json to compare
  --in-b <file>     Second genesis.json to compare

Options:
  --json            Emit single-line JSON envelope instead of human text
  --strict          Exit 2 when genesis_hash differs (default also
                    exits 2 on diffs of any kind, but --strict frames
                    the diagnostic around the identity-hash divergence
                    as an operator alert specifically)
  -h, --help        Show this help

Exit codes:
  0   identical genesis_hash AND no field-level differences
  2   any diff detected (or genesis_hash mismatch with --strict)
  1   file missing / unreadable / malformed / verify-genesis error /
      bad args

JSON shape (--json):
  {"status":              "ok|differ",
   "a_path":              "<path>",
   "b_path":              "<path>",
   "a_genesis_hash":      "<64hex>",
   "b_genesis_hash":      "<64hex>",
   "hashes_match":        true|false,
   "identity_diffs":      [{"field":"...","a":...,"b":...}, ...],
   "consensus_diffs":     [{"field":"...","a":...,"b":...}, ...],
   "economic_diffs":      [{"field":"...","a":...,"b":...,
                            "delta_pct": <signed-float-or-null>}, ...],
   "operational_diffs":   [{"field":"...","a":...,"b":...}, ...],
   "total_diffs":         <int>,
   "strict":              true|false}

Use cases:
  1. Promotion gate — diff staging vs prod genesis before promoting.
  2. Multi-region rollout — confirm only region-specific fields differ.
  3. Post-incident forensics — verify shipped genesis against manifest.
  4. Governance review — confirm a proposed change touches only the
     intended fields.
EOF
}

IN_A=""
IN_B=""
JSON_OUT=0
STRICT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)  usage; exit 0 ;;
    --in-a)     IN_A="$2"; shift 2 ;;
    --in-b)     IN_B="$2"; shift 2 ;;
    --json)     JSON_OUT=1; shift ;;
    --strict)   STRICT=1; shift ;;
    *) echo "operator_genesis_diff: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$IN_A" ] || [ -z "$IN_B" ]; then
  echo "operator_genesis_diff: --in-a <file> and --in-b <file> are required" >&2
  usage >&2
  exit 1
fi

# Existence + readability checks BEFORE invoking the binary so the
# operator gets a path-specific diagnostic, not a generic "cannot_open"
# from verify-genesis.
for label_path in "a:$IN_A" "b:$IN_B"; do
  label=${label_path%%:*}
  path=${label_path#*:}
  if [ ! -f "$path" ]; then
    echo "operator_genesis_diff: --in-$label file not found: $path" >&2
    exit 1
  fi
  if [ ! -r "$path" ]; then
    echo "operator_genesis_diff: --in-$label file not readable: $path" >&2
    exit 1
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── 1. Compute parsed + hashed view for each file via verify-genesis ──
# verify-genesis applies parse + sane-bounds checks AND computes
# compute_genesis_hash. A successful return means the file is a
# deployable genesis. Otherwise we surface the diagnostic verbatim.
VG_A=$("$DETERM" verify-genesis --in "$IN_A" --json 2>&1)
VG_A_RC=$?
if [ "$VG_A_RC" -ne 0 ]; then
  echo "operator_genesis_diff: verify-genesis failed on $IN_A (rc=$VG_A_RC)" >&2
  echo "$VG_A" >&2
  exit 1
fi

VG_B=$("$DETERM" verify-genesis --in "$IN_B" --json 2>&1)
VG_B_RC=$?
if [ "$VG_B_RC" -ne 0 ]; then
  echo "operator_genesis_diff: verify-genesis failed on $IN_B (rc=$VG_B_RC)" >&2
  echo "$VG_B" >&2
  exit 1
fi

# ── 2. Drive the diff in Python ──────────────────────────────────────
# Python is the right tool: it can parse both files once for the raw
# fields verify-genesis omits (governance, sharding salts, full
# creator/balance arrays, timing thresholds), classify each diff by
# tier, compute relative deltas for the economic tier, and emit both
# human + JSON renderings off one set of accessors.
python - "$IN_A" "$IN_B" "$JSON_OUT" "$STRICT" "$VG_A" "$VG_B" <<'PY'
import json, sys

in_a    = sys.argv[1]
in_b    = sys.argv[2]
json_out = sys.argv[3] == "1"
strict  = sys.argv[4] == "1"
vg_a_raw = sys.argv[5]
vg_b_raw = sys.argv[6]

def die(msg):
    sys.stderr.write(f"operator_genesis_diff: {msg}\n")
    sys.exit(1)

# Parse verify-genesis outputs.
try:
    vg_a = json.loads(vg_a_raw)
except Exception as e:
    die(f"verify-genesis(a) JSON not parseable: {e}")
try:
    vg_b = json.loads(vg_b_raw)
except Exception as e:
    die(f"verify-genesis(b) JSON not parseable: {e}")

if vg_a.get("status") != "ok":
    die(f"verify-genesis(a) status!=ok: {vg_a_raw}")
if vg_b.get("status") != "ok":
    die(f"verify-genesis(b) status!=ok: {vg_b_raw}")

# Parse raw files for fields verify-genesis omits (governance,
# subsidy_mode, suspension_slash, unstake_delay, epoch_blocks, merge
# thresholds, shard_address_salt, full initial_creators[] +
# initial_balances[] arrays, inclusion_model).
def load_raw(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        die(f"cannot parse {path} as JSON: {e}")

raw_a = load_raw(in_a)
raw_b = load_raw(in_b)
if not isinstance(raw_a, dict):
    die(f"genesis root not a JSON object: {in_a}")
if not isinstance(raw_b, dict):
    die(f"genesis root not a JSON object: {in_b}")

# Soft accessor with default. Matches GenesisConfig::from_json defaults.
def g(raw, key, default):
    v = raw.get(key, default)
    return v if v is not None else default

# ── Field extraction ────────────────────────────────────────────────
# Two-source rule: identity-bound fields come from verify-genesis
# (canonical); everything else from raw JSON with explicit defaults
# that match the C++ from_json defaults byte-for-byte.

ROLE_NAMES = {0: "SINGLE", 1: "BEACON", 2: "SHARD"}
SUBSIDY_MODE_NAMES = {0: "FLAT", 1: "LOTTERY"}
INCLUSION_NAMES = {0: "stake-inclusion", 1: "domain-inclusion"}
GOV_NAMES = {0: "uncontrolled", 1: "governed"}

def role_name(i):
    return ROLE_NAMES.get(int(i), f"UNKNOWN({i})")

def extract(vg, raw, path):
    chain_role_int = int(vg.get("chain_role", 0))
    inclusion_int  = int(g(raw, "inclusion_model", 0))
    subsidy_int    = int(g(raw, "subsidy_mode", 0))
    gov_int        = int(g(raw, "governance_mode", 0))

    # Param threshold default = N under governed mode (matches genesis.cpp).
    pkh = g(raw, "param_keyholders", [])
    if not isinstance(pkh, list):
        pkh = []
    pth = int(g(raw, "param_threshold", 0))
    if gov_int == 1 and pth == 0:
        pth = len(pkh)

    # initial_creators[] and initial_balances[] need to be diffed by
    # canonicalized content, not order — they're set-like (no semantic
    # significance to the order of entries in the JSON array).
    ic = g(raw, "initial_creators", [])
    if not isinstance(ic, list):
        ic = []
    ib = g(raw, "initial_balances", [])
    if not isinstance(ib, list):
        ib = []

    def canon_creator(c):
        if not isinstance(c, dict):
            return None
        return (c.get("domain", ""),
                c.get("region", "") or "",
                int(c.get("initial_stake", 0)))

    def canon_balance(b):
        if not isinstance(b, dict):
            return None
        return (b.get("domain", ""), int(b.get("balance", 0)))

    creators_canon = sorted([t for t in (canon_creator(c) for c in ic) if t is not None])
    balances_canon = sorted([t for t in (canon_balance(b) for b in ib) if t is not None])

    return {
        # Identity (verify-genesis sourced for the hashed ones)
        "genesis_hash":           vg.get("genesis_hash", ""),
        "chain_id":               vg.get("chain_id", ""),
        "chain_role":             role_name(chain_role_int),
        "shard_id":               int(vg.get("shard_id", 0)),
        "initial_shard_count":    int(vg.get("initial_shard_count", 1)),
        "committee_region":       vg.get("committee_region", "") or "",
        "genesis_message_is_default": bool(vg.get("genesis_message_is_default", True)),
        "genesis_message_bytes":  int(vg.get("genesis_message_bytes", 0)),
        "initial_creators":       creators_canon,
        "initial_balances":       balances_canon,
        "shard_address_salt":     g(raw, "shard_address_salt", "") or "",

        # Consensus
        "m_creators":             int(vg.get("m_creators", 3)),
        "k_block_sigs":           int(vg.get("k_block_sigs", 3)),
        "bft_enabled":            bool(vg.get("bft_enabled", True)),
        "bft_escalation_threshold": int(g(raw, "bft_escalation_threshold", 5)),
        "governance_mode":        GOV_NAMES.get(gov_int, f"UNKNOWN({gov_int})"),
        "param_keyholders":       sorted([str(k) for k in pkh]),
        "param_threshold":        pth,

        # Economic
        "block_subsidy":          int(vg.get("block_subsidy", 0)),
        "subsidy_pool_initial":   int(g(raw, "subsidy_pool_initial", 0)),
        "subsidy_mode":           SUBSIDY_MODE_NAMES.get(subsidy_int, f"UNKNOWN({subsidy_int})"),
        "lottery_jackpot_multiplier": int(g(raw, "lottery_jackpot_multiplier", 0)),
        "zeroth_pool_initial":    int(g(raw, "zeroth_pool_initial", 0)),
        "min_stake":              int(vg.get("min_stake", 1000)),
        "suspension_slash":       int(g(raw, "suspension_slash", 10)),
        "unstake_delay":          int(g(raw, "unstake_delay", 1000)),
        "inclusion_model":        INCLUSION_NAMES.get(inclusion_int, f"UNKNOWN({inclusion_int})"),

        # Operational
        "epoch_blocks":           int(g(raw, "epoch_blocks", 1000)),
        "merge_threshold_blocks": int(g(raw, "merge_threshold_blocks", 100)),
        "revert_threshold_blocks": int(g(raw, "revert_threshold_blocks", 200)),
        "merge_grace_blocks":     int(g(raw, "merge_grace_blocks", 10)),
    }

a = extract(vg_a, raw_a, in_a)
b = extract(vg_b, raw_b, in_b)

# ── Tier definitions ────────────────────────────────────────────────
# Each tier lists the fields it owns. Fields NOT in any tier are not
# diffed (e.g., genesis_hash itself — it's emitted separately as the
# top-level identity verdict).
IDENTITY_FIELDS = [
    "chain_id", "chain_role", "shard_id", "initial_shard_count",
    "committee_region", "genesis_message_is_default",
    "genesis_message_bytes", "initial_creators", "initial_balances",
    "shard_address_salt",
]
CONSENSUS_FIELDS = [
    "m_creators", "k_block_sigs", "bft_enabled",
    "bft_escalation_threshold", "governance_mode",
    "param_keyholders", "param_threshold",
]
ECONOMIC_FIELDS = [
    "block_subsidy", "subsidy_pool_initial", "subsidy_mode",
    "lottery_jackpot_multiplier", "zeroth_pool_initial",
    "min_stake", "suspension_slash", "unstake_delay",
    "inclusion_model",
]
OPERATIONAL_FIELDS = [
    "epoch_blocks", "merge_threshold_blocks",
    "revert_threshold_blocks", "merge_grace_blocks",
]

def make_diff(field, va, vb, want_delta=False):
    if va == vb:
        return None
    entry = {"field": field, "a": va, "b": vb}
    if want_delta:
        # Compute signed relative delta from a → b as a percentage,
        # rounded to 2 decimals. Skip if either side is non-numeric or
        # if a == 0 (delta undefined / infinite).
        try:
            na = float(va); nb = float(vb)
            if na == 0.0:
                entry["delta_pct"] = None  # undefined relative to zero
            else:
                entry["delta_pct"] = round((nb - na) / na * 100.0, 2)
        except (TypeError, ValueError):
            entry["delta_pct"] = None
    return entry

identity_diffs    = [d for d in (make_diff(f, a[f], b[f])              for f in IDENTITY_FIELDS)    if d is not None]
consensus_diffs   = [d for d in (make_diff(f, a[f], b[f])              for f in CONSENSUS_FIELDS)   if d is not None]
economic_diffs    = [d for d in (make_diff(f, a[f], b[f], True)        for f in ECONOMIC_FIELDS)    if d is not None]
operational_diffs = [d for d in (make_diff(f, a[f], b[f])              for f in OPERATIONAL_FIELDS) if d is not None]

total_diffs = len(identity_diffs) + len(consensus_diffs) + len(economic_diffs) + len(operational_diffs)
hashes_match = (a["genesis_hash"] == b["genesis_hash"])
status = "ok" if (hashes_match and total_diffs == 0) else "differ"

# ── Helpers for human-readable rendering ────────────────────────────
def short_hash(h, n=12):
    if not isinstance(h, str) or len(h) < n:
        return h or ""
    return h[:n] + "..."

def fmt_val(v):
    # Render values compactly. Lists print as "<N entries>" with the
    # entries appended on next-line(s) when small enough to be useful.
    if isinstance(v, list):
        return f"<{len(v)} entries>"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        # Quote empty strings explicitly so a "blank == blank" looks
        # different from a "blank vs '0'".
        return f'"{v}"' if v != "" else '""'
    return str(v)

def render_section(title, diffs, with_delta=False):
    if not diffs:
        print(f"{title}:")
        print(f"  (none)")
        return
    print(f"{title}:")
    # Compute longest field name for left-aligned columns within the
    # section, so the values line up cleanly.
    width = max(len(d["field"]) for d in diffs)
    for d in diffs:
        f = d["field"]
        a_v = fmt_val(d["a"])
        b_v = fmt_val(d["b"])
        line = f"  {f:<{width}}  a={a_v}  b={b_v}"
        if with_delta and d.get("delta_pct") is not None:
            sign = "+" if d["delta_pct"] >= 0 else ""
            line += f"  (delta: {sign}{d['delta_pct']}%)"
        elif with_delta:
            line += "  (delta: n/a)"
        print(line)
        # For list-valued fields, show the actual symmetric difference
        # so the operator can see which entries were added/removed.
        if isinstance(d["a"], list) and isinstance(d["b"], list):
            sa = set(map(tuple, d["a"])) if d["a"] and isinstance(d["a"][0], (list, tuple)) else set(d["a"])
            sb = set(map(tuple, d["b"])) if d["b"] and isinstance(d["b"][0], (list, tuple)) else set(d["b"])
            only_a = sa - sb
            only_b = sb - sa
            for item in sorted(only_a):
                print(f"    only-in-a: {item}")
            for item in sorted(only_b):
                print(f"    only-in-b: {item}")

# ── JSON emit ───────────────────────────────────────────────────────
if json_out:
    out = {
        "status":               status,
        "a_path":               in_a,
        "b_path":               in_b,
        "a_genesis_hash":       a["genesis_hash"],
        "b_genesis_hash":       b["genesis_hash"],
        "hashes_match":         hashes_match,
        "identity_diffs":       identity_diffs,
        "consensus_diffs":      consensus_diffs,
        "economic_diffs":       economic_diffs,
        "operational_diffs":    operational_diffs,
        "total_diffs":          total_diffs,
        "strict":               strict,
    }
    print(json.dumps(out))
else:
    # ── Human render ────────────────────────────────────────────────
    print(f"=== Genesis diff (a={in_a}, b={in_b}) ===")
    print("Identity hashes:")
    print(f"  a: {a['genesis_hash']}")
    print(f"  b: {b['genesis_hash']}")
    if hashes_match:
        print("  MATCH")
    else:
        print("  DIFFER -- see below")
    render_section("Identity-affecting differences",  identity_diffs)
    render_section("Consensus-affecting differences", consensus_diffs)
    render_section("Economic differences",            economic_diffs, with_delta=True)
    render_section("Operational differences",         operational_diffs)
    print()
    # Verdict line — sums up the outcome in one human-readable sentence.
    if hashes_match and total_diffs == 0:
        print("[OK] Genesis configs are semantically identical")
    elif not hashes_match:
        print(f"[X] Genesis hashes differ -- chain identity is distinct ({total_diffs} field-level diffs total)")
    else:
        # Hashes match (same chain identity) but operational params
        # differ. This is the S-039 surface: same identity, different
        # behavior. Worth a distinct verdict.
        print(f"[!] Genesis hashes MATCH but {total_diffs} non-identity field(s) differ "
              "-- operators on this chain will diverge silently (S-039)")

# ── Exit code ───────────────────────────────────────────────────────
# 0 only when fully identical. 2 on any diff (or hash mismatch when
# --strict). The two conditions overlap because a hash diff always
# implies a field-level diff in the identity tier; --strict simply
# frames the alert around the identity-hash divergence specifically.
if hashes_match and total_diffs == 0:
    sys.exit(0)
if strict and not hashes_match:
    sys.exit(2)
sys.exit(2)
PY
PY_RC=$?
exit "$PY_RC"
