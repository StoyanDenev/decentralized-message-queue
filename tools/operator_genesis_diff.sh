#!/usr/bin/env bash
# operator_genesis_diff.sh — READ-ONLY field-by-field diff between TWO
# local genesis.json files, focused on the consensus-critical parameters
# that MUST agree across a fleet before bootstrap.
#
# Why this tool exists:
#   Every node in a deployment must boot from a byte-identical genesis or
#   its computed genesis hash diverges and the HELLO handshake rejects the
#   peer. A single drifted field (a stale m_creators, a wrong chain_role,
#   a forgotten v2 activation-height gate) in one operator's copy is a
#   silent fleet-wide mismatch that only surfaces as "peer refused to
#   connect" at runtime. This tool catches that drift offline, before any
#   node starts, by diffing the two files on exactly the fields that move
#   the genesis identity:
#
#     * chain_id, chain_role, sharding (shard_id / initial_shard_count /
#       committee_region)
#     * committee size (m_creators / k_block_sigs) + bft_enabled
#     * timing (epoch_blocks) + merge/revert/grace thresholds
#     * subsidy params (block_subsidy / subsidy_mode / lottery multiplier /
#       subsidy_pool_initial / zeroth_pool_initial) + min_stake
#     * v2 activation heights (v2_7_f2_active_from_height)
#     * the identity counts verify-genesis surfaces (initial_creators,
#       initial_balances, genesis_message), plus the computed genesis_hash
#
#   Only DIFFERING fields are printed, followed by a single SAME / DIFFER
#   verdict. A matching genesis_hash with no field-level diff is SAME;
#   anything else is DIFFER.
#
# Both files are parsed read-only, twice:
#   1. `determ verify-genesis --in <file> --json` — the already-shipped
#      genesis parser. Surfaces the sane-bounds-validated core
#      (genesis_hash, chain_id, chain_role, shard_id, m_creators,
#      k_block_sigs, block_subsidy, min_stake, initial_shard_count,
#      bft_enabled, committee_region, initial_creators/balances counts,
#      genesis_message_is_default / _bytes).
#   2. A second raw-JSON read (via Python — the repo's genesis-parsing
#      tool of choice, mirroring operator_genesis_inspect.sh) for the
#      fields verify-genesis omits: subsidy_mode / lottery multiplier /
#      subsidy_pool_initial / zeroth_pool_initial, epoch_blocks, the
#      merge/revert/grace thresholds, and the v2 activation-height gates.
#
# Sibling positioning:
#   * operator_genesis_inspect.sh      — single-file human summary view.
#   * operator_genesis_dump.sh         — single-file full parameter dump.
#   * operator_genesis_verify_live.sh  — compares a running daemon's
#                                        chain-id RPC against a file hash.
#   * operator_genesis_diff.sh (this)  — TWO-FILE consensus-param diff.
#
# READ-ONLY: no RPC, no daemon, no cluster, no chain mutation. Pure file
# inspection of two local genesis JSONs.
#
# SKIP-with-PASS: in a minimal environment where the determ binary or a
# Python interpreter is unavailable, the script cannot parse the genesis.
# It then SKIPs (no-op) and exits 0 — never a hard fail — so it is a clean
# no-op in build-less checkouts. A missing input file is likewise treated
# as an advisory SKIP-with-PASS (the tool can't compare a file it can't
# read; that is an operator/input condition, not a tool failure).
#
# Output: the two genesis hashes, a field-by-field diff of ONLY the
# differing consensus-critical fields, then a SAME / DIFFER verdict, and
# finally a single terminal PASS:/FAIL: line.
#
# Usage:
#   tools/operator_genesis_diff.sh <genesis-a.json> <genesis-b.json>
#
# Exit codes:
#   0 — comparison completed (files SAME, OR files DIFFER — a detected
#       drift is reported, not an error), or SKIPped because a parser /
#       input file was unavailable
#   1 — real failure: verify-genesis rejected a (present, readable) file /
#       malformed JSON / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_genesis_diff.sh <genesis-a.json> <genesis-b.json>

READ-ONLY field-by-field diff of the consensus-critical parameters
between two local genesis.json files. No RPC, no daemon, no cluster —
pure file inspection. Catches fleet config drift / a mismatched genesis
before it causes a genesis-hash mismatch at the HELLO handshake.

Arguments:
  <genesis-a.json>   First genesis file.
  <genesis-b.json>   Second genesis file.

Options:
  -h, --help         Show this help.

Compares: chain_id, chain_role, sharding (shard_id / initial_shard_count
/ committee_region), committee size (m_creators / k_block_sigs) +
bft_enabled, timing (epoch_blocks + merge/revert/grace thresholds),
subsidy params (block_subsidy / subsidy_mode / lottery multiplier /
subsidy_pool_initial / zeroth_pool_initial) + min_stake, v2 activation
heights, identity counts (initial_creators / initial_balances /
genesis_message), and the computed genesis_hash. Only differing fields
are printed, followed by a SAME / DIFFER verdict.

Exit codes:
  0   comparison completed (SAME or DIFFER — drift is reported, not an
      error), or SKIP — no determ/Python parser, or an input file is
      unavailable
  1   verify-genesis rejected a present/readable file / malformed JSON /
      bad args
EOF
}

IN_A=""
IN_B=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "operator_genesis_diff: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)
      if [ -z "$IN_A" ]; then
        IN_A="$1"; shift
      elif [ -z "$IN_B" ]; then
        IN_B="$1"; shift
      else
        echo "operator_genesis_diff: unexpected extra argument: $1" >&2
        usage >&2; exit 1
      fi
      ;;
  esac
done

if [ -z "$IN_A" ] || [ -z "$IN_B" ]; then
  echo "operator_genesis_diff: two genesis file paths are required" >&2
  usage >&2
  exit 1
fi

cd "$(dirname "$0")/.."

# ── Parser availability gate (SKIP-with-PASS) ──────────────────────────────────
# The determ binary parses + sane-bounds-validates each genesis; Python
# performs the raw augmentation read + diff. If EITHER is unavailable we
# cannot produce a diff — but a missing build is not a failure of this
# tool, so SKIP (no-op) and exit 0. We must decide this BEFORE sourcing
# common.sh, because common.sh hard-exits when the determ binary is absent
# (which would defeat the no-op-SKIP contract in a build-less env).
PY=python
command -v python >/dev/null 2>&1 || PY=python3

DETERM_FOUND=0
if [ -n "${DETERM_BIN:-}" ] && [ -x "${DETERM_BIN}" ]; then
  DETERM_FOUND=1
elif [ -x "build/Release/determ.exe" ] || [ -x "build/determ.exe" ] \
  || [ -x "build/determ" ]            || [ -x "build/Release/determ" ]; then
  DETERM_FOUND=1
fi

if [ "$DETERM_FOUND" != "1" ] || ! command -v "$PY" >/dev/null 2>&1; then
  echo "  SKIP: need both the determ binary and a Python interpreter to"
  echo "        parse the genesis files; build with"
  echo "        cmake --build build --config Release --target determ"
  echo
  echo "  PASS: operator_genesis_diff (no-op skip)"
  exit 0
fi

# ── Input-file availability gate (SKIP-with-PASS / advisory) ────────────────────
# A genesis path that doesn't exist or isn't readable is an operator/input
# condition, not a tool failure. Per the SKIP-with-PASS contract we do NOT
# hard-fail in a minimal env: report it and exit 0 with a terminal PASS so
# the suite stays green. (verify-genesis rejecting a PRESENT, readable file
# is a different story — that IS a real failure, handled below.)
for label_path in "a:$IN_A" "b:$IN_B"; do
  label=${label_path%%:*}
  path=${label_path#*:}
  if [ ! -f "$path" ]; then
    echo "  SKIP: genesis file (--in-$label) not found: $path"
    echo
    echo "  PASS: operator_genesis_diff (no-op skip — input file unavailable)"
    exit 0
  fi
  if [ ! -r "$path" ]; then
    echo "  SKIP: genesis file (--in-$label) not readable: $path"
    echo
    echo "  PASS: operator_genesis_diff (no-op skip — input file unavailable)"
    exit 0
  fi
done

# Both parsers present and both files readable — safe to source common.sh.
source tools/common.sh

# ── Step 1: parsed + validated + hashed view for each file ─────────────────────
# verify-genesis applies parse + sane-bounds checks AND computes
# compute_genesis_hash. A successful return means the file is a deployable,
# sane-bounds-checked genesis. A rejection of a present, readable file is a
# REAL failure (malformed / out-of-bounds), so surface the diagnostic
# verbatim and fail.
VG_A=$("$DETERM" verify-genesis --in "$IN_A" --json 2>&1)
VG_A_RC=$?
if [ "$VG_A_RC" -ne 0 ]; then
  echo "  FAIL: verify-genesis rejected $IN_A (rc=$VG_A_RC)" >&2
  echo "$VG_A" >&2
  echo
  echo "  FAIL: operator_genesis_diff"
  exit 1
fi

VG_B=$("$DETERM" verify-genesis --in "$IN_B" --json 2>&1)
VG_B_RC=$?
if [ "$VG_B_RC" -ne 0 ]; then
  echo "  FAIL: verify-genesis rejected $IN_B (rc=$VG_B_RC)" >&2
  echo "$VG_B" >&2
  echo
  echo "  FAIL: operator_genesis_diff"
  exit 1
fi

# ── Step 2: render the diff via Python ─────────────────────────────────────────
# Python re-reads each raw file once for the fields verify-genesis omits
# (subsidy_mode/pools, epoch_blocks, merge thresholds, v2 heights), folds
# in the verify-genesis JSON, computes the field-by-field diff, prints
# ONLY the differing consensus-critical fields, and emits the SAME / DIFFER
# verdict plus the terminal PASS:/FAIL: line. Each side passes its file
# path + verify-genesis JSON on argv so there is exactly one raw parse pass
# per file.
"$PY" - "$IN_A" "$IN_B" "$VG_A" "$VG_B" <<'PY'
import json, sys

in_a    = sys.argv[1]
in_b    = sys.argv[2]
vg_a_raw = sys.argv[3]
vg_b_raw = sys.argv[4]

def hard_fail(msg):
    # Real failure (malformed JSON, bad parser output). Terminal verdict
    # is a single FAIL: line after a blank line so run_all.sh greps an
    # unambiguous failure marker.
    print(f"  FAIL: {msg}")
    print()
    print("  FAIL: operator_genesis_diff")
    sys.exit(1)

# ── verify-genesis outputs (already validated by the binary). ──────────────
try:
    vg_a = json.loads(vg_a_raw)
except Exception as e:
    hard_fail(f"verify-genesis(a) --json output not parseable: {e}")
try:
    vg_b = json.loads(vg_b_raw)
except Exception as e:
    hard_fail(f"verify-genesis(b) --json output not parseable: {e}")

if vg_a.get("status") != "ok":
    hard_fail(f"verify-genesis(a) status != ok: {vg_a_raw}")
if vg_b.get("status") != "ok":
    hard_fail(f"verify-genesis(b) status != ok: {vg_b_raw}")

# ── Raw file reads for the fields verify-genesis omits. ────────────────────
def load_raw(label, path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        hard_fail(f"cannot parse {path} ({label}) as JSON: {e}")
    if not isinstance(raw, dict):
        hard_fail(f"genesis root ({label}) is not a JSON object: {path}")
    return raw

raw_a = load_raw("a", in_a)
raw_b = load_raw("b", in_b)

# Soft accessor mirroring GenesisConfig::from_json defaults
# (include/determ/chain/genesis.hpp).
def g(raw, key, default):
    v = raw.get(key, default)
    return v if v is not None else default

ROLE_NAMES         = {0: "SINGLE", 1: "BEACON", 2: "SHARD"}
SUBSIDY_MODE_NAMES = {0: "FLAT", 1: "LOTTERY"}

# UINT64_MAX is the "never activate" sentinel for the v2 height gates.
UINT64_MAX = 18446744073709551615
def fmt_height(v):
    iv = int(v)
    if iv == 0:
        return "0 (active from genesis)"
    if iv == UINT64_MAX:
        return f"{iv} (sentinel: never)"
    return str(iv)

def extract(vg, raw):
    chain_role_int = int(vg.get("chain_role", 0))
    subsidy_int    = int(g(raw, "subsidy_mode", 0))
    # The v2 height fields are surfaced even when absent, defaulting to the
    # genesis.hpp default (0 = active from genesis) so a file that sets the
    # key and a file that omits it diff correctly against the implied value.
    fields = {
        # ── Identity ──────────────────────────────────────────────────────
        "genesis_hash":        vg.get("genesis_hash", ""),
        "chain_id":            vg.get("chain_id", ""),
        "chain_role":          "{} ({})".format(
                                   ROLE_NAMES.get(chain_role_int,
                                                  "UNKNOWN"),
                                   chain_role_int),
        "genesis_message_is_default":
                               bool(vg.get("genesis_message_is_default", True)),
        "genesis_message_bytes": int(vg.get("genesis_message_bytes", 0)),
        "initial_creators":    int(vg.get("initial_creators", 0)),
        "initial_balances":    int(vg.get("initial_balances", 0)),
        # ── Sharding ──────────────────────────────────────────────────────
        "shard_id":            int(vg.get("shard_id", 0)),
        "initial_shard_count": int(vg.get("initial_shard_count", 1)),
        "committee_region":    vg.get("committee_region", "") or "",
        # ── Committee / consensus ─────────────────────────────────────────
        "m_creators":          int(vg.get("m_creators", 3)),
        "k_block_sigs":        int(vg.get("k_block_sigs", 3)),
        "bft_enabled":         bool(vg.get("bft_enabled", True)),
        "bft_escalation_threshold": int(g(raw, "bft_escalation_threshold", 5)),
        # ── Timing ────────────────────────────────────────────────────────
        "epoch_blocks":          int(g(raw, "epoch_blocks", 1000)),
        "merge_threshold_blocks":  int(g(raw, "merge_threshold_blocks", 100)),
        "revert_threshold_blocks": int(g(raw, "revert_threshold_blocks", 200)),
        "merge_grace_blocks":      int(g(raw, "merge_grace_blocks", 10)),
        # ── Subsidy / economics ───────────────────────────────────────────
        "block_subsidy":       int(vg.get("block_subsidy", 0)),
        "subsidy_mode":        "{} ({})".format(
                                   SUBSIDY_MODE_NAMES.get(subsidy_int,
                                                          "UNKNOWN"),
                                   subsidy_int),
        "lottery_jackpot_multiplier": int(g(raw, "lottery_jackpot_multiplier", 0)),
        "subsidy_pool_initial":  int(g(raw, "subsidy_pool_initial", 0)),
        "zeroth_pool_initial":   int(g(raw, "zeroth_pool_initial", 0)),
        "min_stake":           int(vg.get("min_stake", 1000)),
        # ── v2 activation heights ─────────────────────────────────────────
        "v2_7_f2_active_from_height":
                               fmt_height(g(raw, "v2_7_f2_active_from_height", 0)),
    }
    return fields

a = extract(vg_a, raw_a)
b = extract(vg_b, raw_b)

# Field render order, grouped. genesis_hash is reported separately as the
# top-level identity verdict, so it is NOT in this per-field diff list.
FIELD_ORDER = [
    # Identity
    "chain_id", "chain_role",
    "genesis_message_is_default", "genesis_message_bytes",
    "initial_creators", "initial_balances",
    # Sharding
    "shard_id", "initial_shard_count", "committee_region",
    # Committee / consensus
    "m_creators", "k_block_sigs", "bft_enabled", "bft_escalation_threshold",
    # Timing
    "epoch_blocks", "merge_threshold_blocks",
    "revert_threshold_blocks", "merge_grace_blocks",
    # Subsidy / economics
    "block_subsidy", "subsidy_mode", "lottery_jackpot_multiplier",
    "subsidy_pool_initial", "zeroth_pool_initial", "min_stake",
    # v2 activation heights
    "v2_7_f2_active_from_height",
]

def fmt_val(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return f'"{v}"' if v == "" else v
    return str(v)

diffs = [(f, a[f], b[f]) for f in FIELD_ORDER if a[f] != b[f]]
hashes_match = (a["genesis_hash"] == b["genesis_hash"])

# ── Human render ───────────────────────────────────────────────────────────
print(f"=== Genesis diff (a={in_a}, b={in_b}) ===")
print("genesis_hash:")
print(f"  a: {a['genesis_hash']}")
print(f"  b: {b['genesis_hash']}")
print("  MATCH" if hashes_match else "  DIFFER")
print()

print("Consensus-critical field differences (only differing fields shown):")
if not diffs:
    print("  (none -- all compared fields identical)")
else:
    width = max(len(f) for f, _, _ in diffs)
    for f, va, vb in diffs:
        print(f"  {f:<{width}}  a={fmt_val(va)}  b={fmt_val(vb)}")
print()

# ── Verdict ────────────────────────────────────────────────────────────────
# SAME requires BOTH a matching genesis_hash AND zero field-level diffs.
# (They should coincide — S-039 binds these consensus params into the hash —
# but we assert both independently so a future field added to this diff but
# not yet bound into the hash can't silently report SAME.)
same = hashes_match and not diffs
if same:
    print("Verdict: SAME -- the two genesis files describe an identical chain.")
else:
    n = len(diffs)
    if not hashes_match:
        print(f"Verdict: DIFFER -- genesis_hash differs ({n} field-level "
              f"diff(s)); nodes booting from one will NOT federate with the "
              f"other.")
    else:
        # Hash matches but a compared field differs: a field this tool diffs
        # is not (yet) bound into compute_genesis_hash. Still a real drift.
        print(f"Verdict: DIFFER -- genesis_hash MATCHES but {n} compared "
              f"field(s) differ; investigate before deploying.")

# Terminal verdict line for the run_all.sh outcome contract. Both SAME and
# DIFFER are a successful COMPARISON (drift is reported, not a tool error),
# so the terminal marker is PASS either way. A single, unambiguous PASS:
# line is printed last, after a blank line.
print()
print("  PASS: operator_genesis_diff")
sys.exit(0)
PY
exit $?
