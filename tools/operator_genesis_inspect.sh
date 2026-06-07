#!/usr/bin/env bash
# operator_genesis_inspect.sh — READ-ONLY human-readable summary of a
# local genesis.json file: chain identity, role + sharding config,
# committee size (M/K), timing profile, supply parameters, and v2
# activation heights (when present).
#
# Local-file tool. No RPC, no running cluster, no chain mutation. The
# file is parsed twice, read-only:
#   1. `determ verify-genesis --in <file> --json` — the already-shipped
#      genesis parser. Surfaces the sane-bounds-validated core (chain_id,
#      chain_role, shard_id, m_creators / k_block_sigs, block_subsidy,
#      min_stake, initial_shard_count, bft_enabled, committee_region).
#   2. A second raw-JSON read (via Python — the repo's genesis-parsing
#      tool of choice, mirroring operator_genesis_dump.sh) for the fields
#      verify-genesis omits: subsidy_mode / subsidy_pool_initial /
#      zeroth_pool_initial, epoch_blocks, the per-balance supply total,
#      and the v2 activation-height gates (v2_7_f2_active_from_height,
#      v2_10_active_from_height) when those keys are present.
#
# Sibling positioning:
#   * operator_genesis_dump.sh         — full parameter dump / compact /
#                                        security-posture; this script is
#                                        the focused operator SUMMARY view.
#   * operator_genesis_verify_live.sh  — compares a running daemon's
#                                        chain-id RPC against a file hash.
#
# SKIP-with-PASS: in a minimal environment where neither the determ
# binary nor a Python interpreter is available, the script cannot parse
# the genesis. It then SKIPs (no-op) and exits 0 — never a hard fail —
# so it is a clean no-op in build-less checkouts.
#
# Output: a grouped human-readable summary, then PASS:/FAIL: lines and a
# final one-line summary.
#
# Usage:
#   tools/operator_genesis_inspect.sh [<genesis.json>]
#   (default path: genesis.json in the repo root)
#
# Exit codes:
#   0 — summary printed (or SKIPped because no parser is available)
#   1 — real failure: file missing / unreadable / malformed /
#       verify-genesis rejected the file / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_genesis_inspect.sh [<genesis.json>]

READ-ONLY human-readable summary of a local genesis.json file. No RPC,
no daemon, no cluster — pure file inspection.

Arguments:
  <genesis.json>   Path to the genesis file (default: genesis.json in the
                   repo root).

Options:
  -h, --help       Show this help.

Reports: chain_id, chain_role, sharding mode + shard config, committee
size (M/K), timing profile (epoch_blocks), supply params (genesis total
from initial_balances + pools, block_subsidy), and v2 activation heights
when present.

Exit codes:
  0   summary printed (or SKIP — no determ/Python parser available)
  1   file missing / unreadable / malformed / verify-genesis error /
      bad args
EOF
}

IN_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "operator_genesis_inspect: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)
      if [ -z "$IN_FILE" ]; then
        IN_FILE="$1"; shift
      else
        echo "operator_genesis_inspect: unexpected extra argument: $1" >&2
        usage >&2; exit 1
      fi
      ;;
  esac
done

cd "$(dirname "$0")/.."

# Default to genesis.json in the repo root when no path is given.
[ -z "$IN_FILE" ] && IN_FILE="genesis.json"

# ── Parser availability gate (SKIP-with-PASS) ──────────────────────────────────
# The determ binary parses + sane-bounds-validates the genesis; Python
# performs the raw augmentation read. If NEITHER is available we cannot
# produce a summary — but a missing build is not a failure of this tool,
# so SKIP (no-op) and exit 0. We must decide this BEFORE sourcing
# common.sh, because common.sh hard-exits when the determ binary is
# absent (which would defeat the no-op-SKIP contract in a build-less env).
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
  echo "        parse the genesis; build with"
  echo "        cmake --build build --config Release --target determ"
  echo "  PASS: operator_genesis_inspect (no-op skip)"
  exit 0
fi

# Both parsers present — safe to source common.sh for $DETERM.
source tools/common.sh

# ── Argument file checks ───────────────────────────────────────────────────────
if [ ! -f "$IN_FILE" ]; then
  echo "  FAIL: genesis file not found: $IN_FILE" >&2
  echo "  0 pass / 1 fail"
  echo "  FAIL: operator_genesis_inspect"
  exit 1
fi
if [ ! -r "$IN_FILE" ]; then
  echo "  FAIL: genesis file not readable: $IN_FILE" >&2
  echo "  0 pass / 1 fail"
  echo "  FAIL: operator_genesis_inspect"
  exit 1
fi

# ── Step 1: parsed + validated core via verify-genesis --json ──────────────────
# A successful return means the file is a deployable, sane-bounds-checked
# genesis. Otherwise surface the diagnostic verbatim and fail.
VG_OUT=$("$DETERM" verify-genesis --in "$IN_FILE" --json 2>&1)
VG_RC=$?
if [ "$VG_RC" -ne 0 ]; then
  echo "  FAIL: verify-genesis rejected $IN_FILE (rc=$VG_RC)" >&2
  echo "$VG_OUT" >&2
  echo "  0 pass / 1 fail"
  echo "  FAIL: operator_genesis_inspect"
  exit 1
fi

# ── Step 2: render the summary via Python ──────────────────────────────────────
# Python re-reads the raw file once for the fields verify-genesis omits
# (subsidy_mode/pools, epoch_blocks, the supply total, v2 heights), folds
# in the verify-genesis JSON, and prints the grouped human summary plus a
# pass/fail tally. Both inputs (file path + verify-genesis JSON) are
# passed on argv so there is exactly one raw parse pass.
"$PY" - "$IN_FILE" "$VG_OUT" <<'PY'
import json, sys

in_path = sys.argv[1]
vg_raw  = sys.argv[2]

fails = 0
def check(cond, msg):
    global fails
    if cond:
        print(f"  PASS: {msg}")
    else:
        print(f"  FAIL: {msg}")
        fails += 1

# ── verify-genesis output (already validated by the binary). ───────────────
try:
    vg = json.loads(vg_raw)
except Exception as e:
    print(f"  FAIL: verify-genesis --json output not parseable: {e}")
    print("  0 pass / 1 fail")
    print("  FAIL: operator_genesis_inspect")
    sys.exit(1)

if vg.get("status") != "ok":
    print(f"  FAIL: verify-genesis status != ok: {vg_raw}")
    print("  0 pass / 1 fail")
    print("  FAIL: operator_genesis_inspect")
    sys.exit(1)

# ── Raw file read for the fields verify-genesis omits. ─────────────────────
try:
    with open(in_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
except Exception as e:
    print(f"  FAIL: cannot parse {in_path} as JSON: {e}")
    print("  0 pass / 1 fail")
    print("  FAIL: operator_genesis_inspect")
    sys.exit(1)

if not isinstance(raw, dict):
    print(f"  FAIL: genesis root is not a JSON object: {in_path}")
    print("  0 pass / 1 fail")
    print("  FAIL: operator_genesis_inspect")
    sys.exit(1)

# Soft accessor mirroring GenesisConfig::from_json defaults
# (include/determ/chain/genesis.hpp).
def g(key, default):
    v = raw.get(key, default)
    return v if v is not None else default

# ── Chain identity + role. ────────────────────────────────────────────────
chain_id        = vg.get("chain_id", "")
chain_role_int  = int(vg.get("chain_role", 0))
shard_id        = int(vg.get("shard_id", 0))
init_shard_n    = int(vg.get("initial_shard_count", 1))
committee_region = vg.get("committee_region", "") or ""
ROLE_NAMES = {0: "SINGLE", 1: "BEACON", 2: "SHARD"}
chain_role_name = ROLE_NAMES.get(chain_role_int, f"UNKNOWN({chain_role_int})")

# Sharding mode derives from the role + shard count (genesis carries no
# separate "sharding_mode" key — that lives in config.json; the chain's
# sharded-ness is expressed by chain_role + initial_shard_count here).
if chain_role_int == 0 and init_shard_n <= 1:
    sharding_desc = "unsharded (SINGLE, 1 shard)"
elif chain_role_int == 1:
    sharding_desc = f"sharded -- BEACON over {init_shard_n} shard(s)"
elif chain_role_int == 2:
    sharding_desc = f"sharded -- SHARD {shard_id} of {init_shard_n}"
else:
    sharding_desc = f"role={chain_role_name}, {init_shard_n} shard(s)"

# ── Committee size (M / K). ───────────────────────────────────────────────
m_creators   = int(vg.get("m_creators", 3))
k_block_sigs = int(vg.get("k_block_sigs", m_creators))
bft_enabled  = bool(vg.get("bft_enabled", True))
if k_block_sigs == m_creators:
    k_mode = "strong K-of-K (full mutual distrust)"
else:
    k_mode = "hybrid BFT-from-start"

# ── Timing profile (genesis-level: epoch_blocks; round timers are
# config-level per PROTOCOL.md §12.3). ─────────────────────────────────────
epoch_blocks = int(g("epoch_blocks", 1000))

# ── Supply parameters. ────────────────────────────────────────────────────
block_subsidy        = int(vg.get("block_subsidy", 0))
subsidy_pool_initial = int(g("subsidy_pool_initial", 0))
zeroth_pool_initial  = int(g("zeroth_pool_initial", 0))
subsidy_mode_int     = int(g("subsidy_mode", 0))
SUBSIDY_MODE_NAMES   = {0: "FLAT", 1: "LOTTERY"}
subsidy_mode_name    = SUBSIDY_MODE_NAMES.get(subsidy_mode_int, f"UNKNOWN({subsidy_mode_int})")
lottery_mult         = int(g("lottery_jackpot_multiplier", 0))
min_stake            = int(vg.get("min_stake", 1000))

initial_balances = g("initial_balances", [])
if not isinstance(initial_balances, list):
    initial_balances = []
balances_total = 0
for b in initial_balances:
    if isinstance(b, dict):
        try:
            balances_total += int(b.get("balance", 0))
        except (TypeError, ValueError):
            pass
# genesis_total = pre-minted balances + the NEF pool, both genesis-pinned
# allocations that count toward the A1 unitary-supply invariant.
genesis_total = balances_total + zeroth_pool_initial

# ── v2 activation heights — only surfaced when the keys are present. ───────
# A bare 0 means "active from genesis"; UINT64_MAX (the sentinel) means
# "never". We print them only when the operator actually set the key.
UINT64_MAX = 18446744073709551615
def fmt_height(v):
    iv = int(v)
    if iv == 0:
        return "0 (active from genesis)"
    if iv == UINT64_MAX:
        return f"{iv} (sentinel: never activate)"
    return str(iv)
v2_heights = []
if "v2_7_f2_active_from_height" in raw:
    v2_heights.append(("v2.7 F2 view-reconciliation",
                       fmt_height(raw["v2_7_f2_active_from_height"])))
if "v2_10_active_from_height" in raw:
    v2_heights.append(("v2.10 threshold randomness",
                       fmt_height(raw["v2_10_active_from_height"])))

# ── Human summary ──────────────────────────────────────────────────────────
print(f"=== Genesis summary (path: {in_path}) ===")
print("Chain identity:")
print(f"  chain_id:    {chain_id}")
print(f"  chain_role:  {chain_role_name} ({chain_role_int})")
print("Sharding:")
print(f"  mode:                {sharding_desc}")
print(f"  shard_id:            {shard_id}")
print(f"  initial_shard_count: {init_shard_n}")
print(f"  committee_region:    {committee_region if committee_region else '(none -- global pool)'}")
print("Committee (M / K):")
print(f"  m_creators:   {m_creators}")
print(f"  k_block_sigs: {k_block_sigs} ({k_mode})")
print(f"  bft_enabled:  {'true' if bft_enabled else 'false'}")
print("Timing:")
print(f"  epoch_blocks: {epoch_blocks}")
print("  (round-timer fields tx_commit_ms / block_sig_ms / abort_claim_ms")
print("   are config-level -- see tools/operator_config_audit.sh)")
print("Supply:")
print(f"  genesis_total:        {genesis_total} (initial_balances {balances_total} + NEF pool {zeroth_pool_initial})")
print(f"  block_subsidy:        {block_subsidy} ({subsidy_mode_name})")
if subsidy_mode_int == 1:
    print(f"  lottery_jackpot_multiplier: {lottery_mult}")
print(f"  subsidy_pool_initial: {subsidy_pool_initial} (0 = perpetual)")
print(f"  min_stake:            {min_stake}")
print("v2 activation heights:")
if v2_heights:
    for name, val in v2_heights:
        print(f"  {name}: {val}")
else:
    print("  (none present -- chain runs the genesis-default activation schedule)")

print("--- checks ---")
# Light sanity checks on the summarized values. These are operator
# guardrails, not consensus rules (verify-genesis already enforced those).
check(bool(chain_id), "chain_id is non-empty")
check(chain_role_int in ROLE_NAMES, f"chain_role is a known role ({chain_role_name})")
check(1 <= k_block_sigs <= m_creators,
      f"k_block_sigs within [1, m_creators] (k={k_block_sigs}, m={m_creators})")
check(init_shard_n >= 1, f"initial_shard_count >= 1 ({init_shard_n})")
check(epoch_blocks >= 1, f"epoch_blocks >= 1 ({epoch_blocks})")
check(genesis_total >= 0, f"genesis_total non-negative ({genesis_total})")

pass_count = 6 - fails
print(f"  {pass_count} pass / {fails} fail")
if fails == 0:
    print("  PASS: operator_genesis_inspect")
    sys.exit(0)
else:
    print("  FAIL: operator_genesis_inspect")
    sys.exit(1)
PY
exit $?
