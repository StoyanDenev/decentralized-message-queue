#!/usr/bin/env bash
# operator_genesis_dump.sh — Comprehensive view of a local genesis.json
# file: full parameter dump, 1-screen compact summary, or security-
# posture review.
#
# Local-file tool. No RPC. Calls `determ verify-genesis --in <file>
# --json` for the parsed + sane-bounds-validated shape, then augments
# with raw-file parsing for any field verify-genesis doesn't surface
# (notably shard_address_salt, governance_mode + param_keyholders +
# param_threshold, initial_creators[], initial_balances[],
# inclusion_model, subsidy_mode + lottery_jackpot_multiplier,
# subsidy_pool_initial, zeroth_pool_initial, suspension_slash,
# unstake_delay, merge thresholds, epoch_blocks, genesis_message body).
#
# Sibling positioning:
#   * operator_genesis_verify_live.sh — compares a running daemon's
#                                       chain-id RPC against the file
#                                       hash; live-only.
#   * operator_genesis_dump.sh (this) — pure file inspection; no daemon
#                                       needed; the full parameter
#                                       surface in human-readable form.
#
# Use cases:
#   1. Pre-deployment review — render the genesis.json an operator is
#      about to roll out so reviewers can eyeball every parameter
#      without writing ad-hoc jq invocations.
#   2. Multi-genesis comparison — `diff <(operator_genesis_dump.sh
#      --in a.json --compact) <(operator_genesis_dump.sh --in b.json
#      --compact)` to spot identity / role / consensus differences at
#      a glance.
#   3. Security review — `--security-posture` summarizes the security-
#      relevant choices (BFT escalation, governance mode + N/M,
#      committee_region pin, suspension_slash configured) with simple
#      check marks / warnings so an auditor can sign off quickly.
#   4. Incident response — when a chain mis-launches, dump the genesis
#      to confirm which fields actually shipped.
#
# Exit codes:
#   0 — successful dump
#   1 — file missing / malformed / verify-genesis error / bad args
#
# Modes:
#   --full              (default) full parameter dump, grouped sections
#   --compact           one-line summary
#   --security-posture  bulleted checklist of security-relevant fields
#
# Output formats:
#   default — human-readable (each mode has its own layout)
#   --json  — single-line JSON envelope; payload shape varies by mode
#             but always includes {"path","mode", ...}
set -u

usage() {
  cat <<'EOF'
Usage: operator_genesis_dump.sh --in <file>
                                [--full | --compact | --security-posture]
                                [--json]

Renders a local genesis.json file in one of three modes. No RPC, no
daemon required.

Required:
  --in <file>           Path to the genesis.json on disk

Mode (mutually exclusive; default = --full):
  --full                Complete parameter dump, grouped by topic
                        (chain identity, consensus, economics,
                        governance, initial state, sharding, timing).
  --compact             One-line summary for diff'ing across files
                        ("genesis=<hex>... role=SHARD shard=2/4 K-of-K=
                        5/4 BFT=on subsidy=50 mode=governed").
  --security-posture    Bulleted checklist of security-relevant
                        choices (BFT escalation, governance posture,
                        committee_region pin, slashing config).

Other options:
  --json                Emit single-line JSON envelope instead of
                        human-readable text. Envelope shape varies by
                        mode but always includes {"path","mode"}.
  -h, --help            Show this help.

Exit codes:
  0   dump succeeded
  1   --in file missing / unreadable / malformed / verify-genesis
      error / bad args

What verify-genesis exposes vs what this script parses raw:
  verify-genesis --json surfaces: genesis_hash, chain_id, chain_role,
  shard_id, m_creators, k_block_sigs, block_subsidy, min_stake,
  initial_shard_count, bft_enabled, committee_region, initial_creators
  count, initial_balances count, genesis_message_is_default,
  genesis_message_bytes.

  This script parses the raw JSON for the remaining fields:
  shard_address_salt, governance_mode + param_keyholders + param_
  threshold, inclusion_model, subsidy_mode + lottery_jackpot_multiplier,
  subsidy_pool_initial, zeroth_pool_initial, suspension_slash,
  unstake_delay, merge_threshold_blocks, revert_threshold_blocks,
  merge_grace_blocks, epoch_blocks, bft_escalation_threshold, plus the
  full initial_creators[] + initial_balances[] arrays (verify-genesis
  only reports their counts).

JSON shape (--json, --full mode):
  {"path": "...",
   "mode": "full",
   "chain_identity":   {...},
   "consensus":        {...},
   "economics":        {...},
   "governance":       {...},
   "initial_state":    {...},
   "sharding":         {...},
   "timing":           {...}}

JSON shape (--json, --compact mode):
  {"path":"...","mode":"compact","line":"genesis=... role=... ..."}

JSON shape (--json, --security-posture mode):
  {"path":"...","mode":"security-posture",
   "checks": [{"name":"...","severity":"OK|INFO|WARN","message":"..."}]}
EOF
}

IN_FILE=""
MODE="full"
JSON_OUT=0
MODES_SET=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --in)                 IN_FILE="$2"; shift 2 ;;
    --full)               MODE="full"; MODES_SET=$((MODES_SET + 1)); shift ;;
    --compact)            MODE="compact"; MODES_SET=$((MODES_SET + 1)); shift ;;
    --security-posture)   MODE="security-posture"; MODES_SET=$((MODES_SET + 1)); shift ;;
    --json)               JSON_OUT=1; shift ;;
    *) echo "operator_genesis_dump: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$IN_FILE" ]; then
  echo "operator_genesis_dump: --in <file> is required" >&2
  usage >&2
  exit 1
fi
if [ "$MODES_SET" -gt 1 ]; then
  echo "operator_genesis_dump: --full / --compact / --security-posture are mutually exclusive" >&2
  exit 1
fi
if [ ! -f "$IN_FILE" ]; then
  echo "operator_genesis_dump: --in file not found: $IN_FILE" >&2
  exit 1
fi
if [ ! -r "$IN_FILE" ]; then
  echo "operator_genesis_dump: --in file not readable: $IN_FILE" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: parsed + validated shape via verify-genesis --json ─────────────────
# Captures: genesis_hash (the chain-identity contract), chain_id,
# chain_role, shard_id, m_creators, k_block_sigs, block_subsidy,
# min_stake, initial_shard_count, bft_enabled, committee_region,
# initial_creators count, initial_balances count,
# genesis_message_is_default, genesis_message_bytes.
#
# verify-genesis already applies sane-bounds + cross-field validation
# (e.g., LOTTERY requires jackpot_multiplier >= 2, governance_mode=1
# requires param_keyholders non-empty), so a successful return here
# means the file is a deployable genesis. Otherwise we surface the
# diagnostic verbatim and exit 1.
VG_OUT=$("$DETERM" verify-genesis --in "$IN_FILE" --json 2>&1)
VG_RC=$?
if [ "$VG_RC" -ne 0 ]; then
  echo "operator_genesis_dump: verify-genesis failed on $IN_FILE (rc=$VG_RC)" >&2
  echo "$VG_OUT" >&2
  exit 1
fi

# ── Step 2: rendering driven by Python ─────────────────────────────────────────
# Python is the right tool for this: it can re-parse the raw file once
# for the fields verify-genesis omits, validate them softly (without
# duplicating the binary's sane-bounds checks — verify-genesis already
# said "ok"), and emit three completely different layouts (full /
# compact / security-posture × text / json) with one set of accessors.
#
# Pass file path, mode, json flag, and the captured verify-genesis JSON
# on argv so we get one parse pass total per surface.
python - "$IN_FILE" "$MODE" "$JSON_OUT" "$VG_OUT" <<'PY'
import json, sys, os

in_path  = sys.argv[1]
mode     = sys.argv[2]
json_out = sys.argv[3] == "1"
vg_raw   = sys.argv[4]

# ── Parse verify-genesis output. ──────────────────────────────────────────
try:
    vg = json.loads(vg_raw)
except Exception as e:
    sys.stderr.write(
        f"operator_genesis_dump: verify-genesis --json output not parseable: {e}\n")
    sys.exit(1)

if vg.get("status") != "ok":
    sys.stderr.write(
        f"operator_genesis_dump: verify-genesis returned status!=ok: {vg_raw}\n")
    sys.exit(1)

# ── Parse the raw file for fields verify-genesis doesn't surface. ─────────
# verify-genesis omits these by design (S-039: the operational params
# it does emit are the ones it found most useful for divergence-spotting
# when paired with the hash). For a full dump we need the rest too.
try:
    with open(in_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
except Exception as e:
    sys.stderr.write(
        f"operator_genesis_dump: cannot parse {in_path} as JSON: {e}\n")
    sys.exit(1)

if not isinstance(raw, dict):
    sys.stderr.write(
        f"operator_genesis_dump: genesis root is not a JSON object: {in_path}\n")
    sys.exit(1)

# Soft accessor with default. Matches GenesisConfig::from_json defaults
# byte-for-byte (see include/determ/chain/genesis.hpp).
def g(key, default):
    v = raw.get(key, default)
    return v if v is not None else default

# Identity (mostly verify-genesis-sourced)
genesis_hash    = vg.get("genesis_hash", "")
chain_id        = vg.get("chain_id", "")
chain_role_int  = int(vg.get("chain_role", 0))
shard_id        = int(vg.get("shard_id", 0))
init_shard_n    = int(vg.get("initial_shard_count", 1))
committee_region = vg.get("committee_region", "") or ""
ROLE_NAMES = {0: "SINGLE", 1: "BEACON", 2: "SHARD"}
chain_role_name = ROLE_NAMES.get(chain_role_int, f"UNKNOWN({chain_role_int})")

# Consensus
m_creators       = int(vg.get("m_creators", 3))
k_block_sigs     = int(vg.get("k_block_sigs", m_creators))
bft_enabled      = bool(vg.get("bft_enabled", True))
bft_thresh       = int(g("bft_escalation_threshold", 5))

# Economics
block_subsidy    = int(vg.get("block_subsidy", 0))
subsidy_pool_initial = int(g("subsidy_pool_initial", 0))
subsidy_mode_int = int(g("subsidy_mode", 0))
SUBSIDY_MODE_NAMES = {0: "FLAT", 1: "LOTTERY"}
subsidy_mode_name = SUBSIDY_MODE_NAMES.get(subsidy_mode_int, f"UNKNOWN({subsidy_mode_int})")
lottery_mult     = int(g("lottery_jackpot_multiplier", 0))
zeroth_pool_initial = int(g("zeroth_pool_initial", 0))
min_stake        = int(vg.get("min_stake", 1000))
suspension_slash = int(g("suspension_slash", 10))
unstake_delay    = int(g("unstake_delay", 1000))
inclusion_int    = int(g("inclusion_model", 0))
INCLUSION_NAMES  = {0: "stake-inclusion", 1: "domain-inclusion"}
inclusion_name   = INCLUSION_NAMES.get(inclusion_int, f"UNKNOWN({inclusion_int})")

# Governance
governance_mode_int = int(g("governance_mode", 0))
GOV_NAMES = {0: "uncontrolled", 1: "governed"}
governance_mode_name = GOV_NAMES.get(governance_mode_int, f"UNKNOWN({governance_mode_int})")
param_keyholders = g("param_keyholders", [])
if not isinstance(param_keyholders, list):
    param_keyholders = []
N_holders = len(param_keyholders)
M_thresh = int(g("param_threshold", 0))
if governance_mode_int == 1 and M_thresh == 0:
    # genesis.cpp defaults absent threshold to N-of-N under governed mode.
    M_thresh = N_holders

# Initial state (full arrays here; verify-genesis only emits counts)
initial_creators = g("initial_creators", [])
if not isinstance(initial_creators, list):
    initial_creators = []
initial_balances = g("initial_balances", [])
if not isinstance(initial_balances, list):
    initial_balances = []

# Sharding
shard_address_salt = g("shard_address_salt", "")
if not isinstance(shard_address_salt, str):
    shard_address_salt = ""
epoch_blocks       = int(g("epoch_blocks", 1000))
merge_threshold   = int(g("merge_threshold_blocks", 100))
revert_threshold  = int(g("revert_threshold_blocks", 200))
merge_grace       = int(g("merge_grace_blocks", 10))

# Genesis message body — verify-genesis exposes only is_default + bytes.
# Raw value is useful for the full dump (operator may want to see the
# inscribed text). Truncate for readability if very long.
genesis_message_body = raw.get("genesis_message", None)
if genesis_message_body is None:
    # Field absent ⇒ default. We still want a renderable value.
    genesis_message_body = ""
genesis_message_is_default = bool(vg.get("genesis_message_is_default", True))
genesis_message_bytes = int(vg.get("genesis_message_bytes", 0))

# Helper: hash short form for compact + human displays.
def short_hash(h, n=8):
    if not isinstance(h, str) or len(h) < n:
        return h or ""
    return h[:n] + "..."

# ── Per-mode emit ─────────────────────────────────────────────────────────

if mode == "compact":
    # One-line summary tailored for diff'ing two genesis files.
    bft_str  = "on" if bft_enabled else "off"
    # Format: K-of-K=<M>/<K> (M first, K second — matches the standard
    # spelling where M is the committee size and K the required-sig count).
    line = (
        f"genesis={short_hash(genesis_hash)} role={chain_role_name} "
        f"shard={shard_id}/{init_shard_n} K-of-K={m_creators}/{k_block_sigs} "
        f"BFT={bft_str} subsidy={block_subsidy} mode={governance_mode_name}")
    if json_out:
        print(json.dumps({"path": in_path, "mode": "compact", "line": line}))
    else:
        print(line)
    sys.exit(0)

if mode == "security-posture":
    # Each check renders as {severity, message}. Severity drives the
    # leading glyph in human view (OK = checkmark, INFO = bullet, WARN =
    # warning sign).
    checks = []

    # BFT escalation gate.
    if bft_enabled:
        checks.append({
            "name": "bft_enabled",
            "severity": "OK",
            "message": f"BFT escalation enabled (threshold {bft_thresh})"})
    else:
        checks.append({
            "name": "bft_enabled",
            "severity": "WARN",
            "message": "BFT escalation disabled — chain stalls on K-honest dropout"})

    # K-vs-M posture.
    if k_block_sigs == m_creators:
        checks.append({
            "name": "k_vs_m",
            "severity": "OK",
            "message": f"K-of-K full mutual distrust (k=m={m_creators})"})
    elif k_block_sigs < m_creators:
        checks.append({
            "name": "k_vs_m",
            "severity": "INFO",
            "message": f"Hybrid BFT-from-start (k={k_block_sigs} < m={m_creators})"})
    else:
        # Should be impossible — verify-genesis would have rejected this.
        checks.append({
            "name": "k_vs_m",
            "severity": "WARN",
            "message": f"k_block_sigs > m_creators ({k_block_sigs} > {m_creators}); invalid"})

    # Governance posture.
    if governance_mode_int == 0:
        checks.append({
            "name": "governance_mode",
            "severity": "INFO",
            "message": "Governance: uncontrolled (consensus constants immutable)"})
    else:
        checks.append({
            "name": "governance_mode",
            "severity": "OK",
            "message": f"Governance: governed mode with N={N_holders} M={M_thresh} keyholders"})

    # Committee region.
    if committee_region:
        checks.append({
            "name": "committee_region",
            "severity": "OK",
            "message": f"committee_region pinned ('{committee_region}')"})
    else:
        # Empty region = global pool. Worth flagging for sharded chains —
        # on a SHARD role chain an empty region means selection is not
        # region-constrained, which may or may not be the operator's
        # intent. Flag WARN for SHARD, INFO for SINGLE/BEACON.
        if chain_role_int == 2:  # SHARD
            checks.append({
                "name": "committee_region",
                "severity": "WARN",
                "message": "committee_region empty on a SHARD chain — selection defaults to global pool"})
        else:
            checks.append({
                "name": "committee_region",
                "severity": "INFO",
                "message": "committee_region empty (global pool — fine for SINGLE/BEACON)"})

    # Slashing config.
    if suspension_slash > 0:
        checks.append({
            "name": "suspension_slash",
            "severity": "OK",
            "message": f"suspension_slash configured ({suspension_slash} per abort)"})
    else:
        checks.append({
            "name": "suspension_slash",
            "severity": "WARN",
            "message": "suspension_slash = 0 — no economic disincentive for silent committee members"})

    # Inclusion model + min_stake coherence.
    if inclusion_int == 0:
        # STAKE_INCLUSION requires a non-zero min_stake to be meaningful.
        if min_stake > 0:
            checks.append({
                "name": "inclusion_min_stake",
                "severity": "OK",
                "message": f"stake-inclusion with min_stake={min_stake}"})
        else:
            checks.append({
                "name": "inclusion_min_stake",
                "severity": "WARN",
                "message": "stake-inclusion with min_stake=0 — no Sybil cost"})
    else:
        # DOMAIN_INCLUSION pins min_stake = 0.
        checks.append({
            "name": "inclusion_min_stake",
            "severity": "INFO",
            "message": "domain-inclusion — Sybil cost via domain registration"})

    # shard_address_salt non-zero check (rev.9 sharded deployments).
    if chain_role_int in (1, 2):
        is_zero_salt = (not shard_address_salt
                        or shard_address_salt == "0" * 64
                        or shard_address_salt == "")
        if is_zero_salt:
            checks.append({
                "name": "shard_address_salt",
                "severity": "WARN",
                "message": "shard_address_salt is all-zero on a sharded chain — predictable routing"})
        else:
            checks.append({
                "name": "shard_address_salt",
                "severity": "OK",
                "message": f"shard_address_salt set ({short_hash(shard_address_salt)})"})

    if json_out:
        print(json.dumps({
            "path":   in_path,
            "mode":   "security-posture",
            "checks": checks,
        }))
        sys.exit(0)

    # Human render.
    print(f"=== Security posture (path: {in_path}) ===")
    sev_glyph = {"OK": "[OK]  ", "INFO": "[INFO]", "WARN": "[WARN]"}
    for c in checks:
        g_ = sev_glyph.get(c["severity"], "[?]   ")
        print(f"  {g_} {c['message']}")
    sys.exit(0)

# ── --full (default) ──────────────────────────────────────────────────────
# JSON envelope first (structured); human form below.

if json_out:
    out = {
        "path": in_path,
        "mode": "full",
        "chain_identity": {
            "genesis_hash":         genesis_hash,
            "chain_id":             chain_id,
            "chain_role":           chain_role_name,
            "chain_role_int":       chain_role_int,
            "shard_id":             shard_id,
            "initial_shard_count":  init_shard_n,
            "committee_region":     committee_region,
        },
        "consensus": {
            "m_creators":               m_creators,
            "k_block_sigs":             k_block_sigs,
            "bft_enabled":              bft_enabled,
            "bft_escalation_threshold": bft_thresh,
        },
        "economics": {
            "block_subsidy":              block_subsidy,
            "subsidy_pool_initial":       subsidy_pool_initial,
            "subsidy_mode":               subsidy_mode_name,
            "subsidy_mode_int":           subsidy_mode_int,
            "lottery_jackpot_multiplier": lottery_mult,
            "zeroth_pool_initial":        zeroth_pool_initial,
            "min_stake":                  min_stake,
            "suspension_slash":           suspension_slash,
            "unstake_delay":              unstake_delay,
            "inclusion_model":            inclusion_name,
            "inclusion_model_int":        inclusion_int,
        },
        "governance": {
            "governance_mode":  governance_mode_name,
            "governance_mode_int": governance_mode_int,
            "param_keyholders": param_keyholders,
            "keyholders_n":     N_holders,
            "param_threshold":  M_thresh,
        },
        "initial_state": {
            "initial_creators": initial_creators,
            "initial_balances": initial_balances,
            "creators_count":   len(initial_creators),
            "balances_count":   len(initial_balances),
        },
        "sharding": {
            "shard_address_salt":      shard_address_salt,
            "epoch_blocks":            epoch_blocks,
            "merge_threshold_blocks":  merge_threshold,
            "revert_threshold_blocks": revert_threshold,
            "merge_grace_blocks":      merge_grace,
        },
        "timing": {
            # Round-timer fields live in config.json, not genesis.json
            # (per PROTOCOL.md §12.3 profile presets). Flagged here so
            # JSON consumers know to look at config_audit's output.
            "note": "round-timer fields (tx_commit_ms, block_sig_ms, abort_claim_ms) are config-level (see operator_config_audit.sh)",
        },
        "genesis_message": {
            "is_default": genesis_message_is_default,
            "bytes":      genesis_message_bytes,
            "body":       genesis_message_body,
        },
    }
    print(json.dumps(out))
    sys.exit(0)

# Human render (--full default).
print(f"=== Genesis dump (path: {in_path}) ===")

print("Chain identity:")
print(f"  genesis_hash:        {genesis_hash}")
print(f"  chain_id:            {chain_id}")
print(f"  chain_role:          {chain_role_name} ({chain_role_int})")
print(f"  shard_id:            {shard_id}")
print(f"  initial_shard_count: {init_shard_n}")
print(f"  committee_region:    {committee_region if committee_region else '(none — global pool)'}")

print("Consensus:")
print(f"  m_creators:               {m_creators}")
# Annotate mode: K=M strong vs K<M hybrid.
if k_block_sigs == m_creators:
    k_mode = "strong K-of-K (full mutual distrust)"
else:
    k_mode = "hybrid BFT-from-start"
print(f"  k_block_sigs:             {k_block_sigs} ({k_mode})")
print(f"  bft_enabled:              {'true' if bft_enabled else 'false'}")
print(f"  bft_escalation_threshold: {bft_thresh}")

print("Economics:")
print(f"  block_subsidy:        {block_subsidy}")
print(f"  subsidy_pool_initial: {subsidy_pool_initial} (0 = perpetual)")
print(f"  subsidy_mode:         {subsidy_mode_name}")
if subsidy_mode_int == 1:
    print(f"  lottery_jackpot_multiplier: {lottery_mult}")
print(f"  zeroth_pool_initial:  {zeroth_pool_initial}")
print(f"  min_stake:            {min_stake}")
print(f"  suspension_slash:     {suspension_slash}")
print(f"  unstake_delay:        {unstake_delay}")
print(f"  inclusion_model:      {inclusion_name}")

print("Governance:")
print(f"  governance_mode:  {governance_mode_name}")
if governance_mode_int == 1:
    if param_keyholders:
        # Truncate hex pubkeys for readability.
        khs_short = [short_hash(k, 12) for k in param_keyholders]
        print(f"  param_keyholders: [{', '.join(khs_short)}]  (N={N_holders})")
    else:
        # Should be impossible under governed mode; verify-genesis would reject.
        print(f"  param_keyholders: (empty)  (N={N_holders})")
    print(f"  param_threshold:  {M_thresh} of {N_holders} (M-of-N)")
else:
    print(f"  (no keyholders; consensus constants are genesis-pinned and immutable)")

print("Initial state:")
print(f"  initial_creators: {len(initial_creators)} entries")
for c in initial_creators:
    if not isinstance(c, dict):
        continue
    dom = c.get("domain", "?")
    rg  = c.get("region", "") or "global"
    stk = c.get("initial_stake", 0)
    print(f"    {dom}  (region={rg}, stake={stk})")
print(f"  initial_balances: {len(initial_balances)} entries")
for b in initial_balances:
    if not isinstance(b, dict):
        continue
    dom = b.get("domain", "?")
    bal = b.get("balance", 0)
    print(f"    {dom}  {bal}")

print("Sharding:")
salt_disp = f"{short_hash(shard_address_salt, 16)} (32 bytes)" if shard_address_salt else "(absent — zero salt)"
print(f"  shard_address_salt:      {salt_disp}")
print(f"  epoch_blocks:            {epoch_blocks}")
print(f"  merge_threshold_blocks:  {merge_threshold}")
print(f"  revert_threshold_blocks: {revert_threshold}")
print(f"  merge_grace_blocks:      {merge_grace}")

# Round-timer surface: these fields are config-level, not genesis-level
# (see PROTOCOL.md §12.3 profile presets). The section header is kept
# so the dump structure is predictable for diff'ing, with a clear note
# pointing at the script that DOES dump those values.
print("Timing (R1):")
print("  (round-timer fields tx_commit_ms / block_sig_ms / abort_claim_ms")
print("   are config-level -- see tools/operator_config_audit.sh)")

# Genesis message (the optional cultural / regulatory inscription).
print("Genesis message:")
if genesis_message_is_default:
    print(f"  (default inscription, {genesis_message_bytes} bytes)")
else:
    # Truncate for readability on very long inscriptions.
    body = genesis_message_body
    if isinstance(body, str) and len(body) > 160:
        body = body[:157] + "..."
    print(f"  (custom, {genesis_message_bytes} bytes): {body!r}")

sys.exit(0)
PY
PY_RC=$?
exit "$PY_RC"
