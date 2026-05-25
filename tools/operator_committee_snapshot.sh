#!/usr/bin/env bash
# operator_committee_snapshot.sh — Single-height committee composition
# snapshot. Forensic helper for the question "who was in the committee
# at block H, did each one sign, and is the composition internally
# consistent?"
#
# Sibling tools and how this one differs:
#   operator_committee_audit.sh
#       Per-validator stake-proportional fairness audit OVER A WINDOW.
#       Asks: "did each validator get the right share of slots across
#       the last N blocks?"
#   operator_committee_membership_history.sh
#       Per-validator timeline + pair-wise co-occurrence over a window.
#       Asks: "which blocks did each validator appear in?"
#   operator_committee_rotation.sh
#       Committee-as-multiset rotation rate across a window.
#   operator_committee_snapshot.sh  (THIS)
#       Single-height composition snapshot. Asks: "at THIS block H, who
#       are the K creators, which signed (sig_present per creator), is
#       any pubkey duplicated, what's the required-sigs gate, and the
#       partner_subset_hash if R4 Phase 3 selection was in effect?"
#
# Use case: an operator suspects committee misconfiguration. Running
# this against several heights reveals whether composition is stable
# or drifting, and whether the K-of-K vs BFT k_bft gate matches the
# observed block consensus_mode.
#
# Args:
#   --rpc-port N    RPC port to query (REQUIRED)
#   --height H      Block index to snapshot (default: chain head - 1,
#                   the highest finalized block)
#   --json          Emit structured JSON envelope
#   -h, --help      Show this help
#
# Output (human mode):
#   Committee at height <H>:
#     size: K=<N>
#     consensus_mode: <mutual_distrust|bft>
#     bft_mode: <on|off>
#     required_sigs: <Q> (K if K-of-K, ceil(2K/3) if BFT)
#     observed_sigs: <S>
#     creators:
#       1. <domain> pubkey=<short> sig_present=<yes|no>
#       2. ...
#     partner_subset_hash: <hex|absent>
#     duplicate_check: <ok|FAIL: domain=X appears N times>
#
# JSON shape:
#   {"height": H, "consensus_mode": "mutual_distrust|bft",
#    "bft_mode_enabled": bool, "committee_size": K,
#    "required_sigs": Q, "observed_sigs": S,
#    "creators": [{"position": i, "domain": "...",
#                  "pubkey_full": "...", "pubkey_short": "...",
#                  "sig_present": bool, "sig_hex": "..."|null}, ...],
#    "partner_subset_hash": "..."|null,
#    "duplicate_check": {"ok": bool, "duplicates": [...]},
#    "rpc_port": N}
#
# Exit codes:
#   0   snapshot rendered, composition consistent
#   1   bad args / RPC error / malformed response / out-of-range height
#   2   duplicate-pubkey check failed (composition anomaly)
set -u

usage() {
  cat <<'EOF'
Usage: operator_committee_snapshot.sh --rpc-port N [--height H] [--json]

Snapshot the committee composition at a single block height. Reports
K creators, per-creator pubkey + block-sig presence, required-sigs
gate (K-of-K or BFT ceil(2K/3)), partner_subset_hash if used, and
runs a duplicate-pubkey sanity check.

Required:
  --rpc-port N    RPC port to query

Options:
  --height H      Block index to snapshot (default: head - 1, the
                  highest finalized block)
  --json          Emit structured JSON envelope
  -h, --help      Show this help

Exit codes:
  0   snapshot rendered, composition consistent
  1   RPC error / bad args / out-of-range height
  2   duplicate-pubkey detected (composition anomaly)
EOF
}

PORT=""
HEIGHT=""
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    --rpc-port)   PORT="${2:-}";   shift 2 ;;
    --height)     HEIGHT="${2:-}"; shift 2 ;;
    --json)       JSON_OUT=1;      shift ;;
    *) echo "operator_committee_snapshot: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORT" ]; then
  echo "operator_committee_snapshot: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_committee_snapshot: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -n "$HEIGHT" ]; then
  case "$HEIGHT" in *[!0-9]*)
    echo "operator_committee_snapshot: --height must be an unsigned integer (got '$HEIGHT')" >&2
    exit 1 ;;
  esac
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve target height ─────────────────────────────────────────────
# Default to head-1 (highest finalized block). If chain.height() == 0 the
# chain has no applied blocks yet and we cannot snapshot — report and
# exit 1.
STATUS_JSON=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_snapshot: RPC error from \`determ status\` (is daemon running on port $PORT?)" >&2
  exit 1
}
CHAIN_HEIGHT=$(printf '%s' "$STATUS_JSON" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('height', 0)))
except Exception:
    print('')
")
case "$CHAIN_HEIGHT" in *[!0-9]*|"")
  echo "operator_committee_snapshot: malformed status JSON (height='$CHAIN_HEIGHT')" >&2
  exit 1 ;;
esac
if [ "$CHAIN_HEIGHT" = "0" ]; then
  echo "operator_committee_snapshot: chain is empty (height=0); nothing to snapshot" >&2
  exit 1
fi
# bft_enabled from status RPC drives the gate interpretation. Note: the
# chain-level bft_enabled config controls whether BFT escalation is
# allowed at all; the per-block consensus_mode field tells us which mode
# THIS block was finalized under.
BFT_ENABLED=$(printf '%s' "$STATUS_JSON" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    p = j.get('protections', {}) or {}
    v = p.get('bft_enabled')
    if v is None:
        v = j.get('bft_enabled', True)
    print('true' if bool(v) else 'false')
except Exception:
    print('true')
")

# Top finalized index = height - 1.
TOP=$(( CHAIN_HEIGHT - 1 ))
if [ -z "$HEIGHT" ]; then
  HEIGHT=$TOP
fi
if [ "$HEIGHT" -gt "$TOP" ]; then
  echo "operator_committee_snapshot: --height $HEIGHT is past chain tip (highest finalized = $TOP)" >&2
  exit 1
fi

# ── Step 2: fetch the block JSON via `determ block-info <H> --json` ───────────
# Block::to_json (src/chain/block.cpp) does NOT include a computed
# block-hash field; the snapshot focuses on committee composition.
# Operators wanting the block hash use `determ block-info <H> --field
# state_root` or one of the dedicated forensic helpers.
BLOCK_JSON=$("$DETERM" block-info "$HEIGHT" --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_snapshot: RPC error from \`determ block-info $HEIGHT\` (port $PORT)" >&2
  exit 1
}

# ── Step 3: fetch validators snapshot for domain→pubkey resolution ────────────
# The block JSON carries creators[] as domain strings (per Block::to_json
# in src/chain/block.cpp). To produce the per-creator pubkey column we
# join against `determ validators --json` (NodeRegistry built from chain
# state at current height). A creator domain that doesn't appear in the
# validator snapshot is flagged with pubkey="<unknown>" — possible if the
# validator deregistered between the snapshot block and now, or for very
# old historical heights.
VAL_JSON=$("$DETERM" validators --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_snapshot: RPC error from \`determ validators\` (port $PORT)" >&2
  exit 1
}

# ── Step 4: process block + validators + render ───────────────────────────────
python - "$BLOCK_JSON" "$VAL_JSON" "$HEIGHT" "$PORT" "$BFT_ENABLED" "$JSON_OUT" <<'PY'
import json, sys

block_raw, val_raw, height_s, port_s, bft_enabled_s, json_out_s = sys.argv[1:7]
height       = int(height_s)
port         = int(port_s)
bft_enabled  = (bft_enabled_s == 'true')
json_out     = (json_out_s == '1')

try:
    blk = json.loads(block_raw)
except Exception as e:
    sys.stderr.write(f"operator_committee_snapshot: malformed block JSON ({e})\n")
    sys.exit(1)
if not isinstance(blk, dict):
    sys.stderr.write("operator_committee_snapshot: block JSON not an object\n")
    sys.exit(1)
try:
    validators = json.loads(val_raw)
except Exception as e:
    sys.stderr.write(f"operator_committee_snapshot: malformed validators JSON ({e})\n")
    sys.exit(1)
if not isinstance(validators, list):
    sys.stderr.write("operator_committee_snapshot: validators JSON not an array\n")
    sys.exit(1)

# Domain → ed_pub lookup. validators RPC entries are
# {domain, ed_pub, active_from, registered_at, stake, region}.
dom2pub = {}
for v in validators:
    if isinstance(v, dict):
        d = v.get("domain")
        p = v.get("ed_pub")
        if isinstance(d, str) and isinstance(p, str):
            dom2pub[d] = p

# Block fields. creators[] is a list of domain strings;
# creator_block_sigs[] is a list of 64-byte hex sigs in matching index
# order (per Block::to_json). consensus_mode is 0 = MUTUAL_DISTRUST,
# 1 = BFT. partner_subset_hash is optional (only emitted when non-zero).
creators           = blk.get("creators") or []
creator_block_sigs = blk.get("creator_block_sigs") or []
consensus_mode_i   = blk.get("consensus_mode", 0)
try:
    consensus_mode_i = int(consensus_mode_i)
except Exception:
    consensus_mode_i = 0
consensus_mode_str = "bft" if consensus_mode_i == 1 else "mutual_distrust"
partner_subset_hash = blk.get("partner_subset_hash")  # may be missing

if not isinstance(creators, list):
    sys.stderr.write("operator_committee_snapshot: block 'creators' is not an array\n")
    sys.exit(1)
creators = [c for c in creators if isinstance(c, str)]

if not isinstance(creator_block_sigs, list):
    creator_block_sigs = []

K = len(creators)

# Required-sigs gate. Mirrors producer.cpp::required_block_sigs:
#   MUTUAL_DISTRUST → K (unanimous within the committee)
#   BFT             → ceil(2 * K / 3)
# Note: in BFT mode the producer-side already shrinks the wire committee
# to k_bft = ceil(2K_genesis/3) before this point, so `creators[]` here
# IS the shrunken committee. The gate Q = ceil(2 * len(creators) / 3)
# is therefore computed off the OBSERVED committee size.
if consensus_mode_i == 1:
    required_sigs = (2 * K + 2) // 3 if K > 0 else 0
else:
    required_sigs = K

# Observed sigs: count non-zero block-sig entries that match the
# expected length. A signature slot is "present" iff (a) it exists at
# this index AND (b) it's not the all-zero sentinel.
def is_nonzero_hex(s):
    if not isinstance(s, str): return False
    if len(s) == 0: return False
    # 64-byte signature = 128 hex chars; tolerate other lengths gracefully
    # (don't fail the snapshot on a malformed-but-recognizable entry).
    return any(ch != '0' for ch in s)

observed_sigs = 0
per_sig_present = []
for i in range(K):
    sig = creator_block_sigs[i] if i < len(creator_block_sigs) else ""
    present = is_nonzero_hex(sig)
    per_sig_present.append(present)
    if present:
        observed_sigs += 1

# Per-creator rows. pubkey_short = first 12 chars of the hex pubkey
# (consistent with the operator-tool convention of short-hash display).
rows = []
for i, dom in enumerate(creators):
    pub_full = dom2pub.get(dom, "")
    pub_short = pub_full[:12] if pub_full else "<unknown>"
    sig_hex = creator_block_sigs[i] if i < len(creator_block_sigs) else None
    if sig_hex is not None and not isinstance(sig_hex, str):
        sig_hex = None
    rows.append({
        "position":     i,
        "domain":       dom,
        "pubkey_full":  pub_full,
        "pubkey_short": pub_short,
        "sig_present":  per_sig_present[i],
        "sig_hex":      sig_hex if per_sig_present[i] else None,
    })

# Duplicate check. By NodeRegistry construction, committee selection
# draws DISTINCT validators (Fisher-Yates / rejection sampling — see
# crypto/random.cpp::select_m_creators). A duplicate domain in a
# block's creators[] would indicate either a chain-state corruption or
# a bug in the producer's commit/finalize path.
dup_counts = {}
for c in creators:
    dup_counts[c] = dup_counts.get(c, 0) + 1
duplicates = [{"domain": d, "count": n} for d, n in dup_counts.items() if n > 1]
duplicates.sort(key=lambda x: (-x["count"], x["domain"]))
dup_ok = len(duplicates) == 0

envelope = {
    "height":             height,
    "consensus_mode":     consensus_mode_str,
    "bft_mode_enabled":   bft_enabled,
    "committee_size":     K,
    "required_sigs":      required_sigs,
    "observed_sigs":      observed_sigs,
    "creators":           rows,
    "partner_subset_hash": partner_subset_hash,  # None if absent
    "duplicate_check": {
        "ok":         dup_ok,
        "duplicates": duplicates,
    },
    "rpc_port":           port,
}

if json_out:
    print(json.dumps(envelope))
    sys.exit(0 if dup_ok else 2)

# Human-readable render.
print(f"Committee at height {height}:")
print(f"  size: K={K}")
print(f"  consensus_mode: {consensus_mode_str}")
print(f"  bft_mode: {'on' if bft_enabled else 'off'}  (chain-level config)")
if consensus_mode_i == 1:
    print(f"  required_sigs: {required_sigs} (BFT: ceil(2K/3))")
else:
    print(f"  required_sigs: {required_sigs} (K-of-K mutual distrust)")
print(f"  observed_sigs: {observed_sigs} of {K}")
print(f"  creators:")
for r in rows:
    flag = "yes" if r["sig_present"] else "no"
    pub  = r["pubkey_short"]
    dom  = r["domain"]
    print(f"    {r['position']+1}. {dom:<32} pubkey={pub:<12} sig_present={flag}")
if partner_subset_hash:
    print(f"  partner_subset_hash: {partner_subset_hash}")
else:
    print(f"  partner_subset_hash: absent (no R4 Phase 3 partner-subset selection)")

if dup_ok:
    print(f"  duplicate_check: ok")
else:
    print(f"  duplicate_check: FAIL")
    for d in duplicates:
        print(f"    - domain={d['domain']} appears {d['count']} times")

sys.exit(0 if dup_ok else 2)
PY
RC=$?
exit $RC
