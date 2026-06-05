#!/usr/bin/env bash
# operator_escalation_consistency.sh — Per-block BFT-escalation legality
# audit over a window of finalized blocks. Walks the chain and, for every
# block, checks that its recorded consensus_mode is internally consistent
# with the escalation invariants the producer + validator enforce
# (src/node/node.cpp escalation gate + src/node/producer.cpp::
# required_block_sigs + src/node/validator.cpp mode-eligibility). A
# finalized block that violates any invariant indicates a producer bug,
# a validator that admitted an illegal block, config drift between nodes,
# or chain-state corruption — all worth an operator alert.
#
# Sibling tools and how this one differs:
#   operator_committee_snapshot.sh
#       SINGLE-height composition snapshot: K creators, per-creator sig
#       presence, required-sigs gate, duplicate-pubkey check. Reports the
#       gate value but does not assert escalation LEGALITY across a window
#       (it never flags an illegal BFT block under bft_enabled=false, nor
#       a bft_proposer absent from creators[]).
#   operator_signature_audit.sh
#       Window-wide SIG-FILL ratios + k_mode/bft_mode bucket counts +
#       per-validator miss-rates. Asks "are committee members signing?"
#       — a participation lens. It buckets blocks by sig count but never
#       checks the BFT committee SIZE invariant or proposer membership.
#   operator_block_inclusion_audit.sh
#       Per-validator participation + bft_proposer CONCENTRATION (who
#       proposes most). Tracks proposer share for centralization, not
#       per-block escalation legality.
#   operator_escalation_consistency.sh  (THIS)
#       Per-block escalation-LEGALITY audit. For each block asserts the
#       five invariants below and reports any violation. Answers: "is
#       every finalized block's consensus_mode internally consistent
#       with the escalation rules, and did any illegal block slip in?"
#
# Per-block invariants (checked against status.k_block_sigs = genesis K
# and status.protections.bft_enabled):
#   I1  illegal_bft_block       consensus_mode == BFT while the chain's
#                               bft_enabled config is false. A BFT block
#                               should be unreachable when escalation is
#                               disabled (validator.cpp rejects BFT-mode
#                               blocks unless bft_enabled_). Its presence
#                               means a node ran with a divergent config
#                               or the validator gate was bypassed.
#   I2  bft_committee_size_bad  consensus_mode == BFT but len(creators)
#                               != k_bft = ceil(2*K/3). The producer
#                               shrinks the committee to exactly k_bft
#                               before a BFT round (node.cpp escalation
#                               gate); a mismatch means the wire committee
#                               wasn't the BFT-shrunk set.
#   I3  bft_proposer_missing    consensus_mode == BFT but bft_proposer is
#                               empty OR not present in creators[]. BFT
#                               mode requires a designated proposer drawn
#                               FROM the committee (block.hpp: bft_proposer
#                               non-empty iff consensus_mode == BFT).
#   I4  md_proposer_set         consensus_mode == MUTUAL_DISTRUST but
#                               bft_proposer is non-empty. MD blocks have
#                               no designated proposer; a set field is a
#                               mode-field inconsistency.
#   I5  sigs_below_quorum       observed non-sentinel block-sigs <
#                               required_sigs, where required_sigs is K
#                               for MD and ceil(2*len(creators)/3) for BFT
#                               (producer.cpp::required_block_sigs). A
#                               finalized block must carry at least the
#                               quorum; fewer means it was admitted below
#                               the gate.
#
# K source caveat: K (genesis k_block_sigs) is read from `determ status`
# at audit time. If governance staged a PARAM_CHANGE to k_block_sigs that
# activated mid-window, the I2/I5 arithmetic uses the CURRENT K for every
# block in the window — historical blocks produced under a different K
# would be mis-flagged. The JSON envelope names the K used so an operator
# can cross-check against operator_param_change_history.sh. For windows
# inside a single K regime (the common case) this is exact.
#
# Read-only RPCs only: `determ status` (once) + `determ block-info <h>`
# per block. Safe against any running daemon; never mutates.
#
# Args:
#   --rpc-port N         RPC port to query (REQUIRED)
#   --from H             Lower window bound, inclusive (default: head-999)
#   --to H               Upper window bound, inclusive (default: head)
#   --last N             Shorthand for [head-N+1, head] (mutually exclusive
#                        with --from/--to)
#   --bft-only           Restrict the walk to blocks recorded as BFT mode
#                        (MD blocks are still counted in the summary but
#                        not row-printed in human mode)
#   --json               Emit structured JSON envelope
#   --anomalies-only     Print only when >=1 violation fires; exit 2 then
#   -h, --help           Show this help
#
# Exit codes:
#   0   audit ran, no invariant violations (or default informational mode)
#   1   bad args / RPC error / malformed response
#   2   --anomalies-only AND >=1 violation detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_escalation_consistency.sh --rpc-port N
                                          [--from H] [--to H] [--last N]
                                          [--bft-only] [--json]
                                          [--anomalies-only]

Per-block BFT-escalation legality audit over a window of finalized
blocks. For each block, extracts consensus_mode, creators[],
creator_block_sigs[], and bft_proposer via `determ block-info <h> --json`
and checks five escalation invariants against the chain's genesis K
(status.k_block_sigs) and bft_enabled config (status.protections):

  I1 illegal_bft_block      BFT block while bft_enabled is false
  I2 bft_committee_size_bad BFT block with len(creators) != ceil(2K/3)
  I3 bft_proposer_missing   BFT block with empty/absent proposer in creators
  I4 md_proposer_set        MD block with a non-empty bft_proposer
  I5 sigs_below_quorum      observed sigs < required_sigs gate

Required:
  --rpc-port N         RPC port to query

Options:
  --from H             Lower window bound, inclusive (default: head-999)
  --to H               Upper window bound, inclusive (default: head)
  --last N             Shorthand for [head-N+1, head] (exclusive with
                       --from/--to)
  --bft-only           Only row-print BFT-mode blocks (MD still summarized)
  --json               Emit structured JSON envelope
  --anomalies-only     Print only when >=1 violation fires; exit 2 then
  -h, --help           Show this help

JSON shape:
  {"window": {"from": F, "to": T, "block_count": W},
   "genesis_k": K, "k_bft": KB, "bft_enabled": bool,
   "counts": {"md_blocks": M, "bft_blocks": B, "blocks_with_violations": V},
   "blocks": [
     {"height": H, "consensus_mode": "mutual_distrust|bft",
      "committee_size": K, "required_sigs": Q, "observed_sigs": S,
      "bft_proposer": "..."|null, "proposer_in_committee": bool|null,
      "violations": [...]}, ...],
   "summary": {"n_blocks": W, "n_violating_blocks": V,
               "violation_counts": {"I1": ..., ...}},
   "anomalies": [...],
   "rpc_port": P}

The `anomalies` array carries each distinct invariant id (I1..I5) that
fired at least once in the window, in I-id order.

Exit codes:
  0   success, no violations (or default informational mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND >=1 violation detected
EOF
}

PORT=""
FROM=""
TO=""
LAST=""
BFT_ONLY=0
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --from)            FROM="${2:-}";   shift 2 ;;
    --to)              TO="${2:-}";     shift 2 ;;
    --last)            LAST="${2:-}";   shift 2 ;;
    --bft-only)        BFT_ONLY=1;      shift ;;
    --json)            JSON_OUT=1;      shift ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_escalation_consistency: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (sibling-script convention; refuses to guess the
# daemon on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_escalation_consistency: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_escalation_consistency: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# --last is mutually exclusive with --from / --to.
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_escalation_consistency: --last cannot be combined with --from/--to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_escalation_consistency: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_escalation_consistency: --last must be >= 1" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works
# the same on Linux/Mac/Git Bash (matches operator_committee_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain head + genesis K + bft_enabled ──────────────────────
STATUS_JSON=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_escalation_consistency: RPC error from \`determ status\` (is daemon running on port $PORT?)" >&2
  exit 1
}
# Extract height, k_block_sigs (genesis K), and protections.bft_enabled in
# one python pass. k_block_sigs is a top-level status field; bft_enabled
# lives under the protections map (src/node/node.cpp rpc_status).
read -r HEIGHT GENESIS_K BFT_ENABLED <<EOF
$(printf '%s' "$STATUS_JSON" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    h = int(j.get('height', 0))
    k = int(j.get('k_block_sigs', 0))
    p = j.get('protections', {}) or {}
    b = p.get('bft_enabled')
    if b is None:
        b = j.get('bft_enabled', True)
    print(h, k, 'true' if bool(b) else 'false')
except Exception:
    print('', '', '')
")
EOF
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_escalation_consistency: malformed status JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac
case "$GENESIS_K" in *[!0-9]*|"")
  echo "operator_escalation_consistency: malformed status JSON (k_block_sigs='$GENESIS_K')" >&2
  exit 1 ;;
esac
if [ "$GENESIS_K" = "0" ]; then
  echo "operator_escalation_consistency: status reports k_block_sigs=0 (no committee size); cannot audit" >&2
  exit 1
fi

# Highest finalized index = height - 1. (Block 0 is genesis with empty
# creators[] / MUTUAL_DISTRUST mode; it never violates an invariant but
# is included in the count if the window covers it.)
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
if [ "$HEIGHT" = "0" ]; then
  echo "operator_escalation_consistency: chain is empty (height=0); nothing to audit" >&2
  exit 1
fi

# Resolve window bounds. Precedence: --last > (--from/--to) > defaults.
if [ -n "$LAST" ]; then
  if [ "$LAST" -gt $(( TOP + 1 )) ]; then
    FROM=0
  else
    FROM=$(( TOP - LAST + 1 ))
  fi
  TO=$TOP
else
  if [ -z "$TO" ]; then TO=$TOP; fi
  if [ -z "$FROM" ]; then
    # Default: last 1000 blocks ending at tip.
    if [ "$TOP" -gt 999 ]; then
      FROM=$(( TOP - 999 ))
    else
      FROM=0
    fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_escalation_consistency: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: per-block walk + invariant checks (driven from Python) ────────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_escalation_consistency: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" "$GENESIS_K" "$BFT_ENABLED" <<'PY'
import json, subprocess, sys, math

determ, port, from_h, to_h, out_path, k_s, bft_s = sys.argv[1:8]
from_h, to_h = int(from_h), int(to_h)
genesis_k    = int(k_s)
bft_enabled  = (bft_s == 'true')

# k_bft = ceil(2 * K / 3) — the BFT-shrunk committee size the producer
# escalates to (node.cpp escalation gate; producer.cpp comment).
k_bft = (2 * genesis_k + 2) // 3

def required_sigs(mode_is_bft, committee_size):
    # Mirrors src/node/producer.cpp::required_block_sigs:
    #   MUTUAL_DISTRUST -> committee_size (unanimous K-of-K)
    #   BFT             -> ceil(2 * committee_size / 3)
    if committee_size == 0:
        return 0
    if mode_is_bft:
        return (2 * committee_size + 2) // 3
    return committee_size

def is_nonzero_hex(s):
    # A signature slot is "present" iff it exists and is not the all-zero
    # sentinel (block.cpp emits lowercase hex; the all-zero Signature{}
    # is K - ceil(2K/3) of the slots in a BFT block by design).
    if not isinstance(s, str) or len(s) == 0:
        return False
    return any(ch != '0' for ch in s)

# Per-invariant tally + per-block records.
viol_counts = {"I1": 0, "I2": 0, "I3": 0, "I4": 0, "I5": 0}
blocks      = []
md_blocks   = 0
bft_blocks  = 0
n_violating = 0

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_escalation_consistency: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_escalation_consistency: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_escalation_consistency: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []
    creators = [c for c in creators if isinstance(c, str)]

    sigs = blk.get("creator_block_sigs") or []
    if not isinstance(sigs, list):
        sigs = []

    mode_i = blk.get("consensus_mode", 0)
    try:
        mode_i = int(mode_i)
    except Exception:
        mode_i = 0
    is_bft = (mode_i == 1)

    proposer = blk.get("bft_proposer", "") or ""
    if not isinstance(proposer, str):
        proposer = ""

    K = len(creators)
    req = required_sigs(is_bft, K)
    observed = sum(1 for i in range(K) if is_nonzero_hex(sigs[i] if i < len(sigs) else ""))

    if is_bft:
        bft_blocks += 1
    else:
        md_blocks += 1

    # ── invariants ──────────────────────────────────────────────────────────
    violations = []
    proposer_in_committee = None
    if is_bft:
        # I1: BFT block while escalation disabled.
        if not bft_enabled:
            violations.append("I1")
            viol_counts["I1"] += 1
        # I2: BFT committee size must equal k_bft = ceil(2K/3).
        if K != k_bft:
            violations.append("I2")
            viol_counts["I2"] += 1
        # I3: designated proposer must be non-empty AND a committee member.
        proposer_in_committee = (proposer in creators) if proposer else False
        if not proposer or not proposer_in_committee:
            violations.append("I3")
            viol_counts["I3"] += 1
    else:
        # I4: MD block must NOT carry a designated proposer.
        if proposer:
            violations.append("I4")
            viol_counts["I4"] += 1

    # I5: observed sigs must meet the required-sigs gate. Genesis block 0
    # has K==0 (req==0) and trivially passes; skip the check there.
    if K > 0 and observed < req:
        violations.append("I5")
        viol_counts["I5"] += 1

    if violations:
        n_violating += 1

    blocks.append({
        "height":                h,
        "consensus_mode":        "bft" if is_bft else "mutual_distrust",
        "committee_size":        K,
        "required_sigs":         req,
        "observed_sigs":         observed,
        "bft_proposer":          proposer if proposer else None,
        "proposer_in_committee": proposer_in_committee,
        "violations":            violations,
    })

W = to_h - from_h + 1

# Distinct invariant ids that fired at least once, in I-id order.
anomalies = [k for k in ("I1", "I2", "I3", "I4", "I5") if viol_counts[k] > 0]

envelope = {
    "window": {
        "from":        from_h,
        "to":          to_h,
        "block_count": W,
    },
    "genesis_k":   genesis_k,
    "k_bft":       k_bft,
    "bft_enabled": bft_enabled,
    "counts": {
        "md_blocks":               md_blocks,
        "bft_blocks":              bft_blocks,
        "blocks_with_violations":  n_violating,
    },
    "blocks":  blocks,
    "summary": {
        "n_blocks":           W,
        "n_violating_blocks": n_violating,
        "violation_counts":   viol_counts,
    },
    "anomalies": anomalies,
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(envelope, f)
PY
if [ "$?" -ne 0 ]; then exit 1; fi

# ── Step 3: render envelope ──────────────────────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$BFT_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WINDOW" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
bft_only  = sys.argv[3] == "1"
out_path  = sys.argv[4]
port      = int(sys.argv[5])
from_h    = int(sys.argv[6])
to_h      = int(sys.argv[7])
window    = int(sys.argv[8])

with open(out_path, "r", encoding="utf-8") as f:
    env = json.load(f)
env["rpc_port"] = port

anomalies = env.get("anomalies", []) or []
n_anom    = len(anomalies)

if json_out:
    print(json.dumps(env))
    sys.exit(0)

# --anomalies-only: suppress normal output unless a violation fired.
if anom_only and n_anom == 0:
    print(f"operator_escalation_consistency: no violations "
          f"(port {port}, window [{from_h}..{to_h}], {window} blocks)")
    sys.exit(0)

genesis_k   = env["genesis_k"]
k_bft       = env["k_bft"]
bft_enabled = env["bft_enabled"]
counts      = env["counts"]
blocks      = env["blocks"]
summary     = env["summary"]

# Human-readable invariant legend (printed once for operator reference).
LEGEND = {
    "I1": "illegal_bft_block (BFT while bft_enabled=false)",
    "I2": f"bft_committee_size_bad (BFT len(creators) != k_bft={k_bft})",
    "I3": "bft_proposer_missing (empty/absent proposer in creators)",
    "I4": "md_proposer_set (MD block with a non-empty bft_proposer)",
    "I5": "sigs_below_quorum (observed sigs < required_sigs)",
}

print(f"=== Escalation-consistency audit (port {port}, window [{from_h}..{to_h}], "
      f"{window} blocks) ===")
print(f"Genesis K: {genesis_k}    k_bft (ceil(2K/3)): {k_bft}    "
      f"bft_enabled: {'true' if bft_enabled else 'false'}")
print(f"MD blocks: {counts['md_blocks']}    BFT blocks: {counts['bft_blocks']}    "
      f"Blocks with violations: {counts['blocks_with_violations']}")
print()

# Per-block table. In --bft-only mode, MD blocks are skipped here (still
# counted in the summary above). Rows with violations are always printed
# regardless of --bft-only so an operator never misses an alert.
rows = []
for b in blocks:
    if bft_only and b["consensus_mode"] != "bft" and not b["violations"]:
        continue
    rows.append(b)

if rows:
    print("Per-block (height / mode / committee / sigs / proposer / violations):")
    print(f"  {'height':>8} {'mode':>16} {'K':>4} {'req':>4} {'obs':>4} "
          f"{'proposer':<18} violations")
    print(f"  {'-'*8} {'-'*16} {'-'*4} {'-'*4} {'-'*4} {'-'*18} {'-'*20}")
    for b in rows:
        prop = b["bft_proposer"] or "-"
        prop = prop[:18]
        vio  = ",".join(b["violations"]) if b["violations"] else "ok"
        print(f"  {b['height']:>8} {b['consensus_mode']:>16} "
              f"{b['committee_size']:>4} {b['required_sigs']:>4} "
              f"{b['observed_sigs']:>4} {prop:<18} {vio}")
    print()

# Violation-count rollup.
vc = summary["violation_counts"]
print(f"Violating blocks: {summary['n_violating_blocks']} / {summary['n_blocks']}")
for k in ("I1", "I2", "I3", "I4", "I5"):
    if vc.get(k, 0) > 0:
        print(f"  {k}: {vc[k]}  — {LEGEND[k]}")

print()
if n_anom == 0:
    print("[OK] All blocks consistent with escalation invariants")
else:
    for a in anomalies:
        print(f"[WARN] {a} fired ({vc.get(a,0)} block(s)) — {LEGEND.get(a, a)}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_escalation_consistency: rendering failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 4: exit-code policy ─────────────────────────────────────────────────
# Same convention as sibling scripts: exit 2 only when --anomalies-only
# AND >=1 violation fired. Default informational mode always exits 0 if
# the RPC walk succeeded.
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f: env = json.load(f)
print(len(env.get("anomalies") or []))
PY
)
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
