#!/usr/bin/env bash
# operator_reorg_resilience.sh — Per-block FORK-CHOICE WEIGHT / reorg-
# resilience margin audit over a window of finalized blocks. For every
# block in the window this tool reconstructs the exact weight the daemon's
# own tie-break would assign it and reports how decisively (or not) that
# block would survive a competing same-height block under fork-choice.
# Read-only RPC composition; safe against a producing chain.
#
# THE OPERATOR QUESTION THIS ANSWERS
#   "If a competing block appeared at one of my recent heights, would my
#    current head win the fork-choice tie-break — and by how much margin?
#    Which of my recent heads are the WEAK links a reorg could displace?"
#
# WHY THIS IS A REAL, UNCOVERED SIGNAL
#   When two blocks compete at the same height Determ resolves the fork
#   deterministically in src/chain/chain.cpp::resolve_fork (lines
#   1516-1537), in strict key order:
#     KEY 1 (primary)  heaviest NON-ZERO creator_block_sigs count wins
#                      (chain.cpp:1517-1526: `sig_count` lambda counts
#                       slots != the all-zero Signature; na>nb ? a : b).
#     KEY 2 (next)     FEWER abort_events wins
#                      (chain.cpp:1528-1529: smaller .size() wins).
#     KEY 3 (final)    smallest compute_hash() wins
#                      (chain.cpp:1531-1535: lexicographic byte compare).
#
#   KEY 1 is the only key an honest competitor can BEAT without colluding
#   on a lower hash: a rival block that gathers MORE non-zero committee
#   signatures than my head out-weighs it outright and a reorg follows.
#   Therefore a head's reorg-resilience on KEY 1 is exactly:
#       sat_headroom = committee_size - nonzero_sigs
#   where committee_size = len(creators) for that block and nonzero_sigs is
#   the count of present signatures. A SATURATED block (sat_headroom == 0,
#   every committee slot signed) cannot be out-weighted on KEY 1 — the
#   strongest possible head. A block with sat_headroom > 0 left signature
#   slots empty, so a competitor that fills more of them wins KEY 1.
#
#   The fields that drive all three keys are emitted verbatim by
#   Block::to_json (src/chain/block.cpp:367) and are PRESERVED by the
#   paged `headers` RPC (src/node/node.cpp::rpc_headers strips only
#   transactions / cross_shard_receipts / inbound_receipts / initial_state
#   at lines 2652-2655 — it KEEPS creators[], creator_block_sigs[],
#   abort_events[], consensus_mode, bft_proposer, and block_hash). So a
#   whole window's fork-choice weights come from one paged
#   `determ block-range FROM TO --json` call, no per-height round trips.
#
#   The minimum non-zero sig count any finalized block can legally carry
#   is the producer's required_block_sigs quorum
#   (src/node/producer.cpp::required_block_sigs):
#       MUTUAL_DISTRUST -> committee_size (unanimous K-of-K)
#       BFT             -> ceil(2 * committee_size / 3)
#   A block sitting AT that quorum (sat_headroom == committee_size - quorum)
#   is the thinnest legally-final head — maximally reorg-exposed on KEY 1.
#   The genesis K (status.k_block_sigs) and bft_enabled (status.protections)
#   bound what quorum applies (src/node/node.cpp rpc_status fields
#   k_block_sigs / protections.bft_enabled).
#
# SIBLING-SCRIPT POSITIONING (none compute the resolve_fork tie-break margin)
#   operator_fork_watch.sh        CROSS-NODE divergence: compares the last
#                                 N blocks on TWO daemons and reports the
#                                 first height they disagree on a field
#                                 (wraps `determ check-fork`). Needs two
#                                 nodes; says nothing about a SINGLE head's
#                                 fork-choice WEIGHT or reorg margin.
#   operator_signature_audit.sh   Window SIG-FILL ratios + per-validator
#                                 miss-rates (a PARTICIPATION lens — "are
#                                 members signing?"). Buckets blocks by sig
#                                 count but never frames it as the KEY-1
#                                 tie-break margin nor flags out-weight-able
#                                 heads against the resolve_fork order.
#   operator_escalation_consistency.sh
#                                 Per-block consensus_mode LEGALITY (is the
#                                 BFT/strong escalation internally valid?).
#                                 Orthogonal axis; ignores fork-choice weight.
#   operator_committee_snapshot.sh
#                                 SINGLE-height committee membership + the
#                                 required-sigs gate. One height, no window,
#                                 no reorg-margin framing.
#   THIS (operator_reorg_resilience.sh)
#                                 The ONLY tool that reconstructs the
#                                 resolve_fork weight per block and reports
#                                 KEY-1 saturation headroom + abort-load
#                                 (KEY 2) as a per-head reorg-resilience
#                                 margin across a window.
#
# OUTPUT
#   Per-block rows: index, consensus_mode, committee_size, nonzero_sigs,
#   quorum, sat_headroom (committee_size - nonzero_sigs), abort_events.
#   A block is flagged when sat_headroom > 0 (out-weight-able on KEY 1) or,
#   under --strict, when it is merely AT quorum (thinnest legal head).
#   Final [OK] / [ANOMALY] verdict + window aggregate (min/worst headroom).
#
# EXIT CODES
#   0  success / informational / clean SKIP (daemon down or empty chain)
#   1  RPC error / malformed response / bad args / empty window
#   2  --anomalies-only AND >=1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_reorg_resilience.sh [--rpc-port N] [--last K | --from A --to B]
                                    [--json] [--anomalies-only] [--strict]

Per-block fork-choice WEIGHT / reorg-resilience audit. For each finalized
block in the window, reconstructs the weight Determ's deterministic
tie-break (src/chain/chain.cpp::resolve_fork) would assign it:

  committee_size = len(creators[])
  nonzero_sigs   = count of present (non-all-zero) creator_block_sigs[]
  quorum         = required_block_sigs(mode, committee_size)
                     MUTUAL_DISTRUST -> committee_size
                     BFT             -> ceil(2 * committee_size / 3)
  sat_headroom   = committee_size - nonzero_sigs   (KEY-1 reorg exposure)
  abort_events   = len(abort_events[])             (KEY-2 tie-break load)

A block with sat_headroom == 0 is SATURATED: every committee slot signed,
so no honest competitor can out-weight it on KEY 1 (the heaviest-sig-set
key). sat_headroom > 0 means empty signature slots a rival could fill to
win the fork-choice tie-break — a reorg-exposed head.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --last K            Audit the last K finalized blocks ending at tip
  --from A --to B     Explicit inclusive block-index window [A..B]
                      (default when neither given: last 256 blocks)
  --json              Emit a structured JSON envelope
  --anomalies-only    Print only flagged blocks; exit 2 if any fired
  --strict            Also flag blocks merely AT quorum (thinnest legal
                      head) even if not strictly out-weight-able
  -h, --help          Show this help

Anomalies:
  reorg_exposed_head  sat_headroom > 0 (out-weight-able on resolve_fork KEY 1)
  at_quorum_head      [--strict only] nonzero_sigs == quorum (thinnest legal)

JSON shape:
  {"rpc_port": P, "from": A, "to": B, "window": W,
   "genesis_k": K, "bft_enabled": true|false,
   "blocks": [{"index": I, "consensus_mode": M, "committee_size": C,
               "nonzero_sigs": S, "quorum": Q, "sat_headroom": H,
               "abort_events": E, "flags": [...]}, ...],
   "worst_sat_headroom": N, "exposed_count": N, "at_quorum_count": N,
   "anomalies": [...], "strict": false}

Exit codes:
  0   success / informational / clean SKIP (daemon down or empty chain)
  1   RPC error / malformed response / bad args / empty window
  2   --anomalies-only AND >=1 anomaly detected
EOF
}

PORT=7778
JSON=0
ANOM_ONLY=0
STRICT=0
LAST=""
FROM=""
TO=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";   shift 2 ;;
    --last)           LAST="${2:-}";   shift 2 ;;
    --from)           FROM="${2:-}";   shift 2 ;;
    --to)             TO="${2:-}";     shift 2 ;;
    --json)           JSON=1;          shift ;;
    --anomalies-only) ANOM_ONLY=1;     shift ;;
    --strict)         STRICT=1;        shift ;;
    *) echo "operator_reorg_resilience: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_reorg_resilience: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -n "$LAST" ]; then
  case "$LAST" in *[!0-9]*|"")
    echo "operator_reorg_resilience: --last must be a positive integer (got '$LAST')" >&2
    exit 1 ;;
  esac
  if [ "$LAST" -lt 1 ]; then
    echo "operator_reorg_resilience: --last must be >= 1" >&2
    exit 1
  fi
  if [ -n "$FROM" ] || [ -n "$TO" ]; then
    echo "operator_reorg_resilience: --last is mutually exclusive with --from/--to" >&2
    exit 1
  fi
fi
if [ -n "$FROM" ]; then
  case "$FROM" in *[!0-9]*) echo "operator_reorg_resilience: --from must be a non-negative integer (got '$FROM')" >&2; exit 1 ;; esac
fi
if [ -n "$TO" ]; then
  case "$TO" in *[!0-9]*) echo "operator_reorg_resilience: --to must be a non-negative integer (got '$TO')" >&2; exit 1 ;; esac
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python behaves
# identically on Linux/Mac/Git Bash (matches sibling audit scripts).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: status snapshot (height, genesis K, bft_enabled) ──────────────────
# Daemon-unreachable here is the clean SKIP path: emit an INFO line (or a
# {"skipped":true} envelope) and exit 0 so a scheduled audit never pages on
# a node that is simply down / not yet up.
STATUS_OUT=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON" = "1" ]; then
    printf '{"skipped":true,"reason":"daemon_unreachable","rpc_port":%s}\n' "$PORT"
  else
    echo "INFO: operator_reorg_resilience: daemon unreachable on port $PORT — SKIP"
  fi
  exit 0
}

# height, k_block_sigs (genesis K), protections.bft_enabled in one pass.
read -r HEIGHT GENESIS_K BFT_ENABLED <<EOF
$(printf '%s' "$STATUS_OUT" | python -c "
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
  echo "operator_reorg_resilience: malformed status JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac
case "$GENESIS_K" in *[!0-9]*|"")
  echo "operator_reorg_resilience: malformed status JSON (k_block_sigs='$GENESIS_K')" >&2
  exit 1 ;;
esac

if [ "$HEIGHT" = "0" ]; then
  # Empty chain (genesis only) — nothing to audit. Clean SKIP, not an error.
  if [ "$JSON" = "1" ]; then
    printf '{"skipped":true,"reason":"empty_chain","rpc_port":%s}\n' "$PORT"
  else
    echo "INFO: operator_reorg_resilience: chain is empty (height=0) — SKIP"
  fi
  exit 0
fi

# Highest finalized index = height - 1. Block 0 is genesis (empty creators[],
# no committee sigs) — included only if the window explicitly covers it; its
# committee_size 0 yields sat_headroom 0 and never flags.
TOP=$(( HEIGHT - 1 ))

# Resolve window. Precedence: --last > (--from/--to) > default last 256.
if [ -n "$LAST" ]; then
  if [ "$LAST" -gt $(( TOP + 1 )) ]; then FROM=0; else FROM=$(( TOP - LAST + 1 )); fi
  TO=$TOP
else
  if [ -z "$TO" ]; then TO=$TOP; fi
  if [ -z "$FROM" ]; then
    if [ "$TOP" -gt 255 ]; then FROM=$(( TOP - 255 )); else FROM=0; fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_reorg_resilience: empty window (--to $TO < --from $FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: per-block walk + fork-choice weight reconstruction (Python) ───────
# The headers RPC (driving `block-range --json`) keeps creators[],
# creator_block_sigs[], abort_events[], consensus_mode — everything
# resolve_fork weighs. Paged fetch is handled inside Python so a large
# window costs O(window/256) RPCs, not O(window).
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_reorg_resilience: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" "$STRICT" <<'PY'
import json, subprocess, sys

determ, port, from_h, to_h, out_path, strict_s = sys.argv[1:7]
from_h, to_h = int(from_h), int(to_h)
strict = (strict_s == '1')

PAGE = 256  # server HEADERS_PAGE_MAX (node.cpp rpc_headers)

def fetch_range(a, b):
    """Paged block-range --json -> list of header dicts for [a..b]."""
    out = []
    cur = a
    while cur <= b:
        end = min(cur + PAGE - 1, b)
        try:
            r = subprocess.run(
                [determ, "block-range", str(cur), str(end), "--json",
                 "--rpc-port", str(port)],
                capture_output=True, text=True, timeout=60)
        except Exception as e:
            return None, "block-range subprocess failed: %s" % e
        if r.returncode != 0:
            return None, "block-range rc=%d: %s" % (r.returncode, r.stderr.strip())
        try:
            j = json.loads(r.stdout)
        except Exception as e:
            return None, "block-range JSON parse: %s" % e
        hdrs = j.get("headers", [])
        if not isinstance(hdrs, list):
            return None, "block-range 'headers' not an array"
        out.extend(hdrs)
        if not hdrs:
            break  # server truncated at tail; stop
        cur = end + 1
    return out, None

ZERO_SIG = "0" * 128  # 64-byte all-zero signature in hex

def nonzero_sig_count(sigs):
    n = 0
    for s in sigs:
        if not isinstance(s, str):
            continue
        t = s.strip().lower()
        # A slot is "present" iff it is hex and not the all-zero signature.
        if t and t.strip("0") != "" and t != ZERO_SIG:
            n += 1
    return n

def required_sigs(mode_is_bft, committee_size):
    # Mirrors src/node/producer.cpp::required_block_sigs.
    if committee_size == 0:
        return 0
    if mode_is_bft:
        return (2 * committee_size + 2) // 3   # ceil(2C/3)
    return committee_size

hdrs, err = fetch_range(from_h, to_h)
if err is not None:
    with open(out_path, "w") as f:
        json.dump({"error": err}, f)
    sys.exit(0)

# consensus_mode encoding (Block::to_json emits uint8): the BFT mode is the
# escalated path. We treat any mode whose required-sig formula is the 2/3
# quorum as BFT; the canonical encoding has MUTUAL_DISTRUST=0, BFT=1
# (see src/chain/block.hpp ConsensusMode). We map defensively: mode != 0
# => BFT-style quorum.
blocks = []
worst = None          # smallest (most exposed) sat_headroom over the window
exposed = 0
at_quorum = 0

for h in hdrs:
    try:
        idx = int(h.get("index"))
    except Exception:
        continue
    if idx < from_h or idx > to_h:
        continue
    creators = h.get("creators") or []
    sigs     = h.get("creator_block_sigs") or []
    aborts   = h.get("abort_events") or []
    try:
        mode = int(h.get("consensus_mode", 0))
    except Exception:
        mode = 0
    csize = len(creators) if isinstance(creators, list) else 0
    nz    = nonzero_sig_count(sigs) if isinstance(sigs, list) else 0
    ne    = len(aborts) if isinstance(aborts, list) else 0
    mode_is_bft = (mode != 0)
    quorum = required_sigs(mode_is_bft, csize)
    sat_headroom = csize - nz

    flags = []
    # KEY-1 reorg exposure: empty signature slots a rival could fill to
    # out-weight this head. Genesis (csize 0) never flags.
    if csize > 0 and sat_headroom > 0:
        flags.append("reorg_exposed_head")
        exposed += 1
    # --strict: even a saturated-vs-quorum distinction — a block merely AT
    # the legal quorum is the thinnest legal head (most exposed of the
    # legal-but-saturated class only when quorum < csize).
    if strict and csize > 0 and quorum > 0 and nz == quorum and quorum < csize:
        if "reorg_exposed_head" not in flags:
            flags.append("at_quorum_head")
        else:
            flags.append("at_quorum_head")
        at_quorum += 1

    if csize > 0 and (worst is None or sat_headroom > worst):
        # "worst" = the largest sat_headroom (most exposed). Track the max.
        worst = sat_headroom
    elif worst is None and csize > 0:
        worst = sat_headroom

    blocks.append({
        "index": idx,
        "consensus_mode": mode,
        "committee_size": csize,
        "nonzero_sigs": nz,
        "quorum": quorum,
        "sat_headroom": sat_headroom,
        "abort_events": ne,
        "flags": flags,
    })

result = {
    "blocks": blocks,
    "worst_sat_headroom": (worst if worst is not None else 0),
    "exposed_count": exposed,
    "at_quorum_count": at_quorum,
}
with open(out_path, "w") as f:
    json.dump(result, f)
PY

if [ ! -s "$TMP_OUT" ]; then
  echo "operator_reorg_resilience: internal error (no audit output produced)" >&2
  exit 1
fi

# Surface a Python-side fetch error as RPC error (exit 1).
PY_ERR=$(printf '%s' "$(cat "$TMP_OUT")" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(j.get('error',''))
except Exception:
    print('parse_error')
")
if [ -n "$PY_ERR" ]; then
  echo "operator_reorg_resilience: $PY_ERR" >&2
  exit 1
fi

# ── Step 3: render ────────────────────────────────────────────────────────────
EXPOSED=$(printf '%s' "$(cat "$TMP_OUT")" | python -c "import sys,json;print(json.load(sys.stdin).get('exposed_count',0))")
AT_QUORUM=$(printf '%s' "$(cat "$TMP_OUT")" | python -c "import sys,json;print(json.load(sys.stdin).get('at_quorum_count',0))")
WORST=$(printf '%s' "$(cat "$TMP_OUT")" | python -c "import sys,json;print(json.load(sys.stdin).get('worst_sat_headroom',0))")
NBLK=$(printf '%s' "$(cat "$TMP_OUT")" | python -c "import sys,json;print(len(json.load(sys.stdin).get('blocks',[])))")

if [ "$NBLK" = "0" ]; then
  echo "operator_reorg_resilience: window [$FROM..$TO] returned no blocks" >&2
  exit 1
fi

# Total anomalies = exposed + (strict ? at_quorum : 0).
ANOM_TOTAL=$EXPOSED
if [ "$STRICT" = "1" ]; then ANOM_TOTAL=$(( EXPOSED + AT_QUORUM )); fi

if [ "$JSON" = "1" ]; then
  # Compose the final envelope from the per-block payload plus the window
  # metadata gathered in shell.
  printf '%s' "$(cat "$TMP_OUT")" | python -c "
import sys, json
j = json.load(sys.stdin)
anomalies = []
for b in j.get('blocks', []):
    for fl in b.get('flags', []):
        if fl not in anomalies:
            anomalies.append(fl)
env = {
    'rpc_port': int('$PORT'),
    'from': int('$FROM'),
    'to': int('$TO'),
    'window': int('$WINDOW'),
    'genesis_k': int('$GENESIS_K'),
    'bft_enabled': ('$BFT_ENABLED' == 'true'),
    'blocks': j.get('blocks', []),
    'worst_sat_headroom': j.get('worst_sat_headroom', 0),
    'exposed_count': j.get('exposed_count', 0),
    'at_quorum_count': j.get('at_quorum_count', 0),
    'anomalies': anomalies,
    'strict': ('$STRICT' == '1'),
}
print(json.dumps(env))
"
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_TOTAL" -gt 0 ]; then exit 2; fi
  exit 0
fi

# Human render: header + per-block rows (or anomalies-only) + verdict.
echo "operator_reorg_resilience: window=[$FROM..$TO] ($WINDOW blocks) port=$PORT genesis_K=$GENESIS_K bft_enabled=$BFT_ENABLED"
echo "  idx        mode  committee  nonzero_sigs  quorum  sat_headroom  aborts  flags"

printf '%s' "$(cat "$TMP_OUT")" | python -c "
import sys, json
j = json.load(sys.stdin)
anom_only = ('$ANOM_ONLY' == '1')
for b in j.get('blocks', []):
    flags = b.get('flags', [])
    if anom_only and not flags:
        continue
    mode = 'BFT' if b['consensus_mode'] != 0 else 'STRONG'
    print('  %-9d %-6s %9d  %12d  %6d  %12d  %6d  %s' % (
        b['index'], mode, b['committee_size'], b['nonzero_sigs'],
        b['quorum'], b['sat_headroom'], b['abort_events'],
        ','.join(flags) if flags else '-'))
"

echo "  ---"
echo "  worst_sat_headroom=$WORST  reorg_exposed_heads=$EXPOSED  at_quorum_heads=$AT_QUORUM"

if [ "$ANOM_TOTAL" -gt 0 ]; then
  echo "[ANOMALY] operator_reorg_resilience: $ANOM_TOTAL block(s) reorg-exposed on resolve_fork KEY 1 (window [$FROM..$TO])"
  if [ "$ANOM_ONLY" = "1" ]; then exit 2; fi
  exit 0
fi

echo "[OK] operator_reorg_resilience: every head in [$FROM..$TO] is signature-saturated (no KEY-1 reorg exposure)"
exit 0
