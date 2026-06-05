#!/usr/bin/env bash
# operator_wire_budget_audit.sh — per-message-type S-022 wire-cap headroom
# audit. Measures the ACTUAL sync/gossip wire artifacts a node emits and
# checks each against the message-type-specific size cap enforced at
# `Peer::read_body` (include/determ/net/messages.hpp::max_message_bytes).
#
# Use case: an operator wants one command that answers "are any of my
# node's outbound sync wire messages at risk of being rejected by a
# peer's per-message-type cap?" S-022 applies DIFFERENT caps per MsgType
# (1 MB consensus chatter, 4 MB BLOCK / BEACON_HEADER / SHARD_TIP /
# CROSS_SHARD_RECEIPT_BUNDLE / HEADERS_RESPONSE, 16 MB only for
# SNAPSHOT_RESPONSE / CHAIN_RESPONSE). A node that produces a wire
# message exceeding its type's cap won't merely shed that message — the
# receiving peer DROPS the connection (`Peer::read_body` oversize close,
# same disposition as the framing-layer overflow). So an over-cap
# HEADERS_RESPONSE silently breaks light-client header sync from this
# node; an over-cap BLOCK breaks block propagation. This audit surfaces
# the headroom margin on each wire-artifact class BEFORE the cap bites.
#
# This is the per-message-TYPE complement to operator_block_size_audit.sh.
# That sibling walks a window of blocks and checks each block's JSON
# envelope against ONE configurable cap (capacity-pressure focus over a
# window). This script instead retrieves the THREE distinct wire
# artifacts a node actually emits over the gossip/sync layer — each as a
# whole message — and judges each against its OWN S-022 per-type cap
# (framing-robustness focus, single-shot). The two are disjoint: block
# size distribution vs per-type wire-budget headroom.
#
# Wire artifacts measured (each mapped to the read RPC that returns the
# exact bytes the gossip layer would frame):
#
#   - HEADERS_RESPONSE (4 MB cap) — fetched via `determ headers --from F
#     --count 256`. This is the real wire envelope the gossip path emits
#     (Node::on_headers_request wraps the byte-identical rpc_headers
#     output in make_headers_response). The 256-header page is the
#     server-capped maximum (HEADERS_PAGE_MAX), so the page measured is
#     the worst-case HEADERS_RESPONSE this node would ever emit at the
#     audited offset. Light-client header sync depends on this staying
#     under 4 MB.
#
#   - BLOCK (4 MB cap) — the chain tip fetched via `determ block-info
#     <tip> --json`. A BLOCK wire message carries the full block JSON
#     (make_block(b) = {BLOCK, b.to_json()}). The tip is the freshest /
#     typically-largest block; auditing it gives the current block-wire
#     headroom. Block propagation depends on this staying under 4 MB.
#
#   - SNAPSHOT_RESPONSE (16 MB cap) — fetched via `determ snapshot create`
#     (which calls the read-only `snapshot` RPC and writes the response
#     to stdout). This is the only legitimately large wire channel; the
#     16 MB cap is its ceiling. Bootstrap of a fresh peer depends on this
#     staying under 16 MB. Auditing it is optional (snapshot serialization
#     can be momentarily expensive on a large chain) and gated by
#     --include-snapshot; off by default to keep the audit light.
#
# Size estimation: for each artifact the size is the canonical-JSON
# length `len(json.dumps(obj, separators=(',',':')))`. This is an UPPER
# BOUND on the binary (wire-version 1) envelope — JSON adds field names,
# quoting, and 2x hex expansion on every digest / sig / payload — but it
# is the conservative number for cap planning: if the JSON estimate
# clears the cap, the binary wire form clears it with room to spare. The
# JSON path is also the cap that bites first in practice, since v0 (JSON)
# is frequently the negotiated wire version per the A3/S8 negotiation
# (see src/net/binary_codec.cpp module comment).
#
# Headroom classification per artifact (share of its type cap):
#   - OK     : size <= --warn-pct of cap (default 75%)
#   - WARN   : --warn-pct < size <= --crit-pct of cap (default 75%-90%)
#   - CRIT   : size > --crit-pct of cap (default > 90%) — an over-cap
#             message is a hard connection-drop; >90% is the last warning
#             before the producer starts emitting unrelayable messages.
#
# Read-only RPC composition; safe against a running daemon. The daemon
# must already be listening on --rpc-port. Issues only head / headers /
# block-info / (optionally) snapshot — never a mutating RPC.
#
# Usage:
#   tools/operator_wire_budget_audit.sh --rpc-port N
#       [--headers-from F] [--include-snapshot]
#       [--warn-pct N] [--crit-pct N]
#       [--json] [--anomalies-only] [-h|--help]
#
# Exit codes:
#   0   audit ran, no CRIT artifact (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND >=1 artifact classed CRIT (operator alert
#       gate — the node is at risk of emitting an over-cap wire message)
set -u

usage() {
  cat <<'EOF'
Usage: operator_wire_budget_audit.sh --rpc-port N
           [--headers-from F] [--include-snapshot]
           [--warn-pct N] [--crit-pct N]
           [--json] [--anomalies-only] [-h|--help]

Per-message-type S-022 wire-cap headroom audit. Retrieves the actual
sync/gossip wire artifacts a node emits (HEADERS_RESPONSE, the BLOCK
tip, and optionally SNAPSHOT_RESPONSE) and checks each against its
message-type-specific cap from include/determ/net/messages.hpp::
max_message_bytes (4 MB / 4 MB / 16 MB respectively). Sizes are the
canonical-JSON length (upper bound on the binary wire envelope).

Options:
  --rpc-port N           RPC port to query (REQUIRED)
  --headers-from F       Start index for the HEADERS_RESPONSE page
                         (default: max(0, tip-255) so the page ends at
                         the tip — the freshest 256-header window).
  --include-snapshot     Additionally audit the SNAPSHOT_RESPONSE artifact
                         (16 MB cap). Off by default — snapshot
                         serialization can be momentarily expensive on a
                         large chain. The HEADERS_RESPONSE + BLOCK
                         artifacts are always audited.
  --warn-pct N           WARN threshold as percent-of-cap (default 75).
  --crit-pct N           CRIT threshold as percent-of-cap (default 90).
                         Must satisfy 1 <= warn-pct <= crit-pct <= 100.
  --json                 Emit structured JSON envelope instead of human
                         table. Shape:
                           {"artifacts": [{"type": "HEADERS_RESPONSE",
                              "cap_bytes": N, "size_bytes": N,
                              "pct_of_cap_bps": N, "classification": "OK",
                              "detail": "..."}, ...],
                            "warn_pct": N, "crit_pct": N,
                            "anomalies": [...], "ok": bool,
                            "rpc_port": N, "head_height": N}
  --anomalies-only       Suppress OK artifact rows; exit 2 if any CRIT.
  -h, --help             Show this help.

Artifacts + caps (per S-022 / max_message_bytes):
  HEADERS_RESPONSE   4 MB   `determ headers --from F --count 256`
  BLOCK (tip)        4 MB   `determ block-info <tip> --json`
  SNAPSHOT_RESPONSE  16 MB  `determ snapshot create`  (--include-snapshot)

Classification (share of each artifact's OWN type cap):
  OK     size <= warn-pct of cap
  WARN   warn-pct < size <= crit-pct of cap
  CRIT   size > crit-pct of cap (over-cap = peer connection drop)

Exit codes:
  0   success (or informational mode), no CRIT artifact
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >=1 artifact classed CRIT
EOF
}

PORT=""
HEADERS_FROM=""
INCLUDE_SNAPSHOT=0
WARN_PCT=75
CRIT_PCT=90
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-port)           PORT="${2:-}";          shift 2 ;;
    --headers-from)       HEADERS_FROM="${2:-}";  shift 2 ;;
    --include-snapshot)   INCLUDE_SNAPSHOT=1;     shift ;;
    --warn-pct)           WARN_PCT="${2:-}";      shift 2 ;;
    --crit-pct)           CRIT_PCT="${2:-}";      shift 2 ;;
    --json)               JSON_OUT=1;             shift ;;
    --anomalies-only)     ANOM_ONLY=1;            shift ;;
    *) echo "operator_wire_budget_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required.
if [ -z "$PORT" ]; then
  echo "operator_wire_budget_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_wire_budget_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# Numeric guards on the percent thresholds.
case "$WARN_PCT" in *[!0-9]*|"")
  echo "operator_wire_budget_audit: --warn-pct must be an integer 1..100 (got '$WARN_PCT')" >&2
  exit 1 ;;
esac
case "$CRIT_PCT" in *[!0-9]*|"")
  echo "operator_wire_budget_audit: --crit-pct must be an integer 1..100 (got '$CRIT_PCT')" >&2
  exit 1 ;;
esac
if [ "$WARN_PCT" -lt 1 ] || [ "$WARN_PCT" -gt 100 ]; then
  echo "operator_wire_budget_audit: --warn-pct must be 1..100 (got '$WARN_PCT')" >&2
  exit 1
fi
if [ "$CRIT_PCT" -lt 1 ] || [ "$CRIT_PCT" -gt 100 ]; then
  echo "operator_wire_budget_audit: --crit-pct must be 1..100 (got '$CRIT_PCT')" >&2
  exit 1
fi
if [ "$WARN_PCT" -gt "$CRIT_PCT" ]; then
  echo "operator_wire_budget_audit: --warn-pct ($WARN_PCT) must be <= --crit-pct ($CRIT_PCT)" >&2
  exit 1
fi
if [ -n "$HEADERS_FROM" ]; then
  case "$HEADERS_FROM" in *[!0-9]*)
    echo "operator_wire_budget_audit: --headers-from must be an unsigned integer (got '$HEADERS_FROM')" >&2
    exit 1 ;;
  esac
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Resolve DETERM to an absolute path. Python's subprocess.run on Windows
# uses CreateProcessW which does not honor the inherited bash cwd the
# same way exec*() does — a relative build/Release/determ.exe resolves
# fine from a bash command but FileNotFoundError's from python on
# Windows. Pre-resolving here keeps the Python driver portable. (Same
# pattern as operator_block_size_audit.sh.)
case "$DETERM" in
  /*|[A-Za-z]:/*|[A-Za-z]:\\*) DETERM_ABS="$DETERM" ;;
  *) DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
esac

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM_ABS" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_wire_budget_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_wire_budget_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: resolve HEADERS_RESPONSE page start ──────────────────────────────
# Default: align the 256-header page to END at the tip (the freshest
# window), i.e. from = max(0, tip - 255). An explicit --headers-from
# overrides (clamp to [0, tip]).
if [ -n "$HEADERS_FROM" ]; then
  HF="$HEADERS_FROM"
  if [ "$HF" -gt "$HEAD_H" ]; then HF=$HEAD_H; fi
else
  if [ "$HEAD_H" -gt 255 ]; then
    HF=$(( HEAD_H - 255 ))
  else
    HF=0
  fi
fi

# ── Step 3: drive the wire-artifact retrieval + sizing in Python ─────────────
# A single Python pass issues the read RPCs, computes the canonical-JSON
# size of each wire artifact, and classifies each against its S-022 cap.
# Output: one TSV record per artifact written to TMP_ART:
#   <type>\t<cap_bytes>\t<size_bytes>\t<detail>
# A retrieval failure for a given artifact writes size_bytes = -1 and a
# detail string; the shell layer treats that as an RPC error (exit 1)
# unless the artifact is optional and absent by design.
TMP_ART=$(mktemp 2>/dev/null) || {
  echo "operator_wire_budget_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_ART" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$HEAD_H" "$HF" "$INCLUDE_SNAPSHOT" "$TMP_ART" <<'PY'
import json, subprocess, sys

(determ, port, head_h, headers_from, include_snapshot, art_path) = sys.argv[1:7]
head_h           = int(head_h)
headers_from     = int(headers_from)
include_snapshot = (include_snapshot == "1")

# S-022 per-message-type caps (mirror include/determ/net/messages.hpp::
# max_message_bytes). Each audited artifact is judged against its own
# cap, NOT a single shared ceiling.
CAP_4MB  = 4  * 1024 * 1024
CAP_16MB = 16 * 1024 * 1024

def canon_size(obj):
    # Canonical-JSON length: upper bound on the binary wire envelope.
    return len(json.dumps(obj, separators=(",", ":")))

def run_determ(args, timeout=30):
    # Returns (rc, stdout, stderr). Never raises — a launch failure is
    # surfaced as rc=-1 with the exception text in stderr so the caller
    # can record a per-artifact failure rather than aborting the whole
    # audit on one missing channel.
    try:
        r = subprocess.run([determ, *args],
                           capture_output=True, text=True, timeout=timeout)
        return (r.returncode, r.stdout, r.stderr)
    except Exception as e:
        return (-1, "", str(e))

records = []   # (type, cap_bytes, size_bytes_or_-1, detail)

# ── Artifact 1: HEADERS_RESPONSE (4 MB cap) ──────────────────────────────────
# `determ headers --from F --count 256` returns the {headers, from,
# count, height} envelope — byte-identical to what make_headers_response
# wraps over the gossip wire (Node::on_headers_request). 256 is the
# server-capped page maximum (HEADERS_PAGE_MAX), so the page measured is
# the worst-case HEADERS_RESPONSE this node emits at this offset.
rc, out, err = run_determ(
    ["headers", "--from", str(headers_from), "--count", "256",
     "--rpc-port", port])
if rc != 0:
    records.append(("HEADERS_RESPONSE", CAP_4MB, -1,
                    f"headers RPC rc={rc}: {err.strip()[:160]}"))
else:
    try:
        env = json.loads(out)
    except Exception:
        records.append(("HEADERS_RESPONSE", CAP_4MB, -1,
                        "headers RPC returned non-JSON"))
        env = None
    if env is not None:
        if not isinstance(env, dict) or "headers" not in env:
            records.append(("HEADERS_RESPONSE", CAP_4MB, -1,
                            "headers envelope missing 'headers' field"))
        else:
            hdrs = env.get("headers") or []
            n = len(hdrs) if isinstance(hdrs, list) else 0
            size = canon_size(env)
            records.append(("HEADERS_RESPONSE", CAP_4MB, size,
                            f"page from={headers_from} count={n} (256-cap)"))

# ── Artifact 2: BLOCK tip (4 MB cap) ─────────────────────────────────────────
# The chain tip is fetched as full block JSON via block-info. A BLOCK
# wire message is make_block(b) = {BLOCK, b.to_json()}; the body is the
# block JSON. We audit the tip as the freshest representative block.
rc, out, err = run_determ(
    ["block-info", str(head_h), "--json", "--rpc-port", port])
if rc != 0:
    records.append(("BLOCK", CAP_4MB, -1,
                    f"block-info {head_h} rc={rc}: {err.strip()[:160]}"))
else:
    try:
        blk = json.loads(out)
    except Exception:
        records.append(("BLOCK", CAP_4MB, -1,
                        f"block-info {head_h} returned non-JSON"))
        blk = None
    if blk is not None:
        if not isinstance(blk, dict):
            records.append(("BLOCK", CAP_4MB, -1,
                            f"block-info {head_h} not a JSON object"))
        else:
            txs = blk.get("transactions") or []
            n_tx = len(txs) if isinstance(txs, list) else 0
            size = canon_size(blk)
            records.append(("BLOCK", CAP_4MB, size,
                            f"tip height={head_h} txs={n_tx}"))

# ── Artifact 3: SNAPSHOT_RESPONSE (16 MB cap) — optional ──────────────────────
# `determ snapshot create` (no --out) calls the read-only `snapshot` RPC
# and writes the response JSON to stdout. This is the SNAPSHOT_RESPONSE
# wire body (make_snapshot_response wraps the same JSON). Gated by
# --include-snapshot since serialization can be momentarily expensive on
# a large chain.
if include_snapshot:
    rc, out, err = run_determ(["snapshot", "create", "--rpc-port", port],
                              timeout=60)
    if rc != 0:
        records.append(("SNAPSHOT_RESPONSE", CAP_16MB, -1,
                        f"snapshot create rc={rc}: {err.strip()[:160]}"))
    else:
        try:
            snap = json.loads(out)
        except Exception:
            records.append(("SNAPSHOT_RESPONSE", CAP_16MB, -1,
                            "snapshot create returned non-JSON"))
            snap = None
        if snap is not None:
            if not isinstance(snap, dict):
                records.append(("SNAPSHOT_RESPONSE", CAP_16MB, -1,
                                "snapshot is not a JSON object"))
            else:
                accts = snap.get("accounts") or []
                n_acct = len(accts) if isinstance(accts, list) else 0
                size = canon_size(snap)
                records.append(("SNAPSHOT_RESPONSE", CAP_16MB, size,
                                f"accounts={n_acct} "
                                f"block_index={snap.get('block_index', 0)}"))

with open(art_path, "w", encoding="utf-8") as f:
    for (t, cap, size, detail) in records:
        # Detail may contain no tabs (we replace any defensively).
        detail = detail.replace("\t", " ")
        f.write(f"{t}\t{cap}\t{size}\t{detail}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_wire_budget_audit: wire-artifact retrieval failed" >&2
  exit 1
fi

if [ ! -s "$TMP_ART" ]; then
  echo "operator_wire_budget_audit: no wire artifacts produced" >&2
  exit 1
fi

# ── Step 4: classify each artifact + detect RPC failures ─────────────────────
# A size_bytes of -1 is a retrieval failure. HEADERS_RESPONSE + BLOCK are
# mandatory (the chain always has a tip and the headers RPC always
# answers on a live daemon), so a -1 there is a hard exit-1 RPC error.
# SNAPSHOT_RESPONSE is only attempted under --include-snapshot; a -1 there
# is likewise treated as an error since the operator explicitly requested
# it.
render_pct() {
  # bps integer -> "NN.N%".
  local bps="$1"
  local whole=$(( bps / 100 ))
  local frac=$(( (bps % 100) / 10 ))
  printf '%d.%d%%' "$whole" "$frac"
}
render_bytes() {
  local b="$1"
  case "$b" in *[!0-9]*|"") echo "0 B"; return ;; esac
  if [ "$b" -ge 1048576 ]; then
    local whole=$(( b / 1048576 ))
    local frac=$(( (b % 1048576) * 10 / 1048576 ))
    printf '%d.%d MB' "$whole" "$frac"
  elif [ "$b" -ge 1024 ]; then
    local whole=$(( b / 1024 ))
    local frac=$(( (b % 1024) * 10 / 1024 ))
    printf '%d.%d KB' "$whole" "$frac"
  else
    printf '%d B' "$b"
  fi
}

RPC_ERROR=0
CRIT_COUNT=0
WARN_COUNT=0
ANOMALIES=""
add_anom() {
  case ",$ANOMALIES," in
    *",$1,"*) : ;;  # already present
    *) if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi ;;
  esac
}

# Parallel arrays of classified artifacts for rendering.
ART_TYPES=""
ART_LINES=""   # newline-delimited: type|cap|size|pct_bps|class|detail

while IFS=$'\t' read -r ATYPE ACAP ASIZE ADETAIL; do
  [ -z "$ATYPE" ] && continue
  if [ "$ASIZE" = "-1" ]; then
    # Retrieval failure for this artifact.
    echo "operator_wire_budget_audit: failed to retrieve $ATYPE: $ADETAIL" >&2
    RPC_ERROR=1
    continue
  fi
  # pct-of-cap in basis points (integer math).
  PCT_BPS=0
  if [ "$ACAP" -gt 0 ]; then
    PCT_BPS=$(( ASIZE * 10000 / ACAP ))
  fi
  WARN_BPS=$(( WARN_PCT * 100 ))
  CRIT_BPS=$(( CRIT_PCT * 100 ))
  if [ "$PCT_BPS" -gt "$CRIT_BPS" ]; then
    CLASS="CRIT"
    CRIT_COUNT=$(( CRIT_COUNT + 1 ))
    add_anom "wire_cap_critical"
  elif [ "$PCT_BPS" -gt "$WARN_BPS" ]; then
    CLASS="WARN"
    WARN_COUNT=$(( WARN_COUNT + 1 ))
    add_anom "wire_cap_approach"
  else
    CLASS="OK"
  fi
  ART_LINES="${ART_LINES}${ATYPE}|${ACAP}|${ASIZE}|${PCT_BPS}|${CLASS}|${ADETAIL}
"
done <"$TMP_ART"

if [ "$RPC_ERROR" = "1" ]; then
  exit 1
fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 5: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"artifacts":['
  FIRST=1
  printf '%s' "$ART_LINES" | while IFS='|' read -r T CAP SIZE PCTBPS CLASS DETAIL; do
    [ -z "$T" ] && continue
    if [ "$FIRST" = "1" ]; then FIRST=0; else printf ','; fi
    # Escape backslash + double-quote in detail for JSON safety.
    ESC=$(printf '%s' "$DETAIL" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"type":"%s","cap_bytes":%s,"size_bytes":%s,"pct_of_cap_bps":%s,"classification":"%s","detail":"%s"}' \
      "$T" "$CAP" "$SIZE" "$PCTBPS" "$CLASS" "$ESC"
  done
  printf '],'
  printf '"warn_pct":%s,"crit_pct":%s,' "$WARN_PCT" "$CRIT_PCT"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],'
  if [ "$CRIT_COUNT" -gt 0 ]; then OK_BOOL=false; else OK_BOOL=true; fi
  printf '"ok":%s,"rpc_port":%s,"head_height":%s}\n' "$OK_BOOL" "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_wire_budget_audit: no wire-cap anomalies (port $PORT, head $HEAD_H)"
  else
    echo "=== Wire-budget audit (port $PORT, head $HEAD_H, warn ${WARN_PCT}% / crit ${CRIT_PCT}%) ==="
    echo
    # Per-artifact table.
    printf "  %-18s  %-9s  %-9s  %-8s  %-5s  %s\n" \
      "type" "size" "cap" "%cap" "state" "detail"
    printf "  %-18s  %-9s  %-9s  %-8s  %-5s  %s\n" \
      "------------------" "---------" "---------" "--------" "-----" "------"
    printf '%s' "$ART_LINES" | while IFS='|' read -r T CAP SIZE PCTBPS CLASS DETAIL; do
      [ -z "$T" ] && continue
      # Under --anomalies-only, drop OK rows.
      if [ "$ANOM_ONLY" = "1" ] && [ "$CLASS" = "OK" ]; then continue; fi
      printf "  %-18s  %-9s  %-9s  %-8s  %-5s  %s\n" \
        "$T" \
        "$(render_bytes "$SIZE")" \
        "$(render_bytes "$CAP")" \
        "$(render_pct "$PCTBPS")" \
        "$CLASS" \
        "$DETAIL"
    done
    echo
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] all audited wire artifacts within ${WARN_PCT}% of their S-022 cap"
    else
      if [ "$CRIT_COUNT" -gt 0 ]; then
        echo "[CRITICAL] $CRIT_COUNT artifact(s) > ${CRIT_PCT}% of cap — over-cap = peer connection drop"
        echo "  wire_cap_critical : a wire message at this size risks rejection at the receiving peer's"
        echo "                      Peer::read_body per-type cap (oversize close). Header sync / block"
        echo "                      propagation / snapshot bootstrap from this node would silently break."
      fi
      if [ "$WARN_COUNT" -gt 0 ]; then
        echo "[WARN] $WARN_COUNT artifact(s) in [${WARN_PCT}%, ${CRIT_PCT}%] of cap"
        echo "  wire_cap_approach : approaching the S-022 per-type cap; budget for future growth."
      fi
    fi
  fi
fi

# ── Step 6: exit-code policy ──────────────────────────────────────────────────
# Same convention as the sibling operator_*.sh scripts: exit 2 only when
# --anomalies-only is set AND at least one CRIT artifact fired. WARN
# alone never gates the exit code (it is surfaced but advisory). Default
# informational mode always exits 0 if the RPC retrieval succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$CRIT_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
