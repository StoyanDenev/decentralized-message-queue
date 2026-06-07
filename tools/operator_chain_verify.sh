#!/usr/bin/env bash
# operator_chain_verify.sh — End-to-end prev_hash chain integrity walk.
#
# Walks a contiguous window of blocks on a running determ daemon and
# verifies the FA1 chain anchor:
#
#   (1) block[0]   (if in the window) has prev_hash = 64 hex zeros
#                  (genesis sentinel — `Chain::head_hash()` returns
#                  Hash{} for the empty pre-genesis chain, which the
#                  genesis block then carries as prev_hash).
#   (2) block[i].prev_hash == block[i-1].compute_hash() for every
#                  contiguous pair in the window — the FA1 anchor that
#                  the SECURITY.md / proofs/Safety.md chain-integrity
#                  story rests on (any local tamper breaks this chain).
#   (3) block[i].index == i sequential (implicit — `headers` RPC
#                  returns blocks in index order and `verify-headers`
#                  re-derives the index column).
#
# Read-only RPC; safe against any running daemon. Daemon must already
# be listening on --rpc-port.
#
# Implementation note: this script is a paging wrapper around
# `determ verify-headers`. The `headers` RPC caps each page at 256
# headers (rpc_headers HEADERS_PAGE_MAX). For full-chain verification
# on long chains we fetch successive pages, concatenate the `headers`
# arrays into one envelope, then feed the combined envelope to
# `determ verify-headers --in <tmpfile>`. verify-headers does the
# actual prev_hash chain walk and genesis-anchor check in C++, so the
# script doesn't reimplement hashing.
#
# Usage:
#   tools/operator_chain_verify.sh [--rpc-port N]
#                                  [--from H --to H | --last N]
#                                  [--genesis-hash HEX64]
#                                  [--json]
#
# Performance: full-chain verification is O(N/256) RPC calls. On a
# 12k-block chain that's ~48 paged fetches, each returning ~256 header
# slices. Long chains (>100k blocks) take noticeable time; the --help
# recommends --last 1000 for spot-checks.
#
# Exit codes:
#   0 — chain integrity holds across the window
#   1 — RPC error / unreachable daemon / malformed response / bad args
#   2 — prev_hash chain mismatch (or genesis-hash mismatch) detected;
#       operator alert gate (fundamental safety violation per FA1)
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_verify.sh [--rpc-port N]
                                [--from H --to H | --last N]
                                [--genesis-hash HEX64]
                                [--json]

Walks a window of finalized blocks and verifies the prev_hash chain
end-to-end (FA1 chain integrity). For every contiguous pair (i-1, i)
the script asserts block[i].prev_hash == block[i-1].compute_hash().
If block[0] is in the window, its prev_hash must equal the 64-zero
genesis sentinel; if --genesis-hash is supplied, block[0].block_hash
must additionally match it (chain identity check).

Range selection (mutually exclusive — pick one form, else defaults to
the full chain [0..tip]):
  --from H --to H    Explicit range, inclusive on both ends.
  --last N           Last N blocks from the tip (window = [tip-N+1..tip]).
                     Recommended for spot-checks on long chains.

Options:
  --rpc-port N       RPC port to query (default: 7778)
  --genesis-hash HEX64
                     Compare block[0].block_hash against this externally-
                     anchored value. Ignored when the window doesn't
                     include block 0. Used to pin chain identity
                     against an out-of-band attestation.
  --json             Emit a structured JSON summary instead of human output
  -h, --help         Show this help

Performance:
  Default (full-chain) mode walks the entire chain and is O(N/256) RPC
  calls. On chains with >100k blocks this takes noticeable time. For
  operator spot-checks prefer `--last 1000` (covers any recent
  finality-window perturbation in O(4) page fetches).

Exit codes:
  0   chain integrity holds across the window
  1   RPC error / bad args
  2   prev_hash chain mismatch (or genesis-hash mismatch) — FA1 broken

Examples:
  # Spot-check the last 1000 blocks against a running daemon.
  tools/operator_chain_verify.sh --rpc-port 7778 --last 1000

  # Full-chain verify with external genesis pin (chain-identity check).
  tools/operator_chain_verify.sh --rpc-port 7778 \
      --genesis-hash 1a2b3c...64hex

  # Explicit range — verify only blocks 5000..5500 (e.g. after a
  # suspected re-org window).
  tools/operator_chain_verify.sh --from 5000 --to 5500 --json
EOF
}

PORT=7778
FROM=""
TO=""
LAST=""
GENESIS_HASH=""
JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port) PORT="$2"; shift 2 ;;
    --from) FROM="$2"; shift 2 ;;
    --to) TO="$2"; shift 2 ;;
    --last) LAST="$2"; shift 2 ;;
    --genesis-hash) GENESIS_HASH="$2"; shift 2 ;;
    --json) JSON=1; shift ;;
    *) echo "operator_chain_verify: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric port guard.
case "$PORT" in *[!0-9]*|"")
  echo "operator_chain_verify: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# Range-form mutual exclusion. --last and --from/--to are exclusive
# (you either anchor on the tip or you supply explicit bounds).
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_chain_verify: --last is mutually exclusive with --from/--to" >&2
  exit 1
fi
if { [ -n "$FROM" ] && [ -z "$TO" ]; } || { [ -z "$FROM" ] && [ -n "$TO" ]; }; then
  echo "operator_chain_verify: --from and --to must be supplied together" >&2
  exit 1
fi

# Numeric guards for any user-supplied bounds.
for V in "$FROM" "$TO" "$LAST"; do
  if [ -n "$V" ]; then
    case "$V" in *[!0-9]*)
      echo "operator_chain_verify: range arguments must be non-negative integers (got '$V')" >&2
      exit 1 ;;
    esac
  fi
done

# --genesis-hash format guard (64 hex chars, case-insensitive). Defer
# the actual identity check to verify-headers; here we just refuse
# obviously-malformed input early.
if [ -n "$GENESIS_HASH" ]; then
  case "$GENESIS_HASH" in
    *[!0-9a-fA-F]*|"")
      echo "operator_chain_verify: --genesis-hash must be 64 hex chars (got '$GENESIS_HASH')" >&2
      exit 1 ;;
  esac
  if [ ${#GENESIS_HASH} -ne 64 ]; then
    echo "operator_chain_verify: --genesis-hash must be exactly 64 hex chars (got length ${#GENESIS_HASH})" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# (1) Resolve chain tip.
HEAD_HEIGHT=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_chain_verify: RPC error (is daemon running on port $PORT?)" >&2
  exit 1
}
HEAD_HEIGHT=$(printf '%s' "$HEAD_HEIGHT" | tr -d '[:space:]')
case "$HEAD_HEIGHT" in *[!0-9]*|"")
  echo "operator_chain_verify: head height not numeric (got '$HEAD_HEIGHT')" >&2
  exit 1 ;;
esac

if [ "$HEAD_HEIGHT" = "0" ]; then
  echo "operator_chain_verify: chain empty (height=0); nothing to verify" >&2
  exit 1
fi

# Tip index (chain height H ⇒ last block index H-1; rpc_headers
# enforces from_index < height before slicing).
TIP=$(( HEAD_HEIGHT - 1 ))

# (2) Resolve [FROM..TO] window from CLI args.
if [ -n "$LAST" ]; then
  if [ "$LAST" -le 0 ]; then
    echo "operator_chain_verify: --last must be > 0 (got $LAST)" >&2
    exit 1
  fi
  TO=$TIP
  FROM=$(( TIP - LAST + 1 ))
  [ "$FROM" -lt 0 ] && FROM=0
elif [ -z "$FROM" ]; then
  # No range form ⇒ default to the full chain.
  FROM=0
  TO=$TIP
fi

# Sanity-check the window against the actual chain.
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_chain_verify: invalid window: --from $FROM > --to $TO" >&2
  exit 1
fi
if [ "$TO" -gt "$TIP" ]; then
  echo "operator_chain_verify: --to $TO exceeds chain tip index $TIP (height=$HEAD_HEIGHT)" >&2
  exit 1
fi

# (3) Page through `determ headers` and accumulate one combined
#     envelope. rpc_headers caps each page at 256 headers
#     (HEADERS_PAGE_MAX). For each page we extract the `headers`
#     array and concatenate into ALL_HEADERS_JSON.
PAGE_SIZE=256
TMPDIR=$(mktemp -d 2>/dev/null) || {
  echo "operator_chain_verify: cannot create tmp dir" >&2; exit 1;
}
trap 'rm -rf "$TMPDIR"' EXIT
COMBINED="$TMPDIR/combined.json"

# Determine whether jq is available — used both for paging extract
# and for the final JSON output. Without jq we fall back to a
# grep/sed approach for the header-array extraction.
HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# Initialize combined.json as an empty envelope. We'll splice in
# `headers` from each page below.
printf '%s\n' '{"headers":[]}' > "$COMBINED"

WINDOW_LEN=$(( TO - FROM + 1 ))
CURSOR=$FROM
PAGES=0
while [ "$CURSOR" -le "$TO" ]; do
  REMAINING=$(( TO - CURSOR + 1 ))
  REQ=$PAGE_SIZE
  [ "$REMAINING" -lt "$PAGE_SIZE" ] && REQ=$REMAINING

  PAGE=$("$DETERM" headers --from "$CURSOR" --count "$REQ" --rpc-port "$PORT" 2>/dev/null) || {
    echo "operator_chain_verify: RPC error fetching headers (from=$CURSOR count=$REQ port=$PORT)" >&2
    exit 1
  }

  if [ "$HAVE_JQ" = "1" ]; then
    # Validate the page contains a non-empty headers array; bail
    # otherwise so we don't silently truncate the window.
    PAGE_COUNT=$(printf '%s' "$PAGE" | jq -r '.headers | length')
    case "$PAGE_COUNT" in *[!0-9]*|"")
      echo "operator_chain_verify: malformed headers response (page from=$CURSOR)" >&2
      exit 1 ;;
    esac
    if [ "$PAGE_COUNT" = "0" ]; then
      echo "operator_chain_verify: headers RPC returned empty page (from=$CURSOR, req=$REQ); chain may have shrunk during verify" >&2
      exit 1
    fi
    # Append page's headers array to combined.json's headers array.
    NEW=$(jq --slurpfile P <(printf '%s' "$PAGE") \
              '.headers += $P[0].headers' "$COMBINED")
    printf '%s' "$NEW" > "$COMBINED"
    CURSOR=$(( CURSOR + PAGE_COUNT ))
  else
    # jq-free fallback. The `headers` RPC envelope is small enough
    # that a single grep/sed pass on the on-disk file works for
    # building up the combined array. We accumulate each page's
    # array contents (between the first `[` after `"headers":` and
    # the matching `]`) into a flat element list, then re-wrap.
    #
    # Use python3 if available — it's the only portable way to do
    # this without jq across Git Bash on Windows + Linux/Mac.
    if command -v python3 >/dev/null 2>&1; then
      python3 - "$COMBINED" <<< "$PAGE" > "$TMPDIR/pagecount.txt" <<PY || {
import json, sys
combined_path = sys.argv[1]
with open(combined_path) as f:
    combined = json.load(f)
page = json.loads(sys.stdin.read())
combined["headers"].extend(page.get("headers", []))
with open(combined_path, "w") as f:
    json.dump(combined, f)
print(len(page.get("headers", [])))
PY
        echo "operator_chain_verify: python3 page-merge failed (from=$CURSOR)" >&2
        exit 1
      }
      PAGE_COUNT=$(cat "$TMPDIR/pagecount.txt" | tr -d '[:space:]')
      case "$PAGE_COUNT" in *[!0-9]*|"")
        echo "operator_chain_verify: python3 page-merge returned non-numeric count" >&2
        exit 1 ;;
      esac
      if [ "$PAGE_COUNT" = "0" ]; then
        echo "operator_chain_verify: headers RPC returned empty page (from=$CURSOR, req=$REQ)" >&2
        exit 1
      fi
      CURSOR=$(( CURSOR + PAGE_COUNT ))
    else
      echo "operator_chain_verify: need either 'jq' or 'python3' on PATH for paged header merge; neither found" >&2
      exit 1
    fi
  fi

  PAGES=$(( PAGES + 1 ))
done

# (4) Hand the combined envelope to `determ verify-headers`. It does
#     the actual chain walk + genesis check in C++. We pass
#     --genesis-hash only when the window starts at 0 (verify-headers
#     enforces that block 0's prev_hash == "0"*64 anyway).
VERIFY_ARGS="--in $COMBINED"
if [ "$FROM" = "0" ] && [ -n "$GENESIS_HASH" ]; then
  VERIFY_ARGS="$VERIFY_ARGS --genesis-hash $GENESIS_HASH"
fi

# Capture both stdout and stderr separately so we can surface the
# verify-headers diagnostic (FAIL line, prev_hash mismatch index)
# into the operator's view.
VERIFY_STDOUT="$TMPDIR/verify.stdout"
VERIFY_STDERR="$TMPDIR/verify.stderr"
# shellcheck disable=SC2086
"$DETERM" verify-headers $VERIFY_ARGS >"$VERIFY_STDOUT" 2>"$VERIFY_STDERR"
VERIFY_RC=$?

# (5) Decode verify-headers result.
OK="false"
FIRST_MISMATCH="null"
GENESIS_CHECK="null"
if [ -n "$GENESIS_HASH" ] && [ "$FROM" = "0" ]; then
  GENESIS_CHECK='"ok"'
fi

if [ "$VERIFY_RC" = "0" ]; then
  OK="true"
else
  # verify-headers emits messages like:
  #   "FAIL: prev_hash chain break at header 5 (index 5678)"
  #   "FAIL: genesis header (index 0) has non-zero prev_hash: <hex>"
  #   "FAIL: genesis block_hash mismatch"
  STDERR_TEXT=$(cat "$VERIFY_STDERR" 2>/dev/null)
  # Extract first mismatch index from the FAIL line if present.
  MISMATCH_LINE=$(printf '%s' "$STDERR_TEXT" | grep -i 'prev_hash chain break' | head -1)
  if [ -n "$MISMATCH_LINE" ]; then
    # Parse "(index N)" from the FAIL line.
    IDX=$(printf '%s' "$MISMATCH_LINE" | sed -n 's/.*(index \([0-9][0-9]*\)).*/\1/p')
    [ -n "$IDX" ] && FIRST_MISMATCH="$IDX"
  fi
  # Genesis-hash mismatch flips GENESIS_CHECK to "mismatch".
  if printf '%s' "$STDERR_TEXT" | grep -q 'genesis block_hash mismatch'; then
    GENESIS_CHECK='"mismatch"'
  fi
fi

# (6) Emit output.
if [ "$JSON" = "1" ]; then
  cat <<EOF
{"window": {"from": $FROM, "to": $TO}, "blocks_verified": $WINDOW_LEN, "ok": $OK, "first_mismatch_index": $FIRST_MISMATCH, "genesis_hash_check": $GENESIS_CHECK, "rpc_port": $PORT}
EOF
  if [ "$OK" = "true" ]; then exit 0; else exit 2; fi
fi

# Human output.
echo "=== Chain verify (port $PORT, window [$FROM..$TO]) ==="
echo "Verifying $WINDOW_LEN blocks via prev_hash chain..."
if [ "$OK" = "true" ]; then
  if [ "$FROM" = "0" ]; then
    echo "Block 0: genesis prev_hash sentinel OK"
    if [ -n "$GENESIS_HASH" ]; then
      echo "Block 0: block_hash matches supplied --genesis-hash OK"
    fi
  fi
  echo "Blocks $FROM..$TO: prev_hash chain links verified ($PAGES page(s) of 256)"
  echo "[OK] All $WINDOW_LEN blocks chained consistently"
  exit 0
fi

# Mismatch path. Surface the verify-headers diagnostic verbatim so
# the operator sees the prev_hash / prior block_hash values.
echo "" >&2
echo "verify-headers diagnostic:" >&2
sed 's/^/  /' "$VERIFY_STDERR" >&2
if [ "$FIRST_MISMATCH" != "null" ]; then
  echo "[X] Chain integrity broken at block $FIRST_MISMATCH" >&2
elif [ "$GENESIS_CHECK" = '"mismatch"' ]; then
  echo "[X] Genesis block_hash does not match supplied --genesis-hash" >&2
else
  echo "[X] verify-headers rejected the chain (rc=$VERIFY_RC); see diagnostic above" >&2
fi
exit 2
