#!/usr/bin/env bash
# operator_dapp_field_consistency_audit.sh — Validate every live DApp
# registry entry on a running determ daemon against the DAPP_REGISTER
# DECODE-RULE structural invariants (the byte-level caps the apply path
# enforces at op=0 decode time) plus the retention enum.
#
# The defining question:
#   "Does every entry currently in the on-chain DApp registry actually
#    satisfy the structural invariants the DAPP_REGISTER decoder would
#    have enforced — topic count, per-topic length, endpoint length,
#    metadata size, service_pubkey width, and the retention enum — or
#    has an out-of-spec entry slipped into the live registry view?"
#
# Why this is a distinct lane (the gap it fills):
#   The DAPP_REGISTER op=0 apply path enforces hard byte-level caps as
#   it decodes the wire payload (src/chain/chain.cpp DAPP_REGISTER case):
#     - service_pubkey is exactly 32 bytes      (chain.cpp:1068-1070)
#     - endpoint_url length rides a u8          => <= 255 == MAX_DAPP_ENDPOINT_LEN
#                                                  (chain.cpp:1073-1076; block.hpp:193)
#     - topic_count > MAX_DAPP_TOPICS (32) aborts the upsert
#                                                  (chain.cpp:1079-1080; block.hpp:191)
#     - each topic length > MAX_DAPP_TOPIC_LEN (64) aborts
#                                                  (chain.cpp:1083-1084; block.hpp:192)
#     - metadata length > MAX_DAPP_METADATA (4096) aborts
#                                                  (chain.cpp:1097-1100; block.hpp:194)
#     - retention is read as a RAW BYTE with NO enum check
#                                                  (chain.cpp:1095) even though only
#                                                  {0,1} are semantically defined
#                                                  (include/determ/chain/chain.hpp:66-71)
#   So a well-formed live registry is supposed to hold ONLY entries that
#   pass all of those caps. But the SNAPSHOT-RESTORE path does NOT
#   re-validate any of them — it copies service_pubkey / endpoint_url /
#   topics / retention straight out of the snapshot JSON with no cap or
#   enum check (src/chain/chain.cpp restore_from_snapshot,
#   chain.cpp:1833-1847). A node that bootstraps from a tampered or
#   legacy snapshot can therefore load an entry the live decode path
#   would have rejected, and rpc_dapp_info (src/node/node.cpp:3045-3066)
#   will faithfully surface that out-of-spec entry over RPC. The S-033
#   state_root gate detects DISAGREEMENT between two nodes, but it does
#   NOT certify that an entry satisfies its own structural decode
#   invariants — so an out-of-spec entry can be internally consistent
#   across a colluding/forked set yet still violate the decode rules.
#   This audit closes exactly that observability gap.
#
#   No existing operator_dapp_*.sh tool checks these structural caps or
#   the retention enum against the live registry:
#     operator_dapp_census.sh            OWNERSHIP roster (owner registered/active)
#     operator_dapp_audit.sh             LIFECYCLE (ACTIVE/DEACTIVATING/INACTIVE)
#     operator_dapp_health.sh            activity HEALTH over a window
#     operator_dapp_endpoint_audit.sh    endpoint REACHABILITY + zero-key
#                                        (URL scheme heuristics — semantic,
#                                         NOT the 255-byte structural cap)
#     operator_dapp_topic_audit.sh       topic SPAM / collision PATTERNS
#                                        (per-DApp distribution — NOT the
#                                         32-count / 64-len structural caps)
#     operator_dapp_inventory.sh         compact activity digest
#     operator_dapp_registry_proof_audit.sh  d:-namespace state-proof readiness
#     operator_dapp_field_consistency_audit.sh  THIS — per-entry structural
#                                        DECODE-RULE caps + retention enum.
#
# Read-only RPC; safe against any running daemon.
#
# Usage:
#   tools/operator_dapp_field_consistency_audit.sh --rpc-port N
#                                                  [--prefix STR]
#                                                  [--anomalies-only]
#                                                  [--json]
#
# Options:
#   --rpc-port N       RPC port to query (REQUIRED)
#   --prefix STR       Server-side domain-prefix filter on dapp-list
#                      (empty matches all)
#   --anomalies-only   Suppress the full per-DApp table; print only the
#                      OUT-OF-SPEC rows + the verdict. Enables the exit-2
#                      anomaly gate.
#   --json             Emit a machine-readable JSON envelope
#   -h, --help         Show this help
#
# RPC dependencies (all read-only; field sets verified against src/):
#   status     current chain height (head) — context only, echoed in output
#              (src/main.cpp "status"; Node::rpc_status)
#   dapp_list  enumerate registered DApps; honours --prefix
#              (src/main.cpp:5662 "dapp-list"; Node::rpc_dapp_list,
#               src/node/node.cpp:3142)
#   dapp_info  per-DApp full record; fields used: service_pubkey (hex),
#              endpoint_url, topics[], retention, metadata (hex)
#              (src/main.cpp:5607 "dapp-info"; Node::rpc_dapp_info,
#               src/node/node.cpp:3045-3066)
#
# Per-entry checks (each maps to one decode-rule invariant):
#   key_width     service_pubkey must be exactly 64 lowercase-hex chars
#                 (32 bytes). The wire decoder copies a fixed 32-byte
#                 blob (chain.cpp:1070); anything else is structurally
#                 impossible from a real DAPP_REGISTER and indicates a
#                 mangled snapshot restore.
#   endpoint_len  len(endpoint_url) in BYTES must be <= 255
#                 (MAX_DAPP_ENDPOINT_LEN; chain.cpp u8 url_len at :1073).
#   topic_count   len(topics) must be <= 32 (MAX_DAPP_TOPICS; chain.cpp:1080).
#   topic_len     each topic, in BYTES, must be <= 64
#                 (MAX_DAPP_TOPIC_LEN; chain.cpp:1084).
#   metadata_len  len(metadata) in BYTES (hex/2) must be <= 4096
#                 (MAX_DAPP_METADATA; chain.cpp:1100).
#   retention     must be 0 or 1 (the only defined values, chain.hpp:66-71).
#                 The decoder accepts any byte 0..255 (chain.cpp:1095) so
#                 an out-of-enum value is a silently-tolerated drift.
#
#   Note on UTF-8 length: the wire caps count BYTES (the decoder works on
#   the raw payload), so all length checks here measure the UTF-8 byte
#   length, not the Unicode code-point count.
#
# Per-DApp verdict:
#   OK           — all six checks pass.
#   OUT_OF_SPEC  — at least one structural cap is violated (key_width,
#                  endpoint_len, topic_count, topic_len, or metadata_len).
#                  A client/light-client honouring the decode rules would
#                  reject this entry; the live node is serving it anyway.
#                  This is the operator-actionable finding.
#   ENUM_DRIFT   — every structural cap passes but retention is outside
#                  {0,1}. Softer than OUT_OF_SPEC (the value rides through
#                  the state_root harmlessly) but still a registry-hygiene
#                  signal worth surfacing.
#
# Exit codes:
#   0   audit ran; every entry OK (or only ENUM_DRIFT), or no DApps
#       registered, or daemon unreachable in a clean SKIP. Also the
#       default (non --anomalies-only) success.
#   2   --anomalies-only AND >= 1 entry is OUT_OF_SPEC
#   1   RPC error / malformed response / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_field_consistency_audit.sh --rpc-port N
                                                [--prefix STR]
                                                [--anomalies-only]
                                                [--json]

Validate every live DApp registry entry against the DAPP_REGISTER
decode-rule structural invariants (the byte-level caps the op=0 decoder
enforces) plus the retention enum {0,1}:

    service_pubkey  exactly 32 bytes (64 hex)
    endpoint_url    <= 255 bytes      (MAX_DAPP_ENDPOINT_LEN)
    topics          <= 32 entries     (MAX_DAPP_TOPICS)
    each topic      <= 64 bytes       (MAX_DAPP_TOPIC_LEN)
    metadata        <= 4096 bytes     (MAX_DAPP_METADATA)
    retention       0 or 1

The snapshot-restore path does NOT re-validate these caps, so a node
bootstrapped from a tampered/legacy snapshot can serve an entry the live
decode path would have rejected. This audit surfaces such drift.

Options:
  --rpc-port N       RPC port to query (REQUIRED)
  --prefix STR       Server-side domain-prefix filter (empty = all)
  --anomalies-only   Print only the problem rows + verdict; enables the
                     exit-2 anomaly gate
  --json             Emit a machine-readable JSON envelope
  -h, --help         Show this help

Exit codes:
  0   audit ran; every entry OK (or only ENUM_DRIFT), or no DApps
      registered, or daemon unreachable (clean SKIP)
  2   --anomalies-only AND >= 1 entry OUT_OF_SPEC
  1   RPC error / malformed response / bad args
EOF
}

PORT=""
PREFIX=""
ANOM_ONLY=0
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";   shift 2 ;;
    --prefix)         PREFIX="${2:-}"; shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;     shift ;;
    --json)           JSON_OUT=1;      shift ;;
    *) echo "operator_dapp_field_consistency_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required: an operator script that defaults the port can
# silently target the wrong daemon on a multi-instance host (mirrors
# operator_dapp_endpoint_audit.sh / operator_dapp_census.sh).
if [ -z "$PORT" ]; then
  echo "operator_dapp_field_consistency_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_dapp_field_consistency_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote $DETERM to an absolute path for the python subprocess loop:
# python's subprocess.run inherits the shell cwd (repo root), but Windows
# CreateProcessW resolves relative paths differently from POSIX exec*();
# the absolute form behaves identically across platforms (same hardening
# as operator_dapp_endpoint_audit.sh / operator_dapp_census.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain height via status (context only) ────────────────────
# A clean SKIP (exit 0) when the daemon is unreachable: an unreachable
# daemon is an operational state, not an audit failure, so this script
# does not return non-zero merely because nothing is listening. In --json
# mode emit a {"skipped":true} envelope so machine callers can tell SKIP
# from a real result.
STATUS_OUT=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON_OUT" -eq 1 ]; then
    echo '{"skipped":true,"reason":"daemon unreachable","rpc_port":'"$PORT"'}'
  else
    echo "operator_dapp_field_consistency_audit: INFO: cannot reach daemon on rpc-port $PORT — SKIP (not an error)"
  fi
  exit 0
}
HEIGHT=$(printf '%s' "$STATUS_OUT" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('height', 0)))
except Exception:
    print('')")
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_dapp_field_consistency_audit: malformed status response (no .height field; port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: enumerate DApps via dapp-list (server-side --prefix) ─────────────
DAPP_LIST_ARGS=("dapp-list" "--rpc-port" "$PORT")
[ -n "$PREFIX" ] && DAPP_LIST_ARGS+=("--prefix" "$PREFIX")
LIST_OUT=$("$DETERM" "${DAPP_LIST_ARGS[@]}" 2>/dev/null) || {
  echo "operator_dapp_field_consistency_audit: dapp-list RPC failed (port $PORT)" >&2
  exit 1
}

# Pass the domain list through a temp file (not stdin): the python heredoc
# that drives the per-DApp loop consumes stdin itself, so piping the list
# into `python - <<PY` would let the heredoc win (same idiom as
# operator_dapp_endpoint_audit.sh / operator_dapp_census.sh).
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_field_consistency_audit: cannot create temp file" >&2
  exit 1
}
TMP_LIST=$(mktemp 2>/dev/null) || {
  echo "operator_dapp_field_consistency_audit: cannot create temp file" >&2
  rm -f "$TMP_OUT" 2>/dev/null
  exit 1
}
trap 'rm -f "$TMP_OUT" "$TMP_LIST" 2>/dev/null' EXIT
printf '%s' "$LIST_OUT" > "$TMP_LIST"

# ── Step 3: per-DApp dapp-info pass + decode-rule classification ─────────────
python - "$DETERM_ABS" "$PORT" "$TMP_LIST" "$TMP_OUT" <<'PY'
import json, subprocess, sys, time, re

determ, port, list_path, out_path = sys.argv[1:5]

# Decode-rule caps (mirror include/determ/chain/block.hpp constants the
# DAPP_REGISTER op=0 decoder enforces in src/chain/chain.cpp).
MAX_DAPP_TOPICS       = 32     # block.hpp:191 ; chain.cpp:1080
MAX_DAPP_TOPIC_LEN    = 64     # block.hpp:192 ; chain.cpp:1084
MAX_DAPP_ENDPOINT_LEN = 255    # block.hpp:193 ; chain.cpp u8 url_len :1073
MAX_DAPP_METADATA     = 4096   # block.hpp:194 ; chain.cpp:1100
KEY_HEX_LEN           = 64     # 32-byte PubKey ; chain.cpp:1068-1070
VALID_RETENTION       = (0, 1) # chain.hpp:66-71 (decoder takes raw byte)

HEX64 = re.compile(r'^[0-9a-f]{64}$')

def run_rpc(args, what, retries=2):
    # Bounded retry on transient blips. A busy committee can intermittently
    # refuse an RPC mid-finalize; a persistent error still aborts (exit 1)
    # after retries, so this never masks a genuinely-down daemon (same
    # pattern as operator_dapp_endpoint_audit.sh).
    last_err = ""
    for attempt in range(retries + 1):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except Exception as e:
            last_err = f"exception: {e}"
        else:
            if r.returncode != 0:
                last_err = f"rc={r.returncode}: {r.stderr.strip()}"
            else:
                try:
                    return json.loads(r.stdout)
                except Exception:
                    last_err = "non-JSON response"
        if attempt < retries:
            time.sleep(0.4)
    sys.stderr.write(f"operator_dapp_field_consistency_audit: {what} {last_err}\n")
    sys.exit(1)

with open(list_path, "r", encoding="utf-8") as f:
    list_raw = f.read()
try:
    listed = json.loads(list_raw)
except Exception:
    sys.stderr.write("operator_dapp_field_consistency_audit: malformed dapp-list response\n")
    sys.exit(1)
if not isinstance(listed, dict):
    sys.stderr.write("operator_dapp_field_consistency_audit: dapp-list not a JSON object\n")
    sys.exit(1)
dapps_raw = listed.get("dapps")
if not isinstance(dapps_raw, list):
    sys.stderr.write("operator_dapp_field_consistency_audit: dapp-list missing .dapps array\n")
    sys.exit(1)

# Dedupe domains defensively (dapp_list returns unique domains by
# construction, but the registry can mutate between RPC calls).
seen = set()
domains = []
for d in dapps_raw:
    if isinstance(d, dict):
        dom = d.get("domain")
        if isinstance(dom, str) and dom and dom not in seen:
            seen.add(dom)
            domains.append(dom)

def byte_len(s):
    # The wire caps count payload BYTES, so measure the UTF-8 encoding.
    try:
        return len(s.encode("utf-8"))
    except Exception:
        return len(s)

records = []
for domain in domains:
    info = run_rpc(
        [determ, "dapp-info", "--domain", domain, "--rpc-port", port],
        f"dapp-info {domain}")
    if isinstance(info, dict) and info.get("error"):
        # Race vs. deregister between dapp-list and dapp-info — skip
        # quietly (the registry can mutate between calls).
        continue
    if not isinstance(info, dict):
        continue

    pub        = info.get("service_pubkey", "")
    ep         = info.get("endpoint_url", "")
    topics     = info.get("topics", [])
    metadata   = info.get("metadata", "")   # hex string per rpc_dapp_info
    retention  = info.get("retention", 0)

    if not isinstance(pub, str):       pub = ""
    if not isinstance(ep, str):        ep = ""
    if not isinstance(topics, list):   topics = []
    if not isinstance(metadata, str):  metadata = ""

    violations = []   # hard structural (OUT_OF_SPEC)
    notes      = []   # soft enum (ENUM_DRIFT)

    # key_width: exactly 64 lowercase-hex chars (32-byte PubKey).
    pkey = pub.strip().lower()
    if not HEX64.match(pkey):
        violations.append(
            f"key_width: service_pubkey not {KEY_HEX_LEN} hex chars (len={len(pkey)})")

    # endpoint_len: <= MAX_DAPP_ENDPOINT_LEN bytes.
    eplen = byte_len(ep)
    if eplen > MAX_DAPP_ENDPOINT_LEN:
        violations.append(
            f"endpoint_len: {eplen} bytes > {MAX_DAPP_ENDPOINT_LEN} (MAX_DAPP_ENDPOINT_LEN)")

    # topic_count: <= MAX_DAPP_TOPICS.
    tcount = len(topics)
    if tcount > MAX_DAPP_TOPICS:
        violations.append(
            f"topic_count: {tcount} > {MAX_DAPP_TOPICS} (MAX_DAPP_TOPICS)")

    # topic_len: each topic <= MAX_DAPP_TOPIC_LEN bytes.
    over_topics = []
    for t in topics:
        ts = t if isinstance(t, str) else ""
        tl = byte_len(ts)
        if tl > MAX_DAPP_TOPIC_LEN:
            disp = ts if len(ts) <= 24 else ts[:21] + "..."
            over_topics.append(f"'{disp}'({tl}B)")
    if over_topics:
        violations.append(
            f"topic_len: {len(over_topics)} topic(s) > {MAX_DAPP_TOPIC_LEN} bytes "
            f"(MAX_DAPP_TOPIC_LEN): " + ", ".join(over_topics[:5]) +
            (" ..." if len(over_topics) > 5 else ""))

    # metadata_len: hex string => byte length is len(hex)/2.
    mhex = metadata.strip()
    if mhex and not re.match(r'^[0-9a-fA-F]*$', mhex):
        # Non-hex metadata should be impossible from rpc_dapp_info (it
        # to_hex's the bytes); flag it structurally rather than guess a size.
        violations.append("metadata: non-hex metadata string (unexpected encoding)")
        mbytes = None
    else:
        mbytes = len(mhex) // 2
        if mbytes > MAX_DAPP_METADATA:
            violations.append(
                f"metadata_len: {mbytes} bytes > {MAX_DAPP_METADATA} (MAX_DAPP_METADATA)")

    # retention enum: only {0,1} defined (decoder accepts any byte).
    try:
        rint = int(retention)
    except Exception:
        rint = None
    if rint is None or rint not in VALID_RETENTION:
        notes.append(
            f"retention: value {retention!r} outside {{0,1}} "
            "(decoder accepts any byte; only 0/1 are defined)")

    if violations:
        verdict = "OUT_OF_SPEC"
    elif notes:
        verdict = "ENUM_DRIFT"
    else:
        verdict = "OK"

    records.append({
        "domain":        domain,
        "verdict":       verdict,
        "service_pubkey_hexlen": len(pkey),
        "endpoint_bytes":        eplen,
        "topic_count":           tcount,
        "metadata_bytes":        (mbytes if mbytes is not None else -1),
        "retention":             (rint if rint is not None else retention),
        "violations":            violations,
        "notes":                 notes,
    })

# Stable ordering: problem rows first (OUT_OF_SPEC, then ENUM_DRIFT, then
# OK), then by domain — operator reads the actionable ones at the top.
rank = {"OUT_OF_SPEC": 0, "ENUM_DRIFT": 1, "OK": 2}
records.sort(key=lambda r: (rank.get(r["verdict"], 3), r["domain"]))

with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"records": records}, f)
PY
if [ "$?" -ne 0 ]; then
  exit 1
fi

# ── Step 4: render envelope (JSON or human table) + verdict ──────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$HEIGHT" "$PORT" "$PREFIX" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
height    = int(sys.argv[4])
port      = int(sys.argv[5])
prefix    = sys.argv[6]

with open(out_path, "r", encoding="utf-8") as f:
    payload = json.load(f)
records = payload["records"]

n_total      = len(records)
n_outofspec  = sum(1 for r in records if r["verdict"] == "OUT_OF_SPEC")
n_enumdrift  = sum(1 for r in records if r["verdict"] == "ENUM_DRIFT")
n_ok         = sum(1 for r in records if r["verdict"] == "OK")

# Anomaly gate: only a hard structural violation (OUT_OF_SPEC) trips the
# exit-2 gate. ENUM_DRIFT is reported but does not fail the audit.
anomaly_flag = n_outofspec > 0
exit_code = 2 if (anom_only and anomaly_flag) else 0

if json_out:
    envelope = {
        "rpc_port":      port,
        "chain_height":  height,
        "prefix":        prefix,
        "dapp_count":    n_total,
        "ok":            n_ok,
        "enum_drift":    n_enumdrift,
        "out_of_spec":   n_outofspec,
        "anomaly_flag":  anomaly_flag,
        "dapps":         records,
    }
    print(json.dumps(envelope, indent=2))
    sys.exit(exit_code)

# Human-readable.
prefix_note = f", prefix='{prefix}'" if prefix else ""
print(f"=== DApp field-consistency audit "
      f"(port {port}, chain height {height}{prefix_note}) ===")
print("Decode-rule caps: pubkey=32B topics<=32 topic<=64B endpoint<=255B "
      "metadata<=4096B retention in {0,1}")

if n_total == 0:
    print("(no DApps registered)")
    print()
    print("[OK] no DApps registered")
    sys.exit(0)

shown = [r for r in records if (not anom_only or r["verdict"] != "OK")]
if shown:
    print()
    for r in shown:
        tag = r["verdict"]
        print(f"  [{tag:<11}] {r['domain']}")
        print(f"      pubkey_hexlen={r['service_pubkey_hexlen']} "
              f"endpoint_bytes={r['endpoint_bytes']} "
              f"topics={r['topic_count']} "
              f"metadata_bytes={r['metadata_bytes']} "
              f"retention={r['retention']}")
        for v in r["violations"]:
            print(f"      ! {v}")
        for nt in r["notes"]:
            print(f"      ~ {nt}")
elif anom_only:
    print()
    print("  (no OUT_OF_SPEC / ENUM_DRIFT entries)")

print()
print(f"Summary: {n_total} DApp(s) — OK={n_ok}, "
      f"ENUM_DRIFT={n_enumdrift}, OUT_OF_SPEC={n_outofspec}")

if anomaly_flag:
    print(f"[ANOMALY] {n_outofspec} entry(ies) violate a DAPP_REGISTER "
          "decode-rule structural cap — the live registry is serving an "
          "entry the wire decoder would have rejected (likely a snapshot-"
          "restore that bypassed the caps).")
elif n_enumdrift > 0:
    print(f"[OK] no structural violations; {n_enumdrift} entry(ies) carry "
          "an out-of-enum retention value (harmless drift, reported only).")
else:
    print("[OK] every registry entry satisfies the decode-rule structural "
          "invariants and retention enum.")

sys.exit(exit_code)
PY
exit $?
