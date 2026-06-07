#!/usr/bin/env bash
# operator_keyfile_audit.sh — READ-ONLY single-keyfile security-posture audit.
#
# Audits ONE keyfile (the arg path) and reports whether it is ENCRYPTED
# (passphrase envelope) or PLAINTEXT (unencrypted private key at rest),
# plus — for the encrypted case — the KDF + its parameters, the cipher,
# and the derived anon-address. The point is operator triage: before a
# key migrates between hosts, gets archived, or lands in a backup, an
# operator wants a one-line answer to "is the private material protected
# on disk?" without ever supplying a passphrase or touching the file.
#
# Determ stores node key material on disk in two distinct shapes:
#
#   ENCRYPTED  A 2-line S-004 keyfile:
#                 line 1:  "DETERM-NODE-V1 <64-hex pubkey>"
#                 line 2:  a DWE1 AEAD envelope blob
#              The private seed is sealed inside the DWE1 envelope:
#              key-derivation is PBKDF2 (the envelope's pbkdf2_iters field
#              is the work factor), the cipher is AES-256-GCM (the DWE1
#              container), and the header pubkey is bound as the AEAD AAD.
#              `determ-wallet keyfile-info` parses both lines and surfaces
#              all of this WITHOUT decrypting (no passphrase, no plaintext
#              recovery). This audit delegates to it.
#
#   PLAINTEXT  A JSON keyfile with the private key in the clear, in any of:
#                 {address, privkey_hex}        (wallet single-account)
#                 {pubkey, priv_seed}           (chain daemon node_key.json)
#                 {accounts: [{address, privkey_hex}, ...]}  (wallet batch)
#              `keyfile-info` rejects these (its header doesn't start with
#              the DETERM-NODE-V1 magic, so it exits 2). When delegation
#              reports "not a canonical encrypted node keyfile", this audit
#              falls back to a READ-ONLY JSON parse to confirm the plaintext
#              shape, extract the address, and WARN — an unencrypted private
#              key sitting on disk is the security finding this tool exists
#              to surface.
#
# This is a pure local inspector. It does NOT decrypt, does NOT require a
# passphrase, does NOT contact any daemon / cluster, and does NOT mutate
# the audited file. It composes with the wallet's passive `keyfile-info`
# (single-keyfile metadata) and pairs with `operator_keystore_audit.sh`
# (whole-directory hazard linter); this script focuses the lens on ONE
# file and the ENCRYPTED-vs-PLAINTEXT axis.
#
# Output (human form):
#   keyfile:       <path>
#   posture:       ENCRYPTED | PLAINTEXT
#   <encrypted:>
#     kdf:         PBKDF2-HMAC-SHA256 (iters=<N>)
#     cipher:      AES-256-GCM (DWE1 envelope)
#     address:     0x<64-hex>
#   <plaintext:>
#     [WARN] unencrypted private key at rest
#     shape:       single | node_key | batch
#     address:     0x<64-hex>  (or "0x<…>, +N more" for batch)
#
# JSON form (--json):
#   {"keyfile":"…","posture":"ENCRYPTED",
#    "kdf":"PBKDF2-HMAC-SHA256","kdf_iters":<N>,
#    "cipher":"AES-256-GCM","address":"0x…","warn":false}
#   {"keyfile":"…","posture":"PLAINTEXT","shape":"single",
#    "address":"0x…","warn":true,
#    "warning":"unencrypted private key at rest"}
#
# Outcome contract: this script honors the tools/run_all.sh verdict
# contract — it ends with a SINGLE terminal "  PASS:" (audit completed
# cleanly) or "  FAIL:" (the keyfile could not be classified) line printed
# after a blank line, so run_all's final-10-lines grep is unambiguous. A
# PLAINTEXT finding is still a clean PASS of the AUDIT (the audit ran and
# reported correctly) with a WARN inside; the terminal verdict reflects
# whether the audit itself succeeded, not the posture it found.
#
# SKIP-with-PASS: if the determ-wallet binary is absent (minimal build /
# CI env that didn't build the wallet target) this SKIPs with a terminal
# PASS and exit 0 — never a hard fail in a minimal environment.
#
# Advisory exit-0: with no keyfile arg at all, prints usage and exits 0
# (advisory) rather than failing — invoking with no target is operator
# fat-finger, not an audit failure.
#
# Run from repo root: bash tools/operator_keyfile_audit.sh <keyfile> [--json]
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# ── Argument parse ────────────────────────────────────────────────────────────
# Positional <keyfile> path + optional --json. --help is advisory (exit 0).
KEYFILE=""
JSON_OUT=0
for a in "$@"; do
    case "$a" in
        --json)        JSON_OUT=1 ;;
        -h|--help)
            echo "Usage: operator_keyfile_audit.sh <keyfile> [--json]"
            echo
            echo "READ-ONLY audit of one keyfile's security posture:"
            echo "  ENCRYPTED  2-line DETERM-NODE-V1 + DWE1 envelope (PBKDF2 +"
            echo "             AES-256-GCM). Reports KDF + iters, cipher, address."
            echo "  PLAINTEXT  JSON keyfile with the private key in the clear."
            echo "             WARNs (unencrypted private key at rest); reports"
            echo "             the shape + address."
            echo
            echo "Delegates to \`determ-wallet keyfile-info\` (no passphrase, no"
            echo "decrypt, no daemon, no mutation). SKIPs with PASS if"
            echo "determ-wallet is absent."
            exit 0 ;;
        --*)
            echo "operator_keyfile_audit: unknown argument: $a" >&2
            echo "Usage: operator_keyfile_audit.sh <keyfile> [--json]" >&2
            # Bad flag is operator error, not an audit failure: advisory exit 0
            # would mask a typo, so this is the one place we hard-fail args.
            echo
            echo "  FAIL: operator_keyfile_audit (bad argument)"
            exit 1 ;;
        *)
            if [ -z "$KEYFILE" ]; then
                KEYFILE="$a"
            else
                echo "operator_keyfile_audit: only one <keyfile> may be given (got extra: $a)" >&2
                echo
                echo "  FAIL: operator_keyfile_audit (multiple keyfile args)"
                exit 1
            fi ;;
    esac
done

# ── Advisory exit-0 when no keyfile arg ───────────────────────────────────────
# Invoking with no target is a fat-finger, not an audit failure. Print
# usage + a benign advisory and exit 0 (no terminal FAIL).
if [ -z "$KEYFILE" ]; then
    echo "operator_keyfile_audit: no keyfile argument given (advisory)"
    echo "Usage: operator_keyfile_audit.sh <keyfile> [--json]"
    echo
    echo "  PASS: operator_keyfile_audit (advisory — nothing to audit)"
    exit 0
fi

# ── SKIP-with-PASS when the wallet binary is absent ───────────────────────────
# Mirrors the test-suite convention: in a minimal build that didn't compile
# the determ-wallet target, this is a SKIP (not a hard fail). Terminal PASS
# keeps run_all's outcome grep happy.
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    echo
    echo "  PASS: operator_keyfile_audit (skipped — determ-wallet absent)"
    exit 0
fi

WALLET="$DETERM_WALLET"

# python / python3 fallback (used only for the read-only plaintext parse +
# JSON field extraction; the encrypted path reads keyfile-info --json fields).
PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ── File-existence pre-check (read-only) ──────────────────────────────────────
if [ ! -e "$KEYFILE" ]; then
    echo "operator_keyfile_audit: keyfile does not exist: $KEYFILE" >&2
    echo
    echo "  FAIL: operator_keyfile_audit (keyfile not found)"
    exit 1
fi
if [ ! -r "$KEYFILE" ]; then
    echo "operator_keyfile_audit: keyfile is not readable: $KEYFILE" >&2
    echo
    echo "  FAIL: operator_keyfile_audit (keyfile unreadable)"
    exit 1
fi

# ── Step 1: delegate to keyfile-info (the canonical encrypted-keyfile path) ───
# keyfile-info exits 0 ONLY for a well-formed 2-line encrypted keyfile, and
# emits the metadata we need (pbkdf2_iters, anon_address) on --json. We run
# it with --json so the field extraction is mechanical. stderr is captured
# separately so the plaintext-fallback decision can read its diagnostic.
#
# IMPORTANT: capture keyfile-info's output WITHOUT a pipe so $? reflects the
# wallet's real exit code (a `... | tr` pipeline would leave $? holding tr's
# exit code, masking the rc=2 keyfile-info returns on non-encrypted files).
# CR stripping happens after the fact via shell parameter expansion.
set +e
INFO_JSON=$("$WALLET" keyfile-info --in "$KEYFILE" --json 2>/dev/null)
INFO_RC=$?
INFO_ERR=$("$WALLET" keyfile-info --in "$KEYFILE" 2>&1 1>/dev/null)
set -e
INFO_JSON=${INFO_JSON//$'\r'/}
INFO_ERR=${INFO_ERR//$'\r'/}

# ── Encrypted posture: keyfile-info accepted the file (exit 0) ────────────────
if [ "$INFO_RC" -eq 0 ]; then
    # Extract pbkdf2_iters + anon_address from the keyfile-info JSON. These
    # fields are the documented --json schema of keyfile-info; we read them
    # rather than re-parsing the file ourselves (single source of truth).
    KDF_ITERS=$(printf '%s' "$INFO_JSON" | $PY -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(int(d.get('envelope', {}).get('pbkdf2_iters', 0)))
except Exception:
    print('')
")
    ADDRESS=$(printf '%s' "$INFO_JSON" | $PY -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('anon_address', ''))
except Exception:
    print('')
")
    case "$KDF_ITERS" in *[!0-9]*|"")
        echo "operator_keyfile_audit: keyfile-info reported exit 0 but its JSON" >&2
        echo "  was unparseable (pbkdf2_iters='$KDF_ITERS'); cannot classify" >&2
        echo
        echo "  FAIL: operator_keyfile_audit (encrypted metadata unparseable)"
        exit 1 ;;
    esac

    # DWE1 envelope is fixed: PBKDF2-HMAC-SHA256 derivation + AES-256-GCM AEAD.
    KDF_NAME="PBKDF2-HMAC-SHA256"
    CIPHER_NAME="AES-256-GCM"

    if [ "$JSON_OUT" = "1" ]; then
        printf '{"keyfile":"%s","posture":"ENCRYPTED","kdf":"%s","kdf_iters":%s,"cipher":"%s","address":"%s","warn":false}\n' \
            "$KEYFILE" "$KDF_NAME" "$KDF_ITERS" "$CIPHER_NAME" "$ADDRESS"
    else
        echo "=== Keyfile security-posture audit ==="
        echo "keyfile:       $KEYFILE"
        echo "posture:       ENCRYPTED"
        echo "  kdf:         $KDF_NAME (iters=$KDF_ITERS)"
        echo "  cipher:      $CIPHER_NAME (DWE1 envelope)"
        echo "  address:     $ADDRESS"
        echo "  [OK] private key is sealed at rest (passphrase required to decrypt)"
    fi

    echo
    echo "  PASS: operator_keyfile_audit (ENCRYPTED)"
    exit 0
fi

# ── Plaintext fallback: keyfile-info rejected the file ────────────────────────
# keyfile-info exits 2 when the header isn't the DETERM-NODE-V1 magic — which
# is exactly what a PLAINTEXT JSON keyfile looks like. Confirm the plaintext
# shape with a READ-ONLY JSON parse, extract the address(es), and WARN.
#
# We only treat the file as PLAINTEXT if it actually parses as one of the
# known plaintext keyfile shapes. A genuinely-malformed file (corrupt
# envelope, random bytes) is neither encrypted nor plaintext: that's a hard
# FAIL of the audit (we cannot certify its posture).
TMP_OUT=$(mktemp 2>/dev/null) || {
    echo "operator_keyfile_audit: cannot create temp file" >&2
    echo
    echo "  FAIL: operator_keyfile_audit (tempfile)"
    exit 1
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

# Normalize the path for the native-Windows Python interpreter (Git Bash
# emits MSYS paths Python can't os.open()); pass through unchanged elsewhere.
if command -v cygpath >/dev/null 2>&1; then
    KEYFILE_FOR_PY=$(cygpath -m -- "$KEYFILE" 2>/dev/null || printf '%s' "$KEYFILE")
else
    KEYFILE_FOR_PY="$KEYFILE"
fi

$PY - "$KEYFILE_FOR_PY" "$TMP_OUT" <<'PY'
import json, sys

path, out_path = sys.argv[1], sys.argv[2]

HEX = set("0123456789abcdef")

def is_hex(s, exact=None):
    if not isinstance(s, str):
        return False
    if exact is not None and len(s) != exact:
        return False
    if len(s) == 0 or len(s) % 2 != 0:
        return False
    return all(c in HEX for c in s.lower())

def is_anon_address(s):
    return (isinstance(s, str) and len(s) == 66
            and s.startswith("0x") and is_hex(s[2:], 64))

result = {"classified": False}

try:
    with open(path, "rb") as f:
        raw = f.read()
except OSError as e:
    result["error"] = f"read_failed: {e}"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f)
    sys.exit(0)

try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    result["error"] = "not_utf8"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f)
    sys.exit(0)

try:
    doc = json.loads(text)
except json.JSONDecodeError:
    result["error"] = "not_json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f)
    sys.exit(0)

if isinstance(doc, dict):
    # single-account wallet: {address, privkey_hex}
    addr = doc.get("address"); priv = doc.get("privkey_hex")
    if isinstance(addr, str) and is_anon_address(addr) and is_hex(priv, 64):
        result.update(classified=True, shape="single",
                      address=addr.lower(), account_count=1)
    else:
        # chain daemon node_key.json: {pubkey, priv_seed}
        pub = doc.get("pubkey"); seed = doc.get("priv_seed")
        if is_hex(pub, 64) and is_hex(seed, 64):
            result.update(classified=True, shape="node_key",
                          address="0x" + pub.lower(), account_count=1)
        else:
            # batch wallet: {accounts: [{address, privkey_hex}, ...]}
            accts = doc.get("accounts")
            if isinstance(accts, list) and accts:
                ok = True
                first = None
                for e in accts:
                    if not isinstance(e, dict):
                        ok = False; break
                    ea = e.get("address"); ep = e.get("privkey_hex")
                    if not (is_anon_address(ea) and is_hex(ep, 64)):
                        ok = False; break
                    if first is None:
                        first = ea
                if ok:
                    result.update(classified=True, shape="batch",
                                  address=(first.lower() if first else None),
                                  account_count=len(accts))

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY

# Read the classifier verdict back.
CLASSIFIED=$($PY -c "
import json, sys
try:
    r = json.load(open(sys.argv[1], encoding='utf-8'))
    print('1' if r.get('classified') else '0')
except Exception:
    print('0')
" "$TMP_OUT")

if [ "$CLASSIFIED" = "1" ]; then
    SHAPE=$($PY -c "import json,sys; print(json.load(open(sys.argv[1],encoding='utf-8')).get('shape',''))" "$TMP_OUT")
    P_ADDR=$($PY -c "import json,sys; print(json.load(open(sys.argv[1],encoding='utf-8')).get('address') or '')" "$TMP_OUT")
    P_COUNT=$($PY -c "import json,sys; print(int(json.load(open(sys.argv[1],encoding='utf-8')).get('account_count',1)))" "$TMP_OUT")

    WARN_MSG="unencrypted private key at rest"

    if [ "$JSON_OUT" = "1" ]; then
        printf '{"keyfile":"%s","posture":"PLAINTEXT","shape":"%s","address":"%s","account_count":%s,"warn":true,"warning":"%s"}\n' \
            "$KEYFILE" "$SHAPE" "$P_ADDR" "$P_COUNT" "$WARN_MSG"
    else
        echo "=== Keyfile security-posture audit ==="
        echo "keyfile:       $KEYFILE"
        echo "posture:       PLAINTEXT"
        echo "  [WARN] $WARN_MSG"
        echo "  shape:       $SHAPE"
        if [ "$SHAPE" = "batch" ] && [ "$P_COUNT" -gt 1 ]; then
            echo "  address:     $P_ADDR  (+$((P_COUNT - 1)) more in batch)"
        else
            echo "  address:     $P_ADDR"
        fi
        echo "  recommendation: encrypt at rest via \`determ-wallet keyfile-create\`,"
        echo "                  then securely delete this plaintext copy."
    fi

    # PLAINTEXT is a successful AUDIT outcome (the audit ran + reported the
    # security finding correctly) — terminal verdict is PASS; the WARN above
    # is the finding. The audit FAILS only when posture cannot be certified.
    echo
    echo "  PASS: operator_keyfile_audit (PLAINTEXT — WARN: $WARN_MSG)"
    exit 0
fi

# ── Neither encrypted nor a known plaintext shape: cannot certify posture ─────
ERRKIND=$($PY -c "import json,sys; print(json.load(open(sys.argv[1],encoding='utf-8')).get('error','unknown'))" "$TMP_OUT" 2>/dev/null || echo "unknown")
echo "operator_keyfile_audit: cannot classify '$KEYFILE'" >&2
echo "  keyfile-info rejected it (rc=$INFO_RC): ${INFO_ERR:-<no diagnostic>}" >&2
echo "  and it is not a recognized plaintext keyfile shape (reason: $ERRKIND)." >&2
echo "  This is neither an encrypted DETERM-NODE-V1 keyfile nor a plaintext" >&2
echo "  account/node_key JSON — posture cannot be certified." >&2
echo
echo "  FAIL: operator_keyfile_audit (unclassifiable — posture uncertain)"
exit 1
