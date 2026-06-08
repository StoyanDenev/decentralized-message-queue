#!/usr/bin/env bash
# ADVERSARIAL robustness suite for the determ-light persisted-anchor LOADER
# (light/persist.cpp::load_light_state), driven end-to-end through the CLI:
#     determ-light state --show --state <crafted>
#
# Contract being hardened (light/main.cpp::cmd_state SHOW branch + the
# try/catch wrapper that turns any thrown std::exception into exit 1):
#
#   * a MISSING state file is a GRACEFUL "no persisted anchor" → exit 0
#     (absence is not an error — light_state_exists() short-circuits before
#     load_light_state() is ever called);
#   * a PRESENT-but-MALFORMED file MUST fail CLOSED:
#       - exit code EXACTLY 1 (the try/catch returns 1; never >1, never a
#         crash/abort/uncaught-exception which a shell sees as 128+signal or
#         the MSVCRT abort code 3),
#       - NEVER a false "no persisted anchor" (that string is the absence
#         path; emitting it on a corrupt-but-present file would silently
#         drop a tampered anchor — the exact LSP fail-open we are guarding),
#       - a diagnostic on stderr.
#
# This mirrors the (B)#5 "corrupt cache fails closed" line in
# tools/test_light_state.sh but fans it out across twelve crafted byte
# payloads that each hit a DIFFERENT validation branch in load_light_state:
#   json::parse throw, is_object(), is_number_unsigned()/is_string() type
#   gates, the schema_version!=1 gate, the is_hex_len(.,64) gates, and the
#   contains() missing-field gates.
#
# Harness conventions copied from tools/test_light_state.sh:
#   set -u; cd repo root; source tools/common.sh; DETERM_LIGHT presence/SKIP
#   guard; ck() pass/fail accounting; mktemp -d tempdir + trap cleanup.
#
# PATH-FORM CAVEAT (same as test_light_state.sh): the determ-light binary is a
# native-Windows .exe, so on Git Bash it RESOLVES the MSYS "/tmp/..." path that
# mktemp -d hands us and PRINTS it back as "C:/Users/.../Temp/..." in its
# diagnostics. The binary itself accepts the MSYS path form on its argv (the
# C++ runtime maps it), so we pass $SP verbatim. We therefore never grep the
# binary's output for the *path*; we only grep it for the literal phrase
# "no persisted anchor" (which is path-independent) and key on the exit code.
#
# BYTE-EXACTNESS: every payload is written with printf so the bytes on disk are
# exactly what we intend (binary-safe — important for the leading UTF-8 BOM in
# case 11 and the embedded newline + trailing garbage in case 12). We do NOT
# use Python's text-mode open() here: on Windows it would translate LF->CRLF
# (corrupting the byte count) AND a native-Windows python can't even open the
# MSYS "/tmp/..." path that mktemp produces (observed: FileNotFoundError),
# which would silently write the file somewhere the binary never reads. bash's
# builtin printf interprets \xNN in the format string, so the BOM is emitted
# as the three raw bytes EF BB BF with no interpreter-path hazard.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

pass=0; fail=0
ck() { if [ "$1" = "$2" ]; then echo "  PASS: $3 (exit $1)"; pass=$((pass+1));
       else echo "  FAIL: $3 (got exit $1, want $2)"; fail=$((fail+1)); fi; }

T="$(mktemp -d 2>/dev/null || echo /tmp/determ_persist_rob_$$)"; mkdir -p "$T"
trap 'rm -rf "$T" 2>/dev/null' EXIT INT
SP="$T/state.json"

H64a=$(printf 'a%.0s' $(seq 1 64))   # 64 'a'  — a valid-shaped hex field
H64b=$(printf 'b%.0s' $(seq 1 64))   # 64 'b'
H63=$(printf 'a%.0s' $(seq 1 63))    # 63 'a'  — one too short
H65=$(printf 'a%.0s' $(seq 1 65))    # 65 'a'  — one too long

# fail_closed <label>
#   Runs `state --show --state "$SP"` against whatever bytes the caller just
#   wrote to $SP, capturing stdout+stderr together and the real exit code, then
#   asserts the full fail-closed contract in one shot:
#     (a) exit code EXACTLY 1 (not 0, and crucially not >1: a >1 / 128+ code
#         would mean a crash, signal, or uncaught exception — NOT a clean
#         fail-closed),
#     (b) the output does NOT contain the absence phrase "no persisted anchor"
#         (which would be a false-negative: silently treating a corrupt-but-
#         PRESENT file as if no anchor existed).
fail_closed() {
    local label="$1"
    local out rc
    out=$("$DETERM_LIGHT" state --show --state "$SP" 2>&1); rc=$?
    # (a) exact exit 1
    ck "$rc" 1 "$label: fails closed (exit 1, not crash/>1)"
    # (b) must NOT claim absence on a present-but-malformed file
    if echo "$out" | grep -q "no persisted anchor"; then
        echo "  FAIL: $label: emitted false 'no persisted anchor' on a PRESENT file"
        echo "$out" | sed 's/^/      /'
        fail=$((fail+1))
    else
        echo "  PASS: $label: no false 'no persisted anchor'"
        pass=$((pass+1))
    fi
}

echo "=== adversarial malformed-state payloads (each MUST fail closed) ==="

# (1) truncated JSON — unterminated object. Hits the json::parse() throw.
printf '{ "schema_version": 1' > "$SP"
fail_closed "(1) truncated JSON object"

# (2) valid JSON but a top-level ARRAY, not an object. Hits the !is_object() gate.
printf '[]' > "$SP"
fail_closed "(2) top-level array, not object"

# (3) head_height as a STRING, not a number. Hits the !is_number_unsigned() gate
#     for head_height (it is_string() instead).
printf '{"schema_version":1,"genesis_hash":"%s","head_height":"42","head_block_hash":"%s","head_state_root":""}\n' \
    "$H64a" "$H64b" > "$SP"
fail_closed "(3) head_height is a string"

# (4) head_height absurdly large (10^26-ish) — overflows uint64_t. nlohmann
#     parses an out-of-range integer literal as a FLOAT, so is_number_unsigned()
#     is false → the missing/invalid 'head_height' gate fires. (Observed: the
#     loader rejects it rather than silently truncating — verified exit 1.)
printf '{"schema_version":1,"genesis_hash":"%s","head_height":99999999999999999999999999,"head_block_hash":"%s","head_state_root":""}\n' \
    "$H64a" "$H64b" > "$SP"
fail_closed "(4) head_height absurdly large (uint64 overflow)"

# (5) genesis_hash 63 hex chars (one too short). Hits is_hex_len(.,64) length gate.
printf '{"schema_version":1,"genesis_hash":"%s","head_height":42,"head_block_hash":"%s","head_state_root":""}\n' \
    "$H63" "$H64b" > "$SP"
fail_closed "(5) genesis_hash 63 hex chars (short)"

# (6) genesis_hash 65 hex chars (one too long). Hits is_hex_len(.,64) length gate.
printf '{"schema_version":1,"genesis_hash":"%s","head_height":42,"head_block_hash":"%s","head_state_root":""}\n' \
    "$H65" "$H64b" > "$SP"
fail_closed "(6) genesis_hash 65 hex chars (long)"

# (7) genesis_hash with a NON-HEX char but the RIGHT length (64). We prefix 'g'
#     onto a 63-char run so length stays exactly 64 — this isolates the
#     non-hex-CHAR rejection from the length rejection (hits the per-char loop
#     in is_hex_len, not the size() check).
printf '{"schema_version":1,"genesis_hash":"g%s","head_height":42,"head_block_hash":"%s","head_state_root":""}\n' \
    "$H63" "$H64b" > "$SP"
fail_closed "(7) genesis_hash 64 chars with a non-hex char"

# (8) missing head_block_hash entirely. Hits the req_str() contains() gate.
printf '{"schema_version":1,"genesis_hash":"%s","head_height":42,"head_state_root":""}\n' \
    "$H64a" > "$SP"
fail_closed "(8) missing head_block_hash"

# (9) schema_version 0 — present, unsigned, but not the supported value 1.
#     Hits the explicit `s.schema_version != 1` reject (NOT the type gate).
printf '{"schema_version":0,"genesis_hash":"%s","head_height":42,"head_block_hash":"%s","head_state_root":""}\n' \
    "$H64a" "$H64b" > "$SP"
fail_closed "(9) schema_version 0 (unsupported)"

# (10) empty file (zero bytes). json::parse("") throws → fail-closed. This is
#      the nastiest false-absence trap: an empty file EXISTS, so
#      light_state_exists() is true and we MUST NOT degrade to "no anchor".
printf '' > "$SP"
fail_closed "(10) empty file (zero bytes)"

# (11) leading UTF-8 BOM (EF BB BF) then an otherwise-valid object.
#      OBSERVED DETERMINISTIC BEHAVIOR: nlohmann::json::parse() skips a single
#      leading UTF-8 BOM by default, so this payload is ACCEPTED and the anchor
#      shows normally → exit 0. This is the ONE crafted case that does NOT fail
#      closed; we assert the ACTUAL observed exit (0) rather than assuming a
#      rejection. The robustness point still holds: the loader does not crash on
#      the BOM, and it does not emit a false absence — it correctly parses the
#      anchor. (If a future nlohmann bump flips BOM handling to a parse error,
#      this assertion turns RED and this comment tells the next maintainer the
#      expectation was pinned to OBSERVED v-current behavior, not a spec mandate.)
printf '\xef\xbb\xbf{"schema_version":1,"genesis_hash":"%s","head_height":42,"head_block_hash":"%s","head_state_root":""}\n' \
    "$H64a" "$H64b" > "$SP"
bom_out=$("$DETERM_LIGHT" state --show --state "$SP" 2>&1); bom_rc=$?
ck "$bom_rc" 0 "(11) leading UTF-8 BOM is ACCEPTED (nlohmann skips BOM; observed exit 0)"
# Whatever the exit, the binary must NOT have crashed (>1 / signal) — exit 0
# already proves that, but assert the anchor actually printed (no false absence
# the other direction) for a complete contrast with the fail-closed cases.
if echo "$bom_out" | grep -q "head_height:        42"; then
    echo "  PASS: (11) BOM payload parsed to the real anchor (height 42)"; pass=$((pass+1))
else
    echo "  FAIL: (11) BOM payload did not surface the anchor"; echo "$bom_out" | sed 's/^/      /'; fail=$((fail+1))
fi

# (12) trailing garbage AFTER a valid object: a complete object, a newline, then
#      a bare token. nlohmann::json::parse() (whole-input, not stream) requires
#      end-of-input after the value, so the trailing 'GARBAGE' is a parse error
#      → fail-closed. Guards against a lenient "parse the first value, ignore the
#      rest" loader that an attacker could exploit to smuggle bytes past the gate.
printf '{"schema_version":1,"genesis_hash":"%s","head_height":42,"head_block_hash":"%s","head_state_root":""}\nGARBAGE\n' \
    "$H64a" "$H64b" > "$SP"
fail_closed "(12) trailing garbage after a valid object"

echo ""
echo "=== contrast control: a genuinely-absent path is GRACEFUL (exit 0) ==="
# The mirror image of every assertion above: with NO file present, the SHOW
# branch must take the light_state_exists()==false short-circuit and exit 0
# WITH the "no persisted anchor" phrase. This proves the fail-closed behavior
# above is specific to PRESENT-but-malformed files, not a blanket exit-1.
rm -f "$SP"
ctl_out=$("$DETERM_LIGHT" state --show --state "$SP" 2>&1); ctl_rc=$?
ck "$ctl_rc" 0 "absent path is graceful (exit 0)"
if echo "$ctl_out" | grep -q "no persisted anchor"; then
    echo "  PASS: absent path emits the 'no persisted anchor' graceful phrase"; pass=$((pass+1))
else
    echo "  FAIL: absent path did not emit 'no persisted anchor'"; echo "$ctl_out" | sed 's/^/      /'; fail=$((fail+1))
fi

echo ""
echo "=== Test summary ==="
echo "  $pass pass / $fail fail"
if [ "$fail" -eq 0 ]; then echo "  PASS: test_light_persist_robustness"; exit 0
else echo "  FAIL: test_light_persist_robustness"; exit 1; fi
