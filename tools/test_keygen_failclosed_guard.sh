#!/usr/bin/env bash
# test_keygen_failclosed_guard.sh — STATIC source guard for the node-identity
# keygen entropy check (register CB-4 / KeygenFailClosedSoundness).
#
# generate_node_key() draws a fresh 32-byte RFC 8032 seed from the OS CSPRNG and
# derives the Ed25519 node identity from it (src/crypto/keys.cpp):
#     if (determ_rng_bytes(key.priv_seed.data(), 32) != 0)
#         throw std::runtime_error("OS entropy source failed (determ_rng_bytes)");
# The security property is FAIL-CLOSED entropy: a partial/failed OS draw must
# ABORT, never become a node identity. determ_rng_bytes returns non-zero on a
# short read; the `!= 0` guard + throw is the only thing standing between an
# entropy failure and an all-zero (or partially-initialised) private seed being
# published as a validator key — a catastrophic, silently-forgeable identity.
#
# THE GAP this closes: nothing pins the fail-closed check at the source. The
# surviving mutation drops the return-code check to a fire-and-forget draw:
#     (void)determ_rng_bytes(key.priv_seed.data(), 32);
# The seed buffer is then whatever the CSPRNG left (all-zero on total failure),
# the pubkey derives cleanly, and generate_node_key returns a VALID-LOOKING but
# entropy-starved key. No unit test exercises the entropy-failure branch (you
# cannot make the OS CSPRNG fail on demand in a portable test), and every
# happy-path keygen test still passes under the mutant — so a dropped check
# survives every existing gate. This is the fail-closed-branch class (SB-3,
# AL-5): a security-critical abort with no source-parity gate pinning it.
#
# This guard pins, at the PRODUCTION source, that the single entropy draw inside
# generate_node_key() is:
#   (a) exactly ONE call (non-vacuity — a rename/second-draw flips the count),
#   (b) inside an `if (... != 0)` fail-closed guard,
#   (c) NOT a `(void)`-cast fire-and-forget draw, and
#   (d) followed by a `throw` that aborts identity creation.
#
# Pure read-only awk over one .cpp file. No build, no node, never SKIPs.
# `SELFTEST=1 bash tools/test_keygen_failclosed_guard.sh` drives a coherent and
# a `(void)`-cast-mutant snippet through the SAME extractor to prove it is live.
# Exit 0 = the entropy draw is fail-closed; exit 1 = drift.
set -u
cd "$(dirname "$0")/.."

KEYS_FILE=src/crypto/keys.cpp

# extract_props <file>
# Scans generate_node_key()'s body and prints "calls|failclosed|voidcast|throws"
#   calls      = number of determ_rng_bytes( draws in the body
#   failclosed = 1 if a draw sits on an `if (... != 0)` line
#   voidcast   = 1 if a draw is a `(void)`-cast (return discarded)
#   throws     = 1 if a `throw` immediately follows the guarded draw
extract_props() {
  awk '
    /^NodeKey generate_node_key\(/ { infn = 1; next }
    infn && /^}/                   { infn = 0 }
    infn {
      line = $0; sub(/\/\/.*/, "", line)
      if (line ~ /determ_rng_bytes[ \t]*\(/) {
        calls++
        if (line ~ /^[ \t]*if[ \t]*\(/ && line ~ /!=[ \t]*0/) failclosed = 1
        if (line ~ /\(void\)[ \t]*determ_rng_bytes/)          voidcast   = 1
        drawline = NR
      }
      if (drawline > 0 && NR == drawline + 1 && line ~ /throw/) throws = 1
    }
    END { printf "%d|%d|%d|%d\n", calls, failclosed, voidcast, throws }
  ' "$1"
}

EXPECTED_RNG_CALLS=1

# ── SELFTEST: the extractor + the drift rule are live ────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: keygen fail-closed source extractor ==="
  ST_FAIL=0
  GOOD=$(extract_props /dev/stdin <<'EOF'
NodeKey generate_node_key() {
    NodeKey key;
    if (determ_rng_bytes(key.priv_seed.data(), 32) != 0)
        throw std::runtime_error("OS entropy source failed (determ_rng_bytes)");
    determ_ed25519_pubkey_from_seed(key.priv_seed.data(), key.pub.data());
    return key;
}
EOF
)
  BAD=$(extract_props /dev/stdin <<'EOF'
NodeKey generate_node_key() {
    NodeKey key;
    (void)determ_rng_bytes(key.priv_seed.data(), 32);
    determ_ed25519_pubkey_from_seed(key.priv_seed.data(), key.pub.data());
    return key;
}
EOF
)
  if [ "$GOOD" = "1|1|0|1" ]; then
    echo "  ok:  a fail-closed draw extracts as calls=1 failclosed=1 voidcast=0 throws=1 [$GOOD]"
  else
    echo "  bad: coherent copy mis-extracted [$GOOD] (extractor wrong)" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  case "$BAD" in
    1\|0\|1\|0) echo "  ok:  a (void)-cast fire-and-forget draw is flagged [$BAD]" ;;
    *)          echo "  bad: (void)-cast mutant NOT flagged [$BAD]" >&2; ST_FAIL=$((ST_FAIL + 1)) ;;
  esac
  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_keygen_failclosed_guard SELFTEST (extractor flags a dropped entropy check)"
    exit 0
  else
    echo "  FAIL: test_keygen_failclosed_guard SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

# ── MAIN: pin the live production draw as fail-closed ─────────────────────────────
VIOL=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOL=$((VIOL + 1)); }

PROPS=$(extract_props "$KEYS_FILE")
CALLS=${PROPS%%|*};      REST=${PROPS#*|}
FAILCLOSED=${REST%%|*};  REST=${REST#*|}
VOIDCAST=${REST%%|*}
THROWS=${REST##*|}

if [ "$CALLS" -eq "$EXPECTED_RNG_CALLS" ]; then
  ok "generate_node_key draws entropy exactly $EXPECTED_RNG_CALLS time (non-vacuity anchor holds)"
else
  bad "generate_node_key has $CALLS determ_rng_bytes draws, expected $EXPECTED_RNG_CALLS (anchor drift / extra draw)"
fi

if [ "$FAILCLOSED" -eq 1 ]; then
  ok "the entropy draw sits inside an 'if (... != 0)' fail-closed guard"
else
  bad "the entropy draw is NOT return-code checked — a failed OS CSPRNG draw could become a node identity"
fi

if [ "$VOIDCAST" -eq 0 ]; then
  ok "the entropy draw is NOT a (void)-cast fire-and-forget (return code is consumed)"
else
  bad "the entropy draw is a (void)-cast — the failure return code is DISCARDED (fail-OPEN)"
fi

if [ "$THROWS" -eq 1 ]; then
  ok "a throw follows the guarded draw — identity creation aborts on entropy failure"
else
  bad "no throw follows the entropy check — the failure path does not abort keygen"
fi

echo ""
if [ "$VIOL" -eq 0 ]; then
  echo "  PASS: test_keygen_failclosed_guard (generate_node_key fails CLOSED on OS entropy failure — no entropy-starved node identity)"
  exit 0
else
  echo "  FAIL: test_keygen_failclosed_guard ($VIOL violation(s) — the node-keygen entropy check has drifted toward fail-open)"
  exit 1
fi
