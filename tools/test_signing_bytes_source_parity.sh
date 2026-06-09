#!/usr/bin/env bash
# test_signing_bytes_source_parity.sh — STATIC signing_bytes layout-parity GUARD.
#
# WHAT THIS IS
# ------------
# The canonical signing_bytes layout (the consensus-critical pre-image over
# which every Ed25519 tx sig is computed, then SHA-256'd into tx_hash) is
# re-implemented in FOUR independent source sites that each deliberately do
# NOT link the chain lib (decoupled TCBs). The runtime sibling
# tools/test_cross_binary_tx_parity.sh proves they agree — but only AFTER you
# build + run all three binaries. THIS guard is the SOURCE-LEVEL complement:
# it parses the four C++ sites directly and turns RED the instant any copy is
# edited to diverge — before any build or binary run.
#
# THE FOUR SITES (located by anchor, not by line number — drift-robust):
#   1. src/chain/block.cpp   Transaction::signing_bytes       (CANONICAL; INCLUDES payload)
#   2. wallet/main.cpp       cmd_tx_sign_verify inline rebuild (INCLUDES payload)
#   3. wallet/main.cpp       cmd_cold_sign      inline rebuild (INCLUDES payload)
#   4. light/sign_tx.cpp     compute_signing_bytes            (OMITS the trailing
#                            payload insert — the ONE allowed structural
#                            difference, because the light sign-tx API has no
#                            payload param so an empty-payload tx is byte-identical)
#
# (Note: wallet's cmd_sign_anon_tx — dispatch wallet/main.cpp sign-anon-tx — is a
#  SEPARATE TRANSFER-only sign path with a TxType::TRANSFER==0 literal first byte
#  and its own variable conventions; it is NOT one of the four canonical-parity
#  targets the runtime test pins, so it is intentionally out of scope here. The
#  four sites above are exactly the ones test_cross_binary_tx_parity.sh exercises.)
#
# HOW IT WORKS
# ------------
# For each site we isolate its layout region (from the type push_back to the
# site's final layout statement) and reduce each statement to a canonical TOKEN,
# collapsing variable-name + whitespace differences (out/sb, from/from_str,
# to/to_str):
#       push_back(static_cast<uint8_t>(type/tx_type))   -> TYPE
#       insert(... from ...)                            -> FROM
#       push_back(0)                                    -> NUL
#       insert(... to ...)                              -> TO
#       push_back(0)                                    -> NUL
#       for(i=7;i>=0;--i) ... amount ...                -> AMOUNT_BE
#       for(i=7;i>=0;--i) ... fee ...                   -> FEE_BE
#       for(i=7;i>=0;--i) ... nonce ...                 -> NONCE_BE
#       insert(... payload ...)                         -> PAYLOAD
# The ordered token sequence is built per site. The guard then asserts:
#   * Sites 1,2,3 each produce EXACTLY:
#         TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE PAYLOAD
#   * Site 4 produces that sequence MINUS the trailing PAYLOAD, and the ONLY
#     difference vs the canonical sequence is that single missing PAYLOAD.
#
# LIVENESS (this is NOT a tautology)
# ----------------------------------
# The token reduction is direction-aware and order-aware, so a real drift in
# ANY copy turns the guard RED:
#   * BE-direction is detected PRECISELY: each amount/fee/nonce loop must
#     iterate 7 DOWN TO 0. A loop rewritten little-endian (i=0;i<8 or i=0;i<=7)
#     yields NO *_BE token for that field, so the sequence loses a token and
#     fails — LE drift is caught.
#   * Field order is positional (AMOUNT_BE before FEE_BE before NONCE_BE):
#     swapping the fee/nonce loops reorders the tokens and fails.
#   * A dropped NUL, a moved PAYLOAD, or a missing field all change the ordered
#     token list and fail.
# LIVENESS IS SELF-VERIFYING (SELFTEST=1): run
#       SELFTEST=1 bash tools/test_signing_bytes_source_parity.sh
# to feed synthetic drifted snippets (LE rewrite, fee/nonce swap, dropped NUL,
# i*4 byte-width corruption) through the SAME extract_tokens() this guard uses and
# assert each one reduces to a token seq that DIFFERS from the canonical — i.e.
# the production guard would flag it RED. The amount/fee/nonce field regexes also
# bind the shift WIDTH to (i * 8), so a byte-width corruption (i*4 / i*16) drops
# the field token rather than silently passing. The self-test creates NO files
# and modifies NO source — it runs entirely on in-memory heredoc snippets.
#
# Pure read-only SOURCE check (awk/grep/sed over .cpp only). Needs NO determ
# binary, never SKIPs, does NOT source tools/common.sh. Deterministic + offline.
# run_all.sh auto-discovers it (tools/test_*.sh) and reads the single terminal
# `  PASS:` / `  FAIL:` marker.
#
# Exit 0 = all four sites structurally agree; exit 1 = layout drift.
set -u
cd "$(dirname "$0")/.."

CANONICAL_SEQ="TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE PAYLOAD"
LIGHT_SEQ="TYPE FROM NUL TO NUL AMOUNT_BE FEE_BE NONCE_BE"   # canonical minus trailing PAYLOAD

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

# ── extract_tokens <file> <mode> ────────────────────────────────────────────────
# Prints the ordered, space-separated token sequence for the layout region of
# ONE site. The region is the inclusive span from the type push_back (begin
# anchor) to the site's final layout statement (end anchor):
#   mode=payload  end = the `insert(... payload ...)` line       (sites 1,2,3)
#   mode=light    end = the nonce BE loop (light has no payload)  (site 4)
# Within that span every statement is reduced to its canonical token; non-layout
# lines (comments, blank, reserve(), declarations) produce nothing.
#
# All regexes are LITERAL inside the awk program (NOT passed via -v, which would
# mangle backslash escapes). Only the plain `mode` string is passed via -v.
# Reading source from a FILE (not the live function name) keeps this robust to
# line-number drift — we anchor on the in-function `static_cast<uint8_t>(` push
# and the final layout statement.
extract_tokens() {
  local file="$1" mode="$2"
  awk -v mode="$mode" '
    BEGIN { inreg = 0 }
    # Enter the region at the begin anchor (the type push_back).
    !inreg && /push_back\(static_cast<uint8_t>\((type|tx_type)\)\)/ { inreg = 1 }
    inreg {
      line = $0
      # Strip // comments so commented tokens never count.
      sub(/\/\/.*/, "", line)
      # Normalize whitespace.
      gsub(/[ \t]+/, " ", line)

      # TYPE: push_back(static_cast<uint8_t>(type/tx_type)).
      # Accept the `type` (chain/light) and `tx_type` (wallet) variable names.
      if (line ~ /push_back\(static_cast<uint8_t>\((type|tx_type)\)\)/) print "TYPE"

      # FROM / TO / PAYLOAD inserts: insert(dst.end(), VAR.begin(), VAR.end()).
      # The destination is `out.end()` / `sb.end()`; the src var (immediately
      # after the comma) carries the field name (from/from_str, to/to_str,
      # payload/payload_bytes). Anchor on `.end(), VAR.begin`.
      else if (line ~ /\.insert\(.*\.end\(\), *(from|from_str)\.begin/) print "FROM"
      else if (line ~ /\.insert\(.*\.end\(\), *(to|to_str)\.begin/)     print "TO"
      else if (line ~ /\.insert\(.*\.end\(\), *(payload|payload_bytes)\.begin/) print "PAYLOAD"

      # NUL separators: push_back(0) (exactly literal 0).
      else if (line ~ /push_back\(0\)/) print "NUL"

      # BE field loops: for(i=7;i>=0;--i) push_back((F >> (i*8)) & 0xFF).
      # Direction enforced INSIDE the regex: 7 DOWN TO 0 only. A loop written
      # little-endian (i=0;i<8 or i=0;i<=7) does NOT match -> no token for that
      # field -> the sequence is short -> drift is caught.
      else if (line ~ /for *\( *int i *= *7 *; *i *>= *0 *; *(--i|i--) *\)/) {
        # Bind the shift WIDTH to (i * 8). Without this, a byte-width corruption
        # (e.g. `>> (i * 4)`) would still match the bare `amount >>` and silently
        # pass as AMOUNT_BE. Requiring the *8 multiplier means such a corruption
        # falls through to BE_UNKNOWN, changing the token seq -> RED.
        if      (line ~ /\( *amount *>> *\( *i *\* *8 *\)/) print "AMOUNT_BE"
        else if (line ~ /\( *fee *>> *\( *i *\* *8 *\)/)    print "FEE_BE"
        else if (line ~ /\( *nonce *>> *\( *i *\* *8 *\)/)  print "NONCE_BE"
        else                                                print "BE_UNKNOWN"
      }

      # Exit after processing the site-appropriate end-anchor line.
      if (mode == "payload" && line ~ /\.insert\(.*\.end\(\), *(payload|payload_bytes)\.begin/) exit
      if (mode == "light"   && line ~ /\( *nonce *>>/) exit
    }
  ' "$file" | tr "\n" " " | sed -E "s/ +/ /g; s/^ //; s/ $//"
}

# ── SELFTEST mode (SELFTEST=1) ──────────────────────────────────────────────────
# Proves the extractor is LIVE (not a tautology that passes on any input) by
# feeding SYNTHETIC drifted layout snippets through the SAME extract_tokens() the
# production guard uses, and asserting each drift produces a token sequence that
#   (a) matches the predicted drifted sequence, AND
#   (b) DIFFERS from the canonical — i.e. the production guard WOULD flag it RED.
# This is the executable form of the LIVENESS argument in the header comment. Run:
#       SELFTEST=1 bash tools/test_signing_bytes_source_parity.sh
# (The normal, un-gated invocation is the production source check and is what
#  run_all.sh discovers; SELFTEST short-circuits into the liveness self-check.)
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: extractor liveness (synthetic drift -> predicted token seq, != canonical) ==="
  ST_FAIL=0
  st_case() {
    # $1 label  $2 expected token seq  (the C++ snippet arrives on stdin; the
    # extractor reads it as /dev/stdin in mode=payload).
    local label="$1" want="$2" got
    got=$(extract_tokens /dev/stdin payload)
    if [ "$got" = "$want" ]; then echo "  ok:  $label -> [$got]"
    else
      echo "  bad: $label" >&2
      echo "       want: [$want]" >&2
      echo "       got:  [$got]" >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
    # Every case EXCEPT the canonical sanity case must differ from canonical
    # (else the drift would slip past the production guard).
    if [ "$label" != "canonical-sanity" ] && [ "$got" = "$CANONICAL_SEQ" ]; then
      echo "  bad: $label produced the CANONICAL seq — drift NOT detected!" >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
  }

  # (0) sanity: a canonical snippet must reduce to the canonical seq (the
  #     extractor faithfully parses a correct layout).
  st_case "canonical-sanity" "$CANONICAL_SEQ" <<'EOF'
  out.push_back(static_cast<uint8_t>(type));
  out.insert(out.end(), from.begin(), from.end());
  out.push_back(0);
  out.insert(out.end(), to.begin(), to.end());
  out.push_back(0);
  for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 8)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);
  out.insert(out.end(), payload.begin(), payload.end());
EOF

  # (1) fee/nonce loops SWAPPED -> token order AMOUNT_BE NONCE_BE FEE_BE.
  st_case "fee-nonce-swap" "TYPE FROM NUL TO NUL AMOUNT_BE NONCE_BE FEE_BE PAYLOAD" <<'EOF'
  out.push_back(static_cast<uint8_t>(type));
  out.insert(out.end(), from.begin(), from.end());
  out.push_back(0);
  out.insert(out.end(), to.begin(), to.end());
  out.push_back(0);
  for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 8)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);
  out.insert(out.end(), payload.begin(), payload.end());
EOF

  # (2) amount loop rewritten LITTLE-ENDIAN (i=0;i<8) -> AMOUNT_BE token dropped.
  st_case "amount-little-endian" "TYPE FROM NUL TO NUL FEE_BE NONCE_BE PAYLOAD" <<'EOF'
  out.push_back(static_cast<uint8_t>(type));
  out.insert(out.end(), from.begin(), from.end());
  out.push_back(0);
  out.insert(out.end(), to.begin(), to.end());
  out.push_back(0);
  for (int i = 0; i < 8; ++i) out.push_back((amount >> (i * 8)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);
  out.insert(out.end(), payload.begin(), payload.end());
EOF

  # (3) dropped NUL after FROM -> one fewer NUL, FROM directly followed by TO.
  st_case "dropped-nul" "TYPE FROM TO NUL AMOUNT_BE FEE_BE NONCE_BE PAYLOAD" <<'EOF'
  out.push_back(static_cast<uint8_t>(type));
  out.insert(out.end(), from.begin(), from.end());
  out.insert(out.end(), to.begin(), to.end());
  out.push_back(0);
  for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 8)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);
  out.insert(out.end(), payload.begin(), payload.end());
EOF

  # (4) amount shift WIDTH corruption (i*4 not i*8) -> AMOUNT_BE -> BE_UNKNOWN.
  #     Validates the width-binding added to the BE field regex: an i*4 must NOT
  #     silently pass as AMOUNT_BE.
  st_case "amount-width-i4" "TYPE FROM NUL TO NUL BE_UNKNOWN FEE_BE NONCE_BE PAYLOAD" <<'EOF'
  out.push_back(static_cast<uint8_t>(type));
  out.insert(out.end(), from.begin(), from.end());
  out.push_back(0);
  out.insert(out.end(), to.begin(), to.end());
  out.push_back(0);
  for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 4)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);
  for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);
  out.insert(out.end(), payload.begin(), payload.end());
EOF

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_signing_bytes_source_parity SELFTEST (extractor flags all drift classes: LE, field-swap, dropped-NUL, width-corruption)"
    exit 0
  else
    echo "  FAIL: test_signing_bytes_source_parity SELFTEST ($ST_FAIL self-test failure(s) — the extractor is NOT live)"
    exit 1
  fi
fi

echo "=== signing_bytes SOURCE-parity guard (4 sites; static complement to test_cross_binary_tx_parity.sh) ==="

# ── Site 1: src/chain/block.cpp Transaction::signing_bytes (CANONICAL) ──────────
SEQ1=""
if [ ! -f src/chain/block.cpp ]; then
  bad "src/chain/block.cpp — MISSING (canonical site)"
else
  SEQ1=$(extract_tokens src/chain/block.cpp payload)
  if [ "$SEQ1" = "$CANONICAL_SEQ" ]; then
    ok "site1 src/chain/block.cpp Transaction::signing_bytes -> [$SEQ1]"
  else
    bad "site1 src/chain/block.cpp signing_bytes layout DRIFT"
    echo "       want: [$CANONICAL_SEQ]" >&2
    echo "       got:  [$SEQ1]" >&2
  fi
fi

# ── Sites 2 + 3: wallet/main.cpp cmd_tx_sign_verify + cmd_cold_sign ─────────────
# Both wallet sites push into `sb` with the exact anchor
# `sb.push_back(static_cast<uint8_t>(tx_type))`. We grab the line numbers of the
# two occurrences and slice the file so each block is parsed in isolation
# (immune to line drift). Later wallet sign paths use `tx_type_int` (a different
# token) so they never collide with this anchor — only the two canonical-parity
# sites match it.
WALLET=wallet/main.cpp
SEQ2=""
SEQ3=""
if [ ! -f "$WALLET" ]; then
  bad "wallet/main.cpp — MISSING (sites 2 + 3)"
else
  TYPE_LINES=$(grep -nE 'sb\.push_back\(static_cast<uint8_t>\(tx_type\)\)' "$WALLET" | cut -d: -f1)
  NTYPE=$(printf '%s\n' "$TYPE_LINES" | grep -c .)
  if [ "$NTYPE" -lt 2 ]; then
    bad "wallet/main.cpp — expected 2 'sb.push_back(static_cast<uint8_t>(tx_type))' anchors (sites 2+3), found $NTYPE"
  else
    L2=$(printf '%s\n' "$TYPE_LINES" | sed -n '1p')
    L3=$(printf '%s\n' "$TYPE_LINES" | sed -n '2p')
    # Site 2 region: [L2 .. L3-1]; site 3 region: [L3 .. L3+40] (layout < 15 lines).
    SLICE2=$(sed -n "${L2},$((L3 - 1))p" "$WALLET")
    SLICE3=$(sed -n "${L3},$((L3 + 40))p" "$WALLET")

    SEQ2=$(printf '%s\n' "$SLICE2" | extract_tokens /dev/stdin payload)
    if [ "$SEQ2" = "$CANONICAL_SEQ" ]; then
      ok "site2 wallet/main.cpp cmd_tx_sign_verify -> [$SEQ2]"
    else
      bad "site2 wallet/main.cpp cmd_tx_sign_verify layout DRIFT"
      echo "       want: [$CANONICAL_SEQ]" >&2
      echo "       got:  [$SEQ2]" >&2
    fi

    SEQ3=$(printf '%s\n' "$SLICE3" | extract_tokens /dev/stdin payload)
    if [ "$SEQ3" = "$CANONICAL_SEQ" ]; then
      ok "site3 wallet/main.cpp cmd_cold_sign -> [$SEQ3]"
    else
      bad "site3 wallet/main.cpp cmd_cold_sign layout DRIFT"
      echo "       want: [$CANONICAL_SEQ]" >&2
      echo "       got:  [$SEQ3]" >&2
    fi
  fi
fi

# ── Site 4: light/sign_tx.cpp compute_signing_bytes (payload OMITTED) ───────────
SEQ4=""
if [ ! -f light/sign_tx.cpp ]; then
  bad "light/sign_tx.cpp — MISSING (site 4)"
else
  SEQ4=$(extract_tokens light/sign_tx.cpp light)
  if [ "$SEQ4" = "$LIGHT_SEQ" ]; then
    ok "site4 light/sign_tx.cpp compute_signing_bytes -> [$SEQ4]  (PAYLOAD intentionally omitted)"
  else
    bad "site4 light/sign_tx.cpp compute_signing_bytes layout DRIFT"
    echo "       want: [$LIGHT_SEQ]  (canonical minus trailing PAYLOAD)" >&2
    echo "       got:  [$SEQ4]" >&2
  fi
fi

# ── Cross-site assertion: the ONLY allowed difference is site4's missing PAYLOAD ─
if [ -n "$SEQ1" ] && [ -n "$SEQ2" ] && [ -n "$SEQ3" ]; then
  if [ "$SEQ1" = "$SEQ2" ] && [ "$SEQ2" = "$SEQ3" ]; then
    ok "cross-site: payload-bearing sites 1,2,3 are token-identical"
  else
    bad "cross-site: payload-bearing sites 1,2,3 DIVERGE"
    echo "       site1: [$SEQ1]" >&2
    echo "       site2: [$SEQ2]" >&2
    echo "       site3: [$SEQ3]" >&2
  fi
fi
if [ -n "$SEQ1" ] && [ -n "$SEQ4" ]; then
  # Strip exactly one trailing PAYLOAD token from the canonical sequence and
  # require the remainder to equal site4 verbatim — i.e. PAYLOAD-omission is the
  # SOLE structural difference.
  SEQ1_NOPAYLOAD=$(printf '%s' "$SEQ1" | sed -E 's/ PAYLOAD$//')
  if [ "$SEQ1_NOPAYLOAD" = "$SEQ4" ]; then
    ok "cross-site: site4 == site1 minus trailing PAYLOAD (the sole allowed diff)"
  else
    bad "cross-site: site4 differs from site1 by MORE than the trailing PAYLOAD"
    echo "       site1 (no trailing payload): [$SEQ1_NOPAYLOAD]" >&2
    echo "       site4:                       [$SEQ4]" >&2
  fi
fi

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_signing_bytes_source_parity (4 source sites structurally agree on the signing_bytes layout)"
  exit 0
else
  echo "  FAIL: test_signing_bytes_source_parity ($VIOLATIONS layout-parity violation(s) — a signing_bytes copy has drifted)"
  exit 1
fi
