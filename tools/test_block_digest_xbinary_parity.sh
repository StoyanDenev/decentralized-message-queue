#!/usr/bin/env bash
# test_block_digest_xbinary_parity.sh — STATIC cross-binary block-digest GUARD.
#
# WHAT THIS IS
# ------------
# The BLOCK DIGEST is the SHA-256 pre-image the K-of-K committee signs in
# Phase 2 (FA1). It is THE single most consensus-critical byte format, and it
# is independently re-implemented in TWO binaries that deliberately do NOT
# share a code path:
#
#   (A) GROUND TRUTH — src/node/producer.cpp::compute_block_digest
#       The node computes this, the committee signs it, every validator
#       re-derives it. Binds the v1 core (index/prev_hash/tx_root/delay_seed/
#       consensus_mode/bft_proposer/creators/tx_lists/ed_sigs/dh_inputs) PLUS
#       two classes of CONDITIONAL appendage:
#         * three F2 view roots — inbound_receipts / equivocation_events /
#           abort_events — bound only on cross-shard / reconciled blocks;
#         * the merged-block tail — partner_subset_hash (R4/R7) then timestamp
#           (reconciled) — bound conditionally on every block class.
#
#   (B) MIRROR — light/verify.cpp::light_compute_block_digest
#       The light client re-derives the digest from an rpc_headers-STRIPPED
#       header to verify each committee member's Ed25519 sig. It is IDENTICAL
#       to (A) for the v1 core AND the partner_subset_hash + timestamp tail
#       (same order, same triggers), but INTENTIONALLY OMITS the three F2 view
#       roots — it cannot reconstruct them from a stripped header, so it
#       fail-closes on F2 / cross-shard blocks (false-NEGATIVE, never false-
#       positive; documented at light/verify.cpp:40-56).
#
# Runtime coverage today does NOT pin (B)==(A) on the conditional tail:
#   * tools/test_block_digest.sh -> `determ test-block-digest` is an in-process
#     unit test of (A) ALONE (mutate-each-field inclusion/exclusion fence).
#     It never touches (B).  [NB: that file's HEADER COMMENT is STALE — it
#     calls partner_subset_hash(#18) + timestamp(#19) "EXCLUDED", but producer
#     now CONDITIONALLY BINDS both (S-030-D2, shipped); the harness was
#     extended 19->25 and the wrapper only greps the final summary so it still
#     passes. That header misrepresents coverage — a separate fix.]
#   * tools/test_light_verify_block_sigs.sh boots a REAL cluster and cross-
#     checks (B) vs (A) end-to-end — but ONLY for block 1, a NON-merged block
#     (partner_subset_hash==0, empty proposer_times). The CONDITIONAL TAIL is
#     therefore NEVER cross-checked between the two implementations.
#
# THE GAP this guard closes: nothing pins the (B)==(A) agreement on the
# conditional merged-block tail at the SOURCE level. A one-line edit to either
# copy's tail — swapping partner_subset_hash/timestamp, changing a trigger
# (is_zero vs empty), or mis-ordering vs the F2 roots — would drift the
# committee-sig digest for merged/reconciled blocks with NO red test. This is
# the block-digest analog of tools/test_signing_bytes_source_parity.sh.
#
# HOW IT WORKS
# ------------
# We isolate each function's body by NAME anchor (drift-robust; no line nums):
#   producer: `Hash compute_block_digest(const Block& b) {`        .. `return h.finalize();`
#   light:    `Hash light_compute_block_digest(const determ::chain::Block& b) {` .. `return h.finalize();`
# Every SHA256Builder append inside the body is reduced to a canonical TOKEN
# (comments stripped first, so a commented-out append never counts):
#       h.append(b.index)                              -> INDEX
#       h.append(b.prev_hash)                          -> PREV_HASH
#       h.append(b.tx_root)                            -> TX_ROOT
#       h.append(b.delay_seed)                         -> DELAY_SEED
#       h.append(static_cast<uint8_t>(b.consensus_mode)) -> CONSENSUS_MODE
#       h.append(b.bft_proposer)                       -> BFT_PROPOSER
#       for (auto& c : b.creators) h.append(c)         -> CREATORS
#       ... for (auto& tx : list) h.append(tx)         -> TX_LISTS
#       h.append(s.data(), s.size())  (creator_ed_sigs)-> ED_SIGS
#       for (auto& d : b.creator_dh_inputs) h.append(d)-> DH_INPUTS
#       h.append(compute_view_root(ikeys))             -> INBOUND_ROOT
#       h.append(compute_view_root(ekeys))             -> EQ_ROOT
#       h.append(compute_view_root(akeys))             -> ABORT_ROOT
#       h.append(b.partner_subset_hash)                -> PARTNER_SUBSET
#       h.append(b.timestamp)                          -> TIMESTAMP
# The F2 roots are disambiguated by their keys vector (ikeys/ekeys/akeys),
# which is the intrinsic, order-stable signal of WHICH root is being appended.
#
# ASSERTIONS
#   * producer seq EXACTLY:
#       INDEX PREV_HASH TX_ROOT DELAY_SEED CONSENSUS_MODE BFT_PROPOSER \
#       CREATORS TX_LISTS ED_SIGS DH_INPUTS INBOUND_ROOT EQ_ROOT ABORT_ROOT \
#       PARTNER_SUBSET TIMESTAMP
#   * light seq EXACTLY producer MINUS the three F2 roots:
#       INDEX PREV_HASH TX_ROOT DELAY_SEED CONSENSUS_MODE BFT_PROPOSER \
#       CREATORS TX_LISTS ED_SIGS DH_INPUTS PARTNER_SUBSET TIMESTAMP
#   * LOAD-BEARING cross-site check: delete EXACTLY the three tokens
#     {INBOUND_ROOT, EQ_ROOT, ABORT_ROOT} from producer's seq and require
#     byte-equality with light's seq. This proves the merged-block tail
#     (PARTNER_SUBSET immediately before TIMESTAMP) is in the SAME relative
#     order in BOTH, and that the ONLY divergence is the documented F2-root
#     omission — nothing else moved.
#   * CONDITIONAL-TRIGGER parity where both bind: both gate PARTNER_SUBSET on a
#     non-zero partner_subset_hash test and TIMESTAMP on a non-empty
#     creator_proposer_times test (the guard expressions are grepped + classed).
#
# LIVENESS (SELFTEST=1)
# ---------------------
# `SELFTEST=1 bash tools/test_block_digest_xbinary_parity.sh` feeds synthetic
# DRIFTED snippets through the SAME extractor and the SAME cross-site logic and
# asserts each drift is flagged RED. Covers: (1) partner/timestamp tail SWAPPED;
# (2) a missing F2 root in producer (only 2 removed -> light wouldn't match);
# (3) light accidentally binding an F2 root (INBOUND_ROOT in light);
# (4) a dropped core field. The self-test creates NO files and modifies NO
# source — it runs entirely on in-memory heredoc snippets.
#
# Pure read-only SOURCE check (awk/grep/sed over the two .cpp files only). Needs
# NO determ binary, never SKIPs, does NOT source tools/common.sh. Deterministic
# + offline. run_all.sh auto-discovers it (tools/test_*.sh) and reads the single
# terminal `  PASS:` / `  FAIL:` marker.
#
# Exit 0 = the two copies agree (sole diff = F2-root omission); exit 1 = drift.
set -u
cd "$(dirname "$0")/.."

PRODUCER_SEQ="INDEX PREV_HASH TX_ROOT DELAY_SEED CONSENSUS_MODE BFT_PROPOSER CREATORS TX_LISTS ED_SIGS DH_INPUTS INBOUND_ROOT EQ_ROOT ABORT_ROOT PARTNER_SUBSET TIMESTAMP"
LIGHT_SEQ="INDEX PREV_HASH TX_ROOT DELAY_SEED CONSENSUS_MODE BFT_PROPOSER CREATORS TX_LISTS ED_SIGS DH_INPUTS PARTNER_SUBSET TIMESTAMP"
# The three F2 view-root tokens light omits — and ONLY these three.
F2_ROOTS="INBOUND_ROOT EQ_ROOT ABORT_ROOT"

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

# ── extract_tokens <file> <fn> ──────────────────────────────────────────────────
# Prints the ordered, space-separated append-token sequence for ONE function
# body. The body is the inclusive span from the function's opening-brace line
# (begin anchor = the signature) to its first `return h.finalize();` (end
# anchor). Within that span every SHA256Builder append is reduced to its
# canonical token; non-append lines (comments, blanks, locals, control flow,
# reserve()) produce nothing.
#
#   fn=producer  begin = `Hash compute_block_digest(const Block& b) {`
#   fn=light     begin = `Hash light_compute_block_digest(const ... Block& b) {`
#
# All regexes are LITERAL inside the awk program (NOT passed via -v, which would
# mangle backslash escapes). Only the plain `fn` string is passed via -v.
# Anchoring on the function NAME (not a line number) keeps this drift-robust.
extract_tokens() {
  local file="$1" fn="$2"
  awk -v fn="$fn" '
    BEGIN { inreg = 0 }
    # Enter the body at the begin anchor (the function signature opening brace).
    !inreg && fn == "producer" && /Hash +compute_block_digest\(const +Block& +b\) +\{/ { inreg = 1; next }
    !inreg && fn == "light"    && /Hash +light_compute_block_digest\(const +determ::chain::Block& +b\) +\{/ { inreg = 1; next }
    inreg {
      line = $0
      # Strip // comments so a commented-out append never counts as a token.
      sub(/\/\/.*/, "", line)
      # Normalize whitespace.
      gsub(/[ \t]+/, " ", line)

      # ── v1 core fields (always bound, in this exact order) ──
      if      (line ~ /\.append\(b\.index\)/)      print "INDEX"
      else if (line ~ /\.append\(b\.prev_hash\)/)  print "PREV_HASH"
      else if (line ~ /\.append\(b\.tx_root\)/)    print "TX_ROOT"
      else if (line ~ /\.append\(b\.delay_seed\)/) print "DELAY_SEED"
      else if (line ~ /\.append\(static_cast<uint8_t>\(b\.consensus_mode\)\)/) print "CONSENSUS_MODE"
      else if (line ~ /\.append\(b\.bft_proposer\)/) print "BFT_PROPOSER"
      # creators loop:        for (auto& c : b.creators) h.append(c);
      else if (line ~ /for *\( *auto& *c *: *b\.creators *\).*\.append\(c\)/) print "CREATORS"
      # creator_tx_lists inner loop:   for (auto& tx : list) h.append(tx);
      else if (line ~ /for *\( *auto& *tx *: *list *\).*\.append\(tx\)/) print "TX_LISTS"
      # creator_ed_sigs:      h.append(s.data(), s.size());
      else if (line ~ /\.append\(s\.data\(\), *s\.size\(\)\)/) print "ED_SIGS"
      # creator_dh_inputs loop: for (auto& d : b.creator_dh_inputs) h.append(d);
      else if (line ~ /for *\( *auto& *d *: *b\.creator_dh_inputs *\).*\.append\(d\)/) print "DH_INPUTS"

      # ── F2 view roots (producer ONLY) — disambiguated by the keys vector ──
      # h.append(compute_view_root(ikeys / ekeys / akeys)). The keys-vector name
      # is the intrinsic, order-stable signal of WHICH root is bound.
      else if (line ~ /\.append\(compute_view_root\(ikeys\)\)/) print "INBOUND_ROOT"
      else if (line ~ /\.append\(compute_view_root\(ekeys\)\)/) print "EQ_ROOT"
      else if (line ~ /\.append\(compute_view_root\(akeys\)\)/) print "ABORT_ROOT"
      # Any OTHER compute_view_root append (renamed keys vec) must NOT silently
      # vanish — flag it so a reordered/renamed root surfaces as drift.
      else if (line ~ /\.append\(compute_view_root\(/) print "VIEW_ROOT_UNKNOWN"

      # ── merged-block conditional tail (BOTH binaries) ──
      else if (line ~ /\.append\(b\.partner_subset_hash\)/) print "PARTNER_SUBSET"
      else if (line ~ /\.append\(b\.timestamp\)/)           print "TIMESTAMP"

      # Any unclassified append inside the body is drift — surface it.
      else if (line ~ /\.append\(/) print "APPEND_UNKNOWN"

      # Exit at the first finalize() (the single return statement).
      if (line ~ /\.finalize\(\)/) exit
    }
  ' "$file" | tr "\n" " " | sed -E "s/ +/ /g; s/^ //; s/ $//"
}

# ── extract_triggers <file> <fn> ────────────────────────────────────────────────
# Prints two lines describing the CONDITIONAL guards for the merged-block tail:
#   PARTNER:<class>   TIMESTAMP:<class>
# where <class> is the normalized predicate kind. We require:
#   PARTNER  guarded by a NON-ZERO partner_subset_hash test (is_zero_hash_ /
#            != zero)  -> class NONZERO_PSH
#   TIMESTAMP guarded by a NON-EMPTY creator_proposer_times test (!...empty())
#            -> class NONEMPTY_PT
# The two binaries spell the partner guard differently (producer:
# `!is_zero_hash_(b.partner_subset_hash)`; light: `b.partner_subset_hash != zero`)
# yet both mean "non-zero", so both normalize to NONZERO_PSH and compare equal.
extract_triggers() {
  local file="$1" fn="$2"
  awk -v fn="$fn" '
    BEGIN { inreg = 0; psh = "NONE"; pt = "NONE" }
    !inreg && fn == "producer" && /Hash +compute_block_digest\(const +Block& +b\) +\{/ { inreg = 1; next }
    !inreg && fn == "light"    && /Hash +light_compute_block_digest\(const +determ::chain::Block& +b\) +\{/ { inreg = 1; next }
    inreg {
      line = $0
      sub(/\/\/.*/, "", line)
      gsub(/[ \t]+/, " ", line)
      # partner_subset_hash non-zero guard — accept either spelling.
      if (line ~ /if *\( *!is_zero_hash_\(b\.partner_subset_hash\) *\)/) psh = "NONZERO_PSH"
      else if (line ~ /if *\( *b\.partner_subset_hash *!= *zero *\)/)    psh = "NONZERO_PSH"
      else if (line ~ /partner_subset_hash/ && line ~ /if *\(/)          psh = "PSH_OTHER"
      # creator_proposer_times non-empty guard.
      if (line ~ /if *\( *!b\.creator_proposer_times\.empty\(\) *\)/)    pt = "NONEMPTY_PT"
      else if (line ~ /creator_proposer_times/ && line ~ /if *\(/)       pt = "PT_OTHER"
      if (line ~ /\.finalize\(\)/) exit
    }
    END { printf "PARTNER:%s TIMESTAMP:%s\n", psh, pt }
  ' "$file"
}

# ── remove_tokens <seq> <tokens-to-remove> ──────────────────────────────────────
# Delete each whitespace-token in $2 from the sequence $1 (one occurrence each,
# order-preserving) and print the remainder. Used to derive "producer minus the
# three F2 roots" for the load-bearing cross-site equality.
remove_tokens() {
  local seq="$1" rm="$2" t
  for t in $rm; do
    # Remove the FIRST occurrence of token t (whole-word) from seq.
    seq=$(printf '%s\n' "$seq" | awk -v t="$t" '{
      out=""; done=0;
      for (i=1;i<=NF;i++){
        if (!done && $i==t){ done=1; continue }
        out = (out=="" ? $i : out" "$i)
      }
      print out
    }')
  done
  printf '%s' "$seq"
}

# ── SELFTEST mode (SELFTEST=1) ──────────────────────────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: cross-binary block-digest extractor + cross-site liveness ==="
  ST_FAIL=0

  # st_seq: feed a C++ snippet on stdin through extract_tokens in <fn> mode and
  # assert the reduced sequence == <want>.
  st_seq() {
    local label="$1" fn="$2" want="$3" got
    got=$(extract_tokens /dev/stdin "$fn")
    if [ "$got" = "$want" ]; then echo "  ok:  $label -> [$got]"
    else
      echo "  bad: $label" >&2
      echo "       want: [$want]" >&2
      echo "       got:  [$got]" >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
  }

  # st_f2_presence: mirror the production guard's belt-and-suspenders F2 presence
  # check — producer MUST contain all three F2 root tokens; light MUST contain
  # none. Returns RED (violation) if either invariant breaks. This is the
  # mechanism that catches a producer that drops an F2 root (the cross-site
  # remove_tokens equality cannot: removing an already-absent token is a no-op,
  # so producer-minus-F2 would collapse to the light seq and falsely agree).
  st_f2_presence() {
    local label="$1" pseq="$2" lseq="$3" red=0 t
    for t in $F2_ROOTS; do
      case " $pseq " in *" $t "*) : ;; *) red=1 ;; esac      # producer missing -> RED
      case " $lseq " in *" $t "*) red=1 ;; *) : ;; esac      # light binds      -> RED
    done
    if [ "$red" -eq 1 ]; then echo "  ok:  $label -> RED (F2 presence invariant violated, as required)"
    else
      echo "  bad: $label produced no F2-presence violation — drift NOT detected!" >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
  }

  # st_crosssite: given a producer seq and a light seq (as strings), assert that
  # the cross-site rule (light == producer minus the three F2 roots) DIVERGES
  # (i.e. would be flagged RED). $3 = "RED" means we expect divergence.
  st_crosssite() {
    local label="$1" pseq="$2" lseq="$3" pminus
    pminus=$(remove_tokens "$pseq" "$F2_ROOTS")
    if [ "$pminus" = "$lseq" ]; then
      # Agreement — only OK for the canonical-sanity pairing.
      if [ "$label" = "crosssite-sanity" ]; then
        echo "  ok:  $label -> producer-minus-F2 == light  [$lseq]"
      else
        echo "  bad: $label produced AGREEMENT — drift NOT detected!" >&2
        echo "       producer-minus-F2: [$pminus]" >&2
        echo "       light:             [$lseq]" >&2
        ST_FAIL=$((ST_FAIL + 1))
      fi
    else
      if [ "$label" = "crosssite-sanity" ]; then
        echo "  bad: crosssite-sanity DIVERGED — extractor or rule is wrong!" >&2
        echo "       producer-minus-F2: [$pminus]" >&2
        echo "       light:             [$lseq]" >&2
        ST_FAIL=$((ST_FAIL + 1))
      else
        echo "  ok:  $label -> RED (producer-minus-F2 != light, as required)"
      fi
    fi
  }

  # (0a) canonical producer snippet reduces to the canonical producer seq.
  st_seq "producer-sanity" producer "$PRODUCER_SEQ" <<'EOF'
Hash compute_block_digest(const Block& b) {
    SHA256Builder h;
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    if (!b.inbound_receipts.empty()) {
        std::vector<Hash> ikeys;
        h.append(compute_view_root(ikeys));
    }
    if (any_nonzero(b.creator_view_eq_roots)) {
        std::vector<Hash> ekeys;
        h.append(compute_view_root(ekeys));
    }
    if (any_nonzero(b.creator_view_abort_roots)) {
        std::vector<Hash> akeys;
        h.append(compute_view_root(akeys));
    }
    if (!is_zero_hash_(b.partner_subset_hash)) {
        h.append(b.partner_subset_hash);
    }
    if (!b.creator_proposer_times.empty()) {
        h.append(b.timestamp);
    }
    return h.finalize();
}
EOF

  # (0b) canonical light snippet reduces to the canonical light seq.
  st_seq "light-sanity" light "$LIGHT_SEQ" <<'EOF'
Hash light_compute_block_digest(const determ::chain::Block& b) {
    determ::crypto::SHA256Builder h;
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    Hash zero{};
    if (b.partner_subset_hash != zero) {
        h.append(b.partner_subset_hash);
    }
    if (!b.creator_proposer_times.empty()) {
        h.append(b.timestamp);
    }
    return h.finalize();
}
EOF

  # (0c) cross-site sanity: producer-minus-F2 must equal light.
  st_crosssite "crosssite-sanity" "$PRODUCER_SEQ" "$LIGHT_SEQ"

  # (1) merged-block TAIL SWAPPED in light (TIMESTAMP before PARTNER_SUBSET).
  #     The reduced light seq differs from canonical -> producer-minus-F2 != light -> RED.
  L_SWAP=$(extract_tokens /dev/stdin light <<'EOF'
Hash light_compute_block_digest(const determ::chain::Block& b) {
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    if (!b.creator_proposer_times.empty()) {
        h.append(b.timestamp);
    }
    if (b.partner_subset_hash != zero) {
        h.append(b.partner_subset_hash);
    }
    return h.finalize();
}
EOF
)
  st_crosssite "tail-swapped-in-light" "$PRODUCER_SEQ" "$L_SWAP"

  # (2) producer MISSING an F2 root (drops ABORT_ROOT). Caught by TWO production
  #     mechanisms: (a) producer seq != canonical PRODUCER_SEQ, and (b) the F2
  #     presence check (producer must contain all three F2 tokens). NOTE: the
  #     cross-site remove_tokens equality does NOT catch this — removing an
  #     already-absent ABORT_ROOT is a no-op, so producer-minus-F2 would collapse
  #     to the light seq and falsely AGREE. This case proves the presence check
  #     is the load-bearing detector for a dropped producer F2 root.
  P_MISS=$(extract_tokens /dev/stdin producer <<'EOF'
Hash compute_block_digest(const Block& b) {
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    if (!b.inbound_receipts.empty()) {
        std::vector<Hash> ikeys;
        h.append(compute_view_root(ikeys));
    }
    if (any_nonzero(b.creator_view_eq_roots)) {
        std::vector<Hash> ekeys;
        h.append(compute_view_root(ekeys));
    }
    if (!is_zero_hash_(b.partner_subset_hash)) {
        h.append(b.partner_subset_hash);
    }
    if (!b.creator_proposer_times.empty()) {
        h.append(b.timestamp);
    }
    return h.finalize();
}
EOF
)
  # First, the producer seq itself must NOT equal the canonical PRODUCER_SEQ.
  if [ "$P_MISS" != "$PRODUCER_SEQ" ]; then
    echo "  ok:  producer-missing-abort-root -> producer seq != canonical (drift seen) [$P_MISS]"
  else
    echo "  bad: producer-missing-abort-root produced canonical seq — drift NOT detected!" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  # The detector for a dropped producer F2 root is the F2 presence check
  # (NOT the cross-site remove_tokens equality — see the case comment above).
  st_f2_presence "producer-missing-abort-root" "$P_MISS" "$LIGHT_SEQ"

  # (3) light ACCIDENTALLY binds an F2 root (INBOUND_ROOT present in light).
  #     light seq gains INBOUND_ROOT -> producer-minus-F2 (which has NO inbound)
  #     != light -> RED. Also light seq != canonical LIGHT_SEQ.
  L_F2=$(extract_tokens /dev/stdin light <<'EOF'
Hash light_compute_block_digest(const determ::chain::Block& b) {
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    if (!b.inbound_receipts.empty()) {
        std::vector<Hash> ikeys;
        h.append(compute_view_root(ikeys));
    }
    if (b.partner_subset_hash != zero) {
        h.append(b.partner_subset_hash);
    }
    if (!b.creator_proposer_times.empty()) {
        h.append(b.timestamp);
    }
    return h.finalize();
}
EOF
)
  if [ "$L_F2" != "$LIGHT_SEQ" ]; then
    echo "  ok:  light-binds-inbound-root -> light seq != canonical (drift seen) [$L_F2]"
  else
    echo "  bad: light-binds-inbound-root produced canonical light seq — drift NOT detected!" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  # Caught by BOTH detectors: cross-site equality (light has an extra token) AND
  # the F2 presence check (light must bind NONE of the F2 roots).
  st_crosssite   "light-binds-inbound-root" "$PRODUCER_SEQ" "$L_F2"
  st_f2_presence "light-binds-inbound-root" "$PRODUCER_SEQ" "$L_F2"

  # (4) dropped CORE field (DELAY_SEED) in producer -> producer seq != canonical
  #     AND producer-minus-F2 != light -> RED on both checks.
  P_DROP=$(extract_tokens /dev/stdin producer <<'EOF'
Hash compute_block_digest(const Block& b) {
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    if (!b.inbound_receipts.empty()) {
        std::vector<Hash> ikeys;
        h.append(compute_view_root(ikeys));
    }
    if (any_nonzero(b.creator_view_eq_roots)) {
        std::vector<Hash> ekeys;
        h.append(compute_view_root(ekeys));
    }
    if (any_nonzero(b.creator_view_abort_roots)) {
        std::vector<Hash> akeys;
        h.append(compute_view_root(akeys));
    }
    if (!is_zero_hash_(b.partner_subset_hash)) {
        h.append(b.partner_subset_hash);
    }
    if (!b.creator_proposer_times.empty()) {
        h.append(b.timestamp);
    }
    return h.finalize();
}
EOF
)
  if [ "$P_DROP" != "$PRODUCER_SEQ" ]; then
    echo "  ok:  producer-dropped-delay-seed -> producer seq != canonical (drift seen) [$P_DROP]"
  else
    echo "  bad: producer-dropped-delay-seed produced canonical seq — drift NOT detected!" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  st_crosssite "producer-dropped-delay-seed" "$P_DROP" "$LIGHT_SEQ"

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_block_digest_xbinary_parity SELFTEST (extractor + cross-site rule flag all drift classes: tail-swap, missing-F2-root, light-binds-F2, dropped-core)"
    exit 0
  else
    echo "  FAIL: test_block_digest_xbinary_parity SELFTEST ($ST_FAIL self-test failure(s) — the guard is NOT live)"
    exit 1
  fi
fi

echo "=== block-digest CROSS-BINARY parity guard (producer.cpp vs light/verify.cpp; static FA1 complement) ==="

PROD_FILE=src/node/producer.cpp
LIGHT_FILE=light/verify.cpp

# ── Producer (ground truth) ─────────────────────────────────────────────────────
PSEQ=""
if [ ! -f "$PROD_FILE" ]; then
  bad "$PROD_FILE — MISSING (ground-truth digest site)"
else
  PSEQ=$(extract_tokens "$PROD_FILE" producer)
  if [ "$PSEQ" = "$PRODUCER_SEQ" ]; then
    ok "producer.cpp::compute_block_digest -> [$PSEQ]"
  else
    bad "producer.cpp::compute_block_digest append-sequence DRIFT"
    echo "       want: [$PRODUCER_SEQ]" >&2
    echo "       got:  [$PSEQ]" >&2
  fi
fi

# ── Light (mirror) ──────────────────────────────────────────────────────────────
LSEQ=""
if [ ! -f "$LIGHT_FILE" ]; then
  bad "$LIGHT_FILE — MISSING (mirror digest site)"
else
  LSEQ=$(extract_tokens "$LIGHT_FILE" light)
  if [ "$LSEQ" = "$LIGHT_SEQ" ]; then
    ok "light/verify.cpp::light_compute_block_digest -> [$LSEQ]  (3 F2 view roots intentionally omitted)"
  else
    bad "light/verify.cpp::light_compute_block_digest append-sequence DRIFT"
    echo "       want: [$LIGHT_SEQ]  (producer minus inbound/eq/abort roots)" >&2
    echo "       got:  [$LSEQ]" >&2
  fi
fi

# ── LOAD-BEARING cross-site assertion ───────────────────────────────────────────
# light == producer with EXACTLY {INBOUND_ROOT, EQ_ROOT, ABORT_ROOT} removed and
# NOTHING ELSE changed. We delete those three tokens from the LIVE producer seq
# and require byte-equality with the LIVE light seq. This proves the conditional
# merged-block tail (PARTNER_SUBSET immediately before TIMESTAMP) is in the SAME
# relative order in BOTH and that the only divergence is the documented F2-root
# omission.
if [ -n "$PSEQ" ] && [ -n "$LSEQ" ]; then
  PSEQ_NO_F2=$(remove_tokens "$PSEQ" "$F2_ROOTS")
  if [ "$PSEQ_NO_F2" = "$LSEQ" ]; then
    ok "cross-site: light == producer minus {INBOUND_ROOT,EQ_ROOT,ABORT_ROOT} (sole allowed diff; tail order identical)"
  else
    bad "cross-site: light differs from producer by MORE than the three F2 view roots"
    echo "       producer minus F2: [$PSEQ_NO_F2]" >&2
    echo "       light:             [$LSEQ]" >&2
  fi
  # Belt-and-suspenders: the three removed tokens must be EXACTLY the F2 set —
  # i.e. producer contains all three and light contains none of them.
  for t in $F2_ROOTS; do
    case " $PSEQ " in *" $t "*) : ;; *) bad "cross-site: producer is MISSING F2 root token [$t]";; esac
    case " $LSEQ " in *" $t "*) bad "cross-site: light UNEXPECTEDLY binds F2 root token [$t]";; *) : ;; esac
  done
fi

# ── Conditional-trigger parity (merged-block tail) ──────────────────────────────
# Both binaries must gate PARTNER_SUBSET on a non-zero partner_subset_hash test
# and TIMESTAMP on a non-empty creator_proposer_times test. Producer + light
# spell the partner guard differently but both mean "non-zero"; both normalize
# to NONZERO_PSH so they compare equal.
EXPECT_TRIG="PARTNER:NONZERO_PSH TIMESTAMP:NONEMPTY_PT"
if [ -f "$PROD_FILE" ]; then
  PTRIG=$(extract_triggers "$PROD_FILE" producer)
  if [ "$PTRIG" = "$EXPECT_TRIG" ]; then
    ok "trigger: producer gates PARTNER on non-zero PSH, TIMESTAMP on non-empty proposer_times"
  else
    bad "trigger: producer conditional guards DRIFT"
    echo "       want: [$EXPECT_TRIG]" >&2
    echo "       got:  [$PTRIG]" >&2
  fi
fi
if [ -f "$LIGHT_FILE" ]; then
  LTRIG=$(extract_triggers "$LIGHT_FILE" light)
  if [ "$LTRIG" = "$EXPECT_TRIG" ]; then
    ok "trigger: light gates PARTNER on non-zero PSH, TIMESTAMP on non-empty proposer_times (matches producer)"
  else
    bad "trigger: light conditional guards DRIFT (must match producer's non-zero/non-empty gating)"
    echo "       want: [$EXPECT_TRIG]" >&2
    echo "       got:  [$LTRIG]" >&2
  fi
fi

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_block_digest_xbinary_parity (producer.cpp + light/verify.cpp agree; sole diff = 3 omitted F2 view roots; merged-block tail order + triggers identical)"
  exit 0
else
  echo "  FAIL: test_block_digest_xbinary_parity ($VIOLATIONS parity violation(s) — a block-digest copy has drifted)"
  exit 1
fi
