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
#       The light client re-derives the digest to verify each committee
#       member's Ed25519 sig. As of F-7 it is a FULL byte-for-byte mirror of
#       (A): it binds EVERY field (A) binds, including the three F2 view roots,
#       on the SAME data-driven conditions. The gates are data-driven, so when
#       (B) is fed an rpc_headers-STRIPPED header the F2 collections are empty /
#       view roots zero and the digest collapses to the v1 core; when fed a
#       FULL block (the walk's F-7 fallback re-fetches the body for any header
#       whose stripped digest fails to verify) the collections are populated and
#       (B) reproduces (A) exactly — so the light client now VERIFIES F2 /
#       cross-shard blocks instead of fail-closing on them.
#
#       [HISTORY: pre-F-7, (B) INTENTIONALLY OMITTED the three F2 roots and
#       fail-closed on cross-shard blocks. F-7 completed the mirror; this guard
#       was flipped from "(B) == (A) minus the F2 roots" to "(B) == (A)".]
#
# THE GAP this guard closes: nothing else pins the (B)==(A) agreement at the
# SOURCE level. A one-line edit to either copy — swapping partner_subset_hash/
# timestamp, dropping/adding a field, changing a trigger (is_zero vs empty),
# mis-ordering the F2 roots vs the tail — would drift the committee-sig digest
# for some block class with NO red test. This is the block-digest analog of
# tools/test_signing_bytes_source_parity.sh. Runtime coverage
# (tools/test_light_verify_block_sigs.sh) cross-checks (B)==(A) end-to-end ONLY
# for block 1 (a non-merged, non-F2 block), so the conditional appendages are
# never runtime-cross-checked between the two implementations; this guard does
# it statically over the full append set.
#
# HOW IT WORKS
# ------------
# We isolate each function's body by NAME anchor (drift-robust; no line nums).
# EQV-height-bind: the digest is a TWO-LEVEL hash — an outer compose
# SHA256("DTM-BLKDIG-v2" || index u64 BE || body_root) over a BODY function
# that binds everything else. The windows anchor on the BODY functions (the
# leading index append moved up into the compose, which is pinned separately
# by the tag-agreement check below):
#   producer: `Hash compute_block_digest_body(const Block& b) {`        .. `return h.finalize();`
#   light:    `Hash light_compute_block_digest_body(const determ::chain::Block& b) {` .. `return h.finalize();`
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
# Both binaries spell these appends identically (light re-implements the four
# F2 helpers — hash_*/compute_view_root — as file-local statics with the same
# names), so the SAME extractor token-maps both.
#
# ASSERTIONS
#   * producer seq EXACTLY (no INDEX — it lives in the outer compose):
#       PREV_HASH TX_ROOT DELAY_SEED CONSENSUS_MODE BFT_PROPOSER \
#       CREATORS TX_LISTS ED_SIGS DH_INPUTS INBOUND_ROOT EQ_ROOT ABORT_ROOT \
#       PARTNER_SUBSET TIMESTAMP
#   * EQV-height-bind tag agreement: the outer compose of BOTH files must
#     carry the byte-identical "DTM-BLKDIG-v2" domain tag.
#   * light seq EXACTLY EQUAL to the producer seq (full F-7 parity — every
#     field, same order, including all three F2 roots).
#   * LOAD-BEARING cross-site check: the LIVE producer seq == the LIVE light
#     seq, token-for-token. This proves the two consensus-critical copies bind
#     the identical field set in the identical order — any divergence (a moved
#     tail, an added/dropped field, a reordered F2 root) is RED.
#   * F2-presence: BOTH binaries must contain all three F2 root tokens
#     {INBOUND_ROOT, EQ_ROOT, ABORT_ROOT} (post-F-7 light binds them too).
#   * CONDITIONAL-TRIGGER parity: both gate PARTNER_SUBSET on a non-zero
#     partner_subset_hash test and TIMESTAMP on a non-empty creator_proposer_
#     times test (the guard expressions are grepped + classed).
#
# LIVENESS (SELFTEST=1)
# ---------------------
# `SELFTEST=1 bash tools/test_block_digest_xbinary_parity.sh` feeds synthetic
# DRIFTED snippets through the SAME extractor and the SAME cross-site logic and
# asserts each drift is flagged RED. Covers: (1) partner/timestamp tail SWAPPED
# in light; (2) a missing F2 root in producer; (3) a missing F2 root in LIGHT
# (the post-F-7 failure mode — light must now bind all three); (4) a dropped
# core field. The self-test creates NO files and modifies NO source — it runs
# entirely on in-memory heredoc snippets.
#
# Pure read-only SOURCE check (awk/grep/sed over the two .cpp files only). Needs
# NO determ binary, never SKIPs, does NOT source tools/common.sh. Deterministic
# + offline. run_all.sh auto-discovers it (tools/test_*.sh) and reads the single
# terminal `  PASS:` / `  FAIL:` marker.
#
# Exit 0 = the two copies are byte-parity equal; exit 1 = drift.
set -u
cd "$(dirname "$0")/.."

# Post-F-7: light binds the SAME append set as producer (full byte-parity).
# A6 (2026-07-09): + the trailing conditional SIG_FORM (signature_form bound
# when non-zero — the §7.5.1 discriminator). D3.4 (2026-07-13): + the trailing
# conditional ELIGIBLE_COUNT (the source shard's eligible_count self-report,
# bound when non-zero — §S-036). D3.5a (2026-07-13): + the trailing conditional
# SHARD_TIP_RECORDS (the beacon's shard-tip-record set root, bound when non-empty
# — §S-036; 18 tokens).
# D3.5e-6 (2026-07-14): + SOURCE_SHARD_ID (the producing shard's identity, bound
# alongside ELIGIBLE_COUNT under the same EXTENDED-source gate — §S-036 Layer 2;
# closes same-region cross-shard tip replay; 19 tokens).
PRODUCER_SEQ="PREV_HASH TX_ROOT DELAY_SEED CONSENSUS_MODE BFT_PROPOSER CREATORS TX_LISTS ED_SIGS DH_INPUTS INBOUND_ROOT EQ_ROOT ABORT_ROOT PARTNER_SUBSET TIMESTAMP SIG_FORM ELIGIBLE_COUNT SOURCE_SHARD_ID SHARD_TIP_RECORDS"
LIGHT_SEQ="$PRODUCER_SEQ"
# The three F2 view-root tokens BOTH binaries must contain.
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
#   fn=producer  begin = `Hash compute_block_digest_body(const Block& b) {`
#   fn=light     begin = `Hash light_compute_block_digest_body(const ... Block& b) {`
#
# All regexes are LITERAL inside the awk program (NOT passed via -v, which would
# mangle backslash escapes). Only the plain `fn` string is passed via -v.
# Anchoring on the function NAME (not a line number) keeps this drift-robust.
extract_tokens() {
  local file="$1" fn="$2"
  awk -v fn="$fn" '
    BEGIN { inreg = 0 }
    # Enter the body at the begin anchor (the function signature opening brace).
    !inreg && fn == "producer" && /Hash +compute_block_digest_body\(const +Block& +b\) +\{/ { inreg = 1; next }
    !inreg && fn == "light"    && /Hash +light_compute_block_digest_body\(const +determ::chain::Block& +b\) +\{/ { inreg = 1; next }
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

      # ── F2 view roots (BOTH binaries post-F-7) — disambiguated by keys vec ──
      # h.append(compute_view_root(ikeys / ekeys / akeys)). The keys-vector name
      # is the intrinsic, order-stable signal of WHICH root is bound.
      else if (line ~ /\.append\(compute_view_root\(ikeys\)\)/) print "INBOUND_ROOT"
      else if (line ~ /\.append\(compute_view_root\(ekeys\)\)/) print "EQ_ROOT"
      else if (line ~ /\.append\(compute_view_root\(akeys\)\)/) print "ABORT_ROOT"
      # D3.5a §S-036: the beacon shard-tip-record set root, disambiguated by its
      # keys vector `tkeys` (like ikeys/ekeys/akeys). MUST precede the
      # VIEW_ROOT_UNKNOWN catch below, else it would be flagged as drift.
      else if (line ~ /\.append\(compute_view_root\(tkeys\)\)/) print "SHARD_TIP_RECORDS"
      # Any OTHER compute_view_root append (renamed keys vec) must NOT silently
      # vanish — flag it so a reordered/renamed root surfaces as drift.
      else if (line ~ /\.append\(compute_view_root\(/) print "VIEW_ROOT_UNKNOWN"

      # ── merged-block conditional tail (BOTH binaries) ──
      else if (line ~ /\.append\(b\.partner_subset_hash\)/) print "PARTNER_SUBSET"
      else if (line ~ /\.append\(b\.timestamp\)/)           print "TIMESTAMP"
      # A6 §7.5.1: the signature_form discriminator (bound when non-zero).
      else if (line ~ /\.append\(static_cast<uint8_t>\(b\.signature_form\)\)/) print "SIG_FORM"
      # D3.4 §S-036: the source shard eligible_count self-report (bound when
      # non-zero; widened to u64 to match the canonical field encoding).
      else if (line ~ /\.append\(static_cast<uint64_t>\(b\.eligible_count\)\)/) print "ELIGIBLE_COUNT"
      # D3.5e-6 §S-036: the source shard identity, bound alongside eligible_count
      # under the SAME EXTENDED-source gate (u64-widened to match). Closes the
      # same-region cross-shard tip replay.
      else if (line ~ /\.append\(static_cast<uint64_t>\(b\.source_shard_id\)\)/) print "SOURCE_SHARD_ID"

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
    !inreg && fn == "producer" && /Hash +compute_block_digest_body\(const +Block& +b\) +\{/ { inreg = 1; next }
    !inreg && fn == "light"    && /Hash +light_compute_block_digest_body\(const +determ::chain::Block& +b\) +\{/ { inreg = 1; next }
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

# ── extract_subhasher_appends <file> <fnname> ───────────────────────────────────
# Prints the ordered, NORMALIZED b.append(...) argument sequence for ONE F2
# sub-hasher body — hash_abort_event (register ADC-3) / hash_equivocation_event /
# hash_cross_shard_receipt. These three feed the akeys/ekeys/ikeys view roots the
# block digest (checked above) binds, and each is RE-IMPLEMENTED in BOTH
# producer.cpp (ground truth) AND light/verify.cpp (the mirror that recomputes
# those roots to verify committee sigs). The block-digest guard above reduces each
# whole view root to ONE token (ABORT_ROOT/EQ_ROOT/INBOUND_ROOT) and therefore
# does NOT see a sub-hasher's internal field order — so a field reorder / add /
# drop / recast in EITHER copy silently drifts the committee-signed view root for
# cross-shard / reconciled blocks, with NO runtime red (the block-1 runtime
# cross-check never populates the F2 collections). This closes that gap by
# pinning the two copies of each sub-hasher EQUAL, append-for-append.
#
# Each `b.append(ARG)` is reduced to ARG with (a) // comments stripped, (b) all
# whitespace removed, (c) the determ:: / chain:: / std:: namespace qualifiers
# stripped — the ONLY spelling difference between the two copies (producer
# `chain::canonical_...` vs light `determ::chain::canonical_...`). The domain-tag
# string append survives normalization intact, so a copy that changed its tag is
# caught. Anchoring on the fn NAME at column 0 keeps it drift-robust and skips the
# indented call sites; the arg-type spelling lives in the signature, not an
# append, so it never enters the token stream. Removing the leading `.append(` and
# the trailing `);` leaves ARG's own balanced parens (static_cast<...>(...),
# canonical_...(...), sig.data(), sig.size()) intact.
extract_subhasher_appends() {
  local file="$1" fn="$2"
  awk -v fn="$fn" '
    BEGIN { inreg = 0 }
    !inreg && $0 ~ ("^Hash +" fn "\\(") { inreg = 1; next }
    inreg {
      line = $0
      sub(/\/\/.*/, "", line)                 # strip // comments
      gsub(/[ \t]+/, "", line)                # remove ALL whitespace
      if (line ~ /\.append\(/) {
        arg = line
        sub(/^.*\.append\(/, "", arg)         # drop through the (single) .append(
        sub(/\);.*$/, "", arg)                # drop the trailing );  -> ARG remains
        gsub(/determ::/, "", arg)             # normalize namespaces (order matters:
        gsub(/chain::/,  "", arg)             #   determ::chain:: -> chain:: -> "")
        gsub(/std::/,    "", arg)
        print arg
      }
      if (line ~ /\.finalize\(\)/) exit       # end of this sub-hasher body
    }
  ' "$file" | tr "\n" " " | sed -E "s/ +/ /g; s/^ //; s/ $//"
}

# ── check_subhasher <fnname> <domain-tag> ───────────────────────────────────────
# Assert the producer + light copies of one F2 sub-hasher have the IDENTICAL
# normalized append sequence, that sequence is NON-EMPTY (anti-vacuity: a missed
# anchor yields "" and ""=="" would false-pass), and it contains the expected
# domain tag (binds WHICH sub-hasher + catches a changed tag).
check_subhasher() {
  local fn="$1" tag="$2" pseq lseq
  pseq=$(extract_subhasher_appends "$PROD_FILE" "$fn")
  lseq=$(extract_subhasher_appends "$LIGHT_FILE" "$fn")
  if [ -z "$pseq" ]; then bad "sub-hasher $fn: producer body not found / no appends (anchor drift)"; return; fi
  if [ -z "$lseq" ]; then bad "sub-hasher $fn: light body not found / no appends (anchor drift)"; return; fi
  case " $pseq " in *"$tag"*) : ;; *) bad "sub-hasher $fn: producer missing domain tag [$tag]" ;; esac
  case " $lseq " in *"$tag"*) : ;; *) bad "sub-hasher $fn: light missing domain tag [$tag]" ;; esac
  if [ "$pseq" = "$lseq" ]; then
    ok "sub-hasher $fn: producer == light append sequence [$pseq]"
  else
    bad "sub-hasher $fn: producer != light (F2 sub-hasher drift — the committee-signed view root would diverge)"
    echo "       producer: [$pseq]" >&2
    echo "       light:    [$lseq]" >&2
  fi
}

# ── SELFTEST mode (SELFTEST=1) ──────────────────────────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: cross-binary block-digest extractor + full-parity cross-site liveness ==="
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

  # st_f2_presence: post-F-7 BOTH copies must contain all three F2 root tokens.
  # Returns RED (violation) if EITHER copy is missing any F2 root. This is the
  # mechanism that catches a copy that drops an F2 root.
  st_f2_presence() {
    local label="$1" pseq="$2" lseq="$3" red=0 t
    for t in $F2_ROOTS; do
      case " $pseq " in *" $t "*) : ;; *) red=1 ;; esac      # producer missing -> RED
      case " $lseq " in *" $t "*) : ;; *) red=1 ;; esac      # light missing    -> RED
    done
    if [ "$red" -eq 1 ]; then echo "  ok:  $label -> RED (F2 presence invariant violated, as required)"
    else
      echo "  bad: $label produced no F2-presence violation — drift NOT detected!" >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
  }

  # st_crosssite: given a producer seq and a light seq (as strings), assert that
  # the full-parity rule (light == producer EXACTLY) DIVERGES (is flagged RED).
  # $label == "crosssite-sanity" is the one pairing that must AGREE.
  st_crosssite() {
    local label="$1" pseq="$2" lseq="$3"
    if [ "$pseq" = "$lseq" ]; then
      if [ "$label" = "crosssite-sanity" ]; then
        echo "  ok:  $label -> producer == light  [$lseq]"
      else
        echo "  bad: $label produced AGREEMENT — drift NOT detected!" >&2
        echo "       producer: [$pseq]" >&2
        echo "       light:    [$lseq]" >&2
        ST_FAIL=$((ST_FAIL + 1))
      fi
    else
      if [ "$label" = "crosssite-sanity" ]; then
        echo "  bad: crosssite-sanity DIVERGED — extractor or rule is wrong!" >&2
        echo "       producer: [$pseq]" >&2
        echo "       light:    [$lseq]" >&2
        ST_FAIL=$((ST_FAIL + 1))
      else
        echo "  ok:  $label -> RED (producer != light, as required)"
      fi
    fi
  }

  # (0a) canonical producer snippet reduces to the canonical producer seq.
  st_seq "producer-sanity" producer "$PRODUCER_SEQ" <<'EOF'
Hash compute_block_digest_body(const Block& b) {
    SHA256Builder h;
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
    if (b.signature_form != 0) {
        h.append(static_cast<uint8_t>(b.signature_form));
    }
    if (b.eligible_count != 0) {
        h.append(static_cast<uint64_t>(b.eligible_count));
        h.append(static_cast<uint64_t>(b.source_shard_id));
    }
    if (!b.shard_tip_records.empty()) {
        std::vector<Hash> tkeys;
        for (auto& r : b.shard_tip_records) tkeys.push_back(hash_shard_tip(r));
        h.append(compute_view_root(tkeys));
    }
    return h.finalize();
}
EOF

  # (0b) canonical light snippet (post-F-7, with the F2 branch) reduces to the
  #      canonical light seq — which is now EQUAL to the producer seq.
  st_seq "light-sanity" light "$LIGHT_SEQ" <<'EOF'
Hash light_compute_block_digest_body(const determ::chain::Block& b) {
    determ::crypto::SHA256Builder h;
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
        for (auto& r : b.inbound_receipts) ikeys.push_back(hash_cross_shard_receipt(r));
        h.append(compute_view_root(ikeys));
    }
    auto any_nonzero = [](const std::vector<Hash>& v) { return false; };
    if (any_nonzero(b.creator_view_eq_roots)) {
        std::vector<Hash> ekeys;
        for (auto& e : b.equivocation_events) ekeys.push_back(hash_equivocation_event(e));
        h.append(compute_view_root(ekeys));
    }
    if (any_nonzero(b.creator_view_abort_roots)) {
        std::vector<Hash> akeys;
        for (auto& a : b.abort_events) akeys.push_back(hash_abort_event(a));
        h.append(compute_view_root(akeys));
    }
    Hash zero{};
    if (b.partner_subset_hash != zero) {
        h.append(b.partner_subset_hash);
    }
    if (!b.creator_proposer_times.empty()) {
        h.append(b.timestamp);
    }
    if (b.signature_form != 0) {
        h.append(static_cast<uint8_t>(b.signature_form));
    }
    if (b.eligible_count != 0) {
        h.append(static_cast<uint64_t>(b.eligible_count));
        h.append(static_cast<uint64_t>(b.source_shard_id));
    }
    if (!b.shard_tip_records.empty()) {
        std::vector<Hash> tkeys;
        for (auto& r : b.shard_tip_records) tkeys.push_back(hash_shard_tip(r));
        h.append(compute_view_root(tkeys));
    }
    return h.finalize();
}
EOF

  # (0c) cross-site sanity: producer == light (full parity).
  st_crosssite "crosssite-sanity" "$PRODUCER_SEQ" "$LIGHT_SEQ"

  # (1) merged-block TAIL SWAPPED in light (TIMESTAMP before PARTNER_SUBSET).
  #     The reduced light seq differs from canonical -> producer != light -> RED.
  L_SWAP=$(extract_tokens /dev/stdin light <<'EOF'
Hash light_compute_block_digest_body(const determ::chain::Block& b) {
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

  # (2) producer MISSING an F2 root (drops ABORT_ROOT). Caught by (a) producer
  #     seq != canonical PRODUCER_SEQ, (b) cross-site (producer != light), and
  #     (c) the F2 presence check (producer must contain all three F2 tokens).
  P_MISS=$(extract_tokens /dev/stdin producer <<'EOF'
Hash compute_block_digest_body(const Block& b) {
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
  if [ "$P_MISS" != "$PRODUCER_SEQ" ]; then
    echo "  ok:  producer-missing-abort-root -> producer seq != canonical (drift seen) [$P_MISS]"
  else
    echo "  bad: producer-missing-abort-root produced canonical seq — drift NOT detected!" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  st_crosssite   "producer-missing-abort-root" "$P_MISS" "$LIGHT_SEQ"
  st_f2_presence "producer-missing-abort-root" "$P_MISS" "$LIGHT_SEQ"

  # (3) light MISSING an F2 root (drops INBOUND_ROOT) — the post-F-7 failure
  #     mode. light seq != canonical AND producer != light -> RED on both, and
  #     the F2 presence check fires (light must bind all three).
  L_MISS=$(extract_tokens /dev/stdin light <<'EOF'
Hash light_compute_block_digest_body(const determ::chain::Block& b) {
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
    if (any_nonzero(b.creator_view_eq_roots)) {
        std::vector<Hash> ekeys;
        h.append(compute_view_root(ekeys));
    }
    if (any_nonzero(b.creator_view_abort_roots)) {
        std::vector<Hash> akeys;
        h.append(compute_view_root(akeys));
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
  if [ "$L_MISS" != "$LIGHT_SEQ" ]; then
    echo "  ok:  light-missing-inbound-root -> light seq != canonical (drift seen) [$L_MISS]"
  else
    echo "  bad: light-missing-inbound-root produced canonical light seq — drift NOT detected!" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  st_crosssite   "light-missing-inbound-root" "$PRODUCER_SEQ" "$L_MISS"
  st_f2_presence "light-missing-inbound-root" "$PRODUCER_SEQ" "$L_MISS"

  # (4) dropped CORE field (DELAY_SEED) in producer -> producer seq != canonical
  #     AND producer != light -> RED on both checks.
  P_DROP=$(extract_tokens /dev/stdin producer <<'EOF'
Hash compute_block_digest_body(const Block& b) {
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

  # ── F2 sub-hasher extractor liveness (ADC-3) ──────────────────────────────────
  # (a) a reordered abort body yields a DIFFERENT normalized sequence than the
  #     canonical (so a producer!=light field-swap drift surfaces RED); (b) the
  #     producer (chain::) and light (determ::chain::) spelling of the SAME body
  #     normalize EQUAL (so ns-qualifier alone is NOT flagged — no false positive).
  # D2-inc3: claims preimage is the canonical binary encoding (domain v2),
  # emitted into a local `enc` and appended as raw bytes. The self-test
  # fixtures mirror the shipped shape.
  ST_SUB_CANON=$(extract_subhasher_appends /dev/stdin hash_abort_event <<'EOF'
Hash hash_abort_event(const chain::AbortEvent& e) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-ABORT-v2"));
    b.append(e.round);
    b.append(e.aborting_node);
    b.append(static_cast<uint64_t>(e.timestamp));
    b.append(e.event_hash);
    auto enc = chain::encode_abort_claims(e.claims);
    b.append(enc.data(), enc.size());
    return b.finalize();
}
EOF
)
  ST_SUB_DRIFT=$(extract_subhasher_appends /dev/stdin hash_abort_event <<'EOF'
Hash hash_abort_event(const determ::chain::AbortEvent& e) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-ABORT-v2"));
    b.append(e.aborting_node);
    b.append(e.round);
    b.append(static_cast<uint64_t>(e.timestamp));
    b.append(e.event_hash);
    auto enc = determ::chain::encode_abort_claims(e.claims);
    b.append(enc.data(), enc.size());
    return b.finalize();
}
EOF
)
  ST_SUB_LIGHT=$(extract_subhasher_appends /dev/stdin hash_abort_event <<'EOF'
Hash hash_abort_event(const determ::chain::AbortEvent& e) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-ABORT-v2"));
    b.append(e.round);
    b.append(e.aborting_node);
    b.append(static_cast<uint64_t>(e.timestamp));
    b.append(e.event_hash);
    auto enc = determ::chain::encode_abort_claims(e.claims);
    b.append(enc.data(), enc.size());
    return b.finalize();
}
EOF
)
  if [ -n "$ST_SUB_CANON" ] && [ "$ST_SUB_CANON" != "$ST_SUB_DRIFT" ]; then
    echo "  ok:  sub-hasher extractor flags a reordered abort field (canon != drift)"
  else
    echo "  bad: sub-hasher extractor did NOT flag a reordered abort field!" >&2
    echo "       canon: [$ST_SUB_CANON]" >&2
    echo "       drift: [$ST_SUB_DRIFT]" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  if [ -n "$ST_SUB_CANON" ] && [ "$ST_SUB_CANON" = "$ST_SUB_LIGHT" ]; then
    echo "  ok:  sub-hasher ns-normalization: chain:: == determ::chain:: spelling (no false positive)"
  else
    echo "  bad: sub-hasher ns-normalization failed (chain:: vs determ::chain:: diverged)!" >&2
    echo "       producer-spelling: [$ST_SUB_CANON]" >&2
    echo "       light-spelling:    [$ST_SUB_LIGHT]" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_block_digest_xbinary_parity SELFTEST (extractor + full-parity rule flag all drift classes: tail-swap, missing-F2-root in producer OR light, dropped-core)"
    exit 0
  else
    echo "  FAIL: test_block_digest_xbinary_parity SELFTEST ($ST_FAIL self-test failure(s) — the guard is NOT live)"
    exit 1
  fi
fi

echo "=== block-digest CROSS-BINARY parity guard (producer.cpp vs light/verify.cpp; static FA1 complement; full F-7 parity) ==="

PROD_FILE=src/node/producer.cpp
LIGHT_FILE=light/verify.cpp

# ── Producer (ground truth) ─────────────────────────────────────────────────────
PSEQ=""
if [ ! -f "$PROD_FILE" ]; then
  bad "$PROD_FILE — MISSING (ground-truth digest site)"
else
  PSEQ=$(extract_tokens "$PROD_FILE" producer)
  if [ "$PSEQ" = "$PRODUCER_SEQ" ]; then
    ok "producer.cpp::compute_block_digest_body -> [$PSEQ]"
  else
    bad "producer.cpp::compute_block_digest_body append-sequence DRIFT"
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
    ok "light/verify.cpp::light_compute_block_digest_body -> [$LSEQ]  (full F-7 parity; all 3 F2 view roots bound)"
  else
    bad "light/verify.cpp::light_compute_block_digest_body append-sequence DRIFT"
    echo "       want: [$LIGHT_SEQ]  (byte-parity with producer)" >&2
    echo "       got:  [$LSEQ]" >&2
  fi
fi

# ── LOAD-BEARING cross-site assertion ───────────────────────────────────────────
# The two consensus-critical copies must bind the IDENTICAL field set in the
# IDENTICAL order — light == producer, token-for-token. Any divergence (moved
# tail, added/dropped field, reordered F2 root) is RED.
if [ -n "$PSEQ" ] && [ -n "$LSEQ" ]; then
  if [ "$PSEQ" = "$LSEQ" ]; then
    ok "cross-site: light == producer (full byte-parity; identical field set + order)"
  else
    bad "cross-site: light differs from producer (the two block-digest copies have drifted)"
    echo "       producer: [$PSEQ]" >&2
    echo "       light:    [$LSEQ]" >&2
  fi
  # Belt-and-suspenders: BOTH copies must contain all three F2 root tokens.
  for t in $F2_ROOTS; do
    case " $PSEQ " in *" $t "*) : ;; *) bad "cross-site: producer is MISSING F2 root token [$t]";; esac
    case " $LSEQ " in *" $t "*) : ;; *) bad "cross-site: light is MISSING F2 root token [$t]";; esac
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

# ── EQV-height-bind: outer-compose tag agreement ────────────────────────────────
# The two-level digest split moved the leading index append into an outer
# compose: digest = SHA256("DTM-BLKDIG-v2" || index u64 BE || body_root).
# The BODY windows above no longer see the tag or the index, so pin the tag
# HERE: it must appear inside the compose function of BOTH files (a copy that
# changed / dropped its tag would diverge every committee-signed digest).
compose_has_tag() {
  local file="$1" fn="$2"
  awk -v fn="$fn" '
    BEGIN { inreg = 0; found = 0 }
    !inreg && $0 ~ ("^Hash +" fn "\\(") { inreg = 1; next }
    inreg {
      if ($0 ~ /DTM-BLKDIG-v2/) found = 1
      if ($0 ~ /\.finalize\(\)/) exit
    }
    END { print found }
  ' "$file"
}
if [ "$(compose_has_tag "$PROD_FILE" compose_block_digest)" = "1" ]; then
  ok "compose tag: producer.cpp::compose_block_digest carries DTM-BLKDIG-v2"
else
  bad "compose tag: producer.cpp::compose_block_digest is missing DTM-BLKDIG-v2 (tag drift)"
fi
if [ "$(compose_has_tag "$LIGHT_FILE" light_compose_block_digest)" = "1" ]; then
  ok "compose tag: light/verify.cpp::light_compose_block_digest carries DTM-BLKDIG-v2"
else
  bad "compose tag: light/verify.cpp::light_compose_block_digest is missing DTM-BLKDIG-v2 (tag drift)"
fi

# ── F2 sub-hasher source-parity (ADC-3 + siblings) ──────────────────────────────
# The three F2 sub-hashers feed the akeys/ekeys/ikeys view roots the block digest
# (checked above) binds. They are re-implemented in BOTH producer.cpp and
# light/verify.cpp, and the block-digest guard reduces each view root to ONE token
# (ABORT_ROOT/EQ_ROOT/INBOUND_ROOT) — it does NOT see a sub-hasher's internal field
# order. Pin the two copies of each sub-hasher EQUAL, append-for-append, so a
# reorder/add/drop/recast in either copy (which would drift the committee-signed
# view root for cross-shard/reconciled blocks with no runtime red) is RED here.
check_subhasher hash_abort_event         DTM-F2-ABORT-v2    # register ADC-3 (D2-inc3: binary claims)
check_subhasher hash_equivocation_event  DTM-F2-EQ-v2       # same class (F2 equivocation view; EQV-height-bind v2)
check_subhasher hash_cross_shard_receipt DTM-F2-RCPT-v1     # same class (F2 inbound-receipt view)

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_block_digest_xbinary_parity (producer.cpp + light/verify.cpp are byte-parity equal; identical field set + order incl. all 3 F2 view roots; merged-block tail triggers identical; + the 3 F2 sub-hashers hash_abort/equivocation/cross_shard_receipt are append-for-append equal across both copies)"
  exit 0
else
  echo "  FAIL: test_block_digest_xbinary_parity ($VIOLATIONS parity violation(s) — a block-digest copy has drifted)"
  exit 1
fi
