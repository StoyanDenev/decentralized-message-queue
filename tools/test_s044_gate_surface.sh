#!/usr/bin/env bash
# test_s044_gate_surface.sh — STATIC source guard pinning the S-044 / S-045
# FIX surface (both findings MITIGATED, 2026) to its shipped shape.
#
# HISTORY / FRAMING
# -----------------
# This guard originally pinned the S-044/S-045 OPEN defect shape and was designed
# to go RED the moment a consensus fix landed. The fix landed:
#   * S-044 (F-a): the abort-claim quorum is now max(2, K-1) via the shared
#     chain::abort_claim_quorum() helper — at K=2 the quorum is unsatisfiable, so
#     no single-claim abort event can form (crash-stop, not wedge-by-cascade).
#   * S-045: the bft_escalation_threshold DEFAULT is now 1 (was 5). θ=1 is reached
#     by the FIRST abort event (which always forms), so the escalation counter can
#     never freeze below it; gate 1 still bars premature escalation when MD margin
#     exists, and the F-a claim floor keeps a single Byzantine node from forcing it.
#   * PROFILE_WEB (the `determ init` default) is now M=4/K=3 (was M=3/K=2) — K>=3
#     disarms the K=2 cascade and gives MD margin 1.
# So this guard now pins the FIXED shape: a REGRESSION (reverting the floor,
# bumping θ back up, un-sharing the helper, or reverting web to K=2) goes RED, and
# the C6 cross-pin requires SECURITY.md to keep S-044/S-045 marked Mitigated. Same
# coherence-guard pattern, inverted target: encode current truth, make drift loud.
# Derivations: docs/proofs/AbortCascadeLiveness.md (FB67) §4.1 (F-a) + §4.3/T-4
# (θ). Canonical status: docs/SECURITY.md "### S-044" / "### S-045" (Mitigated).
#
# THE PINS (shape-anchored: function-body extraction + comment-strip +
# whitespace-free substring match; never line numbers).
#   C1 ESCALATION-CONJUNCTION (unchanged by the fix): check_if_selected still has
#      the pure 4-clause guard (avail<k_target && bft_enabled &&
#      total_aborts>=threshold && avail>=k_bft) — exactly 3 '&&', no '||'. F-c
#      (formation-failure OR-relaxation) was NOT shipped; if it ever is, this pin
#      moves. k_target = cfg_.k_block_sigs.
#   C2 SILENT-RETURN (unchanged): the `if (avail_domains.size() < k_use) return;`
#      stall + the current_aborts_->excluded pool-shrink. The θ fix makes the
#      escalation counter reachable so the wedge is escaped BEFORE this fires in
#      the escalatable regime; the return itself is unchanged (below k_bft it is
#      the designed R7/operator boundary).
#   C3 KBFT-SHARED (S-044 fix hygiene): k_bft is computed via the SHARED helper
#      chain::bft_committee_size(cfg_.k_block_sigs) in check_if_selected — NOT an
#      inline (2K+2)/3 (which risks producer/validator drift, the S-043 class).
#      The helper's ceil(2K/3) body is separately pinned in params.hpp (C7).
#   C4 SINGLE-CLEAR-SITE (unchanged): current_aborts_.clear() appears EXACTLY once
#      (on-accept) and no erase/pop/resize/assign/swap/= removal exists. F-b decay
#      was rejected (§4.2); if it lands this goes RED.
#   C5 QUORUM-FLOOR (S-044 fix): the abort-claim quorum in BOTH writers routes
#      through chain::abort_claim_quorum(...) — on_abort_claim (formation) and
#      on_abort_event (gossip adoption). The bare `size()-1` ternary is GONE from
#      both. Reverting to it goes RED.
#   C6 QUORUM-FLOOR-BODY (S-044 fix): chain::abort_claim_quorum in params.hpp is
#      the max(2, K-1) floor (returns 2 when K-1 < 2). A floor removal / value
#      change goes RED.
#   C7 KBFT-BODY: chain::bft_committee_size in params.hpp is (2K+2)/3 = ceil(2K/3).
#   C8 THRESHOLD-DEFAULT (S-045 fix): bft_escalation_threshold defaults to 1 in
#      genesis.hpp (the GenesisConfig struct default). Bumping it back up goes RED.
#   C9 WEB-PROFILE (S-044 fix): PROFILE_WEB in params.hpp is K>=3 (k_block_sigs
#      field != 2) — the init default is no longer the exposed K=2 posture.
#   C10 DOC-COHERENCE (cross-pin): SECURITY.md must mark `### S-044` and
#      `### S-045` as Mitigated (NOT OPEN). If the code fix is reverted (C1-C9
#      red) but docs still say Mitigated, OR docs flip back to OPEN while the fix
#      is in, that divergence surfaces here.
#
# LIVENESS (SELFTEST=1): feeds the canonical FIXED snippet (green) + regression
# variants (each must go RED at the right pin): revert-quorum-floor -> C5;
# inline-k_bft -> C3; second-clear -> C4; erase-decay -> C4; retry-return -> C2;
# OR-relaxation -> C1; floor-body-removed -> C6; θ-bumped -> C8; web-K2 -> C9;
# docs-flip-to-OPEN -> C10.
#
# Pure read-only SOURCE check (awk/grep/sed). Comment-strip is `//`-only. No
# determ binary, never SKIPs, does not source common.sh. run_all.sh auto-discovers.
set -u
cd "$(dirname "$0")/.."

NODE_FILE=src/node/node.cpp
PARAMS_FILE=include/determ/chain/params.hpp
GENESIS_FILE=include/determ/chain/genesis.hpp
SEC_FILE=docs/SECURITY.md

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

# ── extract_escalation_cond <file> : the ONE if-cond mentioning the threshold ──
extract_escalation_cond() {
  awk '
    function pbal(s,   i, c, b) { b=0; for (i=1;i<=length(s);i++){ c=substr(s,i,1); if(c=="(")b++; else if(c==")")b-- } return b }
    BEGIN { inreg=0; collecting=0; acc=""; bal=0 }
    !inreg && /void +Node::check_if_selected\(\) *\{/ { inreg=1; next }
    !inreg { next }
    /^\}/ { exit }
    {
      line=$0; sub(/\/\/.*/, "", line)
      if (!collecting) { if (line !~ /^[ \t]*([}] *)?(else +)?if[ \t]*\(/) next; acc=line; bal=pbal(line) }
      else { acc=acc " " line; bal+=pbal(line) }
      if (bal>0) { collecting=1; next }
      collecting=0
      if (acc ~ /bft_escalation_threshold/) { gsub(/[ \t]+/, " ", acc); sub(/^ +/, "", acc); print acc; exit }
      acc=""; bal=0
    }
  ' "$1"
}

# ── fn_body_ns <file> <cis|oae|oac> : comment-stripped whitespace-free body ──
fn_body_ns() {
  awk -v fn="$2" '
    BEGIN { inreg=0 }
    !inreg && fn=="cis" && /void +Node::check_if_selected\(\) *\{/ { inreg=1; next }
    !inreg && fn=="oae" && /void +Node::on_abort_event\(/          { inreg=1; next }
    !inreg && fn=="oac" && /void +Node::on_abort_claim\(/          { inreg=1; next }
    !inreg { next }
    /^\}/ { exit }
    { line=$0; sub(/\/\/.*/, "", line); gsub(/[ \t]/, "", line); printf "%s", line }
  ' "$1"
}

count_clear_sites() {
  awk '{ line=$0; sub(/\/\/.*/, "", line); gsub(/[ \t]/, "", line); t += gsub(/current_aborts_\.clear\(\)/, "", line) } END { print t+0 }' "$1"
}
count_other_removals() {
  awk '{ line=$0; sub(/\/\/.*/, "", line); gsub(/[ \t]/, "", line);
         t += gsub(/current_aborts_\.(erase|pop_back|pop_front|resize|assign|swap)\(/, "", line);
         t += gsub(/current_aborts_=[^=]/, "", line) } END { print t+0 }' "$1"
}

# ── run_checks <node> <params> <genesis> <security> ──
run_checks() {
  local file="$1" params="$2" genesis="$3" sec="$4"
  [ -f "$file" ] || { bad "C1..C5 $file MISSING"; return; }

  local cis oae oac
  cis=$(fn_body_ns "$file" cis)
  oae=$(fn_body_ns "$file" oae)
  oac=$(fn_body_ns "$file" oac)

  # ── C1 ESCALATION-CONJUNCTION (still a pure 4-clause &&, no OR-relaxation) ──
  if [ -z "$cis" ]; then
    bad "C1 check_if_selected body NOT FOUND"
    bad "C2 check_if_selected body NOT FOUND"
    bad "C3 check_if_selected body NOT FOUND"
  else
    local cond condns c1ok cl na
    cond=$(extract_escalation_cond "$file"); condns=$(printf '%s' "$cond" | tr -d ' \t')
    if [ -z "$condns" ]; then
      bad "C1 escalation conjunction NOT FOUND in check_if_selected"
    else
      c1ok=1
      for cl in 'avail_domains.size()<k_target' 'cfg_.bft_enabled' \
                'total_aborts>=cfg_.bft_escalation_threshold' 'avail_domains.size()>=k_bft'; do
        case "$condns" in *"$cl"*) : ;; *) bad "C1 escalation conjunction MISSING clause [$cl]"; c1ok=0 ;; esac
      done
      case "$condns" in *"||"*) bad "C1 escalation condition contains '||' — OR-relaxation (F-c) landed; move this pin + reconcile SECURITY.md"; c1ok=0 ;; esac
      na=$(printf '%s' "$condns" | awk -F'&&' '{ print NF-1 }')
      [ "$na" = "3" ] || { bad "C1 escalation condition has $na '&&'; want exactly 3"; c1ok=0; }
      case "$cis" in *'k_target=cfg_.k_block_sigs;'*) : ;; *) bad "C1 k_target = cfg_.k_block_sigs NOT FOUND"; c1ok=0 ;; esac
      [ "$c1ok" = "1" ] && ok "C1 escalation conjunction intact (4 clauses / 3 '&&' / no '||'; k_target=cfg_.k_block_sigs)"
    fi

    # ── C2 SILENT-RETURN + pool-shrink (unchanged by the fix) ──
    local c2ok=1
    case "$cis" in *'if(avail_domains.size()<k_use)return;'*) : ;; *) bad "C2 silent-return stall site NOT FOUND (retry/fallback landed?)"; c2ok=0 ;; esac
    case "$cis" in *'for(auto&ae:current_aborts_)excluded.insert(ae.aborting_node);'*) : ;; *) bad "C2 current_aborts_->excluded pool-shrink NOT FOUND"; c2ok=0 ;; esac
    [ "$c2ok" = "1" ] && ok "C2 silent-return stall + pool-shrink present (below-k_bft boundary is the designed R7/operator territory)"

    # ── C3 KBFT via SHARED helper (not inline (2K+2)/3) ──
    case "$cis" in
      *'k_bft=chain::bft_committee_size(cfg_.k_block_sigs);'*)
        ok "C3 k_bft = chain::bft_committee_size(cfg_.k_block_sigs) (shared producer/validator helper; no inline drift)" ;;
      *'k_bft=(2*cfg_.k_block_sigs+2)/3;'*)
        bad "C3 k_bft is INLINE (2K+2)/3 in check_if_selected — the S-044 fix routes it through chain::bft_committee_size(); inline risks producer/validator drift (S-043 class)" ;;
      *)
        bad "C3 k_bft assignment via chain::bft_committee_size(cfg_.k_block_sigs) NOT FOUND in check_if_selected" ;;
    esac
  fi

  # ── C4 SINGLE-CLEAR-SITE (unchanged: no decay/expiry) ──
  local nclear nother
  nclear=$(count_clear_sites "$file"); nother=$(count_other_removals "$file")
  [ "$nclear" = "1" ] && ok "C4 current_aborts_.clear() appears EXACTLY once (on-accept)" \
                       || bad "C4 current_aborts_.clear() count is $nclear, want 1 (decay landed, or on-accept clear lost)"
  [ "$nother" = "0" ] && ok "C4 no non-clear current_aborts_ removal (erase/pop/resize/assign/swap/=)" \
                      || bad "C4 found $nother non-clear current_aborts_ removal — F-b decay landed; reconcile SECURITY.md"

  # ── C5 QUORUM-FLOOR call in BOTH writers (formation + adoption) ──
  local c5ok=1
  if [ -z "$oac" ]; then bad "C5 on_abort_claim body NOT FOUND"; c5ok=0
  else case "$oac" in
    *'needed=chain::abort_claim_quorum(current_creator_domains_.size());'*) : ;;
    *'?current_creator_domains_.size()-1:0;'*) bad "C5 on_abort_claim still uses the bare size()-1 ternary — F-a quorum floor reverted"; c5ok=0 ;;
    *) bad "C5 on_abort_claim quorum NOT via chain::abort_claim_quorum(...)"; c5ok=0 ;;
  esac; fi
  if [ -z "$oae" ]; then bad "C5 on_abort_event body NOT FOUND"; c5ok=0
  else case "$oae" in
    *'needed=chain::abort_claim_quorum(current_creator_domains_.size());'*) : ;;
    *'?current_creator_domains_.size()-1:0;'*) bad "C5 on_abort_event still uses the bare size()-1 ternary — F-a quorum floor reverted"; c5ok=0 ;;
    *) bad "C5 on_abort_event quorum NOT via chain::abort_claim_quorum(...)"; c5ok=0 ;;
  esac; fi
  [ "$c5ok" = "1" ] && ok "C5 abort-claim quorum routes through chain::abort_claim_quorum() in BOTH on_abort_claim (formation) + on_abort_event (adoption)"

  # ── C6 QUORUM-FLOOR BODY = max(2, K-1) in params.hpp ──
  if [ ! -f "$params" ]; then bad "C6 C7 C9 $params MISSING"; else
    local aq
    aq=$(awk 'BEGIN{inreg=0} /inline +constexpr +size_t +abort_claim_quorum\(/{inreg=1} inreg{ line=$0; sub(/\/\/.*/,"",line); gsub(/[ \t]/,"",line); printf "%s",line; if(line ~ /^\}/ && inreg>1) exit; inreg++ }' "$params")
    case "$aq" in
      *'k_minus_1<2?2:k_minus_1;'*) ok "C6 chain::abort_claim_quorum = max(2, K-1) (k_minus_1 < 2 ? 2 : k_minus_1) — F-a floor intact" ;;
      *) bad "C6 chain::abort_claim_quorum floor 'k_minus_1 < 2 ? 2 : k_minus_1' NOT FOUND in params.hpp (floor removed/changed → K=2 cascade reopens)" ;;
    esac
    # ── C7 KBFT BODY = (2K+2)/3 ──
    local bc
    bc=$(awk 'BEGIN{inreg=0} /inline +constexpr +size_t +bft_committee_size\(/{inreg=1} inreg{ line=$0; sub(/\/\/.*/,"",line); gsub(/[ \t]/,"",line); printf "%s",line; if(line ~ /^\}/ && inreg>1) exit; inreg++ }' "$params")
    case "$bc" in
      *'(2*k_block_sigs+2)/3;'*) ok "C7 chain::bft_committee_size = (2K+2)/3 = ceil(2K/3)" ;;
      *) bad "C7 chain::bft_committee_size '(2*k_block_sigs+2)/3' NOT FOUND in params.hpp" ;;
    esac
    # ── C9 WEB PROFILE K >= 3 (not the exposed K=2 default) ──
    local webk
    webk=$(awk 'f{ if($0 ~ /^};/){f=0} else { n=split($0,a,","); for(i=1;i<=n;i++){ gsub(/[ \t]/,"",a[i]); if(a[i] ~ /^[0-9]+$/) v[++c]=a[i] } } }
               /inline +constexpr +TimingProfile +PROFILE_WEB *\{/{f=1}
               END{ print v[5]+0 }' "$params")
    if [ "${webk:-0}" -ge 3 ] 2>/dev/null; then
      ok "C9 PROFILE_WEB k_block_sigs = ${webk} (>= 3 — init default is no longer the K=2 S-044 posture)"
    else
      bad "C9 PROFILE_WEB k_block_sigs = ${webk:-?} (< 3 — the init default reverted to the exposed K=2 posture)"
    fi
  fi

  # ── C8 THRESHOLD DEFAULT = 1 in genesis.hpp ──
  if [ ! -f "$genesis" ]; then bad "C8 $genesis MISSING"; else
    if grep -Eq 'bft_escalation_threshold\{1\}' "$genesis"; then
      ok "C8 GenesisConfig bft_escalation_threshold default = 1 (S-045: reachable by the first abort event)"
    else
      bad "C8 GenesisConfig bft_escalation_threshold default is NOT 1 in genesis.hpp (S-045 counter-freeze reopens if > K-1)"
    fi
  fi

  # ── C10 DOC-COHERENCE: SECURITY.md marks both Mitigated ──
  if [ ! -f "$sec" ]; then bad "C10 $sec MISSING"; else
    local s44 s45
    s44=$(grep -m1 '^### S-044' "$sec" 2>/dev/null || true)
    s45=$(grep -m1 '^### S-045' "$sec" 2>/dev/null || true)
    case "$s44" in
      "") bad "C10 no '### S-044' heading in $sec" ;;
      *Mitigated*|*MITIGATED*|*mitigated*|*Closed*|*CLOSED*) ok "C10 SECURITY.md S-044 marked Mitigated/Closed (docs agree the fix shipped)" ;;
      *OPEN*) bad "C10 SECURITY.md S-044 still OPEN while the F-a fix is in node.cpp — doc/source divergence" ;;
      *) bad "C10 SECURITY.md S-044 status not recognizably Mitigated (heading: $s44)" ;;
    esac
    case "$s45" in
      "") bad "C10 no '### S-045' heading in $sec" ;;
      *Mitigated*|*MITIGATED*|*mitigated*|*Closed*|*CLOSED*) ok "C10 SECURITY.md S-045 marked Mitigated/Closed" ;;
      *OPEN*) bad "C10 SECURITY.md S-045 still OPEN while the θ=1 fix is in genesis.hpp — doc/source divergence" ;;
      *) bad "C10 SECURITY.md S-045 status not recognizably Mitigated (heading: $s45)" ;;
    esac
  fi
}

# ── SELFTEST (SELFTEST=1): prove each regression class goes RED at the right pin ──
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: S-044/S-045 FIX-surface guard liveness (regression -> expect RED) ==="
  ST_FAIL=0
  tmproot=$(mktemp -d 2>/dev/null || echo "/tmp/s044guard.$$"); mkdir -p "$tmproot"
  trap 'rm -rf "$tmproot"' EXIT

  clean="$tmproot/node.cpp"
  cat > "$clean" <<'EOF'
void Node::check_if_selected() {
    size_t k_target = cfg_.k_block_sigs;       // committee size per round (MD)
    std::set<std::string> excluded;
    for (auto& ae : current_aborts_) excluded.insert(ae.aborting_node);
    std::vector<std::string> avail_domains;
    size_t total_aborts = current_aborts_.size();
    size_t k_bft = chain::bft_committee_size(cfg_.k_block_sigs);   // ceil(2K/3)
    size_t k_use = k_target;
    if (avail_domains.size() < k_target
        && cfg_.bft_enabled
        && total_aborts >= cfg_.bft_escalation_threshold
        && avail_domains.size() >= k_bft) {
        k_use = k_bft;
    }
    if (avail_domains.size() < k_use) return;
}

void Node::on_abort_claim(const AbortClaimMsg& msg) {
    size_t needed = chain::abort_claim_quorum(current_creator_domains_.size());
    if (bucket.size() < needed) return;
    current_aborts_.push_back(ev);
}

void Node::on_abort_event(uint64_t block_index, const Hash& prev_hash,
                            const chain::AbortEvent& ev) {
    if (!ev.claims_json.is_array()) return;
    size_t needed = chain::abort_claim_quorum(current_creator_domains_.size());
    if (ev.claims_json.size() < needed) return;
    current_aborts_.push_back(ev);
}

void Node::apply_block_locked(const chain::Block& b) {
    // current_aborts_.clear();   <- commented decoy must NOT count
    current_aborts_.clear();
    reset_round();
}
EOF

  params="$tmproot/params.hpp"
  cat > "$params" <<'EOF'
inline constexpr size_t bft_committee_size(size_t k_block_sigs) {
    return (2 * k_block_sigs + 2) / 3;   // ceil(2K/3)
}
inline constexpr size_t abort_claim_quorum(size_t committee_size) {
    if (committee_size == 0) return 0;
    size_t k_minus_1 = committee_size - 1;
    return k_minus_1 < 2 ? 2 : k_minus_1;   // max(2, K-1)
}
inline constexpr TimingProfile PROFILE_WEB {
    200, 200, 100, 4, 3, ChainRole::SHARD, ShardingMode::EXTENDED,
    CryptoProfile::MODERN
};
EOF

  genesis="$tmproot/genesis.hpp"
  printf '    uint32_t                        bft_escalation_threshold{1};\n' > "$genesis"

  sec_mit="$tmproot/sec_mit.md"
  cat > "$sec_mit" <<'EOF'
### S-044 — K=2 committees wedge permanently under timing skew (abort-cascade) — ✅ Mitigated
### S-045 — BFT escalation unreachable at the default threshold (counter freeze) — ✅ Mitigated
EOF

  st_green() { local l="$1"; shift; local out; out=$(run_checks "$@" 2>&1)
    if printf '%s\n' "$out" | grep -q "bad:"; then echo "  bad: $l -> clean unexpectedly flagged:" >&2; printf '%s\n' "$out" | grep "bad:" | sed 's/^/       /' >&2; ST_FAIL=$((ST_FAIL+1)); else echo "  ok:  $l -> clean FIXED snippet passes all pins"; fi }
  st_red() { local l="$1" cid="$2"; shift 2; local out; out=$(run_checks "$@" 2>&1)
    if printf '%s\n' "$out" | grep -q "bad: $cid"; then echo "  ok:  $l -> $cid RED (regression flagged)"; else echo "  bad: $l -> $cid NOT flagged" >&2; printf '%s\n' "$out" | sed 's/^/       /' >&2; ST_FAIL=$((ST_FAIL+1)); fi }

  st_green "clean-sanity" "$clean" "$params" "$genesis" "$sec_mit"

  # R1 revert quorum floor in on_abort_event -> C5
  r1="$tmproot/r1.cpp"; sed 's|size_t needed = chain::abort_claim_quorum(current_creator_domains_.size());\n    if (ev|XX|' "$clean" > "$r1"
  awk '{ if ($0 ~ /if \(!ev.claims_json/) { print; getline; print "    size_t needed = current_creator_domains_.size() > 0 ? current_creator_domains_.size() - 1 : 0;"; next } print }' "$clean" > "$r1"
  st_red "R1 revert quorum floor (adoption)" "C5" "$r1" "$params" "$genesis" "$sec_mit"

  # R2 inline k_bft -> C3
  r2="$tmproot/r2.cpp"; sed 's|chain::bft_committee_size(cfg_.k_block_sigs);   // ceil|(2 * cfg_.k_block_sigs + 2) / 3;   // ceil|' "$clean" > "$r2"
  st_red "R2 inline k_bft" "C3" "$r2" "$params" "$genesis" "$sec_mit"

  # R3 second clear -> C4
  r3="$tmproot/r3.cpp"; cp "$clean" "$r3"; printf '\nvoid Node::decay() { current_aborts_.clear(); }\n' >> "$r3"
  st_red "R3 second clear site" "C4" "$r3" "$params" "$genesis" "$sec_mit"

  # R4 erase decay -> C4
  r4="$tmproot/r4.cpp"; cp "$clean" "$r4"; printf '\nvoid Node::decay() { current_aborts_.erase(current_aborts_.begin()); }\n' >> "$r4"
  st_red "R4 erase decay" "C4" "$r4" "$params" "$genesis" "$sec_mit"

  # R5 retry return -> C2
  r5="$tmproot/r5.cpp"; sed 's|if (avail_domains.size() < k_use) return;|if (avail_domains.size() < k_use) { retry(); return; }|' "$clean" > "$r5"
  st_red "R5 retry return" "C2" "$r5" "$params" "$genesis" "$sec_mit"

  # R6 OR-relaxation -> C1
  r6="$tmproot/r6.cpp"; sed 's|&& avail_domains.size() >= k_bft) {|\|\| formation_failures_ >= threshold) {|' "$clean" > "$r6"
  st_red "R6 OR-relaxation" "C1" "$r6" "$params" "$genesis" "$sec_mit"

  # R7 floor body removed -> C6
  r7p="$tmproot/r7params.hpp"; sed 's|k_minus_1 < 2 ? 2 : k_minus_1;|k_minus_1;|' "$params" > "$r7p"
  st_red "R7 floor body removed" "C6" "$clean" "$r7p" "$genesis" "$sec_mit"

  # R8 threshold bumped -> C8
  r8g="$tmproot/r8genesis.hpp"; printf '    uint32_t                        bft_escalation_threshold{5};\n' > "$r8g"
  st_red "R8 threshold bumped to 5" "C8" "$clean" "$params" "$r8g" "$sec_mit"

  # R9 web K=2 -> C9
  r9p="$tmproot/r9params.hpp"; sed 's|200, 200, 100, 4, 3,|200, 200, 100, 3, 2,|' "$params" > "$r9p"
  st_red "R9 web reverted to K=2" "C9" "$clean" "$r9p" "$genesis" "$sec_mit"

  # R10 docs flip back to OPEN -> C10
  sec_open="$tmproot/sec_open.md"; cat > "$sec_open" <<'EOF'
### S-044 — K=2 committees wedge permanently under timing skew (abort-cascade) — ⛔ OPEN (High, liveness)
### S-045 — BFT escalation unreachable at the default threshold (counter freeze) — ⛔ OPEN (High, liveness)
EOF
  st_red "R10 docs flipped back to OPEN" "C10" "$clean" "$params" "$genesis" "$sec_open"

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_s044_gate_surface SELFTEST (clean FIXED snippet green; all 10 regression classes flagged by the right pin)"
    exit 0
  else
    echo "  FAIL: test_s044_gate_surface SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

echo "=== S-044/S-045 abort/escalation FIX-surface guard (static; node.cpp + params.hpp + genesis.hpp + SECURITY.md) ==="
run_checks "$NODE_FILE" "$PARAMS_FILE" "$GENESIS_FILE" "$SEC_FILE"

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_s044_gate_surface (abort/escalation surface matches the SHIPPED S-044/S-045 fix: max(2,K-1) quorum floor via chain::abort_claim_quorum in both writers, k_bft via chain::bft_committee_size, θ default 1, web K>=3; docs mark both Mitigated)"
  exit 0
else
  echo "  FAIL: test_s044_gate_surface ($VIOLATIONS divergence(s) — the fix surface regressed or SECURITY.md drifted; reconcile this guard + SECURITY.md together)"
  exit 1
fi
