#!/usr/bin/env bash
# test_s044_gate_surface.sh — STATIC source guard pinning the S-044 / S-045
# OPEN-defect surface in src/node/node.cpp to its documented shape.
#
# IMPORTANT FRAMING — read this before "fixing" a red run
# --------------------------------------------------------
# This guard does NOT assert the defect is good. It asserts the SOURCE matches
# what docs/SECURITY.md S-044 + S-045 document as OPEN. When a consensus fix
# lands (abort-claim quorum floor / current_aborts_ decay / formation-attempt
# counting), this guard MUST go red — and the right response is to update BOTH
# this guard and SECURITY.md together (the findings close, the pins move).
# Conversely, if SECURITY.md flips S-044/S-045 away from OPEN while the source
# still has the defect shape, the C6 cross-pin goes red. That is the
# FROST-ratchet / coherence-guard pattern: encode current truth, make drift
# loud, never allow silent divergence between code and the security ledger.
#
# THE TWO FINDINGS (canonical text: docs/SECURITY.md "### S-044" / "### S-045",
# at docs/SECURITY.md:1298-1308 + :1312-1318 at the time of writing)
# --------------------------------------------------------------------
# S-044 (High, liveness): K=2 committees wedge permanently under timing skew.
#   At K=2 the abort-claim quorum is K-1 = 1, so a single phase straggle
#   abort-excludes a member on ONE claim; aborts_gen desync (the
#   `msg.aborts_gen != current_aborts_.size()` contrib gate in on_contrib,
#   node.cpp:2113-2116 — documented context, not pinned here) cascades further
#   single-claim aborts; `current_aborts_` clears ONLY on block accept, so
#   exclusions accumulate until the pool falls below K and check_if_selected
#   silently returns forever. BFT escalation cannot rescue K=2 because
#   k_bft = ceil(2K/3) = (2*2+2)/3 = 2 = K — zero escalation headroom.
#   Exposure: the shipped `web` profile — the `determ init` DEFAULT — is
#   M=3/K=2 (PROFILE_WEB, include/determ/chain/params.hpp:142-145; web_test
#   mirrors it at :216-220).
# S-045 (Medium, liveness): BFT escalation unreachable under multi-member
#   abort exclusion. check_if_selected escalates only when
#   avail < k_target && bft_enabled && total_aborts >= bft_escalation_threshold
#   && avail >= k_bft; otherwise, with avail < k_use, it SILENTLY returns.
#   Rounds are what generate abort claims, so once aborts against
#   >= (pool - k_bft + 1) DISTINCT members accumulate while total_aborts is
#   still below the threshold (default 5; include/determ/node/node.hpp:115,
#   include/determ/chain/genesis.hpp:145), the counter freezes and the chain
#   halts permanently — in exactly the regime escalation was meant to rescue.
#
# Derived facts the pins encode:
#   * wedge condition: |distinct aborted members| > pool - k_use blocks ALL
#     further rounds (the silent return fires every time);
#   * escalation is reachable iff aborts concentrate on <= pool - k_bft
#     distinct members long enough for total_aborts to reach the threshold
#     (the green single-dead-member case: tools/test_bft_escalation.sh);
#   * at K=2, k_bft = 2 = K, so there is NO escalation headroom, and the
#     K-1 = 1 claim quorum makes every straggle an exclusion.
#
# Empirical evidence (live cluster runs, 2026-06-11): tools/test_web_hybrid.sh:173
# and tools/test_regional_shards.sh:182 carry `KNOWN-BUG S-044` notes in place
# of the sustained-production bar; tools/test_weak_3node.sh's header documents
# the observed K=2 cascade (it was remediated to K=3); tools/test_bft_escalation.sh
# is the GREEN single-dead-member escalation case that still passes.
#
# THE SIX PINS (each check's comment states which finding it anchors). Line
# numbers below are AT THE TIME OF WRITING; the guard anchors on function /
# expression SHAPE (name anchors + paren-balanced extraction + comment-strip +
# whitespace-free comparison), never on line numbers.
#   C1 ESCALATION-CONJUNCTION (S-045): check_if_selected (node.cpp:729)
#      contains the 4-clause escalation guard (node.cpp:781-784):
#        avail_domains.size() < k_target            [k_target = cfg_.k_block_sigs, :756]
#        && cfg_.bft_enabled
#        && total_aborts >= cfg_.bft_escalation_threshold
#        && avail_domains.size() >= k_bft
#      Extracted by shape (the one if-condition in the body that mentions
#      bft_escalation_threshold, accumulated across lines until parens
#      balance). Asserts all 4 clauses present, EXACTLY 3 `&&` joiners, and
#      no `||` (a disjunctive relaxation — e.g. candidate fix F-c counting
#      failed formation attempts, or a grace-period fallback — changes this
#      shape and goes red here).
#   C2 SILENT-RETURN (S-045 freeze point; S-044 cascade terminal state): the
#      `if (avail_domains.size() < k_use) return;` stall site (node.cpp:788)
#      exists, plus the pool-shrink that feeds it — the excluded-set build
#      from current_aborts_ (node.cpp:762-768). Replacing the bare return
#      with a retry/timer path goes red here.
#   C3 KBFT-FORMULA (S-044): k_bft computed as (2 * cfg_.k_block_sigs + 2) / 3
#      (node.cpp:778) — the ceil(2K/3) that makes K=2 escalation-free.
#   C4 SINGLE-CLEAR-SITE (S-044 "no decay, no expiry, no retry"):
#      current_aborts_.clear() appears EXACTLY once in node.cpp (the on-accept
#      clear in apply_block_locked, node.cpp:1856), AND no other removal/reset
#      site exists (erase/pop_back/pop_front/resize/assign/swap/re-assignment).
#      Candidate fix F-b (wall-clock decay/expiry) lands as a second clear or
#      an erase site — either goes red here. Zero clear sites also = red.
#   C5 CLAIM-QUORUM (S-044 root cause; informational-but-asserted): the K-1
#      claim-quorum validation in on_abort_event (node.cpp:1312) exists in its
#      exact shape: `needed = |committee| > 0 ? |committee| - 1 : 0`
#      (node.cpp:1329-1331) plus the inline-claims count gate and the
#      distinct-claimer gate `seen_claimers.size() < needed` (node.cpp:1354).
#      (The sender-side claim-quorum BUILD with the same K-1 arithmetic lives
#      in on_abort_claim, node.cpp:1274-1296 — same `needed` shape; the
#      validator-side adoption path pinned here is the consensus surface.)
#      Candidate fix F-a (quorum floor max(2, K-1)) changes the ternary and
#      goes red here.
#   C6 DOC-COHERENCE (cross-pin, both findings): docs/SECURITY.md must still
#      mark `### S-044` and `### S-045` as OPEN. If the docs claim closure
#      while C1-C5 still match the defect shape, that is doc drift — red.
#
# LIVENESS (SELFTEST=1)
# ---------------------
# `SELFTEST=1 bash tools/test_s044_gate_surface.sh` feeds synthetic snippets
# (a clean canonical one + 7 drifted variants) through the SAME extraction
# logic and run_checks, and asserts each drift is flagged by the RIGHT check:
#   D1 dropped conjunction clause (no `avail >= k_bft`)        -> C1 red
#   D2 changed k_bft formula ((2K)/3 instead of (2K+2)/3)      -> C3 red
#   D3 added SECOND current_aborts_.clear() site               -> C4 red
#   D4 silent return replaced by a retry path                  -> C2 red
#   D5 quorum floor max(2, K-1) (candidate fix F-a)            -> C5 red
#   D6 current_aborts_ decay via erase (candidate fix F-b)     -> C4 red
#   D7 SECURITY.md flips S-044/S-045 to Mitigated, code as-is  -> C6 red
# The self-test creates scratch files under mktemp only; no real source is
# read or modified by the mutation step.
#
# Pure read-only SOURCE check (awk/grep/sed over node.cpp + SECURITY.md).
# Comment-stripping is `//`-only (node.cpp house style); a commented-out
# decoy never counts. Needs NO determ binary, never SKIPs, does NOT source
# tools/common.sh. Deterministic + offline. run_all.sh auto-discovers it
# (tools/test_*.sh) and reads the single terminal `  PASS:` / `  FAIL:` marker.
#
# Exit 0 = source still matches the documented-OPEN S-044/S-045 shape AND the
#          docs still say OPEN (coherent).
# Exit 1 = the surface diverged — a fix landed or the docs drifted; reconcile
#          this guard and SECURITY.md together.
set -u
cd "$(dirname "$0")/.."

NODE_FILE=src/node/node.cpp
SEC_FILE=docs/SECURITY.md

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

# ── extract_escalation_cond <file> ──────────────────────────────────────────────
# Prints the full, whitespace-normalized text of the ONE if-condition inside
# check_if_selected that mentions bft_escalation_threshold. Shape-anchored:
#   * body = from `void Node::check_if_selected() {` to the first `}` at col 0;
#   * each if-statement's condition is accumulated across lines until its
#     parentheses balance (handles the real 4-line spelling);
#   * `//` comments are stripped first, so a commented-out decoy never counts;
#   * conditions not mentioning bft_escalation_threshold are skipped.
# Prints nothing if no such condition exists (caller treats that as red).
extract_escalation_cond() {
  awk '
    function pbal(s,   i, c, b) {
      b = 0
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if      (c == "(") b++
        else if (c == ")") b--
      }
      return b
    }
    BEGIN { inreg = 0; collecting = 0; acc = ""; bal = 0 }
    !inreg && /void +Node::check_if_selected\(\) *\{/ { inreg = 1; next }
    !inreg { next }
    /^\}/ { exit }
    {
      line = $0
      sub(/\/\/.*/, "", line)
      if (!collecting) {
        if (line !~ /^[ \t]*([}] *)?(else +)?if[ \t]*\(/) next
        acc = line
        bal = pbal(line)
      } else {
        acc = acc " " line
        bal += pbal(line)
      }
      if (bal > 0) { collecting = 1; next }
      collecting = 0
      if (acc ~ /bft_escalation_threshold/) {
        gsub(/[ \t]+/, " ", acc)
        sub(/^ +/, "", acc)
        print acc
        exit
      }
      acc = ""; bal = 0
    }
  ' "$1"
}

# ── fn_body_ns <file> <cis|oae> ─────────────────────────────────────────────────
# Prints the comment-stripped, whitespace-FREE, newline-joined body of one
# function (cis = check_if_selected, oae = on_abort_event). Joining lines into
# one space-free string lets multi-line statements (the `needed` ternary) be
# matched as exact substrings, robust to pure reformatting.
fn_body_ns() {
  awk -v fn="$2" '
    BEGIN { inreg = 0 }
    !inreg && fn == "cis" && /void +Node::check_if_selected\(\) *\{/ { inreg = 1; next }
    !inreg && fn == "oae" && /void +Node::on_abort_event\(/          { inreg = 1; next }
    !inreg { next }
    /^\}/ { exit }
    { line = $0; sub(/\/\/.*/, "", line); gsub(/[ \t]/, "", line); printf "%s", line }
  ' "$1"
}

# ── count_clear_sites <file> ────────────────────────────────────────────────────
# File-wide count of `current_aborts_.clear()` after `//`-comment strip.
count_clear_sites() {
  awk '{
    line = $0
    sub(/\/\/.*/, "", line)
    gsub(/[ \t]/, "", line)
    t += gsub(/current_aborts_\.clear\(\)/, "", line)
  } END { print t + 0 }' "$1"
}

# ── count_other_removals <file> ─────────────────────────────────────────────────
# File-wide count of NON-clear() removal/reset sites on current_aborts_:
# erase/pop_back/pop_front/resize/assign/swap calls, or a re-assignment
# `current_aborts_ = ...`. Any of these = decay/expiry semantics landed.
count_other_removals() {
  awk '{
    line = $0
    sub(/\/\/.*/, "", line)
    gsub(/[ \t]/, "", line)
    t += gsub(/current_aborts_\.(erase|pop_back|pop_front|resize|assign|swap)\(/, "", line)
    t += gsub(/current_aborts_=[^=]/, "", line)
  } END { print t + 0 }' "$1"
}

# ── run_checks <node_cpp> <security_md> ─────────────────────────────────────────
# Runs C1..C6 against the given files. Prints ok/bad per check and bumps
# VIOLATIONS. Used against the real sources (production) and against scratch
# snippets (SELFTEST) — the SAME logic both ways.
run_checks() {
  local file="$1" sec="$2"

  if [ ! -f "$file" ]; then
    bad "C1 C2 C3 C4 C5 $file MISSING (cannot pin the defect surface)"
    return
  fi

  local cis oae
  cis=$(fn_body_ns "$file" cis)
  oae=$(fn_body_ns "$file" oae)

  # ── C1 ESCALATION-CONJUNCTION (anchors S-045) ──
  # The 4-clause guard is the ONLY path off MUTUAL_DISTRUST; any added/dropped
  # clause, OR-relaxation (grace fallback / fix F-c), or k_target rebind
  # changes escalation reachability and must surface here.
  if [ -z "$cis" ]; then
    bad "C1 check_if_selected body NOT FOUND (anchor 'void Node::check_if_selected() {' missing)"
    bad "C2 check_if_selected body NOT FOUND — silent-return pin unverifiable"
    bad "C3 check_if_selected body NOT FOUND — k_bft formula pin unverifiable"
  else
    local cond condns c1ok na cl
    cond=$(extract_escalation_cond "$file")
    condns=$(printf '%s' "$cond" | tr -d ' \t')
    if [ -z "$condns" ]; then
      bad "C1 escalation if-statement (the bft_escalation_threshold conjunction) NOT FOUND in check_if_selected"
    else
      c1ok=1
      for cl in \
        'avail_domains.size()<k_target' \
        'cfg_.bft_enabled' \
        'total_aborts>=cfg_.bft_escalation_threshold' \
        'avail_domains.size()>=k_bft'
      do
        case "$condns" in
          *"$cl"*) : ;;
          *) bad "C1 escalation conjunction MISSING clause [$cl]"; c1ok=0 ;;
        esac
      done
      case "$condns" in
        *"||"*) bad "C1 escalation condition contains '||' — no longer a pure 4-clause conjunction (relaxation landed?)"; c1ok=0 ;;
      esac
      na=$(printf '%s' "$condns" | awk -F'&&' '{ print NF - 1 }')
      if [ "$na" != "3" ]; then
        bad "C1 escalation condition has $na '&&' joiner(s); want exactly 3 (the documented 4-clause conjunction)"
        c1ok=0
      fi
      case "$cis" in
        *'k_target=cfg_.k_block_sigs;'*) : ;;
        *) bad "C1 k_target binding 'k_target = cfg_.k_block_sigs' NOT FOUND in check_if_selected (clause operand redefined)"; c1ok=0 ;;
      esac
      [ "$c1ok" = "1" ] && ok "C1 escalation conjunction intact: 4 clauses / 3 '&&' / no '||' (avail<k_target, bft_enabled, total_aborts>=threshold, avail>=k_bft); k_target = cfg_.k_block_sigs"
    fi

    # ── C2 SILENT-RETURN (anchors S-045's freeze point + S-044's terminal state) ──
    # The bare `return;` with no retry/decay/timer is WHY a wedged height stays
    # wedged. The excluded-set build is the pool-shrink that feeds it.
    local c2ok=1
    case "$cis" in
      *'if(avail_domains.size()<k_use)return;'*) : ;;
      *) bad "C2 silent-return stall site 'if (avail_domains.size() < k_use) return;' NOT FOUND — the S-045 freeze point changed (retry/fallback landed?)"; c2ok=0 ;;
    esac
    case "$cis" in
      *'for(auto&ae:current_aborts_)excluded.insert(ae.aborting_node);'*) : ;;
      *) bad "C2 exclusion build 'for (ae : current_aborts_) excluded.insert(ae.aborting_node)' NOT FOUND — abort->pool-shrink semantics changed"; c2ok=0 ;;
    esac
    [ "$c2ok" = "1" ] && ok "C2 silent-return stall site + current_aborts_->excluded pool shrink present (documented wedge shape: |aborted| > pool - k_use blocks every round)"

    # ── C3 KBFT-FORMULA (anchors S-044) ──
    # ceil(2K/3) spelled (2K+2)/3 — at K=2 this is 2 = K: no committee shrink
    # exists, which is exactly why escalation cannot rescue the web profile.
    case "$cis" in
      *'k_bft=(2*cfg_.k_block_sigs+2)/3;'*)
        ok "C3 k_bft = (2 * cfg_.k_block_sigs + 2) / 3 (ceil(2K/3); K=2 -> k_bft=2=K, zero escalation headroom)" ;;
      *)
        bad "C3 k_bft formula '(2 * cfg_.k_block_sigs + 2) / 3' NOT FOUND in check_if_selected — escalation-headroom semantics changed" ;;
    esac
  fi

  # ── C4 SINGLE-CLEAR-SITE (anchors S-044: "no decay, no expiry, no retry") ──
  # current_aborts_ entries must leave ONLY via the single on-accept clear.
  # A second clear, a lost clear, or any erase-family site = lifetime
  # semantics changed (candidate fix F-b) -> red.
  local nclear nother
  nclear=$(count_clear_sites "$file")
  nother=$(count_other_removals "$file")
  if [ "$nclear" = "1" ]; then
    ok "C4 current_aborts_.clear() appears EXACTLY once (the on-accept clear) — no decay/expiry path"
  else
    bad "C4 current_aborts_.clear() count is $nclear, want exactly 1 — abort-lifetime semantics changed (decay/expiry landed, or the on-accept clear was lost)"
  fi
  if [ "$nother" = "0" ]; then
    ok "C4 no non-clear() current_aborts_ removal/reset site (erase/pop/resize/assign/swap/=) — entries leave ONLY on block accept"
  else
    bad "C4 found $nother non-clear() current_aborts_ removal/reset site(s) — decay/expiry (candidate fix F-b?) landed; reconcile SECURITY.md S-044/S-045"
  fi

  # ── C5 CLAIM-QUORUM (anchors S-044's root cause; informational-but-asserted) ──
  # needed = |committee| - 1 is what makes a SINGLE claim a quorum at K=2.
  # Candidate fix F-a (floor max(2, K-1)) changes the ternary -> red.
  if [ -z "$oae" ]; then
    bad "C5 on_abort_event body NOT FOUND (anchor 'void Node::on_abort_event(' missing)"
  else
    local c5ok=1
    case "$oae" in
      *'needed=current_creator_domains_.size()>0?current_creator_domains_.size()-1:0;'*) : ;;
      *) bad "C5 K-1 claim-quorum shape 'needed = |committee| > 0 ? |committee| - 1 : 0' NOT FOUND in on_abort_event — quorum arithmetic changed (quorum-floor fix F-a?)"; c5ok=0 ;;
    esac
    case "$oae" in
      *'if(ev.claims_json.size()<needed)return;'*) : ;;
      *) bad "C5 inline-claims count gate 'if (ev.claims_json.size() < needed) return;' NOT FOUND in on_abort_event"; c5ok=0 ;;
    esac
    case "$oae" in
      *'if(seen_claimers.size()<needed)return;'*) : ;;
      *) bad "C5 distinct-claimer quorum gate 'if (seen_claimers.size() < needed) return;' NOT FOUND in on_abort_event"; c5ok=0 ;;
    esac
    [ "$c5ok" = "1" ] && ok "C5 K-1 claim-quorum validation intact in on_abort_event (needed = |committee|-1; inline-claims gate + distinct-claimer gate) — at K=2 a single claim is a quorum"
  fi

  # ── C6 DOC-COHERENCE (cross-pin) ──
  # The pins above encode the OPEN shape; SECURITY.md must agree it is OPEN.
  # If a fix lands, C1-C5 go red first; if only the docs flip, C6 goes red.
  if [ ! -f "$sec" ]; then
    bad "C6 $sec MISSING (cannot cross-check S-044/S-045 status)"
  else
    local s44 s45
    s44=$(grep -m1 '^### S-044' "$sec" 2>/dev/null || true)
    s45=$(grep -m1 '^### S-045' "$sec" 2>/dev/null || true)
    case "$s44" in
      "")      bad "C6 no '### S-044' heading in $sec — the finding entry vanished" ;;
      *OPEN*)  ok  "C6 SECURITY.md S-044 still marked OPEN (docs agree with the pinned defect surface)" ;;
      *)       bad "C6 SECURITY.md S-044 is no longer marked OPEN while node.cpp still has the defect shape — doc/source divergence" ;;
    esac
    case "$s45" in
      "")      bad "C6 no '### S-045' heading in $sec — the finding entry vanished" ;;
      *OPEN*)  ok  "C6 SECURITY.md S-045 still marked OPEN (docs agree with the pinned defect surface)" ;;
      *)       bad "C6 SECURITY.md S-045 is no longer marked OPEN while node.cpp still has the defect shape — doc/source divergence" ;;
    esac
  fi
}

# ── SELFTEST mode (SELFTEST=1) ──────────────────────────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: S-044/S-045 gate-surface guard liveness (synthetic drift -> expect RED) ==="
  ST_FAIL=0
  tmproot=$(mktemp -d 2>/dev/null || echo "/tmp/s044guard.$$")
  mkdir -p "$tmproot"
  trap 'rm -rf "$tmproot"' EXIT

  # st_expect_green: run ALL checks on the snippet pair; expect ZERO bad lines.
  st_expect_green() {
    local label="$1" f="$2" s="$3" out
    out=$(run_checks "$f" "$s" 2>&1)
    if printf '%s\n' "$out" | grep -q "bad:"; then
      echo "  bad: $label -> clean snippet unexpectedly flagged:" >&2
      printf '%s\n' "$out" | grep "bad:" | sed 's/^/       /' >&2
      ST_FAIL=$((ST_FAIL + 1))
    else
      echo "  ok:  $label -> clean snippet passes all checks"
    fi
  }

  # st_expect_red: run ALL checks; expect the NAMED check to be among the bad
  # lines (proves the drift is caught by the RIGHT pin, not a side effect).
  st_expect_red() {
    local label="$1" f="$2" s="$3" cid="$4" out
    out=$(run_checks "$f" "$s" 2>&1)
    if printf '%s\n' "$out" | grep -q "bad: $cid"; then
      echo "  ok:  $label -> $cid RED (drift flagged, as required)"
    else
      echo "  bad: $label -> $cid NOT flagged (guard is not live for this drift)" >&2
      printf '%s\n' "$out" | sed 's/^/       /' >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
  }

  # Canonical clean snippet — mirrors the real node.cpp shapes, including a
  # commented-out decoy conjunction + decoy clear (must NOT count) and an
  # `||`-bearing unrelated if (must NOT poison the conjunction check).
  clean="$tmproot/clean.cpp"
  cat > "$clean" <<'EOF'
void Node::check_if_selected() {
    if (!in_sync())                       return;
    if (phase_ != ConsensusPhase::IDLE)   return;
    auto nodes = registry_.eligible_in_region(cfg_.committee_region);
    for (auto& [refugee_shard, refugee_region] :
         chain_.shards_absorbed_by(cfg_.shard_id)) {
        if (refugee_region.empty() || refugee_region == cfg_.committee_region)
            continue;
    }
    size_t k_target = cfg_.k_block_sigs;       // committee size per round (MD)
    std::set<std::string> excluded;
    for (auto& ae : current_aborts_) excluded.insert(ae.aborting_node);
    std::vector<std::string> avail_domains;
    for (auto& nd : nodes) {
        if (excluded.count(nd.domain)) continue;
        avail_domains.push_back(nd.domain);
    }
    size_t total_aborts = current_aborts_.size();
    size_t k_bft = (2 * cfg_.k_block_sigs + 2) / 3;     // ceil(2K/3)
    size_t k_use = k_target;
    chain::ConsensusMode round_mode = chain::ConsensusMode::MUTUAL_DISTRUST;
    // if (avail_domains.size() < k_target && cfg_.bft_enabled && total_aborts >= cfg_.bft_escalation_threshold && avail_domains.size() >= k_bft) { decoy
    if (avail_domains.size() < k_target
        && cfg_.bft_enabled
        && total_aborts >= cfg_.bft_escalation_threshold
        && avail_domains.size() >= k_bft) {
        k_use      = k_bft;
        round_mode = chain::ConsensusMode::BFT;
    }
    if (avail_domains.size() < k_use) return;
    current_round_mode_ = round_mode;
}

void Node::on_abort_event(uint64_t block_index, const Hash& prev_hash,
                            const chain::AbortEvent& ev) {
    if (!ev.claims_json.is_array()) return;
    size_t needed = current_creator_domains_.size() > 0
                  ? current_creator_domains_.size() - 1 : 0;
    if (ev.claims_json.size() < needed) return;
    std::set<std::string> seen_claimers;
    if (seen_claimers.size() < needed) return;
    current_aborts_.push_back(ev);
}

void Node::apply_block_locked(const chain::Block& b) {
    registry_ = NodeRegistry::build_from_chain(chain_, chain_.height());
    // current_aborts_.clear();   <- commented decoy must NOT count
    current_aborts_.clear();
    reset_round();
}
EOF

  sec_open="$tmproot/sec_open.md"
  cat > "$sec_open" <<'EOF'
### S-044 — K=2 committees wedge permanently under timing skew (abort-cascade) — OPEN (High, liveness)
### S-045 — BFT escalation unreachable under multi-member abort exclusion — OPEN (Medium, liveness)
EOF

  # Sanity: the clean snippet pair must pass every check.
  st_expect_green "clean-sanity" "$clean" "$sec_open"

  # D1: dropped conjunction clause (no `&& avail >= k_bft`) -> C1 red.
  d1="$tmproot/d1.cpp"
  sed 's|&& avail_domains\.size() >= k_bft) {|) {|' "$clean" > "$d1"
  st_expect_red "D1 dropped 'avail >= k_bft' clause" "$d1" "$sec_open" "C1"

  # D2: changed k_bft formula ((2K)/3 instead of (2K+2)/3) -> C3 red.
  d2="$tmproot/d2.cpp"
  sed 's|(2 \* cfg_\.k_block_sigs + 2) / 3|(2 * cfg_.k_block_sigs) / 3|' "$clean" > "$d2"
  st_expect_red "D2 changed k_bft formula" "$d2" "$sec_open" "C3"

  # D3: added SECOND current_aborts_.clear() site -> C4 red (count = 2).
  d3="$tmproot/d3.cpp"
  cp "$clean" "$d3"
  printf '\nvoid Node::decay_timer_fired() {\n    current_aborts_.clear();\n}\n' >> "$d3"
  st_expect_red "D3 second current_aborts_.clear() site" "$d3" "$sec_open" "C4"

  # D4: silent return replaced by a retry path -> C2 red.
  d4="$tmproot/d4.cpp"
  sed 's|if (avail_domains\.size() < k_use) return;|if (avail_domains.size() < k_use) { schedule_formation_retry(); return; }|' "$clean" > "$d4"
  st_expect_red "D4 silent return replaced by retry path" "$d4" "$sec_open" "C2"

  # D5: quorum floor max(2, K-1) (candidate fix F-a) -> C5 red.
  d5="$tmproot/d5.cpp"
  sed 's|? current_creator_domains_\.size() - 1 : 0;|? std::max<size_t>(2, current_creator_domains_.size() - 1) : 0;|' "$clean" > "$d5"
  st_expect_red "D5 quorum floor max(2, K-1) (fix F-a shape)" "$d5" "$sec_open" "C5"

  # D6: current_aborts_ decay via erase (candidate fix F-b) -> C4 red.
  d6="$tmproot/d6.cpp"
  cp "$clean" "$d6"
  printf '\nvoid Node::decay_aborts() {\n    current_aborts_.erase(current_aborts_.begin());\n}\n' >> "$d6"
  st_expect_red "D6 current_aborts_ erase decay site (fix F-b shape)" "$d6" "$sec_open" "C4"

  # D7: docs flip to Mitigated while the code keeps the defect shape -> C6 red.
  sec_closed="$tmproot/sec_closed.md"
  cat > "$sec_closed" <<'EOF'
### S-044 — K=2 committees wedge permanently under timing skew (abort-cascade) — Mitigated in-session
### S-045 — BFT escalation unreachable under multi-member abort exclusion — Mitigated in-session
EOF
  st_expect_red "D7 SECURITY.md flipped to Mitigated, code unchanged" "$clean" "$sec_closed" "C6"

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_s044_gate_surface SELFTEST (clean snippet green; all 7 drift classes flagged by the right pin: C1 clause-drop, C3 formula, C4 second-clear + erase-decay, C2 retry, C5 quorum-floor, C6 doc-flip)"
    exit 0
  else
    echo "  FAIL: test_s044_gate_surface SELFTEST ($ST_FAIL self-test failure(s) — the guard is NOT live)"
    exit 1
  fi
fi

echo "=== S-044/S-045 abort/escalation gate-surface guard (static; $NODE_FILE + $SEC_FILE) ==="
run_checks "$NODE_FILE" "$SEC_FILE"

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_s044_gate_surface (node.cpp abort/escalation surface matches the SECURITY.md S-044/S-045 OPEN shape: 4-clause escalation conjunction, silent-return stall, ceil(2K/3) k_bft, single on-accept clear, K-1 claim quorum; docs still say OPEN)"
  exit 0
else
  echo "  FAIL: test_s044_gate_surface ($VIOLATIONS divergence(s) — the abort/escalation surface no longer matches SECURITY.md S-044/S-045; if a consensus fix landed, update this guard AND SECURITY.md together)"
  exit 1
fi
