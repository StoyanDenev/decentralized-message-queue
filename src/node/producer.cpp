// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/node/producer.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/keys.hpp>
#include <determ/crypto/random.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/util/json_validate.hpp>
#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>

namespace determ::node {

using namespace determ::crypto;
using namespace determ::chain;
using determ::util::json_require;
using determ::util::json_require_hex;
using json = nlohmann::json;

// ─── ContribMsg JSON ─────────────────────────────────────────────────────────

json ContribMsg::to_json() const {
    json arr = json::array();
    for (auto& h : tx_hashes) arr.push_back(to_hex(h));
    json out = {
        {"block_index", block_index},
        {"signer",      signer},
        {"prev_hash",   to_hex(prev_hash)},
        {"aborts_gen",  aborts_gen},
        {"tx_hashes",   arr},
        {"dh_input",    to_hex(dh_input)},
        {"ed_sig",      to_hex(ed_sig)}
    };
    // v2.7 F2: emit view fields ONLY when any are non-default. This
    // preserves byte-identical JSON with pre-F2 ContribMsg when no view
    // is bound (backward compat with v1 peers + deterministic gossip
    // bandwidth in pre-activation epochs).
    auto is_zero_hash = [](const Hash& h) {
        for (auto b : h) if (b != 0) return false;
        return true;
    };
    bool has_view =
        !is_zero_hash(view_eq_root) ||
        !is_zero_hash(view_abort_root) ||
        !is_zero_hash(view_inbound_root) ||
        !view_eq_list.empty() ||
        !view_abort_list.empty() ||
        !view_inbound_list.empty();
    if (has_view) {
        out["view_eq_root"]      = to_hex(view_eq_root);
        out["view_abort_root"]   = to_hex(view_abort_root);
        out["view_inbound_root"] = to_hex(view_inbound_root);
        json eq_arr = json::array();
        for (auto& h : view_eq_list)      eq_arr.push_back(to_hex(h));
        json ab_arr = json::array();
        for (auto& h : view_abort_list)   ab_arr.push_back(to_hex(h));
        json in_arr = json::array();
        for (auto& h : view_inbound_list) in_arr.push_back(to_hex(h));
        out["view_eq_list"]      = eq_arr;
        out["view_abort_list"]   = ab_arr;
        out["view_inbound_list"] = in_arr;
    }
    // S-030-D2 timestamp reconciliation: emit proposer_time ONLY when non-zero,
    // so legacy / test contribs that don't commit a time keep byte-identical
    // JSON (and the make_contrib_commitment v1 short-circuit).
    if (proposer_time != 0) out["proposer_time"] = proposer_time;
    return out;
}

ContribMsg ContribMsg::from_json(const json& j) {
    // S-018: typed/required-field extraction. A malformed CONTRIB
    // message produces a "missing/wrong-type field 'X'" diagnostic
    // rather than a nlohmann-internal type error that an operator
    // would have to dig through a stack trace to associate with a
    // field name.
    ContribMsg m;
    m.block_index = json_require<uint64_t>(j, "block_index");
    m.signer      = json_require<std::string>(j, "signer");
    m.prev_hash   = from_hex_arr<32>(json_require_hex(j, "prev_hash", 64));
    m.aborts_gen  = j.value("aborts_gen", uint64_t{0});
    // S-018 defense-in-depth: tx_hashes is optional (Phase-1 contribs
    // can be sent before any txs are queued), but when present it MUST
    // be a JSON array. A peer sending `"tx_hashes": "scalar"` or
    // `"tx_hashes": 42` would otherwise throw an opaque nlohmann
    // internal error rather than a clean "tx_hashes must be array"
    // diagnostic. The field name was previously absent from the
    // S-018 error path; now mirrors Block::from_json's
    // json_require_array pattern.
    if (j.contains("tx_hashes")) {
        if (!j["tx_hashes"].is_array()) {
            throw std::runtime_error(
                "S-018: CONTRIB field 'tx_hashes' must be a JSON array "
                "(got " + std::string(j["tx_hashes"].type_name()) + ")");
        }
        for (auto& h : j["tx_hashes"])
            m.tx_hashes.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    m.dh_input = from_hex_arr<32>(json_require_hex(j, "dh_input", 64));
    // S-030-D2 timestamp reconciliation: optional committed local time.
    // Absent on legacy / pre-feature contribs → 0 (no reconciliation).
    m.proposer_time = j.value("proposer_time", uint64_t{0});

    // v2.7 F2: optional view-reconciliation fields (per F2-SPEC.md §Q1/Q3/Q4).
    // Backward-compat: pre-F2 ContribMsg omits these; default to zero/empty.
    // When present, all three roots + all three lists must be present together
    // (validator's V21..V26 cross-checks them); enforcement of "all-or-none"
    // happens at the validator layer post-activation. Wire-level JSON here is
    // lenient: missing fields default-zero, present fields S-018-validated.
    if (j.contains("view_eq_root"))
        m.view_eq_root = from_hex_arr<32>(json_require_hex(j, "view_eq_root", 64));
    if (j.contains("view_abort_root"))
        m.view_abort_root = from_hex_arr<32>(json_require_hex(j, "view_abort_root", 64));
    if (j.contains("view_inbound_root"))
        m.view_inbound_root = from_hex_arr<32>(json_require_hex(j, "view_inbound_root", 64));
    if (j.contains("view_eq_list")) {
        if (!j["view_eq_list"].is_array())
            throw std::runtime_error(
                "S-018: CONTRIB field 'view_eq_list' must be a JSON array "
                "(got " + std::string(j["view_eq_list"].type_name()) + ")");
        for (auto& h : j["view_eq_list"])
            m.view_eq_list.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    if (j.contains("view_abort_list")) {
        if (!j["view_abort_list"].is_array())
            throw std::runtime_error(
                "S-018: CONTRIB field 'view_abort_list' must be a JSON array "
                "(got " + std::string(j["view_abort_list"].type_name()) + ")");
        for (auto& h : j["view_abort_list"])
            m.view_abort_list.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    if (j.contains("view_inbound_list")) {
        if (!j["view_inbound_list"].is_array())
            throw std::runtime_error(
                "S-018: CONTRIB field 'view_inbound_list' must be a JSON array "
                "(got " + std::string(j["view_inbound_list"].type_name()) + ")");
        for (auto& h : j["view_inbound_list"])
            m.view_inbound_list.push_back(from_hex_arr<32>(h.get<std::string>()));
    }

    m.ed_sig   = from_hex_arr<64>(json_require_hex(j, "ed_sig", 128));
    return m;
}

// ─── AbortClaimMsg JSON ──────────────────────────────────────────────────────

json AbortClaimMsg::to_json() const {
    return {
        {"block_index",     block_index},
        {"round",           round},
        {"prev_hash",       to_hex(prev_hash)},
        {"missing_creator", missing_creator},
        {"claimer",         claimer},
        {"ed_sig",          to_hex(ed_sig)}
    };
}

AbortClaimMsg AbortClaimMsg::from_json(const json& j) {
    // S-018: typed/required-field extraction. See ContribMsg::from_json.
    AbortClaimMsg m;
    m.block_index     = json_require<uint64_t>(j, "block_index");
    m.round           = json_require<uint8_t>(j, "round");
    m.prev_hash       = from_hex_arr<32>(json_require_hex(j, "prev_hash", 64));
    m.missing_creator = json_require<std::string>(j, "missing_creator");
    m.claimer         = json_require<std::string>(j, "claimer");
    m.ed_sig          = from_hex_arr<64>(json_require_hex(j, "ed_sig", 128));
    return m;
}

Hash make_abort_claim_message(uint64_t block_index, uint8_t round,
                               const Hash& prev_hash,
                               const std::string& missing_creator) {
    SHA256Builder b;
    b.append(std::string("DTM-AbortClaim-v1"));
    b.append(block_index);
    b.append(round);
    b.append(prev_hash);
    b.append(missing_creator);
    return b.finalize();
}

AbortClaimMsg make_abort_claim(const NodeKey& key,
                                const std::string& claimer,
                                uint64_t block_index, uint8_t round,
                                const Hash& prev_hash,
                                const std::string& missing_creator) {
    AbortClaimMsg m;
    m.block_index     = block_index;
    m.round           = round;
    m.prev_hash       = prev_hash;
    m.missing_creator = missing_creator;
    m.claimer         = claimer;
    Hash msg = make_abort_claim_message(block_index, round, prev_hash, missing_creator);
    m.ed_sig = sign(key, msg.data(), msg.size());
    return m;
}

// ─── BlockSigMsg JSON ────────────────────────────────────────────────────────

json BlockSigMsg::to_json() const {
    return {
        {"block_index",  block_index},
        {"signer",       signer},
        {"delay_output", to_hex(delay_output)},
        {"dh_secret",    to_hex(dh_secret)},
        {"ed_sig",       to_hex(ed_sig)}
    };
}

BlockSigMsg BlockSigMsg::from_json(const json& j) {
    // S-018: typed/required-field extraction. See ContribMsg::from_json.
    BlockSigMsg m;
    m.block_index  = json_require<uint64_t>(j, "block_index");
    m.signer       = json_require<std::string>(j, "signer");
    m.delay_output = from_hex_arr<32>(json_require_hex(j, "delay_output", 64));
    // rev.9 S-009: dh_secret defaulted to zero for old-format messages.
    if (j.contains("dh_secret"))
        m.dh_secret = from_hex_arr<32>(j["dh_secret"].get<std::string>());
    m.ed_sig       = from_hex_arr<64>(json_require_hex(j, "ed_sig", 128));
    return m;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

Hash make_contrib_commitment(uint64_t block_index, const Hash& prev_hash,
                              const std::vector<Hash>& sorted_tx_hashes,
                              const Hash& dh_input,
                              const Hash& view_eq_root,
                              const Hash& view_abort_root,
                              const Hash& view_inbound_root,
                              uint64_t proposer_time) {
    SHA256Builder inner;
    for (auto& h : sorted_tx_hashes) inner.append(h);
    Hash inner_root = inner.finalize();

    SHA256Builder b;
    b.append(block_index);
    b.append(prev_hash);
    b.append(inner_root);
    b.append(dh_input);

    // v2.7 F2 backward-compat: when all three view roots are zero, fall
    // through to the v1 commit shape (no extra appends). This preserves
    // byte-identical hashes with pre-F2 nodes — critical for the
    // pre-activation epoch where mixed-version peers might receive
    // each other's ContribMsg. Post-activation, the producer always
    // populates non-zero roots so the F2 path is always taken; the v1
    // short-circuit is structurally unreachable.
    auto is_zero_hash = [](const Hash& h) {
        for (auto byte : h) if (byte != 0) return false;
        return true;
    };
    bool any_view = !is_zero_hash(view_eq_root)
                 || !is_zero_hash(view_abort_root)
                 || !is_zero_hash(view_inbound_root);
    if (any_view) {
        // Domain separator: prepend the F2 schema tag so an attacker
        // can't construct a v2-shaped pre-image that hashes to a v1
        // commit value (and vice versa). Without this, a malicious
        // peer could replay v1 sigs as if they bound F2 views.
        b.append(std::string("DTM-F2-v1"));
        b.append(view_eq_root);
        b.append(view_abort_root);
        b.append(view_inbound_root);
    }
    // S-030-D2 timestamp reconciliation: bind the member's committed local
    // time when non-zero, AFTER the F2 block, behind its own domain separator
    // so it can't be confused with an F2 view root or a v1 pre-image. Zero
    // (legacy / test contribs) appends nothing → byte-identical commitment.
    // The Phase-1 signature over this commitment is what stops a member from
    // equivocating on the time it later contributes to the median.
    if (proposer_time != 0) {
        b.append(std::string("DTM-TS-v1"));
        b.append(proposer_time);
    }
    return b.finalize();
}

// Message-form overload (S-043 hardening). Extracts EVERY field the commitment
// binds straight from the message, so a verification-side recompute cannot
// silently omit one via a trailing default-zero arg (the S-043 root cause).
// Byte-identical to the field-form call with these same fields.
Hash make_contrib_commitment(const ContribMsg& m) {
    return make_contrib_commitment(m.block_index, m.prev_hash, m.tx_hashes,
                                    m.dh_input, m.view_eq_root,
                                    m.view_abort_root, m.view_inbound_root,
                                    m.proposer_time);
}

// S-030-D2: deterministic lower-median of K committed proposer times. Sorts a
// copy and returns sorted[(K-1)/2] — always one of the committed values, so the
// result is integer + deterministic, and under f < K/3 Byzantine members it
// always lands within the honest-clock spread (the order statistic at index
// (K-1)/2 is flanked by honest values on both sides when f ≤ (K-1)/2, which
// f < K/3 implies for K ≥ 3). Returns 0 for an empty input (no reconciliation).
uint64_t reconcile_median_time(const std::vector<uint64_t>& times) {
    if (times.empty()) return 0;
    std::vector<uint64_t> v = times;
    std::sort(v.begin(), v.end());
    return v[(v.size() - 1) / 2];
}

Hash compute_tx_root(const std::vector<std::vector<Hash>>& creator_tx_lists) {
    std::set<Hash> u;
    for (auto& list : creator_tx_lists)
        for (auto& h : list) u.insert(h);

    SHA256Builder b;
    for (auto& h : u) b.append(h);
    return b.finalize();
}

// ─── v2.7 F2 view reconciliation helpers ───────────────────────────────────
//
// Per-record canonical hashes for view-list materialization. Each helper
// hashes ALL consensus-bound fields of its struct in declared order under
// a unique DTM-F2-<TYPE>-v1 domain separator. Two peers observing the
// same struct content compute the same Hash; mixing struct types into a
// single view list is impossible because of the cross-domain separator.

Hash hash_equivocation_event(const chain::EquivocationEvent& e) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-EQ-v1"));
    b.append(e.equivocator);
    b.append(e.block_index);
    b.append(e.digest_a);
    b.append(e.sig_a.data(), e.sig_a.size());
    b.append(e.digest_b);
    b.append(e.sig_b.data(), e.sig_b.size());
    // Forensic-trace fields (shard_id, beacon_anchor_height): included
    // so peers' Hash matches across observers with identical struct
    // content. Each observation point will fill these consistently.
    b.append(static_cast<uint64_t>(e.shard_id));
    b.append(e.beacon_anchor_height);
    return b.finalize();
}

Hash hash_abort_event(const chain::AbortEvent& e) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-ABORT-v1"));
    b.append(e.round);
    b.append(e.aborting_node);
    b.append(static_cast<uint64_t>(e.timestamp));
    b.append(e.event_hash);
    // claims_json: serialize to canonical string form via nlohmann's
    // dump(). All peers using nlohmann::json see the same dump() output
    // for the same parsed input (nlohmann sorts object keys), so this
    // is deterministic across observers.
    b.append(e.claims_json.dump());
    return b.finalize();
}

Hash hash_cross_shard_receipt(const chain::CrossShardReceipt& r) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-RCPT-v1"));
    b.append(static_cast<uint64_t>(r.src_shard));
    b.append(static_cast<uint64_t>(r.dst_shard));
    b.append(r.src_block_index);
    b.append(r.src_block_hash);
    b.append(r.tx_hash);
    b.append(r.from);
    b.append(r.to);
    b.append(r.amount);
    b.append(r.fee);
    b.append(r.nonce);
    return b.finalize();
}

// `compute_view_root` produces the canonical Merkle root over a sorted SET
// of hash items. Same shape as `compute_tx_root` (which also dedupes via
// std::set + appends in canonical order) so a view-root over the same
// items as a tx_root produces an identical hash. This shared structure is
// intentional — both are deterministic commitments over a member's
// observed pool, and using the same primitive simplifies the validator's
// re-derivation check.
Hash compute_view_root(const std::vector<Hash>& items) {
    std::set<Hash> u(items.begin(), items.end());
    SHA256Builder b;
    for (auto& h : u) b.append(h);
    return b.finalize();
}

// Union reconciliation across K committee members' lists. Used for
// equivocation_events + abort_events per F2-SPEC.md Q1. Censorship-
// resistance applies: any single honest member's observation suffices.
std::vector<Hash> reconcile_union(
        const std::vector<std::vector<Hash>>& member_lists) {
    std::set<Hash> u;
    for (auto& list : member_lists)
        for (auto& h : list) u.insert(h);
    return std::vector<Hash>(u.begin(), u.end());
}

// Intersection reconciliation across K committee members' lists. Used
// for inbound_receipts per F2-SPEC.md Q1 — credit only on unanimous
// observation (one bad relayer cannot unilaterally cause credit). Empty
// result if `member_lists` is empty or any member's list is empty.
std::vector<Hash> reconcile_intersection(
        const std::vector<std::vector<Hash>>& member_lists) {
    if (member_lists.empty()) return {};
    // Start with the first list's set; iteratively intersect with the rest.
    std::set<Hash> isect(member_lists[0].begin(), member_lists[0].end());
    for (size_t i = 1; i < member_lists.size(); ++i) {
        std::set<Hash> other(member_lists[i].begin(), member_lists[i].end());
        std::set<Hash> tmp;
        std::set_intersection(isect.begin(), isect.end(),
                               other.begin(), other.end(),
                               std::inserter(tmp, tmp.begin()));
        isect = std::move(tmp);
        if (isect.empty()) break;  // early exit
    }
    return std::vector<Hash>(isect.begin(), isect.end());
}

// ─── Validator-side F2 checks (V21..V26) ──────────────────────────────────
//
// These mirror the producer-side primitives but apply them in reverse:
// the validator receives K contribs + a proposed block, and must verify
// (a) each contrib's view-roots match its committed view-lists, and
// (b) the block body's canonical lists match the F2 reconciliation of
// the contribs' views. Same primitives — compute_view_root /
// reconcile_union / reconcile_intersection — wired into a single
// validator-friendly check.

namespace {
bool is_zero_hash_(const Hash& h) {
    for (auto byte : h) if (byte != 0) return false;
    return true;
}
} // namespace

bool validate_contrib_view_roots(const ContribMsg& msg, std::string* reason) {
    auto set_reason = [&](const char* m) { if (reason) *reason = m; };

    // v1-compat short-circuit: all roots zero AND all lists empty is a
    // valid pre-F2 contrib (no view binding). The caller (validator
    // height-gate logic) decides whether to ACCEPT this at the current
    // height; this helper just confirms it's well-formed.
    bool all_roots_zero = is_zero_hash_(msg.view_eq_root)
                       && is_zero_hash_(msg.view_abort_root)
                       && is_zero_hash_(msg.view_inbound_root);
    bool all_lists_empty = msg.view_eq_list.empty()
                        && msg.view_abort_list.empty()
                        && msg.view_inbound_list.empty();
    if (all_roots_zero && all_lists_empty) return true;

    // V21: bandwidth cap on each list per F2-SPEC.md §Q3.
    if (msg.view_eq_list.size()      > F2_VIEW_LIST_CAP) {
        set_reason("V21: view_eq_list exceeds F2_VIEW_LIST_CAP");
        return false;
    }
    if (msg.view_abort_list.size()   > F2_VIEW_LIST_CAP) {
        set_reason("V21: view_abort_list exceeds F2_VIEW_LIST_CAP");
        return false;
    }
    if (msg.view_inbound_list.size() > F2_VIEW_LIST_CAP) {
        set_reason("V21: view_inbound_list exceeds F2_VIEW_LIST_CAP");
        return false;
    }

    // V22..V24: each root must equal compute_view_root over its list.
    // Member can't equivocate between Phase-1 commit and Phase-2 reveal:
    // the root was bound into make_contrib_commitment + signed.
    if (compute_view_root(msg.view_eq_list)      != msg.view_eq_root) {
        set_reason("V22: view_eq_root does not match list");
        return false;
    }
    if (compute_view_root(msg.view_abort_list)   != msg.view_abort_root) {
        set_reason("V23: view_abort_root does not match list");
        return false;
    }
    if (compute_view_root(msg.view_inbound_list) != msg.view_inbound_root) {
        set_reason("V24: view_inbound_root does not match list");
        return false;
    }
    return true;
}

F2CanonicalViews derive_canonical_view_lists(
        const std::vector<ContribMsg>& contribs) {
    F2CanonicalViews out;
    std::vector<std::vector<Hash>> eq_views;
    std::vector<std::vector<Hash>> abort_views;
    std::vector<std::vector<Hash>> inbound_views;
    eq_views.reserve(contribs.size());
    abort_views.reserve(contribs.size());
    inbound_views.reserve(contribs.size());
    for (auto& c : contribs) {
        eq_views.push_back(c.view_eq_list);
        abort_views.push_back(c.view_abort_list);
        inbound_views.push_back(c.view_inbound_list);
    }
    out.equivocation_events = reconcile_union(eq_views);
    out.abort_events         = reconcile_union(abort_views);
    out.inbound_receipts     = reconcile_intersection(inbound_views);
    return out;
}

bool validate_view_reconciliation(
        const std::vector<ContribMsg>& contribs,
        const std::vector<Hash>& block_eq,
        const std::vector<Hash>& block_abort,
        const std::vector<Hash>& block_inbound,
        std::string* reason) {
    auto set_reason = [&](const char* m) { if (reason) *reason = m; };

    // V21..V24 per-contrib pass.
    for (size_t i = 0; i < contribs.size(); ++i) {
        std::string sub;
        if (!validate_contrib_view_roots(contribs[i], &sub)) {
            if (reason) {
                *reason = "contrib[" + std::to_string(i) + "]: " + sub;
            }
            return false;
        }
    }

    // V25..V26: canonical reconciliation.
    auto canonical = derive_canonical_view_lists(contribs);

    // The block's canonical lists are also expected to be in canonical
    // sorted order (they were produced by the same primitives). A direct
    // vector comparison suffices.
    if (block_eq != canonical.equivocation_events) {
        set_reason("V25: block equivocation_events != reconcile_union");
        return false;
    }
    if (block_abort != canonical.abort_events) {
        set_reason("V25: block abort_events != reconcile_union");
        return false;
    }
    if (block_inbound != canonical.inbound_receipts) {
        set_reason("V26: block inbound_receipts != reconcile_intersection");
        return false;
    }
    return true;
}

// ─── end v2.7 F2 helpers ───────────────────────────────────────────────────

// S-025 closure: compute_tx_root_intersection deleted as unused. The
// function was a relic of a pre-v1 design where the canonical tx set
// was the intersection of committee members' lists (every member must
// independently propose the tx). v1 settled on union semantics —
// censorship requires ALL K to omit. The intersection helper has no
// callers in the current code base and is removed to reduce confusion.
// If a future v2 mode wants intersection semantics, it can re-introduce
// the function or guard it under a feature flag.

Hash compute_delay_seed(uint64_t block_index, const Hash& prev_hash,
                         const Hash& tx_root,
                         const std::vector<Hash>& creator_dh_inputs) {
    SHA256Builder b;
    b.append(block_index);
    b.append(prev_hash);
    b.append(tx_root);
    for (auto& h : creator_dh_inputs) b.append(h);
    return b.finalize();
}

size_t proposer_idx(const Hash& prev_cum_rand,
                    const std::vector<AbortEvent>& aborts,
                    size_t committee_size) {
    if (committee_size == 0) return 0;
    SHA256Builder b;
    b.append(prev_cum_rand);
    for (auto& ae : aborts) b.append(ae.event_hash);
    b.append(std::string("bft-proposer"));
    Hash mix = b.finalize();
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i)
        v = (v << 8) | mix[i];
    return static_cast<size_t>(v % committee_size);
}

size_t count_round1_aborts(const std::vector<AbortEvent>& aborts) {
    size_t n = 0;
    for (auto& ae : aborts) if (ae.round == 1) ++n;
    return n;
}

size_t required_block_sigs(ConsensusMode mode, size_t committee_size) {
    if (mode == ConsensusMode::MUTUAL_DISTRUST) return committee_size;
    // BFT: Q = ceil(2 * committee_size / 3).
    //
    // Note: `committee_size` here is the BFT-shrunk committee (k_bft),
    // NOT the genesis K. start_new_round (node.cpp ~L768) sets
    // current_creator_domains_.size() = k_bft = ceil(2K/3) before this
    // function gets called in BFT mode, so the two-level shrinkage looks
    // like one level from this function's perspective. The result is
    // Q = ceil(2·k_bft/3); at K=3 the shrinkage is degenerate (Q=k_bft=2);
    // at K=6 Q=3 within k_bft=4; at K=9 Q=4 within k_bft=6.
    return (2 * committee_size + 2) / 3;
}

// rev.9 S-009 closure: block_digest excludes delay_output. The delay
// output is determined by Phase-2-revealed secrets which arrive after
// digest signing — we cannot include them in the digest without a
// chicken-and-egg waiting protocol. Safety holds because delay_output
// is recomputed by every node from delay_seed (Phase-1 inputs, signed)
// + creator_dh_secrets (each verifiable against the signed commit in
// creator_dh_inputs[i]). The validator's recomputation rejects any
// tampered delay_output. The block hash (via Block::signing_bytes)
// still binds delay_output and creator_dh_secrets so block identity
// is unique.
// S-030 D2 (block-digest field-coverage gap): the K-of-K committee
// signature target excludes evidence and receipt lists, leaving a
// one-block window where two valid K-of-K-signed block instances
// can differ in those fields behind the same digest. See
// docs/proofs/S030-D2-Analysis.md for the full analysis and why a
// naive digest extension does not work (gossip-async views).
//
// Status: a Phase-1-side view reconciliation mechanism (ContribMsg
// includes a hash of each member's evidence-pool view; assembly
// reconciles at Phase 1→2 transition; canonical reconciliation feeds
// the digest) is the correct fix. Tracked as a v2 work item; not in
// this v1.x release.
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
    // v2.7 F2 / S-016: bind the admitted inbound-receipt set into the digest so
    // the K-of-K block signature attests to it. The per-creator sigs cover the
    // view ROOTS but not the producer's chosen SET, and check_inbound_receipts'
    // intersection test is subset-only — so without this a relayer could STRIP
    // an inbound receipt after signing and the two versions would share a
    // digest (the S-030-D2 removal gap). Bound via a single root over the sorted
    // receipt keys; skipped (no append) when there are no inbound receipts, so
    // non-cross-shard blocks keep a byte-identical v1 digest.
    if (!b.inbound_receipts.empty()) {
        std::vector<Hash> ikeys;
        ikeys.reserve(b.inbound_receipts.size());
        for (auto& r : b.inbound_receipts)
            ikeys.push_back(hash_cross_shard_receipt(r));
        h.append(compute_view_root(ikeys));
    }
    // v2.7 F2 / S-030-D2 (eq/abort dimension): bind the reconciled equivocation/
    // abort sets into the digest, like inbound above, so the K-of-K sig attests
    // to the exact set (closing the removal gap). Gated on a NON-ZERO per-creator
    // view root — the intrinsic, JSON-stable signal that this block went through
    // F2 reconciliation (build_body only carries a non-zero eq/abort root at/after
    // the activation height). A non-F2 block (all roots zero) keeps the byte-
    // identical v1 digest; its eq/abort sets are the un-reconciled local pool and
    // MUST NOT be bound (binding them would reintroduce the gossip-async divergence
    // that the reconciliation removes). compute_block_digest only sees the Block,
    // so the root is the gate it can read. Field order: inbound, eq, abort.
    auto any_nonzero = [](const std::vector<Hash>& v) {
        for (auto& r : v) if (!is_zero_hash_(r)) return true;
        return false;
    };
    if (any_nonzero(b.creator_view_eq_roots)) {
        std::vector<Hash> ekeys;
        ekeys.reserve(b.equivocation_events.size());
        for (auto& e : b.equivocation_events) ekeys.push_back(hash_equivocation_event(e));
        h.append(compute_view_root(ekeys));
    }
    if (any_nonzero(b.creator_view_abort_roots)) {
        std::vector<Hash> akeys;
        akeys.reserve(b.abort_events.size());
        for (auto& a : b.abort_events) akeys.push_back(hash_abort_event(a));
        h.append(compute_view_root(akeys));
    }
    // S-030-D2 (partner_subset_hash dimension): bind the R4 merged-signing
    // partner-subset commitment into the digest ONLY when non-zero. Unlike
    // the pool-fed eq/abort/inbound fields above, partner_subset_hash is NOT
    // a gossip-async per-member view — it is DETERMINISTIC: every committee
    // member at a merged height computes the identical value from the merge
    // state (S030-D2-Analysis.md §3.2), so binding it raw cannot reintroduce
    // the gossip-async digest divergence §2 warns about. Conditional-on-
    // non-zero mirrors signing_bytes (block.cpp:323) so every non-merged
    // block keeps a byte-identical v1 digest. Closes the partner_subset_hash
    // ✗ row: a relayer that strips/alters the partner commitment after the
    // K-of-K Phase-2 signature now changes the digest, so the signatures no
    // longer verify. Field order: inbound, eq, abort, partner_subset_hash.
    if (!is_zero_hash_(b.partner_subset_hash)) {
        h.append(b.partner_subset_hash);
    }
    // S-030-D2 (timestamp dimension): bind the canonical block timestamp ONLY
    // when the block carries per-creator proposer times — i.e. it went through
    // timestamp reconciliation (build_body set b.timestamp = lower-median of the
    // K committed times). That median is a deterministic function of the K
    // signed Phase-1 commits, so every honest assembler digests the identical
    // value (no gossip-async divergence — the §5 obstacle to a RAW timestamp).
    // A legacy / pre-feature block (empty creator_proposer_times, timestamp =
    // assembler wall-clock) appends nothing, keeping the byte-identical v1
    // digest. The validator re-derives the median from creator_proposer_times
    // and rejects on mismatch; the per-creator times are authenticated via
    // creator_ed_sigs (the Phase-1 commitment binds proposer_time). Field order:
    // inbound, eq, abort, partner_subset_hash, timestamp.
    if (!b.creator_proposer_times.empty()) {
        h.append(b.timestamp);
    }
    // A6 / §7.5.1: bind signature_form ONLY when non-zero — the committee's
    // Phase-2 signatures then cover the discriminator that says how those
    // very signatures are to be interpreted, so a post-sign relabel of the
    // sig array changes the digest and the signatures no longer verify.
    // DETERMINISTIC (a block field, not a gossip-async view), so raw binding
    // is safe per the S-030-D2 §3.2 argument. v1.1 blocks are all form 0
    // (validator fail-closes on non-zero) → byte-identical v1 digest. Field
    // order: inbound, eq, abort, partner_subset_hash, timestamp,
    // signature_form.
    if (b.signature_form != 0) {
        h.append(static_cast<uint8_t>(b.signature_form));
    }
    return h.finalize();
}

// rev.9 S-009: post-Phase-2 randomness output. Computed once K secrets
// gather. ordered_secrets[i] must correspond to creators[i] (same
// committee selection order as creator_dh_inputs).
Hash compute_block_rand(const Hash& delay_seed,
                          const std::vector<Hash>& ordered_secrets) {
    SHA256Builder h;
    h.append(delay_seed);
    for (auto& s : ordered_secrets) h.append(s);
    return h.finalize();
}

// ─── make_contrib ────────────────────────────────────────────────────────────

ContribMsg make_contrib(const NodeKey& key,
                         const std::string& domain,
                         uint64_t block_index,
                         const Hash& prev_hash,
                         uint64_t aborts_gen,
                         const std::vector<Hash>& tx_snapshot,
                         const Hash& dh_input,
                         const std::vector<Hash>& view_eq_list,
                         const std::vector<Hash>& view_abort_list,
                         const std::vector<Hash>& view_inbound_list,
                         uint64_t proposer_time) {
    ContribMsg m;
    m.block_index   = block_index;
    m.signer        = domain;
    m.prev_hash     = prev_hash;
    m.aborts_gen    = aborts_gen;
    m.tx_hashes     = tx_snapshot;
    m.dh_input      = dh_input;
    m.proposer_time = proposer_time;
    std::sort(m.tx_hashes.begin(), m.tx_hashes.end());
    m.tx_hashes.erase(std::unique(m.tx_hashes.begin(), m.tx_hashes.end()),
                      m.tx_hashes.end());

    // v2.7 F2 view-binding (sub-step 2 partial).
    //
    // If any view list is non-empty, canonicalize (sort + dedup) each
    // list, compute its Merkle root, populate the ContribMsg view fields,
    // and bind the three roots into the commit hash. When ALL lists are
    // empty (default args / pre-F2 / F2-not-yet-active heights), the
    // view fields stay zero/empty and the commit falls back to the v1
    // short-circuit (byte-identical to pre-F2 commits).
    auto canonicalize = [](std::vector<Hash> v) {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
        return v;
    };
    bool any_view = !view_eq_list.empty()
                 || !view_abort_list.empty()
                 || !view_inbound_list.empty();
    if (any_view) {
        m.view_eq_list      = canonicalize(view_eq_list);
        m.view_abort_list   = canonicalize(view_abort_list);
        m.view_inbound_list = canonicalize(view_inbound_list);
        m.view_eq_root      = compute_view_root(m.view_eq_list);
        m.view_abort_root   = compute_view_root(m.view_abort_list);
        m.view_inbound_root = compute_view_root(m.view_inbound_list);
    }
    // else: m.view_X_root stays Hash{} (zero); m.view_X_list stays empty.

    Hash commit = make_contrib_commitment(
        block_index, prev_hash, m.tx_hashes, dh_input,
        m.view_eq_root, m.view_abort_root, m.view_inbound_root,
        m.proposer_time);
    m.ed_sig = sign(key, commit.data(), commit.size());
    return m;
}

// ─── make_block_sig ──────────────────────────────────────────────────────────

BlockSigMsg make_block_sig(const NodeKey& key,
                            const std::string& domain,
                            uint64_t block_index,
                            const Hash& delay_output,
                            const Hash& block_digest,
                            const Hash& dh_secret) {
    BlockSigMsg m;
    m.block_index  = block_index;
    m.signer       = domain;
    m.delay_output = delay_output;
    m.dh_secret    = dh_secret;
    m.ed_sig       = sign(key, block_digest.data(), block_digest.size());
    return m;
}

// ─── build_body ──────────────────────────────────────────────────────────────

Block build_body(
    const std::map<Hash, Transaction>& tx_store,
    const Chain&                       chain,
    const std::vector<AbortEvent>&     aborts,
    const std::vector<std::string>&    creator_domains,
    const std::vector<ContribMsg>&     contribs,
    const Hash&                        delay_output,
    uint32_t                           m_pool_size,
    ConsensusMode                      mode,
    const std::string&                 bft_proposer_domain,
    const std::vector<EquivocationEvent>& equivocation_events,
    const std::vector<CrossShardReceipt>& inbound_receipts,
    const std::vector<Hash>&              ordered_secrets) {

    Block b;
    b.index               = chain.empty() ? 1 : chain.height();
    b.prev_hash           = chain.empty() ? Hash{} : chain.head_hash();
    b.timestamp           = now_unix();
    b.creators            = creator_domains;

    // Per-creator Phase-1 evidence in selection order.
    for (auto& c : contribs) {
        b.creator_tx_lists.push_back(c.tx_hashes);
        b.creator_ed_sigs.push_back(c.ed_sig);
        b.creator_dh_inputs.push_back(c.dh_input);
        // v2.7 F2 / S-016: carry each creator's Phase-1 view roots into the
        // block so the validator can recompute the F2-bound creator commit.
        // Zero for v1 contribs (Block::to_json then omits them entirely).
        b.creator_view_eq_roots.push_back(c.view_eq_root);
        b.creator_view_abort_roots.push_back(c.view_abort_root);
        b.creator_view_inbound_roots.push_back(c.view_inbound_root);
        b.creator_view_inbound_lists.push_back(c.view_inbound_list);  // site 3
        // v2.7 F2 / S-030-D2: carry each creator's committed eq/abort view
        // LISTS so the validator can re-derive reconcile_union and authenticate
        // the block's evidence set (subset-of-union).
        b.creator_view_eq_lists.push_back(c.view_eq_list);
        b.creator_view_abort_lists.push_back(c.view_abort_list);
        // S-030-D2 timestamp reconciliation: carry each member's committed
        // local time (selection order, parallel to creators).
        b.creator_proposer_times.push_back(c.proposer_time);
    }

    // S-030-D2 timestamp reconciliation: when EVERY committee member committed
    // a non-zero proposer_time (production path), the canonical block timestamp
    // is the deterministic lower-median of those K committed times — a pure
    // function of the K signed Phase-1 commits, so every honest assembler
    // computes the identical value and compute_block_digest can bind it without
    // the gossip-async divergence §2/§5 of S030-D2-Analysis.md warns about.
    // Otherwise (any member legacy / zero — pre-activation or test) fall back to
    // the assembler's wall-clock (b.timestamp set above) and DROP the
    // proposer-times vector so the block keeps its byte-identical v1 shape (no
    // creator_proposer_times field, timestamp NOT digest-bound).
    {
        bool all_set = !b.creator_proposer_times.empty();
        for (uint64_t t : b.creator_proposer_times) if (t == 0) { all_set = false; break; }
        if (all_set) {
            b.timestamp = reconcile_median_time(b.creator_proposer_times);
        } else {
            b.creator_proposer_times.clear();  // legacy: keep v1 block shape
        }
    }

    // v2.7 F2 / S-030-D2 (eq/abort dimension): reconcile equivocation/abort
    // evidence to the committee-wide UNION of the members' committed Phase-1
    // views (F2-SPEC §Q1 — union, vs inbound's intersection). When F2 is active,
    // the block's evidence is the assembler's local pool RESTRICTED to events
    // some committee member committed in Phase-1 — i.e. the subset of the union
    // the assembler can materialize. So the set is committee-attested, not the
    // assembler's unilateral pool, and compute_block_digest binds it (a post-
    // signing strip changes the digest — the S-030-D2 removal gap). SUBSET, not
    // exact-cardinality: hash_equivocation_event / hash_abort_event include
    // observer-dependent forensic fields (shard_id / beacon_anchor_height set at
    // detection time), so two honest observers can commit different hashes for
    // one misbehavior; forcing the assembler to materialize every witness in the
    // union would stall when it lacks a peer's exact struct. The assembler's own
    // committed view covers its own pool, so its evidence is never dropped. See
    // docs/proofs/EqAbortViewDigestExtension.md. Pre-activation: direct assign.
    if (b.index >= chain.f2_active_from_height()) {
        std::set<Hash> eq_union, ab_union;
        { auto u = reconcile_union(b.creator_view_eq_lists);    eq_union.insert(u.begin(), u.end()); }
        { auto u = reconcile_union(b.creator_view_abort_lists); ab_union.insert(u.begin(), u.end()); }
        for (auto& e : equivocation_events)
            if (eq_union.count(hash_equivocation_event(e))) b.equivocation_events.push_back(e);
        for (auto& a : aborts)
            if (ab_union.count(hash_abort_event(a))) b.abort_events.push_back(a);
    } else {
        b.abort_events        = aborts;
        b.equivocation_events = equivocation_events;
    }

    // rev.9 S-009: when ordered_secrets is provided, the block is being
    // built for finalization (try_finalize_round) — populate
    // creator_dh_secrets and recompute delay_output as
    // SHA256(delay_seed || ordered_secrets). When empty, the block is
    // being built for a Phase-2 candidate digest sign (delay_output
    // isn't in the digest, so its value at this stage is irrelevant —
    // we still set it to the caller-provided value for compatibility,
    // but signers don't bind it).
    if (!ordered_secrets.empty())
        b.creator_dh_secrets = ordered_secrets;

    // tx_root = union of K-committee tx_hashes lists. Same rule for both
    // K=M_pool (strong) and K<M_pool (hybrid). Censorship requires every
    // committee member to omit. Intersection is preserved as a helper for
    // v2 / specialized chains but is not used in v1.
    (void)m_pool_size;
    b.tx_root        = compute_tx_root(b.creator_tx_lists);
    b.delay_seed     = compute_delay_seed(b.index, b.prev_hash, b.tx_root, b.creator_dh_inputs);
    // rev.9 S-009: if secrets supplied (finalize path), derive delay_output
    // from them. Otherwise (Phase-2 candidate digest), leave delay_output as
    // caller-provided — block_digest excludes delay_output anyway.
    b.delay_output   = ordered_secrets.empty()
                        ? delay_output
                        : compute_block_rand(b.delay_seed, ordered_secrets);
    b.consensus_mode = mode;
    b.bft_proposer   = bft_proposer_domain;

    // cumulative_rand derives from the actual block delay_output (which
    // is the commit-reveal output when secrets are populated, else the
    // caller-provided value). Using b.delay_output keeps the validator
    // and producer in sync regardless of which path set it.
    Hash prev_rand = chain.empty() ? Hash{} : chain.head().cumulative_rand;
    b.cumulative_rand = SHA256Builder{}
        .append(prev_rand)
        .append(b.delay_output)
        .finalize();

    // Resolve hashes to actual txs. The canonical set is the union of K
    // committee tx_hashes lists — a tx is included if any committee member
    // has it. Censorship requires ALL K to collude (K-conjunction within
    // the committee); rotation gives liveness over the M_pool.
    std::set<Hash> selected_hashes;
    for (auto& list : b.creator_tx_lists)
        for (auto& h : list) selected_hashes.insert(h);

    std::vector<Transaction> ordered;
    ordered.reserve(selected_hashes.size());
    for (auto& h : selected_hashes) {
        auto it = tx_store.find(h);
        if (it != tx_store.end()) ordered.push_back(it->second);
    }
    std::sort(ordered.begin(), ordered.end(),
        [](const Transaction& a, const Transaction& b_) {
            if (a.from  != b_.from)  return a.from  < b_.from;
            if (a.nonce != b_.nonce) return a.nonce < b_.nonce;
            return a.hash < b_.hash;
        });

    std::map<std::string, uint64_t> bal, nonces, locked;
    auto get_bal = [&](const std::string& d) -> uint64_t& {
        auto it = bal.find(d);
        if (it == bal.end()) it = bal.emplace(d, chain.balance(d)).first;
        return it->second;
    };
    auto get_nonce = [&](const std::string& d) -> uint64_t& {
        auto it = nonces.find(d);
        if (it == nonces.end()) it = nonces.emplace(d, chain.next_nonce(d)).first;
        return it->second;
    };
    auto get_locked = [&](const std::string& d) -> uint64_t& {
        auto it = locked.find(d);
        if (it == locked.end()) it = locked.emplace(d, chain.stake(d)).first;
        return it->second;
    };

    auto decode_amount = [](const std::vector<uint8_t>& p) -> uint64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8 && i < (int)p.size(); ++i) v |= uint64_t(p[i]) << (8 * i);
        return v;
    };

    for (auto& tx : ordered) {
        uint64_t& nn = get_nonce(tx.from);
        if (tx.nonce != nn) continue;

        uint64_t& sb = get_bal(tx.from);
        switch (tx.type) {
        case TxType::PQ_TRANSFER:   // §3.21: identical build-body semantics to TRANSFER
        case TxType::TRANSFER: {
            uint64_t cost = tx.amount + tx.fee;
            if (sb < cost) continue;
            sb -= cost;
            // rev.9 B3.2: cross-shard TRANSFERs are debited locally and
            // emit a receipt for delivery to the destination shard. The
            // local credit is suppressed (the destination shard credits
            // `to` after verifying the receipt against this block in
            // Stage B3.4).
            if (chain.is_cross_shard(tx.to)) {
                CrossShardReceipt r;
                r.src_shard       = chain.my_shard_id();
                r.dst_shard       = crypto::shard_id_for_address(
                                        tx.to, chain.shard_count(), chain.shard_salt());
                r.src_block_index = b.index;
                // src_block_hash stays zero in the on-chain stored
                // receipt (it would be circular — receipts are part of
                // the block hash). Filled in by the gossip-bundle layer
                // (B3.3) at relay time, derived from the produced block.
                r.tx_hash = tx.hash;
                r.from    = tx.from;
                r.to      = tx.to;
                r.amount  = tx.amount;
                r.fee     = tx.fee;
                r.nonce   = tx.nonce;
                b.cross_shard_receipts.push_back(r);
            } else {
                get_bal(tx.to) += tx.amount;
            }
            break;
        }
        case TxType::REGISTER:
        case TxType::DEREGISTER: {
            if (sb < tx.fee) continue;
            sb -= tx.fee;
            break;
        }
        case TxType::STAKE: {
            if (tx.payload.size() != 8) continue;
            uint64_t amount = decode_amount(tx.payload);
            uint64_t cost   = amount + tx.fee;
            if (sb < cost) continue;
            sb -= cost;
            get_locked(tx.from) += amount;
            break;
        }
        case TxType::UNSTAKE: {
            if (tx.payload.size() != 8) continue;
            uint64_t amount = decode_amount(tx.payload);
            if (sb < tx.fee) continue;
            uint64_t& lk = get_locked(tx.from);
            if (lk < amount) continue;
            // S-017: skip too-early UNSTAKE so it doesn't reach validators
            // (which now also reject it — see validator.cpp UNSTAKE branch).
            // Apply-time refund branch in chain.cpp remains as a defense
            // against tx-included-by-buggy-producer paths.
            if (b.index < chain.stake_unlock_height(tx.from)) continue;
            sb -= tx.fee;
            break;
        }
        case TxType::SHIELD: {
            // §3.22 transparent->confidential on-ramp: debit (amount + fee);
            // NO transparent credit (value moves into the confidential pool).
            uint64_t cost = tx.amount + tx.fee;
            if (sb < cost) continue;
            sb -= cost;
            break;
        }
        case TxType::UNSHIELD: {
            // §3.22b confidential->transparent withdraw: NO transparent debit
            // (value comes from the confidential pool); credit tx.to with
            // amount - fee. Provisional — apply re-checks note membership + the
            // context-bound proof and removes the note (its own nullifier).
            if (tx.amount < tx.fee) continue;
            if (chain.is_cross_shard(tx.to)) continue;   // §3.22b single-shard only (v1)
            get_bal(tx.to) += tx.amount - tx.fee;
            break;
        }
        case TxType::CONFIDENTIAL_TRANSFER:
            // §3.22c pool -> pool: no transparent debit/credit (the public fee
            // moves from the confidential pool to creators at apply). Provisional
            // accounting is a no-op; apply verifies the bundle + consumes/produces
            // the notes authoritatively.
            break;
        case TxType::ROTATE_AUDIT_KEY:
        case TxType::LOG_AUDIT_ACCESS: {
            // A2 audit txs are fee-only (validator enforces amount==0/to empty);
            // provisional accounting debits just the fee.
            if (sb < tx.fee) continue;
            sb -= tx.fee;
            break;
        }
        }
        nn++;
        b.transactions.push_back(tx);
    }

    // rev.9 B3.4: bake inbound receipts addressed to this shard. Skip
    // any receipt already credited (replayed bundle) or addressed to a
    // different shard (defensive — Node should pre-filter, but the
    // chain check is canonical).
    // v2.7 F2 / S-016 (site 3): when F2 is active, restrict the inbound set to
    // the committee-wide intersection of the members' committed Phase-1 views.
    // A receipt not in EVERY committee member's view waits for a later block
    // where it is unanimous — the deterministic Option-1 rule that replaces the
    // Option-2 local first-seen latency heuristic. Pre-activation: no filter.
    bool f2_active = (b.index >= chain.f2_active_from_height());
    std::set<Hash> f2_inbound_intersection;
    if (f2_active) {
        auto isect = reconcile_intersection(b.creator_view_inbound_lists);
        f2_inbound_intersection.insert(isect.begin(), isect.end());
    }
    for (auto& r : inbound_receipts) {
        if (r.dst_shard != chain.my_shard_id()) continue;
        if (chain.inbound_receipt_applied(r.src_shard, r.tx_hash)) continue;
        if (f2_active
            && !f2_inbound_intersection.count(hash_cross_shard_receipt(r)))
            continue;
        b.inbound_receipts.push_back(r);
    }

    return b;
}

} // namespace determ::node
