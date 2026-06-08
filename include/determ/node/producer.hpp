// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/chain/block.hpp>
#include <determ/chain/chain.hpp>
#include <determ/crypto/keys.hpp>
#include <determ/types.hpp>
#include <map>
#include <string>
#include <vector>

namespace determ::node {

// ─── Phase 1 — TxCommit + DhInput (combined) ─────────────────────────────────
// Each committee member broadcasts their proposed tx_hashes plus a fresh
// dh_input (32 random bytes), Ed25519-signed. The union of K tx_hashes lists
// is the canonical tx set; the K dh_inputs combine into the delay-hash seed.
struct ContribMsg {
    uint64_t           block_index{0};
    std::string        signer;
    Hash               prev_hash{};
    // Number of AbortEvents the sender has seen so far at this height. Used
    // for runtime generation matching: peers ignore contribs from a different
    // generation than their own. Different gens never share a beacon.
    uint64_t           aborts_gen{0};
    std::vector<Hash>  tx_hashes;     // sorted ascending
    Hash               dh_input{};    // fresh 32 B

    // ─── v2.7 F2 view-reconciliation fields ────────────────────────────────
    //
    // Per docs/proofs/F2-SPEC.md §Q1/Q3/Q4: each committee member commits
    // to their view of three pool-fed fields at Phase-1 commit time. The
    // roots bind the member to their committed view (no equivocation
    // between Phase-1 commit and Phase-2 reveal). The actual lists travel
    // alongside so the validator can re-derive the canonical reconciled
    // list AND verify each member's Merkle binding.
    //
    // Per F2-SPEC.md §Q3 bandwidth budget: each list is capped at 64
    // entries per member (the validator's V-check enforces this).
    //
    // Backward-compatibility: pre-F2 ContribMsg JSON omits these fields;
    // the JSON roundtrip defaults them to zero-hash / empty-vector. Pre-
    // F2 commit-signature compatibility is preserved by the rule that
    // make_contrib_commitment() falls back to the v1 hash when ALL three
    // view-roots are zero. The validator's V21..V26 checks fire only
    // when v2_7_f2_active_from_height (genesis-pinned) is reached.
    Hash               view_eq_root{};      // root over sorted equivocation_events view
    Hash               view_abort_root{};   // root over sorted abort_events view
    Hash               view_inbound_root{}; // root over sorted inbound_receipts view
    std::vector<Hash>  view_eq_list;        // sorted, capped at 64 per Q3
    std::vector<Hash>  view_abort_list;     // sorted, capped at 64 per Q3
    std::vector<Hash>  view_inbound_list;   // sorted, capped at 64 per Q3
    // ─── end v2.7 F2 ────────────────────────────────────────────────────────

    // ─── S-030-D2 timestamp reconciliation field ────────────────────────────
    // Each committee member commits its local wall-clock (now_unix) at Phase-1
    // commit time. At the Phase 1→2 boundary the assembler reconciles the K
    // committed times to a deterministic LOWER-MEDIAN (build_body), sets it as
    // the canonical block timestamp, and compute_block_digest binds that
    // timestamp — closing the last S-030-D2 ✗ row. Bound into
    // make_contrib_commitment ONLY when non-zero (legacy/test contribs with
    // proposer_time == 0 keep the byte-identical v1 commitment). Per
    // S030-D2-Analysis.md §5: a raw timestamp cannot be digest-bound because
    // honest clocks differ within the validator's ±30s window; committing each
    // member's time in Phase-1 (signed) and reconciling to the median makes the
    // bound value a deterministic function of the K signed commits — every
    // honest assembler computes the identical digest, no spurious round aborts.
    // The lower-median (sorted[(K-1)/2]) is robust: under f < K/3 it always
    // lands within the honest-clock spread.
    uint64_t           proposer_time{0};
    // ─── end S-030-D2 timestamp reconciliation ───────────────────────────────

    Signature          ed_sig{};      // Ed25519 over commit message

    nlohmann::json    to_json() const;
    static ContribMsg from_json(const nlohmann::json& j);
};

// ─── S7 — AbortClaim ─────────────────────────────────────────────────────────
// When a creator's local timer fires with fewer than M valid contributions
// (Phase 1) or block-sigs (Phase 2), they sign and broadcast an AbortClaim
// naming the first missing creator in selection order. M-1 matching claims
// form a quorum certificate that can advance the round; this prevents
// unilateral abort-blame divergence across peers.
struct AbortClaimMsg {
    uint64_t    block_index{0};
    uint8_t     round{0};         // 1 = CONTRIB phase, 2 = BLOCK_SIG phase
    Hash        prev_hash{};
    std::string missing_creator;
    std::string claimer;
    Signature   ed_sig{};         // Ed25519 over the abort_claim_message digest

    nlohmann::json    to_json() const;
    static AbortClaimMsg from_json(const nlohmann::json& j);
};

// Domain-separated commitment that each AbortClaim's Ed25519 sig covers.
Hash make_abort_claim_message(uint64_t block_index, uint8_t round,
                               const Hash& prev_hash,
                               const std::string& missing_creator);

AbortClaimMsg make_abort_claim(const crypto::NodeKey& key,
                                const std::string& claimer,
                                uint64_t block_index, uint8_t round,
                                const Hash& prev_hash,
                                const std::string& missing_creator);

// ─── Phase 2 — BlockSig (after local delay-hash completes) ───────────────────
// Each committee member publishes the revealed Phase-1 secret and an
// Ed25519 sig over the block digest. K parallel Ed25519 sigs authenticate
// the block; each peer's revealed secret is bound to that peer's Phase-1
// commit (carried as ContribMsg.dh_input = SHA256(secret || pubkey)).
//
// rev.9 S-009 closure: dh_secret is the commit-reveal mechanism that
// replaces the SHA-256^T delay function. The selective-abort defense
// shifts from compute-time (T iterations of SHA-256) to information-
// theoretic (SHA-256 preimage resistance — an attacker cannot extract
// any honest member's secret from its commit).
//
// delay_output = SHA256(delay_seed || ordered_secrets) is recomputed by
// every node at finalize time; it's no longer in compute_block_digest
// (so members can sign at Phase-2 entry without waiting for K-1 peer
// secrets to gather first).
struct BlockSigMsg {
    uint64_t              block_index{0};
    std::string           signer;
    Hash                  delay_output{};
    Hash                  dh_secret{};   // rev.9 S-009: revealed secret
    Signature             ed_sig{};      // Ed25519 over block_digest

    nlohmann::json    to_json() const;
    static BlockSigMsg from_json(const nlohmann::json& j);
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Domain-separated commitment that each creator's Ed25519 sig covers in Phase 1.
//
// v2.7 F2 extension: three view roots bound into the commit per F2-SPEC.md §Q4.
// Default zero values preserve byte-identical commitment with the v1 (pre-F2)
// commit shape for backward-compat. When `v2_7_f2_active_from_height` is
// reached, the producer populates all three roots from its local pool snapshots
// and the validator binds against them.
//
// The "all-zero ⇒ v1 commit" rule is structural, not flag-based: if a caller
// passes zero hashes (no F2 view bound), the inner builder appends them but
// the result is bit-identical to what the v1 builder would produce if the
// v1 builder were extended with three null appends. To preserve EXACT v1
// hashes for legacy peers, callers MUST NOT include the view-root args
// (they're trailing default-zero); the implementation has an explicit
// short-circuit when all three roots are zero (= v1 path).
Hash make_contrib_commitment(uint64_t block_index, const Hash& prev_hash,
                              const std::vector<Hash>& sorted_tx_hashes,
                              const Hash& dh_input,
                              const Hash& view_eq_root = Hash{},
                              const Hash& view_abort_root = Hash{},
                              const Hash& view_inbound_root = Hash{},
                              // S-030-D2: each member's committed local time.
                              // Bound ONLY when non-zero — a zero keeps the
                              // byte-identical pre-feature commitment, exactly
                              // like the all-zero view-root short-circuit above.
                              uint64_t proposer_time = 0);

// Canonical tx_root: union of K-committee tx_hashes lists. Used in strong
// mode (K=M_pool, every creator on committee) — censorship requires every
// creator to omit a tx.
Hash compute_tx_root(const std::vector<std::vector<Hash>>& creator_tx_lists);

// S-030-D2: deterministic lower-median of the K committed proposer times —
// the canonical block timestamp. sorted[(K-1)/2]; 0 for empty input. Robust
// under f < K/3 (the chosen order statistic is honest-flanked). The producer
// (build_body), the validator, and the light client all call this so they
// agree on the bound timestamp byte-for-byte.
uint64_t reconcile_median_time(const std::vector<uint64_t>& times);

// ─── v2.7 F2 view reconciliation helpers ───────────────────────────────────
//
// Per `docs/proofs/F2-SPEC.md`, F2 closes the consensus-layer view of
// S-030 D2. Each committee member commits to their view of three pool-fed
// fields at Phase-1 commit time via Merkle roots over sorted contents;
// the validator re-derives the canonical list via per-field reconciliation
// rules (Q1: union for equivocation_events + abort_events, intersection
// for inbound_receipts). These helpers are the deterministic primitives.
//
// `compute_view_root(items)` is the canonical Merkle root over a sorted
// SET of hash-typed items. Sorting is via the existing `Hash` `operator<`
// (lexicographic on the 32 bytes). The result is bound into the
// extended `make_contrib_commitment` so members can't equivocate on
// their committed view between Phase-1 commit and Phase-2 reveal.

// View root over a sorted SET of hashes (canonical, dedup'd).
Hash compute_view_root(const std::vector<Hash>& items);

// Union reconciliation across K committee members' lists (used for
// equivocation_events + abort_events per Q1). Returns the deduplicated
// union in canonical sorted order.
std::vector<Hash> reconcile_union(
    const std::vector<std::vector<Hash>>& member_lists);

// Intersection reconciliation across K committee members' lists (used
// for inbound_receipts per Q1). Returns hashes present in ALL K lists,
// in canonical sorted order. Empty result when K < 1 or when any list
// is empty (every credit must be witnessed by every member).
std::vector<Hash> reconcile_intersection(
    const std::vector<std::vector<Hash>>& member_lists);

// === F2 per-record canonical hashes (sub-step 2 prep) ===
//
// The view-lists in ContribMsg are `std::vector<Hash>`, where each Hash
// is the canonical hash of one EquivocationEvent / AbortEvent /
// CrossShardReceipt. These helpers materialize those hashes from the
// in-memory structs so the producer can snapshot pending_* pools at
// Phase-1 and hash each entry into the view list.
//
// Domain-separated to defeat cross-struct collision (an EquivocationEvent
// hashing to the same Hash as an AbortEvent would let an attacker craft
// a contrib whose view_eq_root incorrectly matches a list of mixed
// types). Each helper prefixes its SHA256Builder with a unique
// `DTM-F2-<TYPE>-v1` domain tag.
//
// Field selection: all consensus-bound fields of each struct, in
// declared order. Optional / forensic-only fields (e.g.,
// EquivocationEvent's beacon_anchor_height which is "not consumed by
// validator correctness checks" per the block.hpp comment) are still
// included — F2 hashes a member's COMPLETE observation, and any peer
// observing the same struct should produce the same Hash.

Hash hash_equivocation_event(const chain::EquivocationEvent& e);
Hash hash_abort_event(const chain::AbortEvent& e);
Hash hash_cross_shard_receipt(const chain::CrossShardReceipt& r);

// === Validator-side F2 checks (V21..V26 per F2-SPEC.md) ===
//
// These helpers are pure functions: no consensus-state dependency, so
// they unit-test in isolation. The eventual validator integration (sub-
// step 3 wire-in) calls them from the existing per-contrib + per-block
// V-check pass and emits the appropriate reject reason.

// Per-contrib bandwidth cap on view lists (F2-SPEC.md §Q3). The validator
// rejects any contrib whose claimed view_X_list exceeds this; bounded
// gossip cost is part of F2's safety story.
inline constexpr size_t F2_VIEW_LIST_CAP = 64;

// V21..V24: per-contrib well-formedness + Merkle binding.
//
//   V21: each view_X_list.size() <= F2_VIEW_LIST_CAP (bandwidth budget)
//   V22: view_eq_root      == compute_view_root(view_eq_list)
//   V23: view_abort_root   == compute_view_root(view_abort_list)
//   V24: view_inbound_root == compute_view_root(view_inbound_list)
//
// Returns true if all four checks pass; sets `*reason` (when non-null)
// to a short human-readable reject reason on failure. Treats the v1-
// compat case (all roots zero AND all lists empty) as valid no-op so
// pre-F2 contribs received at heights below the genesis activation gate
// trivially pass this check.
bool validate_contrib_view_roots(const ContribMsg& msg,
                                  std::string* reason = nullptr);

// Derive the canonical view lists from K contributors' per-field views,
// per F2-SPEC.md §Q1 reconciliation rules:
//
//   equivocation_events : union (one observer suffices)
//   abort_events        : union (one observer suffices)
//   inbound_receipts    : intersection (every member must witness)
//
// Returns the three reconciled lists in canonical sorted order. The
// validator compares these to the block body's eq/abort/inbound fields
// in V25..V26.
struct F2CanonicalViews {
    std::vector<Hash> equivocation_events;  // union over contribs
    std::vector<Hash> abort_events;          // union over contribs
    std::vector<Hash> inbound_receipts;      // intersection over contribs
};
F2CanonicalViews derive_canonical_view_lists(
    const std::vector<ContribMsg>& contribs);

// V25..V26: composite per-block check — every contrib passes V21..V24
// AND the canonical lists in the block body match the F2 reconciliation
// of the contribs' views.
//
//   V25: block.equivocation_events == reconcile_union  (across views)
//   V26: block.abort_events        == reconcile_union  (across views)
//        block.inbound_receipts    == reconcile_intersection
//
// `block_eq` / `block_abort` / `block_inbound` are the canonical lists
// as proposed by the block assembler. The validator extracts these from
// the block body (block.equivocation_events.hash_each() etc.) before
// calling this helper — the helper itself stays Hash-list-shaped so
// it's wire-format agnostic. Returns true iff all checks pass; sets
// `*reason` to a diagnostic on failure.
bool validate_view_reconciliation(
    const std::vector<ContribMsg>& contribs,
    const std::vector<Hash>& block_eq,
    const std::vector<Hash>& block_abort,
    const std::vector<Hash>& block_inbound,
    std::string* reason = nullptr);

// ─── end v2.7 F2 helpers ───────────────────────────────────────────────────

// S-025 (deleted in-session): compute_tx_root_intersection was a relic
// of the pre-v1 design where canonical tx set was the intersection of
// K committee members' lists. v1 settled on union semantics (censorship
// requires ALL K to omit). The intersection helper was unused and
// removed to reduce confusion. If a future v2 mode wants intersection
// semantics, re-introduce it then.

// Delay-hash seed — combined DH inputs in selection order, anchored to
// (idx, prev, tx_root).
Hash compute_delay_seed(uint64_t block_index, const Hash& prev_hash,
                         const Hash& tx_root,
                         const std::vector<Hash>& creator_dh_inputs);

// Phase 2 sig domain: hash that each creator_block_sigs[i] covers. Includes
// every consensus-critical field of the block so equivocation on any of them
// produces an unverifiable sig.
Hash compute_block_digest(const chain::Block& b);

// rev.9 S-009: post-Phase-2 randomness output. delay_output is computed
// from delay_seed (Phase-1 inputs commitment) plus the K revealed
// secrets. ordered_secrets[i] must correspond to creators[i] (same
// committee selection order as creator_dh_inputs).
Hash compute_block_rand(const Hash& delay_seed,
                          const std::vector<Hash>& ordered_secrets);

// rev.8 BFT-mode designated proposer. Deterministic from
// (prev_cumulative_rand ‖ abort_event_hashes) so the proposer rotates across
// abort retries within the same height. Only used when consensus_mode == BFT.
size_t proposer_idx(const Hash& prev_cum_rand,
                    const std::vector<chain::AbortEvent>& aborts,
                    size_t committee_size);

// Count round-1 (Phase 1) AbortEvents — used to decide whether a round
// should escalate to BFT. Only round-1 aborts count (round-2 are timing-skew
// noisy, same reason suspension only counts round-1).
size_t count_round1_aborts(const std::vector<chain::AbortEvent>& aborts);

// Required signature count for a given mode + committee size.
//   MD  → all K
//   BFT → ceil(2K/3)
size_t required_block_sigs(chain::ConsensusMode mode, size_t committee_size);

// Build a signed ContribMsg for this node's Phase-1 commit.
//
// v2.7 F2 forward-compat (sub-step 2 partial): the optional view-list
// args carry this member's per-field view at Phase-1 commit time. When
// any of the three lists is non-empty, the produced ContribMsg:
//   - has its view_X_list field set to the sorted+deduped input
//   - has its view_X_root field set to compute_view_root(view_X_list)
//   - is signed over the extended make_contrib_commitment (which prepends
//     the DTM-F2-v1 domain separator + binds the three roots)
//
// When ALL three lists are empty (the default — pre-F2 contribs and
// F2-not-yet-active heights), the produced ContribMsg has zero-Hash
// view_X_roots + empty view_X_lists, and the commit hash falls back
// to the v1 short-circuit (byte-identical to pre-F2 commits). Pre-
// existing callers do not need to change.
//
// The caller (typically `Node::start_contrib_round`) is responsible
// for the height-gate logic: when `block_index < v2_7_f2_active_from_height`
// the caller passes empty lists; at heights >= activation the caller
// snapshots pending_equivocation_evidence_ / pending_abort_records_ /
// pending_inbound_receipts_, hashes their entries, and passes the
// resulting Hash vectors.
ContribMsg make_contrib(const crypto::NodeKey& key,
                         const std::string& domain,
                         uint64_t block_index,
                         const Hash& prev_hash,
                         uint64_t aborts_gen,
                         const std::vector<Hash>& tx_snapshot,
                         const Hash& dh_input,
                         const std::vector<Hash>& view_eq_list      = {},
                         const std::vector<Hash>& view_abort_list   = {},
                         const std::vector<Hash>& view_inbound_list = {},
                         // S-030-D2: the committing member's local wall-clock
                         // (now_unix). Stored in the ContribMsg + bound into the
                         // Phase-1 commitment when non-zero. Default 0 = legacy /
                         // test contribs (byte-identical v1 commitment).
                         uint64_t proposer_time = 0);

BlockSigMsg make_block_sig(const crypto::NodeKey& key,
                            const std::string& domain,
                            uint64_t block_index,
                            const Hash& delay_output,
                            const Hash& block_digest,
                            const Hash& dh_secret);

// Build the canonical block body. `m_pool_size` is the chain-wide registered
// pool size from genesis (cfg_.m_creators); the K-committee is the size of
// `creator_domains`/`contribs`. tx_root is always the union of K hash lists.
//
// `mode` and `bft_proposer_domain` are written into the block. In MD mode,
// `bft_proposer_domain` must be empty. In BFT mode it must be the
// deterministically-chosen proposer (the caller computes via proposer_idx).
//
// `equivocation_events` (rev.8 follow-on) bakes any equivocation evidence the
// node has assembled into this block. The validator verifies the two-sig
// proof; on apply, each equivocator's stake is fully forfeited.
chain::Block build_body(
    const std::map<Hash, chain::Transaction>& tx_store,
    const chain::Chain&                       chain,
    const std::vector<chain::AbortEvent>&     aborts,
    const std::vector<std::string>&           creator_domains,
    const std::vector<ContribMsg>&            contribs,        // K, in selection order
    const Hash&                               delay_output,
    uint32_t                                  m_pool_size,
    chain::ConsensusMode                      mode = chain::ConsensusMode::MUTUAL_DISTRUST,
    const std::string&                        bft_proposer_domain = "",
    const std::vector<chain::EquivocationEvent>& equivocation_events = {},
    // rev.9 B3.4: inbound cross-shard receipts available to bake into
    // this block. Producer dedupes against the chain's
    // inbound_receipt_applied() set and includes those addressed to
    // this shard. SINGLE / BEACON producers should pass empty.
    const std::vector<chain::CrossShardReceipt>& inbound_receipts = {},
    // rev.9 S-009: ordered Phase-2 secret reveals (one per committee
    // member, same order as creator_domains). Empty when called for a
    // pre-Phase-2 tentative digest computation; populated at finalize
    // when K BlockSigMsgs have arrived. delay_output is recomputed
    // from these (compute_block_rand) when non-empty.
    const std::vector<Hash>&                  ordered_secrets = {});

} // namespace determ::node
