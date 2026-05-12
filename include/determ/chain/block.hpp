// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/types.hpp>
#include <determ/crypto/keys.hpp>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <nlohmann/json.hpp>

namespace determ::chain {

// Consensus mode for a block. Per-height escalation: shards default to
// MUTUAL_DISTRUST and escalate to BFT after `bft_escalation_threshold`
// consecutive Phase-1 aborts at the same height. Single-chain v1 also
// uses MUTUAL_DISTRUST as the steady state.
enum class ConsensusMode : uint8_t {
    MUTUAL_DISTRUST = 0,    // K-of-K within committee, unconditional safety
    BFT             = 1,    // ceil(2K/3) + designated proposer, safe under f<N/3
};

enum class TxType : uint8_t {
    TRANSFER       = 0,
    REGISTER       = 1,
    DEREGISTER     = 2,
    STAKE          = 3,
    UNSTAKE        = 4,
    // rev.9 R1: reserved for v2 epoch-boundary region rebalancing
    // (Resolved decision #1 in plan.md, Path A). NO apply path in
    // v1.x — validator unconditionally rejects with a clear "reserved
    // for future use" error. Locks the wire-format slot so v2 can
    // ship without a tx-format break.
    REGION_CHANGE  = 5,
    // A5: governance parameter-change tx. Valid only under
    // `governance_mode = governed` (genesis-pinned). Carries
    // `(parameter_name, new_value, effective_height)` plus a vector of
    // (keyholder_index, ed_sig) pairs whose count meets/exceeds
    // `param_threshold` (default N-of-N over `param_keyholders`).
    // Payload encoding (canonical, little-endian where noted):
    //   [name_len: u8][name: utf8]
    //   [value_len: u16 LE][value: bytes]
    //   [effective_height: u64 LE]
    //   [sig_count: u8]
    //   sig_count × { [keyholder_index: u16 LE][ed_sig: 64B] }
    // Off-whitelist parameter names → rejected. Mode=uncontrolled →
    // rejected. Insufficient threshold → rejected.
    PARAM_CHANGE   = 6,
    // R4 (under-quorum merge): a beacon-emitted event that announces
    // a shard temporarily merging its committee operations with its
    // modular-next shard, or reverting from such a merge. Valid only
    // under EXTENDED sharding mode + BEACON chain role; rejected
    // elsewhere. Payload encoding (canonical, LE where noted):
    //   [event_type: u8]            // 0 = MERGE_BEGIN, 1 = MERGE_END
    //   [shard_id: u32 LE]
    //   [partner_id: u32 LE]        // must == (shard_id + 1) mod num_shards
    //   [effective_height: u64 LE]
    //   [evidence_window_start: u64 LE]   // BEGIN only; 0 for END
    // Authentication piggybacks on the enclosing beacon block's K-of-K
    // signatures — no per-tx multisig. Witness-window validation
    // (S-036 mitigation) lives in BlockValidator: for MERGE_BEGIN, the
    // historical beacon block contents over [evidence_window_start,
    // evidence_window_start + merge_threshold_blocks) must support the
    // trigger condition (no SHARD_TIP_s + eligible_in_region < 2K).
    MERGE_EVENT    = 7,
};

struct Transaction {
    TxType               type{TxType::TRANSFER};
    std::string          from;
    std::string          to;
    uint64_t             amount{0};
    uint64_t             fee{0};
    uint64_t             nonce{0};
    std::vector<uint8_t> payload;
    Signature            sig{};
    Hash                 hash{};

    std::vector<uint8_t> signing_bytes() const;
    Hash                 compute_hash() const;

    nlohmann::json       to_json() const;
    static Transaction   from_json(const nlohmann::json& j);
};

// Forward declaration — full struct lives in node/producer.hpp.
} // namespace determ::chain
namespace determ::node { struct AbortClaimMsg; }
namespace determ::chain {

struct AbortEvent {
    uint8_t     round{0};
    std::string aborting_node;
    int64_t     timestamp{0};
    Hash        event_hash{};

    // S7: each AbortEvent carries the M-1 signed AbortClaimMsgs that
    // authorized it. Encoded inline as JSON so block.cpp doesn't need to
    // include node/producer.hpp.
    nlohmann::json claims_json;

    nlohmann::json    to_json() const;
    static AbortEvent from_json(const nlohmann::json& j);
};

// rev.8 follow-on: full equivocation slashing. An EquivocationEvent is
// proof that `equivocator` signed two conflicting BlockSigMsgs at the same
// `block_index` — i.e., signed two different `block_digest`s with the same
// Ed25519 key. When baked into a finalized block, the equivocator's full
// staked balance is forfeited on apply (much harsher than the
// SUSPENSION_SLASH economic disincentive — equivocation is a deliberate
// double-sign attack, not just absence).
//
// The two signed messages live inline (digest_a + sig_a, digest_b + sig_b)
// so any node can independently verify the event by checking both sigs
// against the equivocator's registered Ed25519 key. The validator rejects
// events where digest_a == digest_b (no equivocation), or the two sigs
// don't both verify, or the equivocator isn't registered.
struct EquivocationEvent {
    std::string equivocator;          // domain whose key signed both digests
    uint64_t    block_index{0};       // height at which equivocation occurred
    Hash        digest_a{};
    Signature   sig_a{};
    Hash        digest_b{};
    Signature   sig_b{};

    // rev.9 B2c.4: cross-chain provenance. When the equivocation is
    // detected on a shard chain, these record which shard observed it
    // and which beacon block was the anchor for that shard's epoch at
    // detection time. Used for forensic trace + governance audits;
    // not consumed by validator correctness checks (the two-sig proof
    // is independently verifiable against the equivocator's
    // beacon-registered Ed25519 key, regardless of where it was first
    // observed).
    //   shard_id == 0 AND beacon_anchor_height == 0 → SINGLE chain or
    //   beacon-side detection (default). Nonzero → shard-detected.
    uint32_t    shard_id{0};
    uint64_t    beacon_anchor_height{0};

    nlohmann::json           to_json() const;
    static EquivocationEvent from_json(const nlohmann::json& j);
};

// rev.9 B3: cross-shard receipt. Emitted by a source-shard block when
// a TRANSFER's `to` address routes (via shard_id_for_address) to a
// different shard. Carries the full source-shard provenance so the
// destination shard can verify the receipt was actually produced by
// the source's K-of-K committee:
//   * src_block_index + src_block_hash pin the producing block.
//   * tx_hash + (from, to, amount, fee, nonce) duplicate the originating
//     tx fields so dst can match against src's transactions[].
// Verification (Stage B3.4):
//   1. dst node has src's committee (derivable from beacon-anchored
//      pool + epoch_committee_seed for src_shard).
//   2. dst loads the source block (via beacon's shard_summaries or a
//      direct request); verifies K-of-K sigs against src's committee.
//   3. tx_hash is present in src_block.transactions[] with matching
//      fields.
// Once verified, dst credits `to` with `amount` (sender debit + fee
// burn already happened on src). Idempotent on (src_shard, tx_hash).
// R4: canonical MERGE_EVENT payload. Encoded/decoded by free helpers
// below; the apply path + validator both use these to avoid duplicate
// byte-counting logic.
//
// Wire format (variable size = 26 + region_len):
//   [event_type: u8]            // 0 = BEGIN, 1 = END
//   [shard_id: u32 LE]
//   [partner_id: u32 LE]
//   [effective_height: u64 LE]
//   [evidence_window_start: u64 LE]
//   [merging_shard_region_len: u8]
//   [merging_shard_region: utf8 bytes, len bytes]
//
// merging_shard_region is the refugee shard's committee_region tag.
// It lets the partner shard's producer + validator extend their
// eligible pool with refugee validators (Phase 4 stress branch) WITHOUT
// requiring shards to load the global shard manifest. The region is
// normalized to lowercase ASCII at validate time and constrained to
// the same [a-z0-9-_], <= 32 bytes rule used elsewhere.
//
// Empty region (region_len == 0) is valid when refugee shard runs in
// CURRENT mode or uses the global pool. END events have region empty
// since the partner stops absorbing.
struct MergeEvent {
    enum Type : uint8_t { BEGIN = 0, END = 1 };
    uint8_t      event_type{BEGIN};
    uint32_t     shard_id{0};
    uint32_t     partner_id{0};
    uint64_t     effective_height{0};
    uint64_t     evidence_window_start{0};   // BEGIN only; 0 for END
    std::string  merging_shard_region{};     // refugee shard's region

    // Canonical serialization. signing_bytes-style: order + endianness
    // fixed, no version byte (locked by TxType::MERGE_EVENT).
    std::vector<uint8_t> encode() const;
    // Decode the canonical form. Returns std::nullopt on size mismatch,
    // invalid event_type, or region_len exceeding 32. Used by Apply
    // + Validator.
    static std::optional<MergeEvent> decode(const std::vector<uint8_t>& p);
};

struct CrossShardReceipt {
    ShardId      src_shard{0};
    ShardId      dst_shard{0};
    uint64_t     src_block_index{0};
    Hash         src_block_hash{};
    Hash         tx_hash{};
    std::string  from;
    std::string  to;
    uint64_t     amount{0};
    uint64_t     fee{0};
    uint64_t     nonce{0};

    nlohmann::json    to_json() const;
    static CrossShardReceipt from_json(const nlohmann::json& j);
};

// Carried only by block 0 (genesis). Populates account_state, stake_table, and
// registrants_ at chain construction.
struct GenesisAlloc {
    std::string domain;
    PubKey      ed_pub{};
    uint64_t    balance{0};
    uint64_t    stake{0};
    // rev.9 R1: region tag for the seeded creator. Empty = no region
    // (legacy / global pool). Mirrors the per-validator region carried
    // in REGISTER tx payloads.
    std::string region{};

    nlohmann::json     to_json() const;
    static GenesisAlloc from_json(const nlohmann::json& j);
};

// Block produced by the K-committee via the 2-phase + delay-hash protocol:
//
//   Phase 1 (TxCommit + DhInput): each committee member signs (tx_hashes,
//     dh_input) with Ed25519. Union of tx_hashes lists is canonical.
//     Combined dh_inputs plus prev_hash + tx_root form the delay seed.
//
//   Local delay: every node computes R = delay_hash(seed, T) on a worker
//     thread. T iterations of SHA-256 — sequential by construction; an
//     attacker can't grind candidate seeds during the Phase 1 window.
//
//   Phase 2 (BlockSig): each committee member publishes delay_output and
//     an Ed25519 signature over block_digest. K parallel sigs authenticate
//     the block.
//
// Block fields:
//   - tx_root: canonical commitment to the tx set
//   - creator_tx_lists / creator_ed_sigs / creator_dh_inputs: per-committee
//                        Phase-1 evidence
//   - delay_seed / delay_output: sequential delay binding randomness to seed
//   - creator_block_sigs: K Ed25519 sigs over block_digest
struct Block {
    uint64_t                 index{0};
    Hash                     prev_hash{};
    int64_t                  timestamp{0};
    std::vector<Transaction> transactions;          // canonical (from, nonce, hash) order

    std::vector<std::string>          creators;            // K domain names, selection order
    std::vector<std::vector<Hash>>    creator_tx_lists;    // K (Phase 1 tx_hashes lists)
    std::vector<Signature>            creator_ed_sigs;     // K (Phase 1 Ed25519 over commit)
    std::vector<Hash>                 creator_dh_inputs;   // K (Phase 1 commits = SHA256(secret_i || pubkey_i))
    std::vector<Hash>                 creator_dh_secrets;  // K (Phase 2 revealed secrets)

    Hash                     tx_root{};
    Hash                     delay_seed{};
    Hash                     delay_output{};
    std::vector<Signature>   creator_block_sigs;            // K (Phase 2 Ed25519 over block_digest)

    // rev.8 per-height escalation. Default mode = MUTUAL_DISTRUST (K-of-K,
    // today's behavior). After `bft_escalation_threshold` consecutive
    // round-1 aborts at the same height, the next round escalates to BFT
    // (ceil(2K/3) sigs + designated proposer). bft_proposer is non-empty
    // iff consensus_mode == BFT. In MD blocks, every position in
    // creator_block_sigs is non-zero (full K-of-K). In BFT blocks, up to
    // K - ceil(2K/3) positions may be sentinel-zero Signature{}.
    ConsensusMode            consensus_mode{ConsensusMode::MUTUAL_DISTRUST};
    std::string              bft_proposer;                 // empty for MD blocks

    Hash                     cumulative_rand{};
    std::vector<AbortEvent>  abort_events;
    std::vector<EquivocationEvent> equivocation_events;

    // rev.9 B3: cross-shard receipts emitted by this block. When a
    // TRANSFER targets an address routed to a different shard, the
    // sender is debited locally and a receipt records the credit owed
    // to the destination shard. Empty for SINGLE chains and for any
    // block that contains only same-shard transfers. Stage B3.2 wires
    // the apply-side; B3.3-B3.4 carry receipts cross-chain and credit.
    std::vector<CrossShardReceipt> cross_shard_receipts;

    // rev.9 B3.4: inbound receipts applied by this block. When this
    // shard's producer assembles a block, it dequeues receipts whose
    // dst_shard == my_shard_id from pending_inbound_receipts_ and
    // bakes them in here. Apply credits each receipt's `to` address
    // with `amount`; (src_shard, tx_hash) is recorded in the chain's
    // applied set so a receipt is delivered exactly once even under
    // duplicate-bundle gossip. Empty for SINGLE chains.
    std::vector<CrossShardReceipt> inbound_receipts;

    // R4 Phase 3: when a merged committee produces a block on shard T
    // while absorbing shard S, the committee's K-of-K signatures cover
    // H(merged_tx_set) — the union of T's and S's tx subsets at this
    // height. Each chain publishes only its own tx subset in
    // `transactions`; the partner's subset is summarized by this
    // hash so a chain can verify its own block signature locally
    // (recompute signed digest = H(my_subset || partner_subset_hash))
    // without ever needing to see the partner's subset.
    //
    // Zero-hash (default) means "no partner" — the block was produced
    // under regular non-merged consensus. Validator (Phase 3) gates:
    //   * non-zero partner_subset_hash requires the chain to know that
    //     this shard is currently absorbing or absorbed (consult
    //     Chain::merge_state_).
    //   * zero partner_subset_hash on a chain currently in a merge
    //     transition window is also valid — merge BEGIN/END happens at
    //     effective_height boundaries; not every block in a merged
    //     window need carry the union digest (only blocks whose
    //     committee is the merged committee do).
    Hash partner_subset_hash{};

    // Populated only at index 0 (genesis). Encodes the initial accounts /
    // stakes / registry that seed the chain. Invalid for any other block.
    std::vector<GenesisAlloc> initial_state;

    std::vector<uint8_t> signing_bytes() const;
    Hash                 compute_hash() const;

    nlohmann::json to_json() const;
    static Block   from_json(const nlohmann::json& j);
};

} // namespace determ::chain
