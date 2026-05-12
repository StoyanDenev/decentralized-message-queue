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
    // v2.4 composable transactions. Outer tx is signed by a submitter
    // who pays the outer fee and consumes their next_nonce; the
    // payload is a serialized vector<Transaction> of inner txs, each
    // independently signed by its own sender. Apply path runs all
    // inner txs inside chain.atomic_scope: if any inner tx fails
    // shape, sig, balance, or nonce checks, the entire batch rolls
    // back atomically — including any state mutations from earlier
    // inner txs in the same batch. Enables:
    //   - Atomic multi-account swaps (A pays B iff B pays C)
    //   - Bid + lock + release patterns (auctions, escrow)
    //   - Bundled transfers with single-fee amortization
    //   - Multi-sig parallel approval (M signers act independently,
    //     commit iff all M land in the batch)
    //
    // Payload encoding (canonical, LE where noted):
    //   [inner_count: u16 LE]                 # 1..MAX_COMPOSABLE_INNER
    //   inner_count × Transaction (binary_codec serialized)
    //
    // Validator constraints:
    //   - inner_count in [1, MAX_COMPOSABLE_INNER]; reject empty or
    //     oversized batches at submit-time
    //   - Each inner tx must validate independently (shape + sig +
    //     known sender for non-bearer types)
    //   - Inner txs MUST NOT be COMPOSABLE_BATCH themselves (flat,
    //     no recursion — keeps the scope stack depth bounded and
    //     avoids subtle pathological cases)
    //   - Inner txs MUST have fee == 0 (outer batch pays the chain fee)
    //
    // Apply semantics:
    //   - Outer batch consumes submitter's next_nonce (one slot)
    //   - Outer fee is charged to submitter regardless of inner success
    //     (submitter paid for the BLOCK SPACE; inner failure rolls back
    //     state changes but not the fee — same model as gas in EVMs)
    //   - Inner txs are applied in array order via atomic_scope
    //   - On any inner tx failure: rollback all inner mutations,
    //     outer fee still charged, outer nonce still consumed
    //
    // Wallet-side semantics: a relayer can build a COMPOSABLE_BATCH on
    // behalf of multiple users — each user signs their inner tx
    // separately and hands it to the relayer, who packages them and
    // signs the outer envelope. No user has to trust the others;
    // signatures bind each user's intent independently.
    COMPOSABLE_BATCH = 8,
    // v2.18 (Theme 7 DApp support): register / update / deactivate a
    // DApp service. tx.from must already be a Determ registered domain
    // (REGISTER'd). The DApp registry is a sibling of registrants_ on
    // Chain; it stores discovery + encryption metadata so light clients
    // and wallets can find DApps and encrypt payloads to them. See
    // docs/V2-DAPP-DESIGN.md for the full design.
    //
    // Payload encoding (canonical, LE where noted):
    //   [op: u8]                # 0 = create/update, 1 = deactivate
    //   if op == 0:
    //     [service_pubkey: 32B] # libsodium box pubkey (E2E encryption)
    //     [endpoint_url_len: u8]
    //     [endpoint_url: utf8]  # primary discovery (https/onion/etc.)
    //     [topic_count: u8]     # <= MAX_DAPP_TOPICS
    //     topic_count × {
    //       [topic_len: u8]
    //       [topic: utf8]       # lowercase [a-z0-9._-]+, <= 64 bytes
    //     }
    //     [retention: u8]       # 0 = full, 1 = pruneable-after-K
    //     [metadata_len: u16 LE]
    //     [metadata: bytes]     # opaque DApp-defined info, <= MAX_DAPP_METADATA
    //   if op == 1:
    //     (no further bytes — tx.from identifies the entry)
    //
    // Apply: inserts/updates dapp_registry_[tx.from] for op=0; sets
    // inactive_from = current_height + DAPP_GRACE_BLOCKS for op=1.
    // No state change to other containers. DApp registry contributes
    // a "d:" namespace leaf to state_root (analogous to "r:" for
    // registrants).
    DAPP_REGISTER  = 9,
    // v2.19 (Theme 7 Phase 7.2): authenticated message to a registered
    // DApp. tx.to is the DApp's owning domain; tx.amount is an optional
    // payment that credits the DApp's account (same model as TRANSFER's
    // credit leg). The payload carries the actual application message,
    // opaque to the chain — typically encrypted to the DApp's
    // service_pubkey via libsodium sealed-box.
    //
    // Block-level ordering is canonical message ordering for the DApp.
    // Two DApp validator-nodes monitoring the chain see the same
    // sequence; each filters by tx.to == own_dapp_domain.
    //
    // Payload encoding (canonical, LE where noted):
    //   [topic_len: u8]
    //   [topic: utf8]               # routing tag; must be "" or in
    //                               # DApp's registered topics
    //   [ciphertext_len: u32 LE]
    //   [ciphertext: bytes]         # opaque to chain; size cap
    //                               # MAX_DAPP_CALL_PAYLOAD
    //
    // Validator constraints (v2.19):
    //   - tx.to must be a currently-active DApp in dapp_registry_
    //   - topic must be "" or in DApp.topics
    //   - ciphertext_len matches remaining payload bytes
    //   - Total payload size <= MAX_DAPP_CALL_PAYLOAD
    //   - tx.to NOT cross-shard (cross-shard DAPP_CALL is Phase 7.6,
    //     requires beacon-relay extension to carry payload bytes
    //     across shards; v2.19 ships single-shard only)
    //
    // Apply semantics:
    //   - Charge tx.fee from sender (paid to validators like any tx)
    //   - Debit sender by tx.amount, credit DApp by tx.amount
    //     (S-007 overflow-checked on the credit leg)
    //   - Advance sender's nonce
    //   - Payload itself: NO state mutation. The message is just
    //     recorded in the block stream, tx_root commits to it, and
    //     DApp nodes filter the chain for it.
    //
    // Off-chain consumption: a DApp node reads finalized blocks (via
    // RPC subscription or chain replay), filters DAPP_CALL where
    // tx.to == own_domain, decrypts the payload with its
    // service_pubkey, and dispatches to internal handlers.
    DAPP_CALL      = 10,
};

// v2.4 cap on inner-tx count per batch. 64 is generous for the use
// cases (atomic swaps, bundled transfers) without exposing the chain
// to memory-exhaustion via gigantic batches. Validator rejects
// batches exceeding this; producer wouldn't accept them either.
inline constexpr uint16_t MAX_COMPOSABLE_INNER = 64;

// v2.18 DApp registration caps. Genesis-pinned; can be promoted to
// governance-mutable via PARAM_CHANGE later if needed.
inline constexpr uint8_t  MAX_DAPP_TOPICS         = 32;
inline constexpr uint8_t  MAX_DAPP_TOPIC_LEN      = 64;
inline constexpr uint8_t  MAX_DAPP_ENDPOINT_LEN   = 255;
inline constexpr uint16_t MAX_DAPP_METADATA       = 4096;  // 4 KB
inline constexpr uint64_t DAPP_GRACE_BLOCKS       = 100;

// v2.19 DAPP_CALL payload cap. 16 KB is generous for typical messages
// (signed JSON commands, small encrypted blobs) without exposing the
// chain to memory pressure from gigantic payloads. Larger DApp data
// should use the off-chain-pointer pattern (carry hash + URL in the
// ciphertext, fetch payload off-chain). Genesis-pinned; can be
// PARAM_CHANGE-promoted if the ecosystem demands it.
inline constexpr uint32_t MAX_DAPP_CALL_PAYLOAD   = 16384; // 16 KB

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

    // S-033 / v2.1 foundation: cryptographic commitment to state-after-apply.
    // Zero (the default) means "this block doesn't commit state" —
    // preserves byte-identical hashes for all pre-S-033 blocks and chains.
    // Non-zero means `state_root == Chain::compute_state_root()` after this
    // block applies; validators re-derive and reject on mismatch.
    //
    // Once a chain emits a non-zero state_root in any block, all subsequent
    // blocks should also (since they're sequential and the apply path is
    // deterministic). Mixed populated/unpopulated state_roots within a chain
    // are not invalid by themselves — the validator only checks non-zero
    // entries — but operationally indicate either a producer bug or a
    // mid-chain feature toggle.
    //
    // The full v2.1 sparse-Merkle-tree extension (inclusion proofs for
    // light clients, v2.2) replaces this single 32-byte hash with a
    // Merkle root over the SMT. Wire format stays the same — only the
    // computation changes. Inclusion proofs are queried via a new RPC
    // separate from the block format.
    Hash state_root{};

    // Populated only at index 0 (genesis). Encodes the initial accounts /
    // stakes / registry that seed the chain. Invalid for any other block.
    std::vector<GenesisAlloc> initial_state;

    std::vector<uint8_t> signing_bytes() const;
    Hash                 compute_hash() const;

    nlohmann::json to_json() const;
    static Block   from_json(const nlohmann::json& j);
};

} // namespace determ::chain
