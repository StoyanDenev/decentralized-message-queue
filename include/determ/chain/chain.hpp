// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/chain/block.hpp>
#include <determ/crypto/merkle.hpp>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <optional>
#include <cstdint>
#include <utility>
#include <vector>
#include <functional>

namespace determ::chain {

struct AccountState {
    uint64_t balance{0};
    uint64_t next_nonce{0};
};

struct StakeEntry {
    uint64_t locked{0};
    // Block height at which UNSTAKE is allowed to release `locked` back to
    // balance. While the domain is registered (active_from <= h < inactive_from)
    // unlock_height is held at UINT64_MAX. A DEREGISTER tx at block h sets
    // unlock_height = inactive_from + UNSTAKE_DELAY.
    uint64_t unlock_height{UINT64_MAX};
};

struct RegistryEntry {
    PubKey    ed_pub{};
    uint64_t  registered_at{0};
    uint64_t  active_from{0};
    // UINT64_MAX while still in the active set; set by DEREGISTER to
    // inclusion_height + 1 + (rand % REGISTRATION_DELAY_WINDOW).
    uint64_t  inactive_from{UINT64_MAX};
    // rev.9 R1: validator-declared region tag. Empty = no region claim
    // (treated as "global pool member" — eligible for any committee_region
    // == "" shard but not for region-pinned shards). Normalized lowercase
    // ASCII, charset [a-z0-9-_], <= 32 bytes (validator enforces).
    std::string region{};
};

class Chain {
public:
    Chain() = default;
    explicit Chain(Block genesis);

    void             append(Block b);
    const Block&     head() const;
    const Block&     at(uint64_t index) const;
    uint64_t         height() const { return blocks_.size(); }
    bool             empty() const  { return blocks_.empty(); }
    Hash             head_hash() const;

    // ─── State accessors ────────────────────────────────────────────────────
    uint64_t balance(const std::string& domain)    const;
    uint64_t next_nonce(const std::string& domain) const;
    uint64_t stake(const std::string& domain)      const;
    uint64_t stake_unlock_height(const std::string& domain) const;
    std::optional<RegistryEntry> registrant(const std::string& domain) const;

    // A9 Phase 2C foundation: lock-free committed-view readers for
    // accounts_. These do NOT require the caller to hold state_mutex_;
    // they atomic-load a shared_ptr to the committed view published
    // at the last successful apply commit. The returned snapshot is
    // immutable for as long as the reader holds the shared_ptr; the
    // writer (apply path) constructs and atomic-stores a new snapshot
    // at each commit without disturbing readers.
    //
    // Semantics: balance_lockfree returns the COMMITTED state at the
    // last finalized block apply. During an in-progress apply, this
    // is the prior block's state — correct for external observers
    // (the in-progress apply hasn't been gossiped/finalized yet).
    // The existing balance()/next_nonce() above remain for callers
    // inside apply that want to see the in-progress state, or for
    // callers that already hold state_mutex_ shared_lock and want
    // identical semantics to the pre-Phase-2C path.
    //
    // Node-side adoption (follow-on commit): RPC handlers that today
    // take state_mutex_ shared_lock solely to call balance()/next_nonce
    // will switch to the lock-free path, realizing the user-facing
    // concurrent-read benefit. That commit is Phase 2C-Node.
    //
    // Implementation note: uses std::atomic_load/atomic_store free
    // functions on shared_ptr — these are deprecated in C++20 and
    // removed in C++26. Migration to std::atomic<std::shared_ptr<T>>
    // is mechanical when the toolchain requires it; current MSVC
    // (matches /std:c++17 default) supports the free functions
    // without warning. Tracked as a follow-on cleanup.
    uint64_t balance_lockfree(const std::string& domain) const;
    uint64_t next_nonce_lockfree(const std::string& domain) const;

    // Phase 2C extension to stakes_ and registrants_. Same shared_ptr
    // publish-at-commit mechanism; same semantics (returns the last
    // finalized state, lock-free, safe to call without state_mutex_).
    // The corresponding Node RPC handlers (rpc_stake_info, rpc_account)
    // now use these and no longer block on apply's writer lock.
    uint64_t                     stake_lockfree(const std::string& domain) const;
    uint64_t                     stake_unlock_height_lockfree(const std::string& domain) const;
    std::optional<RegistryEntry> registrant_lockfree(const std::string& domain) const;

    // A9 Phase 2C refinement: bundled state view for callers that read
    // multiple containers and need cross-container atomicity (i.e.,
    // all reads must come from the same commit, not straddle one).
    //
    // Per-field lockfree accessors above each do their own atomic_load.
    // If a caller queries balance, then stake, then registrant in
    // sequence, the three reads can return values from DIFFERENT
    // committed states if an apply commits between calls. For display
    // queries (rpc_account) this rare race is benign, but a caller
    // that needs internally-consistent multi-field reads should grab
    // the bundle once and read multiple fields from the SAME shared_ptr.
    //
    // Usage:
    //   auto view = chain.committed_state_view();
    //   if (!view) return error;  // pre-apply edge case
    //   auto bal_it = view->accounts.find(addr);
    //   auto stk_it = view->stakes.find(addr);
    //   // bal_it and stk_it are guaranteed from the same commit
    //
    // The shared_ptr keeps the bundle alive for the caller's duration;
    // the writer's next commit publishes a new bundle without
    // disturbing in-flight readers.
    struct CommittedStateBundle {
        std::map<std::string, AccountState>  accounts;
        std::map<std::string, StakeEntry>    stakes;
        std::map<std::string, RegistryEntry> registrants;
    };
    std::shared_ptr<const CommittedStateBundle> committed_state_view() const;

    // Rev. 4: per-block subsidy minted to creators on apply. Set by Node
    // after loading GenesisConfig; chain-wide constant.
    uint64_t block_subsidy() const { return block_subsidy_; }
    void     set_block_subsidy(uint64_t s) { block_subsidy_ = s; }
    // E4: finite subsidy fund. 0 = unlimited; non-zero = hard cap on
    // total cumulative subsidy ever paid. Genesis-pinned via
    // GenesisConfig.subsidy_pool_initial.
    uint64_t subsidy_pool_initial() const { return subsidy_pool_initial_; }
    void     set_subsidy_pool_initial(uint64_t v) { subsidy_pool_initial_ = v; }
    uint64_t subsidy_paid()          const { return accumulated_subsidy_; }
    uint64_t subsidy_pool_remaining() const {
        if (subsidy_pool_initial_ == 0) return UINT64_MAX;
        return subsidy_pool_initial_ > accumulated_subsidy_
            ? subsidy_pool_initial_ - accumulated_subsidy_ : 0;
    }
    // E3: lottery mode (0=FLAT, 1=LOTTERY). Genesis-pinned.
    uint8_t  subsidy_mode()                 const { return subsidy_mode_; }
    void     set_subsidy_mode(uint8_t m)          { subsidy_mode_ = m; }
    uint32_t lottery_jackpot_multiplier()   const { return lottery_jackpot_multiplier_; }
    void     set_lottery_jackpot_multiplier(uint32_t m) { lottery_jackpot_multiplier_ = m; }

    // rev.8 follow-on: validator-eligibility stake threshold.
    // STAKE_INCLUSION chains use 1000 (MIN_STAKE default);
    // DOMAIN_INCLUSION chains pin 0. Registry build reads this rather
    // than chain/params.hpp::MIN_STAKE.
    uint64_t min_stake() const { return min_stake_; }
    void     set_min_stake(uint64_t s) { min_stake_ = s; }

    // S-032: per-domain Phase-1 abort accumulator, maintained
    // incrementally in apply_transactions. NodeRegistry::build_from_chain
    // reads this rather than walking the chain log on every call. Without
    // this cache, each call is O(N · T) for N = chain.height(),
    // T = txs/block; total cost over the chain's lifetime is O(N²).
    // With the cache, build_from_chain becomes O(|registrants| + |stakes|).
    //
    // Semantics: `count` is the total number of Phase-1 (round=1) abort
    // events against this domain that have been baked into a finalized
    // block. `last_block` is the index of the most recent such block.
    // build_from_chain's exponential-suspension formula reads both fields.
    //
    // Phase-2 (round=2) aborts are NOT recorded — timing skew on healthy
    // creators can produce Phase-2 false-positives that wouldn't be
    // suspension-worthy. Matches the existing build_from_chain behavior.
    struct AbortRecord {
        uint64_t count{0};
        uint64_t last_block{0};
    };
    const std::map<std::string, AbortRecord>& abort_records() const {
        return abort_records_;
    }

    // S-033 / v2.1 foundation: cryptographic commitment to current state.
    // Computes a SHA-256 hash over the byte-canonical serialization of:
    //   1. accounts_                 (sorted by domain)
    //   2. stakes_                   (sorted by domain)
    //   3. registrants_              (sorted by domain)
    //   4. applied_inbound_receipts_ (sorted set, deterministic)
    //   5. abort_records_            (sorted by domain)
    //   6. merge_state_              (sorted by shard_id)
    //   7. pending_param_changes_    (sorted by effective_height)
    //   8. genesis-pinned constants  (block_subsidy, min_stake,
    //                                  suspension_slash, unstake_delay,
    //                                  merge_threshold_blocks,
    //                                  revert_threshold_blocks,
    //                                  merge_grace_blocks, shard_count,
    //                                  my_shard_id)
    //   9. A1 supply counters        (genesis_total_,
    //                                  accumulated_subsidy_,
    //                                  accumulated_slashed_,
    //                                  accumulated_inbound_,
    //                                  accumulated_outbound_)
    //
    // The hash is byte-canonical by construction: every container is
    // std::map (sorted-key iteration) or std::set, every primitive is
    // little-endian, every string is length-prefixed. Two honest nodes
    // applying the same block sequence MUST produce byte-identical
    // state_root values. A divergence indicates a real consensus break.
    //
    // Future evolution (v2.1 full): replace this single hash with a
    // sparse Merkle root over the same canonical serialization, paired
    // with an inclusion-proof API for light-client state queries. The
    // wire format (32-byte Hash in Block.state_root) stays the same;
    // only the computation changes. Light clients verify SMT proofs
    // against this same field.
    Hash compute_state_root() const;

    // v2.2 light-client foundation: inclusion proof for any state key.
    // The light client fetches a trusted Block header (from gossip /
    // checkpoint / committee-signed beacon), reads block.state_root,
    // and calls a full node via state_proof RPC. The full node returns
    // a StateProof; the light client calls crypto::merkle_verify to
    // confirm the (key, value_hash) pair is committed by state_root.
    //
    // Key encoding (must match build_state_leaves exactly):
    //   accounts:                "a:" + domain
    //   stakes:                  "s:" + domain
    //   registrants:             "r:" + domain
    //   applied_inbound_receipts:"i:" + src_shard_be8 + tx_hash
    //   abort_records:           "b:" + domain
    //   merge_state:             "m:" + shard_id_be4
    //   pending_param_changes:   "p:" + eff_height_be8 + idx_be4
    //   constants:               "k:" + name
    //   counters:                "k:c:" + name
    //
    // Returns nullopt if the key is not in the tree. Non-membership
    // proofs are NOT supported by the current sorted-leaves design;
    // a future SMT migration would add them.
    struct StateProof {
        std::vector<uint8_t> key;
        Hash                 value_hash;
        size_t               target_index;
        size_t               leaf_count;
        std::vector<Hash>    proof;
    };
    std::optional<StateProof> state_proof(const std::vector<uint8_t>& key) const;

    // A5 Phase 3: promoted from static constants in params.hpp so the
    // governance whitelist can mutate them at run-time. Default values
    // match the pre-A5 constants: SUSPENSION_SLASH=10, UNSTAKE_DELAY=1000.
    uint64_t suspension_slash() const { return suspension_slash_; }
    void     set_suspension_slash(uint64_t s) { suspension_slash_ = s; }
    uint64_t unstake_delay()    const { return unstake_delay_; }
    void     set_unstake_delay(uint64_t d)    { unstake_delay_ = d; }

    // R4 Phase 1: under-quorum merge thresholds. Read by the upcoming
    // beacon-side trigger detection logic (Phase 2).
    uint32_t merge_threshold_blocks() const { return merge_threshold_blocks_; }
    void     set_merge_threshold_blocks(uint32_t n) { merge_threshold_blocks_ = n; }
    uint32_t revert_threshold_blocks() const { return revert_threshold_blocks_; }
    void     set_revert_threshold_blocks(uint32_t n) { revert_threshold_blocks_ = n; }
    uint32_t merge_grace_blocks()     const { return merge_grace_blocks_; }
    void     set_merge_grace_blocks(uint32_t n)     { merge_grace_blocks_ = n; }

    // R4 Phase 2+4: per-shard merge state. Keys are shard_ids currently
    // in the MERGED (refugee) state; values are (partner_id,
    // refugee_region). Absence from the map = NOT MERGED. Mutates only
    // when a MERGE_EVENT applies. The refugee_region is read at
    // committee-selection time by the partner shard to extend its
    // eligible pool (Phase 4 stress branch) without needing the global
    // shard manifest on every shard.
    struct MergePartnerInfo {
        ShardId     partner_id{0};
        std::string refugee_region{};   // empty = global pool
    };
    using MergeStateMap = std::map<ShardId, MergePartnerInfo>;
    const MergeStateMap& merge_state() const { return merge_state_; }
    // Returns true if shard s is currently merged with another. The
    // partner is written to out_partner on hit. Read by validator /
    // producer paths during EXTENDED-mode block production.
    bool is_shard_merged(ShardId s, ShardId* out_partner = nullptr) const {
        auto it = merge_state_.find(s);
        if (it == merge_state_.end()) return false;
        if (out_partner) *out_partner = it->second.partner_id;
        return true;
    }
    // Inverse lookup: (shard_id, refugee_region) pairs whose merge
    // partner is `partner`. The Phase 4 stress branch extends the
    // committee pool with validators tagged with each refugee region.
    std::vector<std::pair<ShardId, std::string>>
    shards_absorbed_by(ShardId partner) const {
        std::vector<std::pair<ShardId, std::string>> out;
        for (auto& [s, info] : merge_state_)
            if (info.partner_id == partner)
                out.emplace_back(s, info.refugee_region);
        return out;
    }

    // A5 Phase 2: governance parameter staging. A validated PARAM_CHANGE
    // tx stages a (name, value) pair to activate at `effective_height`.
    // At the start of each apply_transactions(b), pending entries with
    // effective_height <= b.index are activated — i.e., the named chain
    // state field is mutated, after which the block applies under the
    // new value. Activation is deterministic across replays because the
    // pending map and apply order are baked into the canonical block
    // stream + chain snapshot.
    //
    // The optional ParamChangedHook is invoked once per activated param
    // so the Node can mirror governance-relevant fields (param_keyholders,
    // param_threshold, bft_escalation_threshold) back to the validator.
    // Chain-internal fields (min_stake_) update locally and need no
    // outside notification.
    using ParamChangedHook =
        std::function<void(const std::string& name,
                             const std::vector<uint8_t>& value)>;
    void set_param_changed_hook(ParamChangedHook h) {
        param_changed_hook_ = std::move(h);
    }

    // Stages a parameter change for activation. Called from apply path
    // when a valid PARAM_CHANGE tx is applied; safe to call from outside
    // (e.g., a tool replaying a chain that already accepted the tx).
    void stage_param_change(uint64_t effective_height,
                             std::string name,
                             std::vector<uint8_t> value);

    // Read-only view for diagnostics / RPC.
    const std::map<uint64_t,
                   std::vector<std::pair<std::string, std::vector<uint8_t>>>>&
    pending_param_changes() const { return pending_param_changes_; }

    // rev.9 B3: shard routing parameters. Genesis-pinned and chain-wide.
    // Set by Node from GenesisConfig before replay so apply-side
    // cross-shard semantics are deterministic across all nodes.
    void     set_shard_routing(uint32_t shard_count,
                                 const Hash& salt,
                                 ShardId my_shard_id);
    uint32_t shard_count()     const { return shard_count_; }
    const Hash& shard_salt()   const { return shard_salt_; }
    ShardId  my_shard_id()     const { return my_shard_id_; }
    // True iff `to` routes to a different shard than this chain owns.
    // SINGLE chains (shard_count_ <= 1) return false unconditionally.
    bool     is_cross_shard(const std::string& to) const;

    // rev.9 B3.4: idempotency check for inbound receipts. True if
    // (src_shard, tx_hash) has already been credited by a previously-
    // applied block on this chain. Producer + validator both consult
    // this to ensure each cross-shard transfer credits the destination
    // exactly once, even if the same bundle is gossiped repeatedly.
    bool     inbound_receipt_applied(ShardId src_shard,
                                       const Hash& tx_hash) const;

    const std::map<std::string, AccountState>&   accounts()    const { return accounts_;    }
    const std::map<std::string, StakeEntry>&     stakes()      const { return stakes_;      }
    const std::map<std::string, RegistryEntry>&  registrants() const { return registrants_; }

    // ─── Unitary-balance invariant (A1) ────────────────────────────────────
    // GENESIS_TOTAL is fixed at genesis-apply time as the sum of all
    // initial balances + initial stakes (+ Zeroth pool / pseudo-account
    // balances once those state structures land — currently 0). Total
    // supply on a live chain drifts predictably:
    //
    //   expected = genesis_total
    //            + accumulated_subsidy   (block_subsidy minted per block)
    //            - accumulated_slashed   (suspension + equivocation forfeit)
    //            + accumulated_inbound   (cross-shard receipts credited here)
    //            - accumulated_outbound  (cross-shard transfers debited here,
    //                                       credit delivered on dst shard)
    //
    // After every block apply we assert
    //   Σ accounts.balance + Σ stakes.locked == expected_total()
    // The walk is a uint64 sum over two small maps; no allocation, no
    // string formatting unless the assertion fires (then we throw with a
    // diagnostic). Always-on, cheap.
    uint64_t genesis_total() const { return genesis_total_; }
    uint64_t accumulated_subsidy()  const { return accumulated_subsidy_; }
    uint64_t accumulated_slashed()  const { return accumulated_slashed_; }
    uint64_t accumulated_inbound()  const { return accumulated_inbound_; }
    uint64_t accumulated_outbound() const { return accumulated_outbound_; }
    // expected_total = the value the live sum must equal post-apply.
    uint64_t expected_total() const {
        return genesis_total_
             + accumulated_subsidy_
             + accumulated_inbound_
             - accumulated_slashed_
             - accumulated_outbound_;
    }
    // Live sum across accounts.balance + stakes.locked. O(N) over two
    // maps — used by the post-apply assertion and by RPC.
    uint64_t live_total_supply() const;

    // Fewest-fallbacks fork resolution: given two chains sharing a common prefix,
    // return the canonical tip (the better block at the diverging height).
    static const Block& resolve_fork(const Block& a, const Block& b);

    void        save(const std::string& path) const;

    // rev.9 B6.basic: serialize the chain's CURRENT STATE (accounts,
    // stakes, registrants, dedup set) plus the last `header_count`
    // blocks. Operators host this as a snapshot for fast bootstrap of
    // new nodes (replaying from genesis to a mature chain's tip is
    // O(N) verification work). The snapshot also includes
    // genesis-pinned chain-wide constants (block_subsidy, min_stake,
    // shard_count, shard_salt, my_shard_id) so a restorer doesn't need
    // the original genesis to make sense of the state.
    //
    // No state root in v1 — verification is by trust-the-source +
    // post-restore consistency check (replay the next handful of
    // blocks and confirm head matches majority of network peers).
    // Adding a state root is a v2 protocol change.
    nlohmann::json serialize_state(uint32_t header_count = 16) const;

    // Round-trip counterpart to serialize_state. Builds an in-memory
    // Chain populated with state directly from the snapshot — no
    // apply_transactions replay. Tail headers from the snapshot become
    // blocks_ so chain.height() / chain.head_hash() / chain.head() all
    // work normally; subsequent block apply extends from the head.
    //
    // The returned chain is self-consistent at the snapshot's
    // block_index. Wiring it into Node::start (as the bootstrap path
    // when chain.json is absent) is a follow-on commit.
    static Chain restore_from_snapshot(const nlohmann::json& snapshot);
    // block_subsidy must be passed at load time so replay credits creators
    // correctly. Caller (Node) loads it from GenesisConfig before this call.
    // rev.9 B3: shard routing params must also be passed so apply-side
    // cross-shard semantics replay deterministically. Defaults represent
    // SINGLE chain (shard_count=1, no cross-shard branches taken).
    static Chain load(const std::string& path,
                       uint64_t block_subsidy = 0,
                       uint32_t shard_count = 1,
                       const Hash& shard_salt = Hash{},
                       ShardId my_shard_id = 0);

private:
    std::vector<Block>                          blocks_;
    std::map<std::string, AccountState>         accounts_;
    std::map<std::string, StakeEntry>           stakes_;
    std::map<std::string, RegistryEntry>        registrants_;

    // A9 Phase 2C: single lock-free committed view bundling accounts,
    // stakes, and registrants. Published at every successful apply
    // via std::atomic_store on the shared_ptr. Readers atomic_load
    // the pointer once and read from any container in the bundle —
    // all three are guaranteed to be from the same commit. The
    // shared_ptr keeps the bundle alive for the reader's duration;
    // writers publish a fresh bundle at commit without disturbing
    // in-flight readers.
    //
    // Cost: one make_shared<CommittedStateBundle>(...) per successful
    // apply — three map deep-copies into the bundle's fields. Same
    // total work as the previous three-separate-shared_ptr design;
    // the bundling buys cross-container atomicity at no per-block cost.
    // Per-field lockfree accessors (balance_lockfree, stake_lockfree,
    // etc.) atomic_load the bundle internally and read their specific
    // field; multi-field callers should use committed_state_view()
    // to load once and read multiple fields from the same bundle.
    std::shared_ptr<const CommittedStateBundle>
                                                committed_state_view_;

    uint64_t                                    block_subsidy_{0};
    // E4: optional finite subsidy fund. 0 = unlimited / perpetual subsidy
    // (the historical pre-E4 default, backward-compatible). Non-zero =
    // a hard cap on total subsidy ever paid. Once `accumulated_subsidy_`
    // reaches this cap, subsequent blocks pay only transaction fees;
    // chain remains live, validators are rewarded purely from fees.
    uint64_t                                    subsidy_pool_initial_{0};
    // E3: lottery distribution. 0 = FLAT (default), 1 = LOTTERY. Under
    // LOTTERY each block draws from a two-point distribution seeded by
    // its own `cumulative_rand`. lottery_jackpot_multiplier_ is the M in
    // {prob=1/M -> pay block_subsidy*M; prob=(M-1)/M -> pay 0}. Expected
    // per-block value equals FLAT subsidy.
    uint8_t                                     subsidy_mode_{0};
    uint32_t                                    lottery_jackpot_multiplier_{0};
    uint64_t                                    min_stake_{1000};
    // S-032 cache: see public abort_records() getter above.
    std::map<std::string, AbortRecord>          abort_records_;
    // A5 Phase 3: instance-state promotion of params.hpp constants.
    uint64_t                                    suspension_slash_{10};
    uint64_t                                    unstake_delay_{1000};
    // R4 Phase 1: merge thresholds (defaults match GenesisConfig).
    uint32_t                                    merge_threshold_blocks_{100};
    uint32_t                                    revert_threshold_blocks_{200};
    uint32_t                                    merge_grace_blocks_{10};
    // R4 Phase 2: per-shard merge state. key = shard_id currently
    // absorbed into a partner; value = partner shard. Mutated only
    // by MERGE_EVENT apply (BEGIN inserts, END erases).
    MergeStateMap                               merge_state_{};
    uint32_t                                    shard_count_{1};
    Hash                                        shard_salt_{};
    ShardId                                     my_shard_id_{0};
    // rev.9 B3.4: dedup tracking for delivered inbound receipts.
    // Populated during apply (also during replay via load), consulted
    // by producer + validator to guarantee exactly-once credit.
    std::set<std::pair<ShardId, Hash>>           applied_inbound_receipts_;

    // A1: unitary-balance invariant counters. genesis_total_ is set once
    // by the index-0 apply branch (or by snapshot restore). The others
    // are running totals updated per non-genesis block. See expected_total()
    // for how they combine. All zero on a freshly default-constructed Chain.
    uint64_t                                    genesis_total_{0};
    uint64_t                                    accumulated_subsidy_{0};
    uint64_t                                    accumulated_slashed_{0};
    uint64_t                                    accumulated_inbound_{0};
    uint64_t                                    accumulated_outbound_{0};

    // A5 Phase 2: staged governance parameter changes keyed by
    // activation height. Ordered map ensures deterministic activation
    // even when two PARAM_CHANGE txs (in different blocks) target the
    // same effective_height — the vector preserves apply order.
    std::map<uint64_t,
             std::vector<std::pair<std::string, std::vector<uint8_t>>>>
                                                pending_param_changes_;
    ParamChangedHook                            param_changed_hook_{};

    // Activate pending entries with eff_height <= current. Called at
    // the start of every apply_transactions(b) before tx replay so the
    // block sees the new values.
    void activate_pending_params(uint64_t current_height);

    // v2.2 light-client foundation: build the canonical Merkle leaves
    // vector covering all chain state. Single implementation used by
    // both compute_state_root() (which calls merkle_root over the
    // leaves) and state_proof() (which calls merkle_proof). Keeping
    // them in one function is the invariant — any leaf-encoding
    // change must apply to both consumers identically.
    std::vector<crypto::MerkleLeaf> build_state_leaves() const;

    // A9 Phase 1: atomic block apply via snapshot + restore.
    //
    // Problem: apply_transactions mutates ~13 state containers + a
    // dozen scalar counters across ~700 lines of tx-loop logic. A
    // throw from anywhere inside (invariant assertion, malformed tx,
    // bug) left the chain with partially-mutated state — accounts
    // credited but stakes not unlocked, abort_records bumped but the
    // block not in blocks_, etc. The next apply_transactions call
    // would then operate on garbage. Tests masked this because
    // throws were rare in happy-path replays.
    //
    // Fix: snapshot every mutable state field at apply entry; on any
    // exception, move-restore the snapshot before re-throwing. The
    // chain is observably unchanged from the failed apply — either
    // the full block applies or nothing does.
    //
    // Cost: one copy per block of N (accounts) + M (stakes/registrants
    // /etc.) maps. These are byte-shallow (std::map nodes hold POD
    // values and short strings); the copy is dominated by allocator
    // overhead, not data movement. Measured on bearer test: <1ms per
    // block at 10k accounts. Acceptable until Phase 2 (overlay/delta
    // primitive) makes the snapshot cheaper still.
    //
    // Phase 2 (deferred): replace the std::map deep-copy with an
    // overlay layer — a small per-block diff map that mutators write
    // to, with read-through to the base map. Commit = merge overlay
    // into base; rollback = drop overlay. Enables concurrent readers
    // during apply, batched txs, and is the foundation for the
    // composable-tx primitive in v2.4.
    // A9 Phase 2A/2B: containers below in std::optional are captured
    // lazily on first mutation per apply, not unconditionally at
    // entry. Blocks that don't touch a given container leave its
    // snapshot at nullopt and skip the deep-copy cost.
    //
    // Containers that benefit from lazy:
    //   - stakes (Phase 2B): TRANSFER-only blocks skip; only REGISTER/
    //     STAKE/UNSTAKE/DEREGISTER/slashing/equivocation paths touch
    //   - registrants (Phase 2B): only REGISTER/DEREGISTER/equivocate
    //   - abort_records (Phase 2A): only Phase-1 slashing path
    //   - merge_state (Phase 2A): only MERGE_EVENT apply
    //   - applied_inbound_receipts (Phase 2A): only cross-shard inbound
    //
    // Containers that stay eager:
    //   - accounts: mutated on every block (subsidy distribution) — lazy
    //     adds ensure() check overhead at every site with no skip benefit
    //   - pending_param_changes: mutated by activate_pending_params at
    //     apply entry; threading an ensure-lambda there is awkward and
    //     the container is usually tiny anyway
    struct StateSnapshot {
        std::map<std::string, AccountState>          accounts;
        std::optional<std::map<std::string, StakeEntry>>    stakes;
        std::optional<std::map<std::string, RegistryEntry>> registrants;
        std::optional<std::map<std::string, AbortRecord>>   abort_records;
        std::optional<MergeStateMap>                        merge_state;
        std::optional<std::set<std::pair<ShardId, Hash>>>   applied_inbound_receipts;
        std::map<uint64_t,
                 std::vector<std::pair<std::string,
                                       std::vector<uint8_t>>>>
                                                     pending_param_changes;
        // Scalars: all mutable counters + governance-promoted params.
        // Genesis-pinned routing fields (shard_count_, shard_salt_,
        // my_shard_id_) are NOT snapshotted — they cannot change
        // during apply.
        uint64_t genesis_total{0};
        uint64_t accumulated_subsidy{0};
        uint64_t accumulated_slashed{0};
        uint64_t accumulated_inbound{0};
        uint64_t accumulated_outbound{0};
        uint64_t min_stake{0};
        uint64_t suspension_slash{0};
        uint64_t unstake_delay{0};
        uint32_t merge_threshold_blocks{0};
        uint32_t revert_threshold_blocks{0};
        uint32_t merge_grace_blocks{0};
        uint64_t block_subsidy{0};
        uint64_t subsidy_pool_initial{0};
        uint8_t  subsidy_mode{0};
        uint32_t lottery_jackpot_multiplier{0};
    };
    StateSnapshot create_state_snapshot() const;
    void          restore_state_snapshot(StateSnapshot&& s);

    void apply_transactions(const Block& b);
};

} // namespace determ::chain
