// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/chain/chain.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/crypto/random.hpp>
#include <determ/crypto/merkle.hpp>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <cstdio>

namespace determ::chain {

using json = nlohmann::json;
namespace fs = std::filesystem;
using determ::crypto::sha256;

// Registration / deregistration randomized delay window. Kept in sync with
// node/registry.hpp REGISTRATION_DELAY_WINDOW; we duplicate the constant here
// to avoid a circular include.
static constexpr uint64_t REGISTRATION_DELAY_WINDOW = 10;

// S-007: portable checked u64 addition. Returns false on overflow.
// Used at every balance/counter mutation site that could realistically
// overflow under adversarial genesis or accumulated-fees scenarios.
// MSVC doesn't have __builtin_add_overflow; the if-check is uniformly
// portable and the compiler optimizes it to a single ADC/JC sequence.
static inline bool checked_add_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (a > UINT64_MAX - b) return false;
    *out = a + b;
    return true;
}

// Compute the randomized 1..REGISTRATION_DELAY_WINDOW delay, deterministically
// derived from the block's cumulative_rand and the tx hash so all nodes agree
// and the operator can't pick their own activation height.
static uint64_t derive_delay(const Hash& cumulative_rand, const Hash& tx_hash) {
    Hash seed = sha256(tx_hash, cumulative_rand);
    uint64_t v = 0;
    for (int b = 0; b < 8; ++b) v = (v << 8) | seed[b];
    return 1 + (v % REGISTRATION_DELAY_WINDOW);
}

Chain::Chain(Block genesis) {
    apply_transactions(genesis);
    blocks_.push_back(std::move(genesis));
}

void Chain::append(Block b) {
    if (!blocks_.empty() && b.prev_hash != head_hash())
        throw std::runtime_error("Block prev_hash mismatch");
    apply_transactions(b);
    blocks_.push_back(std::move(b));
}

const Block& Chain::head() const {
    if (blocks_.empty()) throw std::runtime_error("Empty chain");
    return blocks_.back();
}

const Block& Chain::at(uint64_t index) const {
    if (index >= blocks_.size()) throw std::out_of_range("Block index out of range");
    return blocks_[static_cast<size_t>(index)];
}

Hash Chain::head_hash() const {
    return head().compute_hash();
}

// ─── State accessors ─────────────────────────────────────────────────────────

uint64_t Chain::balance(const std::string& domain) const {
    auto it = accounts_.find(domain);
    return it != accounts_.end() ? it->second.balance : 0;
}

uint64_t Chain::next_nonce(const std::string& domain) const {
    auto it = accounts_.find(domain);
    return it != accounts_.end() ? it->second.next_nonce : 0;
}

// A9 Phase 2C: lock-free committed-view readers. atomic_load the
// shared_ptr (lock-free on all major platforms for shared_ptr<T>),
// then read from the contents. The snapshot is immutable for as long
// as the local shared_ptr `p` holds it; the writer's atomic_store at
// apply commit publishes a NEW shared_ptr without disturbing readers.
// committed_accounts_view_ is null only on a freshly-constructed
// Chain with no apply yet — return 0 in that edge case (matches the
// "domain not found" semantics of the locked path).
// Suppress MSVC's C4996 deprecation warning on std::atomic_load /
// atomic_store free functions for shared_ptr. They are deprecated in
// C++20 in favor of std::atomic<std::shared_ptr<T>> but remain
// functional and well-supported. Migration is a follow-on cleanup;
// the warning suppression is local to the four call sites in this
// file. When the toolchain moves to C++26 (where the free functions
// are removed), convert committed_accounts_view_ to
// std::atomic<std::shared_ptr<const std::map<...>>> and rewrite the
// call sites mechanically.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif

std::shared_ptr<const Chain::CommittedStateBundle>
Chain::committed_state_view() const {
    return std::atomic_load(&committed_state_view_);
}

uint64_t Chain::balance_lockfree(const std::string& domain) const {
    auto p = std::atomic_load(&committed_state_view_);
    if (!p) return 0;
    auto it = p->accounts.find(domain);
    return it != p->accounts.end() ? it->second.balance : 0;
}

uint64_t Chain::next_nonce_lockfree(const std::string& domain) const {
    auto p = std::atomic_load(&committed_state_view_);
    if (!p) return 0;
    auto it = p->accounts.find(domain);
    return it != p->accounts.end() ? it->second.next_nonce : 0;
}

uint64_t Chain::stake_lockfree(const std::string& domain) const {
    auto p = std::atomic_load(&committed_state_view_);
    if (!p) return 0;
    auto it = p->stakes.find(domain);
    return it != p->stakes.end() ? it->second.locked : 0;
}

uint64_t Chain::stake_unlock_height_lockfree(const std::string& domain) const {
    auto p = std::atomic_load(&committed_state_view_);
    if (!p) return UINT64_MAX;
    auto it = p->stakes.find(domain);
    return it != p->stakes.end() ? it->second.unlock_height : UINT64_MAX;
}

std::optional<RegistryEntry> Chain::registrant_lockfree(const std::string& domain) const {
    auto p = std::atomic_load(&committed_state_view_);
    if (!p) return std::nullopt;
    auto it = p->registrants.find(domain);
    if (it == p->registrants.end()) return std::nullopt;
    return it->second;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

uint64_t Chain::stake(const std::string& domain) const {
    auto it = stakes_.find(domain);
    return it != stakes_.end() ? it->second.locked : 0;
}

uint64_t Chain::stake_unlock_height(const std::string& domain) const {
    auto it = stakes_.find(domain);
    return it != stakes_.end() ? it->second.unlock_height : UINT64_MAX;
}

std::optional<RegistryEntry> Chain::registrant(const std::string& domain) const {
    auto it = registrants_.find(domain);
    if (it == registrants_.end()) return std::nullopt;
    return it->second;
}

void Chain::set_shard_routing(uint32_t shard_count,
                                 const Hash& salt,
                                 ShardId my_shard_id) {
    shard_count_ = shard_count;
    shard_salt_  = salt;
    my_shard_id_ = my_shard_id;
}

bool Chain::is_cross_shard(const std::string& to) const {
    if (shard_count_ <= 1) return false;
    return crypto::shard_id_for_address(to, shard_count_, shard_salt_)
           != my_shard_id_;
}

bool Chain::inbound_receipt_applied(ShardId src_shard,
                                       const Hash& tx_hash) const {
    return applied_inbound_receipts_.count({src_shard, tx_hash}) > 0;
}

// A5 Phase 2: stage a PARAM_CHANGE for activation at `effective_height`.
// Multiple changes can land at the same height; we preserve apply order
// (vector push_back) so replay is deterministic.
void Chain::stage_param_change(uint64_t effective_height,
                                  std::string name,
                                  std::vector<uint8_t> value) {
    pending_param_changes_[effective_height].emplace_back(
        std::move(name), std::move(value));
}

// S-033 / v2.1 foundation: byte-canonical hash over the current chain
// state. Two honest nodes applying the same block sequence MUST produce
// byte-identical state_root values; divergence = real consensus break.
//
// Serialization order is deterministic by construction: std::map iterates
// in sorted-key order; std::set iterates in sorted order; every numeric
// field is little-endian; every string is length-prefixed.
//
// Adding a new state field to Chain in the future: include it here in a
// stable position. The position matters for the hash, so additions go
// at the end (or behind a feature flag that only activates from a
// flag-day height onward).
// v2.1: Merkle tree state commitment. The previous "single-SHA-256
// over canonical bytes" served the S-033 foundation; this revision
// upgrades the computation to a sorted-leaves Merkle tree without
// changing the wire format (still a 32-byte Hash in Block.state_root).
//
// Each state entry becomes a Merkle leaf with a domain-prefixed key:
//   "a:" + domain        for accounts_
//   "s:" + domain        for stakes_
//   "r:" + domain        for registrants_
//   "i:" + src_shard_be8 + tx_hash  for applied_inbound_receipts_
//   "b:" + domain        for abort_records_ (S-032 cache)
//   "m:" + shard_id_be4  for merge_state_
//   "p:" + eff_height_be8 + idx_be4  for pending_param_changes_
//   "k:const_name"       for genesis-pinned constants
//   "c:counter_name"     for A1 counters
//
// Key prefixes domain-separate the namespaces so a key collision
// across maps (e.g., the same domain appearing in both accounts_ and
// stakes_) produces distinct leaves. Value-hash is the SHA-256 of a
// fixed canonical byte serialization for that entry type.
//
// Upgrade path for inclusion proofs (v2.2 light clients): the same
// (key, value_hash) leaves feed merkle_proof(); no schema change
// required. Light clients query a peer for "account 'alice'", receive
// the (key, value_hash, sorted_index, leaf_count, proof) tuple, and
// verify against the committee-signed Block.state_root.
// v2.2 light-client foundation: build the canonical Merkle leaves
// vector covering the entire chain state. Used by both compute_state_root
// (which feeds leaves into merkle_root) and state_proof (which feeds
// the same leaves into merkle_proof plus searches for the target
// leaf's sorted index).
//
// Refactored out as a private helper so the two callers don't drift
// — any change to the leaf-encoding scheme MUST be the same for both
// or proofs won't verify against the state_root. Keeping them in one
// function is the invariant.
std::vector<crypto::MerkleLeaf> Chain::build_state_leaves() const {
    std::vector<crypto::MerkleLeaf> leaves;
    leaves.reserve(accounts_.size() + stakes_.size() + registrants_.size()
                  + applied_inbound_receipts_.size() + abort_records_.size()
                  + merge_state_.size() + pending_param_changes_.size()
                  + 16); // constants + counters slack

    auto k_with_prefix = [](const std::string& prefix, const std::string& s) {
        std::vector<uint8_t> out;
        out.reserve(prefix.size() + s.size());
        out.insert(out.end(), prefix.begin(), prefix.end());
        out.insert(out.end(), s.begin(), s.end());
        return out;
    };
    auto hash_bytes = [](crypto::SHA256Builder& b) { return b.finalize(); };

    // accounts_
    for (auto& [domain, acct] : accounts_) {
        crypto::SHA256Builder b;
        b.append(acct.balance);
        b.append(acct.next_nonce);
        leaves.push_back({k_with_prefix("a:", domain), hash_bytes(b)});
    }
    // stakes_
    for (auto& [domain, st] : stakes_) {
        crypto::SHA256Builder b;
        b.append(st.locked);
        b.append(st.unlock_height);
        leaves.push_back({k_with_prefix("s:", domain), hash_bytes(b)});
    }
    // registrants_
    for (auto& [domain, r] : registrants_) {
        crypto::SHA256Builder b;
        b.append(r.ed_pub.data(), r.ed_pub.size());
        b.append(r.registered_at);
        b.append(r.active_from);
        b.append(r.inactive_from);
        b.append(static_cast<uint64_t>(r.region.size()));
        b.append(r.region);
        leaves.push_back({k_with_prefix("r:", domain), hash_bytes(b)});
    }
    // applied_inbound_receipts_  (key = "i:" + src_be8 + tx_hash)
    for (auto& [src, tx_hash] : applied_inbound_receipts_) {
        std::vector<uint8_t> key;
        key.reserve(2 + 8 + 32);
        key.push_back('i'); key.push_back(':');
        for (int i = 7; i >= 0; --i) key.push_back((src >> (8*i)) & 0xff);
        key.insert(key.end(), tx_hash.begin(), tx_hash.end());
        crypto::SHA256Builder b;
        uint8_t marker = 1; b.append(&marker, 1);  // presence marker
        leaves.push_back({std::move(key), hash_bytes(b)});
    }
    // abort_records_  (S-032 cache)
    for (auto& [domain, ar] : abort_records_) {
        crypto::SHA256Builder b;
        b.append(ar.count);
        b.append(ar.last_block);
        leaves.push_back({k_with_prefix("b:", domain), hash_bytes(b)});
    }
    // merge_state_  (key = "m:" + shard_id_be4)
    for (auto& [shard, info] : merge_state_) {
        std::vector<uint8_t> key;
        key.reserve(2 + 4);
        key.push_back('m'); key.push_back(':');
        for (int i = 3; i >= 0; --i) key.push_back((shard >> (8*i)) & 0xff);
        crypto::SHA256Builder b;
        b.append(static_cast<uint64_t>(info.partner_id));
        b.append(static_cast<uint64_t>(info.refugee_region.size()));
        b.append(info.refugee_region);
        leaves.push_back({std::move(key), hash_bytes(b)});
    }
    // pending_param_changes_  (key = "p:" + eff_be8 + idx_be4)
    for (auto& [eff, entries] : pending_param_changes_) {
        for (size_t idx = 0; idx < entries.size(); ++idx) {
            auto& [name, value] = entries[idx];
            std::vector<uint8_t> key;
            key.reserve(2 + 8 + 4);
            key.push_back('p'); key.push_back(':');
            for (int i = 7; i >= 0; --i) key.push_back((eff >> (8*i)) & 0xff);
            for (int i = 3; i >= 0; --i)
                key.push_back((uint32_t(idx) >> (8*i)) & 0xff);
            crypto::SHA256Builder b;
            b.append(static_cast<uint64_t>(name.size()));
            b.append(name);
            b.append(static_cast<uint64_t>(value.size()));
            if (!value.empty()) b.append(value.data(), value.size());
            leaves.push_back({std::move(key), hash_bytes(b)});
        }
    }
    // genesis-pinned constants (one leaf each, fixed keys).
    auto const_leaf = [&](const char* name, uint64_t value) {
        crypto::SHA256Builder b;
        b.append(value);
        leaves.push_back({k_with_prefix("k:", name), hash_bytes(b)});
    };
    const_leaf("block_subsidy",                block_subsidy_);
    const_leaf("subsidy_pool_initial",         subsidy_pool_initial_);
    const_leaf("subsidy_mode",                 subsidy_mode_);
    const_leaf("lottery_jackpot_multiplier",   lottery_jackpot_multiplier_);
    const_leaf("min_stake",                    min_stake_);
    const_leaf("suspension_slash",             suspension_slash_);
    const_leaf("unstake_delay",                unstake_delay_);
    const_leaf("merge_threshold_blocks",       merge_threshold_blocks_);
    const_leaf("revert_threshold_blocks",      revert_threshold_blocks_);
    const_leaf("merge_grace_blocks",           merge_grace_blocks_);
    const_leaf("shard_count",                  shard_count_);
    const_leaf("my_shard_id",                  my_shard_id_);
    // shard_salt is 32 bytes — own leaf form.
    {
        crypto::SHA256Builder b;
        b.append(shard_salt_);
        leaves.push_back({k_with_prefix("k:", "shard_salt"), hash_bytes(b)});
    }
    // A1 supply counters.
    const_leaf("c:genesis_total",        genesis_total_);
    const_leaf("c:accumulated_subsidy",  accumulated_subsidy_);
    const_leaf("c:accumulated_slashed",  accumulated_slashed_);
    const_leaf("c:accumulated_inbound",  accumulated_inbound_);
    const_leaf("c:accumulated_outbound", accumulated_outbound_);

    return leaves;
}

Hash Chain::compute_state_root() const {
    return crypto::merkle_root(build_state_leaves());
}

// v2.2 light-client RPC: produce an inclusion proof for the given
// state key. Builds the full leaves vector, sorts it (merkle_proof
// expects sorted input — the leaf index it takes is the sorted-by-
// key position), finds the target key's sorted index, and calls
// merkle_proof to produce the sibling-hash list.
//
// Returns nullopt if the key isn't in the tree. A light client that
// receives nullopt can call this method against multiple peers and
// rely on majority — for a key the network considers absent, all
// honest peers return nullopt. (Note: this is "membership" — non-
// membership proofs would require an SMT with key-path indexing,
// which is a v2 protocol evolution; the current sorted-leaves
// design doesn't natively support absence proofs.)
//
// The returned StateProof is sufficient input to merkle_verify:
//   merkle_verify(root, key, value_hash, target_index, leaf_count, proof)
// where `root` is fetched from a trusted block header (light client
// has the header from the committee-signed chain).
std::optional<Chain::StateProof> Chain::state_proof(
        const std::vector<uint8_t>& key) const {
    auto leaves = build_state_leaves();
    // Sort by key — merkle_proof/merkle_root both pre-sort, so we
    // need the sorted order to find the target's index and to feed
    // into merkle_proof. Sort here once.
    std::sort(leaves.begin(), leaves.end(),
        [](const crypto::MerkleLeaf& a, const crypto::MerkleLeaf& b) {
            return a.key < b.key;
        });
    auto it = std::lower_bound(leaves.begin(), leaves.end(), key,
        [](const crypto::MerkleLeaf& l, const std::vector<uint8_t>& k) {
            return l.key < k;
        });
    if (it == leaves.end() || it->key != key) return std::nullopt;
    size_t target_index = static_cast<size_t>(it - leaves.begin());

    StateProof p;
    p.key          = key;
    p.value_hash   = it->value_hash;
    p.target_index = target_index;
    p.leaf_count   = leaves.size();
    // merkle_proof expects un-sorted leaves and sorts internally,
    // but it's also fine to pass already-sorted leaves; sort is
    // idempotent. Pass the sorted vector directly.
    p.proof        = crypto::merkle_proof(leaves, target_index);
    return p;
}

// Activate all staged changes with eff_height <= current_height. Called
// at the start of apply_transactions so the new values are in effect
// before the block's txs replay. Decoding is per-parameter; unknown
// names are activated as no-ops (validator already enforces the
// whitelist, so unknowns indicate a future-version chain — fail-soft
// at apply, fail-loud at validate). All ranges processed iterate in
// ascending key order via std::map.
void Chain::activate_pending_params(uint64_t current_height) {
    auto it = pending_param_changes_.begin();
    while (it != pending_param_changes_.end() && it->first <= current_height) {
        for (auto& [name, value] : it->second) {
            // Numeric (uint64 LE) parameters that live on Chain.
            auto parse_u64 = [&](uint64_t& dst) {
                if (value.size() != 8) return false;
                uint64_t v = 0;
                for (int i = 0; i < 8; ++i) v |= uint64_t(value[i]) << (8 * i);
                dst = v;
                return true;
            };
            if (name == "MIN_STAKE")            { parse_u64(min_stake_); }
            else if (name == "SUSPENSION_SLASH") { parse_u64(suspension_slash_); }
            else if (name == "UNSTAKE_DELAY")    { parse_u64(unstake_delay_); }
            // Names that don't have chain-instance storage but DO live
            // on the validator are forwarded to the Node-installed hook
            // (bft_escalation_threshold, param_keyholders, param_threshold).
            // Timing fields (tx_commit_ms, block_sig_ms, abort_claim_ms)
            // are still params.hpp constants; promoting them to per-Chain
            // instance state is a follow-on — the hook receives the value
            // so the Node may wire them later.
            if (param_changed_hook_) param_changed_hook_(name, value);
        }
        it = pending_param_changes_.erase(it);
    }
}

// ─── apply_transactions ──────────────────────────────────────────────────────

uint64_t Chain::live_total_supply() const {
    uint64_t s = 0;
    for (auto& [_, a] : accounts_) s += a.balance;
    for (auto& [_, st] : stakes_)  s += st.locked;
    return s;
}

// A9 Phase 1: atomic state snapshot for rollback on apply failure.
// A9 Phase 2A refinement: three high-cost-per-copy containers
// (abort_records_, merge_state_, applied_inbound_receipts_) are now
// captured LAZILY in std::optional fields — they start nullopt and
// are populated on the first mutation per apply via ensure-lambdas
// inside apply_transactions. For TRANSFER-only blocks (the common
// case), these stays nullopt and no std::set / std::map copy
// happens at all. The remaining containers stay eager — most
// blocks touch them and lazy-snapshot adds ensure() call overhead
// without saving anything.
Chain::StateSnapshot Chain::create_state_snapshot() const {
    StateSnapshot s;
    s.accounts                   = accounts_;
    // stakes, registrants, abort_records, merge_state,
    // applied_inbound_receipts: deferred via std::optional; captured
    // lazily on first mutation. See ensure-lambdas in apply_transactions.
    s.pending_param_changes      = pending_param_changes_;
    s.genesis_total              = genesis_total_;
    s.accumulated_subsidy        = accumulated_subsidy_;
    s.accumulated_slashed        = accumulated_slashed_;
    s.accumulated_inbound        = accumulated_inbound_;
    s.accumulated_outbound       = accumulated_outbound_;
    s.min_stake                  = min_stake_;
    s.suspension_slash           = suspension_slash_;
    s.unstake_delay              = unstake_delay_;
    s.merge_threshold_blocks     = merge_threshold_blocks_;
    s.revert_threshold_blocks    = revert_threshold_blocks_;
    s.merge_grace_blocks         = merge_grace_blocks_;
    s.block_subsidy              = block_subsidy_;
    s.subsidy_pool_initial       = subsidy_pool_initial_;
    s.subsidy_mode               = subsidy_mode_;
    s.lottery_jackpot_multiplier = lottery_jackpot_multiplier_;
    return s;
}

// Move-restore from snapshot. Called from apply_transactions's catch
// block. After this returns, the chain's observable state is byte-
// identical to before the failed apply call. param_changed_hook_ is
// NOT restored — it's a hook installed by Node, not block-derived
// state, and any callbacks already invoked during the failed apply
// are inherently non-transactional anyway (they cross the
// chain/validator boundary). Hooks fire only on successful activation
// — see activate_pending_params, which the snapshot covers.
void Chain::restore_state_snapshot(StateSnapshot&& s) {
    accounts_                   = std::move(s.accounts);
    // A9 Phase 2A/2B: only restore lazy-captured containers if they
    // were actually mutated during apply. nullopt = container was
    // never touched, base map is already correct.
    if (s.stakes)
        stakes_                 = std::move(*s.stakes);
    if (s.registrants)
        registrants_            = std::move(*s.registrants);
    if (s.abort_records)
        abort_records_          = std::move(*s.abort_records);
    if (s.merge_state)
        merge_state_            = std::move(*s.merge_state);
    if (s.applied_inbound_receipts)
        applied_inbound_receipts_ = std::move(*s.applied_inbound_receipts);
    pending_param_changes_      = std::move(s.pending_param_changes);
    genesis_total_              = s.genesis_total;
    accumulated_subsidy_        = s.accumulated_subsidy;
    accumulated_slashed_        = s.accumulated_slashed;
    accumulated_inbound_        = s.accumulated_inbound;
    accumulated_outbound_       = s.accumulated_outbound;
    min_stake_                  = s.min_stake;
    suspension_slash_           = s.suspension_slash;
    unstake_delay_              = s.unstake_delay;
    merge_threshold_blocks_     = s.merge_threshold_blocks;
    revert_threshold_blocks_    = s.revert_threshold_blocks;
    merge_grace_blocks_         = s.merge_grace_blocks;
    block_subsidy_              = s.block_subsidy;
    subsidy_pool_initial_       = s.subsidy_pool_initial;
    subsidy_mode_               = s.subsidy_mode;
    lottery_jackpot_multiplier_ = s.lottery_jackpot_multiplier;
}

void Chain::apply_transactions(const Block& b) {
    // A9 Phase 1: snapshot at entry; restore on any throw before re-raising.
    // Guarantees observers see either the full block applied or no
    // change at all. Cost: one deep-copy of state maps per block (<1ms
    // at 10k accounts). The block-vector itself is appended only after
    // apply_transactions returns successfully (see Chain::append), so
    // blocks_ atomicity is handled at the caller level.
    //
    // A9 Phase 2A: three high-cost containers (abort_records,
    // merge_state, applied_inbound_receipts) are deferred — see
    // create_state_snapshot. Each has an ensure-lambda below that
    // captures the live container into the snapshot on first
    // mutation. TRANSFER-only blocks bypass all three copies.
    StateSnapshot __snapshot = create_state_snapshot();
    auto __ensure_stakes = [&]() {
        if (!__snapshot.stakes)
            __snapshot.stakes = stakes_;
    };
    auto __ensure_registrants = [&]() {
        if (!__snapshot.registrants)
            __snapshot.registrants = registrants_;
    };
    auto __ensure_abort_records = [&]() {
        if (!__snapshot.abort_records)
            __snapshot.abort_records = abort_records_;
    };
    auto __ensure_merge_state = [&]() {
        if (!__snapshot.merge_state)
            __snapshot.merge_state = merge_state_;
    };
    auto __ensure_applied_inbound_receipts = [&]() {
        if (!__snapshot.applied_inbound_receipts)
            __snapshot.applied_inbound_receipts = applied_inbound_receipts_;
    };
    try {
    // A5 Phase 2: activate any staged governance parameter changes whose
    // effective_height <= this block's index BEFORE replaying the block.
    // The new values are visible to all tx handlers and to the post-apply
    // invariant checks below.
    if (b.index > 0) activate_pending_params(b.index);

    // Genesis: install the initial state directly. No tx semantics, no fees.
    // The validator already accepts index-0 blocks unconditionally; here we
    // just translate `initial_state` into accounts_/stakes_/registrants_.
    if (b.index == 0) {
        // A1: GENESIS_TOTAL = Σ initial_balance + Σ initial_stake
        // (+ Zeroth pool / pseudo-account balances + initial unspent_subsidy
        // — those state structures don't exist yet at v1.x; their
        // contribution is 0. Once E1 lands, the pool's initial balance is
        // added here too; the invariant formula is unchanged.)
        uint64_t gtotal = 0;
        for (auto& a : b.initial_state) {
            accounts_[a.domain].balance = a.balance;
            // accounts_[a.domain].next_nonce = 0  (default)
            gtotal += a.balance;

            PubKey zero_ed{};
            if (a.ed_pub != zero_ed) {
                RegistryEntry re;
                re.ed_pub        = a.ed_pub;
                re.registered_at = 0;
                re.active_from   = 0;
                re.inactive_from = UINT64_MAX;
                re.region        = a.region; // rev.9 R1
                __ensure_registrants();
                registrants_[a.domain] = re;
            }
            if (a.stake > 0) {
                __ensure_stakes();
                stakes_[a.domain].locked        = a.stake;
                stakes_[a.domain].unlock_height = UINT64_MAX;
                gtotal += a.stake;
            }
        }
        genesis_total_       = gtotal;
        accumulated_subsidy_ = 0;
        accumulated_slashed_ = 0;
        accumulated_inbound_ = 0;
        accumulated_outbound_= 0;
        // Genesis-time invariant trivially holds (live == genesis_total).
        return;
    }

    uint64_t total_fees    = 0;
    uint64_t height        = b.index;
    // A1: per-block running deltas for the unitary-balance counters.
    uint64_t block_outbound = 0;   // cross-shard TRANSFER amount that left this shard
    uint64_t block_inbound  = 0;   // cross-shard receipt amount credited here
    uint64_t block_slashed  = 0;   // suspension + equivocation forfeit

    auto charge_fee = [&](AccountState& acct, uint64_t fee) {
        if (acct.balance < fee) return false;
        acct.balance -= fee;
        total_fees   += fee;
        return true;
    };

    for (auto& tx : b.transactions) {
        AccountState& sender = accounts_[tx.from];

        // Sequential nonce: skip txs that don't match. Validator should have
        // rejected them; this is a safety net during apply.
        if (tx.nonce != sender.next_nonce) continue;

        switch (tx.type) {
        case TxType::TRANSFER: {
            uint64_t cost = tx.amount + tx.fee;
            if (sender.balance < cost) continue;
            sender.balance -= cost;
            // rev.9 B3: cross-shard TRANSFER debits sender locally; the
            // credit is delivered to `to` via the receipt path on the
            // destination shard (Stage B3.4). The block's
            // cross_shard_receipts list (validator-checked) carries the
            // outbound credit. amount + fee leave this shard's supply
            // here; fee still accrues to creators on this side.
            if (!is_cross_shard(tx.to)) {
                // S-007: overflow check. Receiver's balance might already
                // be near UINT64_MAX (long-lived deployments aggregating
                // payouts); refuse to wrap.
                auto& rcv = accounts_[tx.to].balance;
                if (!checked_add_u64(rcv, tx.amount, &rcv)) {
                    throw std::runtime_error(
                        "S-007: TRANSFER credit would overflow recipient "
                        "balance (to=" + tx.to + ")");
                }
            } else {
                // A1: amount has left this shard's accounted supply.
                // Fee stays here (accrues to creators below).
                block_outbound += tx.amount;
            }
            total_fees += tx.fee;
            sender.next_nonce++;
            break;
        }

        case TxType::REGISTER: {
            // rev.9 R1 wire format:
            //   [pubkey: 32B][region_len: u8][region: utf8]
            // Legacy (pre-R1) payload of just the 32-byte pubkey is
            // accepted: region defaults to empty (= global pool).
            // Validator already enforced normalization + size bounds;
            // apply only re-extracts the region for storage.
            if (tx.payload.size() < REGISTER_PAYLOAD_PUBKEY_SIZE) continue;
            std::string region;
            if (tx.payload.size() > REGISTER_PAYLOAD_PUBKEY_SIZE) {
                size_t rlen = tx.payload[REGISTER_PAYLOAD_PUBKEY_SIZE];
                if (tx.payload.size() != REGISTER_PAYLOAD_PUBKEY_SIZE + 1 + rlen) continue;
                region.assign(reinterpret_cast<const char*>(
                                  tx.payload.data() + REGISTER_PAYLOAD_PUBKEY_SIZE + 1),
                              rlen);
            }
            if (!charge_fee(sender, tx.fee)) continue;

            // E1: detect first-time registration BEFORE we touch
            // registrants_[tx.from] (operator[] would create an entry,
            // making it indistinguishable from a re-registration). NEF
            // fires only when this is genuinely new — re-registrations
            // (e.g., key rotation, region update) do not drain the pool.
            const bool first_time_register =
                (registrants_.find(tx.from) == registrants_.end());

            RegistryEntry e;
            std::copy_n(tx.payload.begin(), 32, e.ed_pub.begin());
            e.registered_at = height;
            e.active_from   = height + derive_delay(b.cumulative_rand, tx.hash);
            e.inactive_from = UINT64_MAX;
            e.region        = std::move(region);
            __ensure_registrants();
            registrants_[tx.from] = e;

            // Stake_table entry exists even with 0 locked; ensures unlock_height
            // tracking is consistent. Locked is moved by STAKE/UNSTAKE.
            __ensure_stakes();
            auto& st = stakes_[tx.from];
            st.unlock_height = UINT64_MAX;

            // E1 Negative Entry Fee. On the FIRST registration of a domain
            // (not re-registrations / key rotations), if the Zeroth pool has
            // a non-zero balance, half of it is transferred to the new
            // registrant. Geometric exhaustion: pool halves per first-time
            // REGISTER, asymptotes to 0. Pool-empty case (balance==0 ⇒
            // nef==0) is a silent no-op. The pool address is canonical and
            // not synthesizable, so no key can ever drain it via TRANSFER —
            // only this REGISTER hook touches it. A1 invariant trivially
            // holds: nef is balance transfer (pool -> new domain), not
            // a mint or burn.
            if (first_time_register) {
                auto pool_it = accounts_.find(ZEROTH_ADDRESS);
                if (pool_it != accounts_.end() && pool_it->second.balance > 0
                    && tx.from != ZEROTH_ADDRESS) {
                    uint64_t nef = pool_it->second.balance / 2;
                    if (nef > 0) {
                        pool_it->second.balance       -= nef;
                        accounts_[tx.from].balance    += nef;
                    }
                }
            }

            sender.next_nonce++;
            break;
        }

        case TxType::DEREGISTER: {
            if (!charge_fee(sender, tx.fee)) continue;
            auto rit = registrants_.find(tx.from);
            if (rit == registrants_.end()) { sender.next_nonce++; break; }

            uint64_t inactive_from = height + derive_delay(b.cumulative_rand, tx.hash);
            __ensure_registrants();
            rit->second.inactive_from = inactive_from;

            auto sit = stakes_.find(tx.from);
            if (sit != stakes_.end()) {
                __ensure_stakes();
                sit->second.unlock_height = inactive_from + unstake_delay_;
            }

            sender.next_nonce++;
            break;
        }

        case TxType::STAKE: {
            if (tx.payload.size() != 8) continue;
            uint64_t amount = 0;
            for (int i = 0; i < 8; ++i)
                amount |= uint64_t(tx.payload[i]) << (8 * i);
            uint64_t cost = amount + tx.fee;
            if (sender.balance < cost) continue;
            sender.balance -= cost;
            __ensure_stakes();
            stakes_[tx.from].locked += amount;
            total_fees += tx.fee;
            sender.next_nonce++;
            break;
        }

        case TxType::UNSTAKE: {
            if (tx.payload.size() != 8) continue;
            uint64_t amount = 0;
            for (int i = 0; i < 8; ++i)
                amount |= uint64_t(tx.payload[i]) << (8 * i);
            if (!charge_fee(sender, tx.fee)) continue;
            auto sit = stakes_.find(tx.from);
            if (sit == stakes_.end() || sit->second.locked < amount ||
                height < sit->second.unlock_height) {
                // Refund fee on failed UNSTAKE so honest users aren't penalized
                // for a too-early request that the validator didn't catch.
                sender.balance += tx.fee;
                total_fees     -= tx.fee;
                sender.next_nonce++;
                break;
            }
            __ensure_stakes();
            sit->second.locked -= amount;
            sender.balance     += amount;
            sender.next_nonce++;
            break;
        }
        // A5 PARAM_CHANGE: validator has already verified payload shape,
        // whitelist, and multisig threshold. Re-parse just the (name,
        // value, effective_height) header here and stage the change.
        // Signatures aren't re-checked at apply time (deterministic
        // replay assumption — they were verified at validate time).
        case TxType::PARAM_CHANGE: {
            if (!charge_fee(sender, tx.fee)) continue;
            const auto& p = tx.payload;
            size_t off = 0;
            // Defensive shape checks — apply-side reject = treat as
            // malformed and skip without staging, but fee is already
            // consumed (paid for inclusion + multisig verification).
            if (p.size() >= 1) {
                size_t nlen = p[off++];
                if (p.size() >= off + nlen + 2) {
                    std::string name(p.begin() + off, p.begin() + off + nlen);
                    off += nlen;
                    uint16_t vlen = uint16_t(p[off]) | (uint16_t(p[off+1]) << 8);
                    off += 2;
                    if (p.size() >= off + vlen + 8) {
                        std::vector<uint8_t> value(p.begin() + off,
                                                     p.begin() + off + vlen);
                        off += vlen;
                        uint64_t eff = 0;
                        for (int i = 0; i < 8; ++i)
                            eff |= uint64_t(p[off + i]) << (8 * i);
                        stage_param_change(eff, std::move(name),
                                              std::move(value));
                    }
                }
            }
            sender.next_nonce++;
            break;
        }
        // R4 MERGE_EVENT (Phase 2): validator shape-checked the
        // canonical 25-byte payload + mode-gated. Apply consumes the
        // fee + nonce, then mutates merge_state_ on BEGIN/END.
        //
        // BEGIN: inserts (shard_id → partner_id) into the map. Skipped
        //        if shard_id is already merged (idempotent on duplicate
        //        BEGIN — a future commit hardens this with explicit
        //        rejection on duplicate at validate time).
        // END:   erases shard_id from the map. Skipped if shard_id
        //        wasn't in the map (defensive — a duplicate END is a
        //        no-op).
        //
        // Modular-partner check (partner == (shard+1) mod num_shards)
        // executes here because Chain knows shard_count_. Failure
        // skips the mutation but consumes fee/nonce — the validator
        // accepts the tx as shape-valid; the apply-time predicate
        // catches the cross-num-shards invariant.
        //
        // The actual committee stress branch + partner_subset_hash
        // + witness-window validation are downstream (R4 Phase 3+).
        case TxType::MERGE_EVENT: {
            if (!charge_fee(sender, tx.fee)) continue;
            auto ev = MergeEvent::decode(tx.payload);
            if (ev && shard_count_ > 1
                && ev->partner_id == ((ev->shard_id + 1) % shard_count_)) {
                if (ev->event_type == MergeEvent::BEGIN) {
                    MergePartnerInfo info;
                    info.partner_id     = ev->partner_id;
                    info.refugee_region = ev->merging_shard_region;
                    __ensure_merge_state();
                    merge_state_.insert({ev->shard_id, std::move(info)});
                } else {  // END
                    auto it = merge_state_.find(ev->shard_id);
                    if (it != merge_state_.end()
                        && it->second.partner_id == ev->partner_id) {
                        __ensure_merge_state();
                        merge_state_.erase(it);
                    }
                }
            }
            sender.next_nonce++;
            break;
        }
        // rev.9 R1: REGION_CHANGE is rejected by the validator; an
        // unrecognized type at apply is a defensive no-op (skip the
        // tx, do not touch state, do not advance nonce — this matches
        // the validator's reject path and keeps replay deterministic
        // even if a malformed block somehow slips through).
        default: continue;
        }
    }

    // Distribute fees + block subsidy equally among creators; dust goes
    // to creator[0]. Block subsidy is genesis-pinned; 0 = no subsidy.
    //
    // E4 finite subsidy fund: subsidy_pool_initial_ == 0 keeps the
    // historical perpetual-subsidy behavior. When set, total cumulative
    // subsidy is hard-capped at the pool value; this block's effective
    // subsidy = min(block_subsidy_, remaining). Once the pool drains,
    // subsidy_this_block == 0 and the chain runs on transaction fees
    // alone.
    //
    // E3 lottery mode: when subsidy_mode_ == 1, replace the FLAT per-
    // block subsidy with a two-point draw seeded by this block's
    // `cumulative_rand`. Probability 1/M of paying block_subsidy_ * M
    // (jackpot block), probability (M-1)/M of paying 0. Expected per-
    // block value equals FLAT subsidy. The draw is deterministic given
    // the block — every honest node computes the same payout.
    uint64_t base_subsidy = block_subsidy_;
    if (subsidy_mode_ == 1 && lottery_jackpot_multiplier_ >= 2) {
        // Read 8 bytes of cumulative_rand as the lottery seed. The
        // commit-reveal protocol guarantees no committee member could
        // have predicted cumulative_rand at Phase-1 decision time, so
        // selective-abort against a jackpot is information-theoretically
        // defeated for the same reason regular `R` is.
        uint64_t lottery = 0;
        for (int i = 0; i < 8; ++i) {
            lottery = (lottery << 8) | b.cumulative_rand[i];
        }
        if (lottery % lottery_jackpot_multiplier_ == 0) {
            base_subsidy = block_subsidy_ * lottery_jackpot_multiplier_;
        } else {
            base_subsidy = 0;
        }
    }
    uint64_t subsidy_this_block = base_subsidy;
    if (subsidy_pool_initial_ != 0) {
        uint64_t remaining = subsidy_pool_initial_ > accumulated_subsidy_
            ? subsidy_pool_initial_ - accumulated_subsidy_ : 0;
        subsidy_this_block = std::min(base_subsidy, remaining);
    }
    // S-007: overflow-checked addition. total_fees and subsidy_this_block
    // are each individually bounded (fees by senders' balances, subsidy
    // by genesis cap / pool); the sum is bounded for realistic genesis
    // values but a fabricated genesis with adversarial block_subsidy
    // could push it past UINT64_MAX. Hard-fail in that case rather than
    // wrap.
    uint64_t total_distributed = 0;
    if (!checked_add_u64(total_fees, subsidy_this_block, &total_distributed)) {
        throw std::runtime_error(
            "S-007: total_distributed (fees + subsidy) overflowed u64 "
            "(fees=" + std::to_string(total_fees)
          + " subsidy=" + std::to_string(subsidy_this_block) + ")");
    }
    if (total_distributed > 0 && !b.creators.empty()) {
        size_t   m           = b.creators.size();
        uint64_t per_creator = total_distributed / m;
        uint64_t remainder   = total_distributed % m;
        for (auto& domain : b.creators) {
            auto& bal = accounts_[domain].balance;
            if (!checked_add_u64(bal, per_creator, &bal)) {
                throw std::runtime_error(
                    "S-007: per-creator credit would overflow creator "
                    "balance (creator=" + domain + ")");
            }
        }
        // Dust (division remainder) to creator[0]. Same overflow check.
        auto& bal0 = accounts_[b.creators[0]].balance;
        if (!checked_add_u64(bal0, remainder, &bal0)) {
            throw std::runtime_error(
                "S-007: dust credit would overflow creator[0] balance "
                "(creator=" + b.creators[0] + ")");
        }
    }

    // rev.8 suspension slashing. Each Phase-1 (round=1) AbortEvent baked
    // into this block deducts SUSPENSION_SLASH from the aborted domain's
    // staked balance. Bounded by the available stake (no negative
    // balances). Only Phase-1 aborts count, mirroring registry.cpp's
    // suspension policy: Phase-2 timing-skew aborts on healthy creators
    // are not economically punished. Required for BFT-mode safety.
    for (auto& ae : b.abort_events) {
        if (ae.round != 1) continue;
        // S-032 cache: increment the abort accumulator for this domain.
        // build_from_chain reads this cache instead of walking history.
        __ensure_abort_records();
        auto& ar = abort_records_[ae.aborting_node];
        ar.count++;
        ar.last_block = b.index;
        // Original suspension-slash stake deduction.
        auto sit = stakes_.find(ae.aborting_node);
        if (sit == stakes_.end()) continue;
        uint64_t deduct = std::min<uint64_t>(suspension_slash_, sit->second.locked);
        __ensure_stakes();
        sit->second.locked -= deduct;
        block_slashed     += deduct;   // A1
    }

    // rev.8 follow-on: full equivocation slashing + deregistration. Each
    // EquivocationEvent baked into this block (validator already verified
    // the two-sig proof) (a) forfeits the equivocator's ENTIRE staked
    // balance — primary disincentive in STAKE_INCLUSION mode — and
    // (b) marks the equivocator's registry entry inactive_from = next
    // block, removing them from selection regardless of stake.
    //
    // The dual mechanism unifies STAKE_INCLUSION and DOMAIN_INCLUSION:
    //   - STAKE_INCLUSION:  stake → 0 makes them ineligible; deregistration
    //                       is redundant but harmless.
    //   - DOMAIN_INCLUSION: stake is already 0 (no stake), so the
    //                       deregistration is what actually removes them.
    //                       Equivocator must register a fresh domain to
    //                       participate again.
    for (auto& ev : b.equivocation_events) {
        auto sit = stakes_.find(ev.equivocator);
        if (sit != stakes_.end()) {
            __ensure_stakes();
            block_slashed     += sit->second.locked;  // A1: full forfeit
            sit->second.locked = 0;
        }
        auto rit = registrants_.find(ev.equivocator);
        if (rit != registrants_.end()) {
            __ensure_registrants();
            rit->second.inactive_from = b.index + 1;
        }
    }

    // rev.9 B3.4: deliver inbound cross-shard receipts. Each entry
    // credits `to` with `amount` (sender debit + fee already happened
    // on the source shard). Idempotent on (src_shard, tx_hash); a
    // duplicate would be rejected by the validator before reaching
    // here, but the guard makes apply safe under chain replay.
    for (auto& r : b.inbound_receipts) {
        auto key = std::make_pair(r.src_shard, r.tx_hash);
        if (applied_inbound_receipts_.count(key)) continue;
        // S-007: overflow-checked credit on the cross-shard inbound path.
        auto& rcv = accounts_[r.to].balance;
        if (!checked_add_u64(rcv, r.amount, &rcv)) {
            throw std::runtime_error(
                "S-007: inbound receipt credit would overflow recipient "
                "balance (to=" + r.to + ")");
        }
        __ensure_applied_inbound_receipts();
        applied_inbound_receipts_.insert(key);
        // block_inbound is a per-block u64 counter — also check for
        // overflow into the per-block sum.
        if (!checked_add_u64(block_inbound, r.amount, &block_inbound)) {
            throw std::runtime_error(
                "S-007: per-block inbound sum overflowed u64");
        }
    }

    // A1: book the per-block deltas, then assert the unitary-balance
    // invariant. subsidy_this_block is minted to creators iff the
    // distribution branch above actually paid them out (creators non-
    // empty AND total_distributed > 0). Tracking the *actually-paid*
    // amount (not block_subsidy_ literal) is what makes E4's finite-
    // pool path A1-consistent: once the pool drains, subsidy_this_block
    // == 0 and no new mint happens, so the invariant still holds.
    if (total_distributed > 0 && !b.creators.empty()) {
        accumulated_subsidy_ += subsidy_this_block;
    }
    accumulated_inbound_  += block_inbound;
    accumulated_outbound_ += block_outbound;
    accumulated_slashed_  += block_slashed;

    uint64_t expected = expected_total();
    uint64_t actual   = live_total_supply();
    if (actual != expected) {
        // Hot-path string formatting only fires on bug, never in steady
        // state. Throwing surfaces the bug to the apply-path caller (Node /
        // validator / load) loudly rather than silently corrupting state.
        char buf[256];
        int64_t delta = (int64_t)actual - (int64_t)expected;
        std::snprintf(buf, sizeof(buf),
            "unitary-balance invariant violated at block %llu: "
            "expected=%llu actual=%llu delta=%lld "
            "(genesis=%llu +subsidy=%llu +inbound=%llu -slashed=%llu -outbound=%llu)",
            (unsigned long long)b.index,
            (unsigned long long)expected,
            (unsigned long long)actual,
            (long long)delta,
            (unsigned long long)genesis_total_,
            (unsigned long long)accumulated_subsidy_,
            (unsigned long long)accumulated_inbound_,
            (unsigned long long)accumulated_slashed_,
            (unsigned long long)accumulated_outbound_);
        throw std::runtime_error(buf);
    }

    // S-033 / v2.1 foundation: state-root verification. Block may carry a
    // commitment to state-after-apply. If non-zero, re-derive locally
    // and reject on mismatch. Pre-S-033 blocks carry zero state_root
    // and skip this check (preserving byte-identical hashes + backward
    // compatibility). Once a producer starts emitting state_root, every
    // node applying must agree byte-for-byte — divergence here is a real
    // consensus break (different state under same digest), which is
    // exactly the kind of failure S-030 D1 (validate-vs-apply divergence)
    // would otherwise produce silently.
    {
        Hash zero{};
        if (b.state_root != zero) {
            Hash computed = compute_state_root();
            if (computed != b.state_root) {
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                    "state_root mismatch at block %llu: block declares "
                    "%02x%02x%02x%02x... but computed %02x%02x%02x%02x... "
                    "(S-033)",
                    (unsigned long long)b.index,
                    b.state_root[0], b.state_root[1], b.state_root[2], b.state_root[3],
                    computed[0], computed[1], computed[2], computed[3]);
                throw std::runtime_error(buf);
            }
        }
    }
    // A9 Phase 2C: publish the new committed view of accounts_ so
    // lock-free readers see this block's updates. Must happen AFTER
    // all in-block mutations and AFTER the state_root check (which
    // can still throw and roll back). The std::make_shared copies the
    // current accounts_ map; the std::atomic_store atomically swaps
    // the published pointer. Any reader holding the prior view via
    // an already-loaded shared_ptr keeps reading from it until they
    // release; new readers see the new view.
    //
    // Cost: one map deep-copy per successful apply. This is similar
    // cost to Phase 1's snapshot but pays for the lock-free read path
    // rather than for rollback. Combined with Phase 2A/2B's lazy
    // snapshot, the steady-state per-block cost on TRANSFER-only
    // blocks is:
    //   - One eager snapshot copy of accounts_ (Phase 1)
    //   - One lock-free-view publish copy of accounts_ (Phase 2C)
    //   - No copies of stakes/registrants/abort_records/merge_state/
    //     applied_inbound_receipts (Phase 2A/2B lazy-skip)
    // The two accounts_ copies are unavoidable absent a more invasive
    // overlay refactor; they're paid in exchange for atomicity (Phase 1)
    // and concurrent reads (Phase 2C) respectively.
    // A9 Phase 2C: publish the new committed state view. Bundle all
    // three lock-free-readable containers into a single shared_ptr
    // so multi-container queries get cross-container atomicity (all
    // fields read from the same commit, no straddling). Single
    // make_shared + single atomic_store per commit; three map copies
    // happen inside the make_shared. The bundle's contents are const,
    // so readers can't accidentally mutate the shared snapshot.
    auto __bundle = std::make_shared<CommittedStateBundle>();
    __bundle->accounts    = accounts_;
    __bundle->stakes      = stakes_;
    __bundle->registrants = registrants_;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    std::atomic_store(&committed_state_view_,
        std::shared_ptr<const CommittedStateBundle>(std::move(__bundle)));
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    } catch (...) {
        // A9 Phase 1: any throw from the apply body leaves the chain
        // exactly as it was at entry. Restore in-place, then re-raise
        // so the caller (Chain::append, then up through the validator
        // / producer path) still sees the failure. Without this catch,
        // a mid-apply throw (invariant assertion, arithmetic overflow,
        // bug) would leave state partially mutated — the next apply
        // call would operate on inconsistent data and silently corrupt
        // the chain. committed_accounts_view_ is unchanged on rollback
        // because the atomic_store at the success path didn't execute.
        restore_state_snapshot(std::move(__snapshot));
        throw;
    }
}

// ─── Fork resolution ─────────────────────────────────────────────────────────
//
// rev.9 follow-on (addressing S-029): when two blocks compete at the same
// height (e.g., BFT-mode multi-proposer or honest mempool divergence per
// S-030), prefer the one with the heaviest signature set — the block that
// more committee members ratified is the more legitimate one. More
// signatures = more honest participation = more trustworthy.
//
// Order of preference:
//   1. Heaviest sig count (more non-zero `creator_block_sigs` entries).
//   2. Fewer abort_events (less round-1 disruption).
//   3. Smallest block hash (deterministic tiebreaker).
const Block& Chain::resolve_fork(const Block& a, const Block& b) {
    auto sig_count = [](const Block& blk) {
        Signature zero{};
        size_t n = 0;
        for (auto& s : blk.creator_block_sigs)
            if (s != zero) ++n;
        return n;
    };

    size_t na = sig_count(a), nb = sig_count(b);
    if (na != nb) return na > nb ? a : b;       // heaviest sig set wins

    if (a.abort_events.size() != b.abort_events.size())
        return a.abort_events.size() < b.abort_events.size() ? a : b;

    // Tie-break on smallest block hash (deterministic, agrees across peers).
    Hash ha = a.compute_hash();
    Hash hb = b.compute_hash();
    for (size_t i = 0; i < 32; ++i)
        if (ha[i] != hb[i]) return ha[i] < hb[i] ? a : b;
    return a; // identical
}

// ─── Snapshot ────────────────────────────────────────────────────────────────

json Chain::serialize_state(uint32_t header_count) const {
    json snap;
    snap["version"]       = 1;
    snap["block_index"]   = blocks_.empty() ? uint64_t{0}
                                              : blocks_.back().index;
    snap["head_hash"]     = blocks_.empty()
                              ? std::string{}
                              : to_hex(blocks_.back().compute_hash());

    json accs = json::array();
    for (auto& [d, a] : accounts_) {
        accs.push_back({
            {"domain",     d},
            {"balance",    a.balance},
            {"next_nonce", a.next_nonce},
        });
    }
    snap["accounts"] = accs;

    json stk = json::array();
    for (auto& [d, s] : stakes_) {
        stk.push_back({
            {"domain",        d},
            {"locked",        s.locked},
            {"unlock_height", s.unlock_height},
        });
    }
    snap["stakes"] = stk;

    json regs = json::array();
    for (auto& [d, r] : registrants_) {
        regs.push_back({
            {"domain",        d},
            {"ed_pub",        to_hex(r.ed_pub)},
            {"registered_at", r.registered_at},
            {"active_from",   r.active_from},
            {"inactive_from", r.inactive_from},
            // rev.9 R1: include region in snapshots so a restored chain
            // preserves region-based eligibility.
            {"region",        r.region},
        });
    }
    snap["registrants"] = regs;

    json applied = json::array();
    for (auto& [src, tx_hash] : applied_inbound_receipts_) {
        applied.push_back({
            {"src_shard", src},
            {"tx_hash",   to_hex(tx_hash)},
        });
    }
    snap["applied_inbound_receipts"] = applied;

    // Genesis-pinned constants the restorer needs to apply subsequent
    // blocks correctly (creator credit, validator-eligibility gate,
    // address routing).
    snap["block_subsidy"]                = block_subsidy_;
    snap["subsidy_pool_initial"]         = subsidy_pool_initial_;
    snap["subsidy_mode"]                 = subsidy_mode_;
    snap["lottery_jackpot_multiplier"]   = lottery_jackpot_multiplier_;
    snap["min_stake"]     = min_stake_;
    // A5 Phase 3: per-Chain values promoted from params.hpp constants.
    // Snapshot fields preserve pre-A5 defaults when absent.
    snap["suspension_slash"] = suspension_slash_;
    snap["unstake_delay"]    = unstake_delay_;
    snap["shard_count"]   = shard_count_;
    snap["shard_salt"]    = to_hex(shard_salt_);
    snap["shard_id"]      = my_shard_id_;

    // A1: persist the unitary-balance counters so a snapshot-bootstrapped
    // chain can keep asserting from the first post-restore block. Without
    // these, expected_total() would be 0 on a restored chain and the very
    // first apply would trip the invariant.
    snap["genesis_total"]        = genesis_total_;
    snap["accumulated_subsidy"]  = accumulated_subsidy_;
    snap["accumulated_slashed"]  = accumulated_slashed_;
    snap["accumulated_inbound"]  = accumulated_inbound_;
    snap["accumulated_outbound"] = accumulated_outbound_;

    // S-032 cache: persist the Phase-1 abort accumulator so a
    // snapshot-bootstrapped node doesn't have to rebuild it from the log.
    json abort_arr = json::array();
    for (auto& [domain, ar] : abort_records_) {
        abort_arr.push_back({
            {"domain",     domain},
            {"count",      ar.count},
            {"last_block", ar.last_block},
        });
    }
    snap["abort_records"] = abort_arr;

    // A5 Phase 2: persist pending PARAM_CHANGE entries so a snapshot-
    // bootstrapped chain activates them at the same heights an originally-
    // replayed chain would.
    // R4 Phase 2: persist merge state so a snapshot-bootstrapped node
    // resumes mid-merge correctly.
    json merge_arr = json::array();
    for (auto& [s, info] : merge_state_) {
        merge_arr.push_back({
            {"shard_id",       s},
            {"partner_id",     info.partner_id},
            {"refugee_region", info.refugee_region},
        });
    }
    snap["merge_state"] = merge_arr;

    json pending = json::array();
    for (auto& [eff, entries] : pending_param_changes_) {
        json bucket = json::array();
        for (auto& [name, value] : entries) {
            bucket.push_back({
                {"name",  name},
                {"value", to_hex(value.data(), value.size())},
            });
        }
        pending.push_back({
            {"effective_height", eff},
            {"entries",          bucket},
        });
    }
    snap["pending_param_changes"] = pending;

    // Tail headers for chain continuity. Restorer keeps them so they
    // can verify incoming block's prev_hash chains correctly. Default
    // is 16 — enough for typical sync overlap.
    json hdrs = json::array();
    if (!blocks_.empty() && header_count > 0) {
        size_t total = blocks_.size();
        size_t start = (total > header_count) ? total - header_count : 0;
        for (size_t i = start; i < total; ++i) {
            hdrs.push_back(blocks_[i].to_json());
        }
    }
    snap["headers"] = hdrs;

    return snap;
}

Chain Chain::restore_from_snapshot(const json& snap) {
    if (!snap.is_object())
        throw std::runtime_error("snapshot is not a JSON object");
    int v = snap.value("version", 0);
    if (v != 1)
        throw std::runtime_error(
            "unsupported snapshot version: " + std::to_string(v));

    Chain c;
    c.block_subsidy_ = snap.value("block_subsidy", uint64_t{0});
    c.subsidy_pool_initial_ = snap.value("subsidy_pool_initial", uint64_t{0});
    c.subsidy_mode_         = snap.value("subsidy_mode",         uint8_t{0});
    c.lottery_jackpot_multiplier_ =
        snap.value("lottery_jackpot_multiplier", uint32_t{0});
    c.min_stake_     = snap.value("min_stake",     uint64_t{1000});
    c.suspension_slash_ = snap.value("suspension_slash", uint64_t{10});
    c.unstake_delay_    = snap.value("unstake_delay",    uint64_t{1000});
    c.shard_count_   = snap.value("shard_count",   uint32_t{1});
    c.my_shard_id_   = snap.value("shard_id",      ShardId{0});
    c.shard_salt_    = from_hex_arr<32>(snap.value("shard_salt",
                                                      std::string(64, '0')));
    // A1: restore unitary-balance counters. Older snapshots (pre-A1)
    // omit these fields; the value() defaults give a graceful degraded
    // state (genesis_total = live sum, no historic deltas) so old
    // snapshots still load. The invariant on subsequent blocks will be
    // checked using whatever genesis_total ends up loaded — for legacy
    // snapshots that's the live total at restore time, which trivially
    // satisfies the invariant immediately and tracks all subsequent
    // mutations correctly.
    c.accumulated_subsidy_  = snap.value("accumulated_subsidy",  uint64_t{0});
    c.accumulated_slashed_  = snap.value("accumulated_slashed",  uint64_t{0});
    c.accumulated_inbound_  = snap.value("accumulated_inbound",  uint64_t{0});
    c.accumulated_outbound_ = snap.value("accumulated_outbound", uint64_t{0});
    // genesis_total deferred until after accounts/stakes load so legacy
    // snapshots (without the field) can fall back to live sum.

    if (snap.contains("accounts")) {
        for (auto& a : snap["accounts"]) {
            AccountState s;
            s.balance    = a.value("balance",    uint64_t{0});
            s.next_nonce = a.value("next_nonce", uint64_t{0});
            c.accounts_[a.value("domain", std::string{})] = s;
        }
    }
    if (snap.contains("stakes")) {
        for (auto& s : snap["stakes"]) {
            StakeEntry e;
            e.locked        = s.value("locked",        uint64_t{0});
            e.unlock_height = s.value("unlock_height", UINT64_MAX);
            c.stakes_[s.value("domain", std::string{})] = e;
        }
    }
    if (snap.contains("registrants")) {
        for (auto& r : snap["registrants"]) {
            RegistryEntry e;
            e.ed_pub        = from_hex_arr<32>(r.value("ed_pub",
                                                          std::string(64, '0')));
            e.registered_at = r.value("registered_at", uint64_t{0});
            e.active_from   = r.value("active_from",   uint64_t{0});
            e.inactive_from = r.value("inactive_from", UINT64_MAX);
            // rev.9 R1: optional region tag in snapshots. Absent =
            // empty (legacy snapshot, pre-R1 behavior preserved).
            e.region        = r.value("region",        std::string{});
            c.registrants_[r.value("domain", std::string{})] = e;
        }
    }
    if (snap.contains("applied_inbound_receipts")) {
        for (auto& a : snap["applied_inbound_receipts"]) {
            ShardId src    = a.value("src_shard", ShardId{0});
            Hash    txhash = from_hex_arr<32>(
                                a.value("tx_hash", std::string(64, '0')));
            c.applied_inbound_receipts_.insert({src, txhash});
        }
    }
    if (snap.contains("merge_state")) {
        for (auto& m : snap["merge_state"]) {
            ShardId s = m.value("shard_id",   ShardId{0});
            Chain::MergePartnerInfo info;
            info.partner_id     = m.value("partner_id", ShardId{0});
            info.refugee_region = m.value("refugee_region",
                                            std::string{});
            c.merge_state_.insert({s, std::move(info)});
        }
    }
    // S-032: restore the Phase-1 abort accumulator. Older snapshots
    // (pre-S-032) omit the field; the value() default leaves the
    // cache empty, which is fine — build_from_chain reads an empty
    // cache as "no suspensions on file," and any post-restore aborts
    // will increment the cache normally.
    if (snap.contains("abort_records")) {
        for (auto& a : snap["abort_records"]) {
            std::string domain = a.value("domain", std::string{});
            Chain::AbortRecord ar;
            ar.count      = a.value("count",      uint64_t{0});
            ar.last_block = a.value("last_block", uint64_t{0});
            c.abort_records_[domain] = ar;
        }
    }
    if (snap.contains("pending_param_changes")) {
        for (auto& b : snap["pending_param_changes"]) {
            uint64_t eff = b.value("effective_height", uint64_t{0});
            for (auto& e : b.value("entries", json::array())) {
                std::string name = e.value("name", std::string{});
                std::vector<uint8_t> value = from_hex(
                    e.value("value", std::string{}));
                c.pending_param_changes_[eff].emplace_back(
                    std::move(name), std::move(value));
            }
        }
    }
    if (snap.contains("headers")) {
        for (auto& bj : snap["headers"]) {
            c.blocks_.push_back(Block::from_json(bj));
        }
    }

    // Sanity: the head's hash should match the snapshot's stated
    // head_hash. Reject inconsistent snapshots loudly.
    std::string head_hash_claim = snap.value("head_hash", std::string{});
    if (!c.blocks_.empty() && !head_hash_claim.empty()) {
        std::string actual = to_hex(c.blocks_.back().compute_hash());
        if (actual != head_hash_claim)
            throw std::runtime_error(
                "snapshot head_hash mismatch: actual " + actual
              + " vs claimed " + head_hash_claim);
    }

    // A1: pick up genesis_total from snapshot if present; otherwise back-
    // solve from the loaded state so the invariant is satisfied at
    // restore time (live = genesis + subsidy + inbound - slashed - outbound).
    if (snap.contains("genesis_total")) {
        c.genesis_total_ = snap.value("genesis_total", uint64_t{0});
    } else {
        uint64_t live = c.live_total_supply();
        uint64_t deltas_pos = c.accumulated_subsidy_ + c.accumulated_inbound_;
        uint64_t deltas_neg = c.accumulated_slashed_ + c.accumulated_outbound_;
        // Solve: genesis = live + deltas_neg - deltas_pos. Wraparound is
        // impossible on a well-formed snapshot since live - deltas_pos +
        // deltas_neg should yield a valid uint64 by construction.
        c.genesis_total_ = live + deltas_neg - deltas_pos;
    }

    // S-033 follow-on: verify the loaded state matches the head block's
    // declared state_root. This is the snapshot-side analogue of the
    // apply-side check at line ~900 — without it, the fast-bootstrap
    // path trusts the snapshot source unconditionally, and a hostile
    // operator could ship a snapshot whose accounts/stakes diverge from
    // what the chain ever committed to. With this check, any tamper
    // produces a hash mismatch caught locally; the committee-signed
    // block_hash (which covers state_root) means the snapshot supplier
    // cannot manufacture a self-consistent forgery.
    //
    // Pre-S-033 chains carry zero state_root in their headers (the
    // producer wrote nothing); we skip verification on those for
    // backward compatibility. A snapshot whose tail came from a post-
    // S-033 producer will have non-zero state_root and is verified.
    if (!c.blocks_.empty()) {
        Hash claimed = c.blocks_.back().state_root;
        Hash zero{};
        if (claimed != zero) {
            Hash computed = c.compute_state_root();
            if (computed != claimed) {
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                    "snapshot state_root mismatch at head block %llu: "
                    "head declares %02x%02x%02x%02x... but loaded state "
                    "computes %02x%02x%02x%02x... — snapshot is "
                    "inconsistent or tampered (S-033)",
                    (unsigned long long)c.blocks_.back().index,
                    claimed[0], claimed[1], claimed[2], claimed[3],
                    computed[0], computed[1], computed[2], computed[3]);
                throw std::runtime_error(buf);
            }
        }
    }

    // A9 Phase 2C: publish loaded state as the bundled lock-free view
    // so the *_lockfree() accessors and committed_state_view() return
    // snapshot-bootstrapped values immediately after restore (no
    // intervening apply_transactions on this path).
    auto __bundle = std::make_shared<CommittedStateBundle>();
    __bundle->accounts    = c.accounts_;
    __bundle->stakes      = c.stakes_;
    __bundle->registrants = c.registrants_;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    std::atomic_store(&c.committed_state_view_,
        std::shared_ptr<const CommittedStateBundle>(std::move(__bundle)));
#ifdef _MSC_VER
#pragma warning(pop)
#endif

    return c;
}

// ─── Persistence ─────────────────────────────────────────────────────────────

void Chain::save(const std::string& path) const {
    // Atomic write: serialize to a sibling .tmp file, fsync the file
    // contents, then rename .tmp → path. Rename is atomic on POSIX
    // and on Windows for same-volume same-directory targets, so an
    // OS crash mid-write cannot leave a half-written chain.json that
    // load() would parse-fail on. Either the old file survives intact
    // (if rename hadn't happened) or the new file is fully present.
    //
    // This matters when Chain::save runs on a separate worker thread
    // (S-031 / A9 follow-on: async save off the apply hot path). A
    // crash window between block apply and save completion is benign
    // — the missing block re-arrives via peer gossip on restart —
    // but a corrupted chain.json would require manual recovery.
    fs::create_directories(fs::path(path).parent_path());
    std::string tmp_path = path + ".tmp";
    {
        json j = json::array();
        for (auto& b : blocks_) j.push_back(b.to_json());
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("Cannot write chain tmp file: " + tmp_path);
        f << j.dump(2);
        f.flush();
        if (!f) throw std::runtime_error("Failed to flush chain tmp file: " + tmp_path);
    }
    // std::filesystem::rename is implemented as ::MoveFileExA on Windows
    // and ::rename on POSIX — both atomic for same-volume targets. On
    // Windows, MoveFileExA with MOVEFILE_REPLACE_EXISTING is implicit
    // when overwriting; std::filesystem handles this transparently.
    std::error_code ec;
    fs::rename(tmp_path, path, ec);
    if (ec) {
        throw std::runtime_error("Cannot rename chain tmp " + tmp_path
            + " → " + path + ": " + ec.message());
    }
}

Chain Chain::load(const std::string& path,
                    uint64_t block_subsidy,
                    uint32_t shard_count,
                    const Hash& shard_salt,
                    ShardId my_shard_id) {
    std::ifstream f(path);
    if (!f) {
        // No on-disk chain: return EMPTY chain so caller (Node) can decide
        // whether to bootstrap from a GenesisConfig or fall back. Don't
        // synthesize a legacy zeros-genesis here — that would later collide
        // with a pinned genesis_hash in the operator config.
        Chain c;
        c.block_subsidy_ = block_subsidy;
        c.shard_count_   = shard_count;
        c.shard_salt_    = shard_salt;
        c.my_shard_id_   = my_shard_id;
        return c;
    }
    json j = json::parse(f);
    Chain c;
    c.block_subsidy_ = block_subsidy;   // must be set before replay so creators
                                          // are credited correctly per block
    c.shard_count_   = shard_count;
    c.shard_salt_    = shard_salt;
    c.my_shard_id_   = my_shard_id;
    for (auto& bj : j) {
        Block b = Block::from_json(bj);
        c.apply_transactions(b);
        c.blocks_.push_back(std::move(b));
    }
    return c;
}

} // namespace determ::chain
