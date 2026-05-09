#pragma once
#include <dhcoin/chain/block.hpp>
#include <map>
#include <set>
#include <string>
#include <optional>
#include <cstdint>
#include <utility>

namespace dhcoin::chain {

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

    // Rev. 4: per-block subsidy minted to creators on apply. Set by Node
    // after loading GenesisConfig; chain-wide constant.
    uint64_t block_subsidy() const { return block_subsidy_; }
    void     set_block_subsidy(uint64_t s) { block_subsidy_ = s; }

    // rev.8 follow-on: validator-eligibility stake threshold.
    // STAKE_INCLUSION chains use 1000 (MIN_STAKE default);
    // DOMAIN_INCLUSION chains pin 0. Registry build reads this rather
    // than chain/params.hpp::MIN_STAKE.
    uint64_t min_stake() const { return min_stake_; }
    void     set_min_stake(uint64_t s) { min_stake_ = s; }

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

    // Fewest-fallbacks fork resolution: given two chains sharing a common prefix,
    // return the canonical tip (the better block at the diverging height).
    static const Block& resolve_fork(const Block& a, const Block& b);

    void        save(const std::string& path) const;
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
    uint64_t                                    block_subsidy_{0};
    uint64_t                                    min_stake_{1000};
    uint32_t                                    shard_count_{1};
    Hash                                        shard_salt_{};
    ShardId                                     my_shard_id_{0};
    // rev.9 B3.4: dedup tracking for delivered inbound receipts.
    // Populated during apply (also during replay via load), consulted
    // by producer + validator to guarantee exactly-once credit.
    std::set<std::pair<ShardId, Hash>>           applied_inbound_receipts_;

    void apply_transactions(const Block& b);
};

} // namespace dhcoin::chain
