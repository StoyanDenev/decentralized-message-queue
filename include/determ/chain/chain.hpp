#pragma once
#include <determ/chain/block.hpp>
#include <map>
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

    // A5 Phase 3: promoted from static constants in params.hpp so the
    // governance whitelist can mutate them at run-time. Default values
    // match the pre-A5 constants: SUSPENSION_SLASH=10, UNSTAKE_DELAY=1000.
    uint64_t suspension_slash() const { return suspension_slash_; }
    void     set_suspension_slash(uint64_t s) { suspension_slash_ = s; }
    uint64_t unstake_delay()    const { return unstake_delay_; }
    void     set_unstake_delay(uint64_t d)    { unstake_delay_ = d; }

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
    // A5 Phase 3: instance-state promotion of params.hpp constants.
    uint64_t                                    suspension_slash_{10};
    uint64_t                                    unstake_delay_{1000};
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

    void apply_transactions(const Block& b);
};

} // namespace determ::chain
