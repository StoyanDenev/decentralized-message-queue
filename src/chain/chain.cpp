#include <dhcoin/chain/chain.hpp>
#include <dhcoin/chain/genesis.hpp>
#include <dhcoin/chain/params.hpp>
#include <dhcoin/crypto/sha256.hpp>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <stdexcept>

namespace dhcoin::chain {

using json = nlohmann::json;
namespace fs = std::filesystem;
using dhcoin::crypto::sha256;

// Registration / deregistration randomized delay window. Kept in sync with
// node/registry.hpp REGISTRATION_DELAY_WINDOW; we duplicate the constant here
// to avoid a circular include.
static constexpr uint64_t REGISTRATION_DELAY_WINDOW = 10;

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

// ─── apply_transactions ──────────────────────────────────────────────────────

void Chain::apply_transactions(const Block& b) {
    // Genesis: install the initial state directly. No tx semantics, no fees.
    // The validator already accepts index-0 blocks unconditionally; here we
    // just translate `initial_state` into accounts_/stakes_/registrants_.
    if (b.index == 0) {
        for (auto& a : b.initial_state) {
            accounts_[a.domain].balance = a.balance;
            // accounts_[a.domain].next_nonce = 0  (default)

            PubKey zero_ed{};
            if (a.ed_pub != zero_ed) {
                RegistryEntry re;
                re.ed_pub        = a.ed_pub;
                re.registered_at = 0;
                re.active_from   = 0;
                re.inactive_from = UINT64_MAX;
                registrants_[a.domain] = re;
            }
            if (a.stake > 0) {
                stakes_[a.domain].locked        = a.stake;
                stakes_[a.domain].unlock_height = UINT64_MAX;
            }
        }
        return;
    }

    uint64_t total_fees = 0;
    uint64_t height     = b.index;

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
            accounts_[tx.to].balance += tx.amount;
            total_fees += tx.fee;
            sender.next_nonce++;
            break;
        }

        case TxType::REGISTER: {
            if (tx.payload.size() != REGISTER_PAYLOAD_SIZE) continue;
            if (!charge_fee(sender, tx.fee)) continue;

            RegistryEntry e;
            std::copy_n(tx.payload.begin(), 32, e.ed_pub.begin());
            e.registered_at = height;
            e.active_from   = height + derive_delay(b.cumulative_rand, tx.hash);
            e.inactive_from = UINT64_MAX;
            registrants_[tx.from] = e;

            // Stake_table entry exists even with 0 locked; ensures unlock_height
            // tracking is consistent. Locked is moved by STAKE/UNSTAKE.
            auto& st = stakes_[tx.from];
            st.unlock_height = UINT64_MAX;

            sender.next_nonce++;
            break;
        }

        case TxType::DEREGISTER: {
            if (!charge_fee(sender, tx.fee)) continue;
            auto rit = registrants_.find(tx.from);
            if (rit == registrants_.end()) { sender.next_nonce++; break; }

            uint64_t inactive_from = height + derive_delay(b.cumulative_rand, tx.hash);
            rit->second.inactive_from = inactive_from;

            auto sit = stakes_.find(tx.from);
            if (sit != stakes_.end())
                sit->second.unlock_height = inactive_from + UNSTAKE_DELAY;

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
            sit->second.locked -= amount;
            sender.balance     += amount;
            sender.next_nonce++;
            break;
        }
        }
    }

    // Distribute fees + block subsidy equally among creators; dust goes
    // to creator[0]. Block subsidy is genesis-pinned; 0 = no subsidy.
    uint64_t total_distributed = total_fees + block_subsidy_;
    if (total_distributed > 0 && !b.creators.empty()) {
        size_t   m           = b.creators.size();
        uint64_t per_creator = total_distributed / m;
        uint64_t remainder   = total_distributed % m;
        for (auto& domain : b.creators)
            accounts_[domain].balance += per_creator;
        accounts_[b.creators[0]].balance += remainder;
    }

    // rev.8 suspension slashing. Each Phase-1 (round=1) AbortEvent baked
    // into this block deducts SUSPENSION_SLASH from the aborted domain's
    // staked balance. Bounded by the available stake (no negative
    // balances). Only Phase-1 aborts count, mirroring registry.cpp's
    // suspension policy: Phase-2 timing-skew aborts on healthy creators
    // are not economically punished. Required for BFT-mode safety.
    for (auto& ae : b.abort_events) {
        if (ae.round != 1) continue;
        auto sit = stakes_.find(ae.aborting_node);
        if (sit == stakes_.end()) continue;
        uint64_t deduct = std::min<uint64_t>(SUSPENSION_SLASH, sit->second.locked);
        sit->second.locked -= deduct;
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
        if (sit != stakes_.end()) sit->second.locked = 0;
        auto rit = registrants_.find(ev.equivocator);
        if (rit != registrants_.end()) {
            rit->second.inactive_from = b.index + 1;
        }
    }
}

// ─── Fork resolution ─────────────────────────────────────────────────────────

const Block& Chain::resolve_fork(const Block& a, const Block& b) {
    if (a.abort_events.size() != b.abort_events.size())
        return a.abort_events.size() < b.abort_events.size() ? a : b;

    // Tie-break on smallest block hash (deterministic, agrees across peers).
    Hash ha = a.compute_hash();
    Hash hb = b.compute_hash();
    for (size_t i = 0; i < 32; ++i)
        if (ha[i] != hb[i]) return ha[i] < hb[i] ? a : b;
    return a; // identical
}

// ─── Persistence ─────────────────────────────────────────────────────────────

void Chain::save(const std::string& path) const {
    fs::create_directories(fs::path(path).parent_path());
    json j = json::array();
    for (auto& b : blocks_) j.push_back(b.to_json());
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write chain file: " + path);
    f << j.dump(2);
}

Chain Chain::load(const std::string& path, uint64_t block_subsidy) {
    std::ifstream f(path);
    if (!f) {
        // No on-disk chain: return EMPTY chain so caller (Node) can decide
        // whether to bootstrap from a GenesisConfig or fall back. Don't
        // synthesize a legacy zeros-genesis here — that would later collide
        // with a pinned genesis_hash in the operator config.
        Chain c;
        c.block_subsidy_ = block_subsidy;
        return c;
    }
    json j = json::parse(f);
    Chain c;
    c.block_subsidy_ = block_subsidy;   // must be set before replay so creators
                                          // are credited correctly per block
    for (auto& bj : j) {
        Block b = Block::from_json(bj);
        c.apply_transactions(b);
        c.blocks_.push_back(std::move(b));
    }
    return c;
}

} // namespace dhcoin::chain
