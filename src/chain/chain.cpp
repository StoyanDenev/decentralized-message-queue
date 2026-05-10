#include <determ/chain/chain.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/crypto/random.hpp>
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

// ─── apply_transactions ──────────────────────────────────────────────────────

uint64_t Chain::live_total_supply() const {
    uint64_t s = 0;
    for (auto& [_, a] : accounts_) s += a.balance;
    for (auto& [_, st] : stakes_)  s += st.locked;
    return s;
}

void Chain::apply_transactions(const Block& b) {
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
                registrants_[a.domain] = re;
            }
            if (a.stake > 0) {
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
                accounts_[tx.to].balance += tx.amount;
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

            RegistryEntry e;
            std::copy_n(tx.payload.begin(), 32, e.ed_pub.begin());
            e.registered_at = height;
            e.active_from   = height + derive_delay(b.cumulative_rand, tx.hash);
            e.inactive_from = UINT64_MAX;
            e.region        = std::move(region);
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
            block_slashed     += sit->second.locked;  // A1: full forfeit
            sit->second.locked = 0;
        }
        auto rit = registrants_.find(ev.equivocator);
        if (rit != registrants_.end()) {
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
        accounts_[r.to].balance += r.amount;
        applied_inbound_receipts_.insert(key);
        block_inbound += r.amount;     // A1
    }

    // A1: book the per-block deltas, then assert the unitary-balance
    // invariant. block_subsidy_ is minted to creators iff the distribution
    // branch above actually paid them out (creators non-empty AND
    // total_distributed > 0). Match that gate exactly so the counter
    // tracks reality, not intent.
    if ((total_fees + block_subsidy_) > 0 && !b.creators.empty()) {
        accumulated_subsidy_ += block_subsidy_;
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
    snap["block_subsidy"] = block_subsidy_;
    snap["min_stake"]     = min_stake_;
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
    c.min_stake_     = snap.value("min_stake",     uint64_t{1000});
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

    return c;
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
