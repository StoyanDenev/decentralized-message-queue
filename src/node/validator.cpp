#include <dhcoin/node/validator.hpp>
#include <dhcoin/node/producer.hpp>
#include <dhcoin/chain/params.hpp>
#include <dhcoin/crypto/sha256.hpp>
#include <dhcoin/crypto/random.hpp>
#include <dhcoin/crypto/keys.hpp>
#include <dhcoin/crypto/delay_hash.hpp>
#include <algorithm>
#include <chrono>
#include <map>
#include <set>

namespace dhcoin::node {

using namespace dhcoin::crypto;
using namespace dhcoin::chain;

BlockValidator::Result BlockValidator::validate(const Block& b,
                                                const Chain& chain,
                                                const NodeRegistry& registry) const {
    // Genesis is unauthenticated by signatures — its trust comes from the
    // pinned genesis hash in operator config.
    if (b.index == 0) return {true, ""};

    if (auto r = check_prev_hash(b, chain);              !r.ok) return r;
    if (auto r = check_creators_registered(b, registry); !r.ok) return r;
    if (auto r = check_creator_selection(b, registry, chain); !r.ok) return r;
    if (auto r = check_creator_tx_commitments(b, registry); !r.ok) return r;
    if (auto r = check_abort_certs(b, chain, registry);  !r.ok) return r;
    if (auto r = check_delay(b);                         !r.ok) return r;
    if (auto r = check_block_sigs(b, registry);          !r.ok) return r;
    if (auto r = check_cumulative_rand(b, chain);        !r.ok) return r;
    if (auto r = check_transactions(b, chain, registry); !r.ok) return r;
    if (auto r = check_timestamp(b);                     !r.ok) return r;
    return {true, ""};
}

BlockValidator::Result BlockValidator::check_prev_hash(const Block& b,
                                                        const Chain& chain) const {
    if (chain.empty()) return {true, ""};
    if (b.prev_hash != chain.head_hash())
        return {false, "prev_hash mismatch"};
    return {true, ""};
}

BlockValidator::Result BlockValidator::check_creators_registered(
    const Block& b, const NodeRegistry& registry) const {
    for (auto& d : b.creators) {
        if (!registry.contains(d))
            return {false, "creator not registered or not staked: " + d};
    }
    return {true, ""};
}

BlockValidator::Result BlockValidator::check_creator_selection(
    const Block& b, const NodeRegistry& registry, const Chain& chain) const {
    if (chain.empty()) return {true, ""};

    Hash   prev_rand = chain.head().cumulative_rand;
    auto   nodes     = registry.sorted_nodes();
    // m = K-committee size (b.creators.size()).
    size_t m         = b.creators.size();
    if (k_block_sigs_ != 0 && m != k_block_sigs_)
        return {false, "block creators count != committee size K (genesis-pinned)"};

    // Build available pool: registry minus aborted domains in this block.
    // Mirrors node.cpp::check_if_selected — exclusion + abort-mixed rand.
    std::set<std::string> excluded;
    for (auto& ae : b.abort_events) excluded.insert(ae.aborting_node);
    std::vector<std::string> avail_domains;
    for (auto& nd : nodes) {
        if (excluded.count(nd.domain)) continue;
        avail_domains.push_back(nd.domain);
    }
    if (avail_domains.size() < m)
        return {false, "insufficient eligible nodes after exclusion"};

    Hash rand = prev_rand;
    for (auto& ae : b.abort_events) {
        rand = SHA256Builder{}.append(rand).append(ae.event_hash).finalize();
    }
    auto indices = select_m_creators(rand, avail_domains.size(), m);

    for (size_t i = 0; i < m; ++i) {
        if (avail_domains[indices[i]] != b.creators[i])
            return {false, "creator[" + std::to_string(i) + "] mismatch: expected "
                         + avail_domains[indices[i]]};
    }
    return {true, ""};
}

BlockValidator::Result BlockValidator::check_creator_tx_commitments(
    const Block& b, const NodeRegistry& registry) const {

    if (b.creator_tx_lists.size()  != b.creators.size())
        return {false, "creator_tx_lists size != creators size"};
    if (b.creator_ed_sigs.size()   != b.creators.size())
        return {false, "creator_ed_sigs size != creators size"};
    if (b.creator_dh_inputs.size() != b.creators.size())
        return {false, "creator_dh_inputs size != creators size"};

    for (size_t i = 0; i < b.creators.size(); ++i) {
        auto e = registry.find(b.creators[i]);
        if (!e) return {false, "creator not found: " + b.creators[i]};

        const auto& list = b.creator_tx_lists[i];
        for (size_t k = 1; k < list.size(); ++k) {
            if (!(list[k - 1] < list[k]))
                return {false, "creator_tx_lists[" + std::to_string(i)
                             + "] not sorted ascending unique"};
        }
        Hash commit = make_contrib_commitment(b.index, b.prev_hash, list,
                                                b.creator_dh_inputs[i]);
        if (!verify(e->pubkey, commit.data(), commit.size(), b.creator_ed_sigs[i]))
            return {false, "creator commit sig invalid: " + b.creators[i]};
    }

    // tx_root = union of K-committee tx_hashes lists, regardless of K vs
    // M_pool. Strong mode (K=M_pool) and hybrid mode (K<M_pool) share the
    // same union semantics — they differ only in committee size, which is
    // already enforced by check_creator_selection.
    Hash expected_root = compute_tx_root(b.creator_tx_lists);
    if (expected_root != b.tx_root)
        return {false, "tx_root mismatch with union(creator_tx_lists)"};

    return {true, ""};
}

BlockValidator::Result BlockValidator::check_abort_certs(
    const Block& b, const Chain& chain, const NodeRegistry& registry) const {

    // Each AbortEvent in the block must carry a valid M-1 quorum of signed
    // AbortClaimMsgs. The "M-1" is over the creator set that was selected
    // BEFORE this AbortEvent (i.e., the canonical M chosen for this height
    // after preceding aborts have been applied).
    if (chain.empty()) {
        // Genesis path; AbortEvents shouldn't appear here.
        if (!b.abort_events.empty())
            return {false, "abort_events present at genesis"};
        return {true, ""};
    }

    Hash prev_rand = chain.head().cumulative_rand;
    Hash prev_hash = chain.head_hash();
    auto nodes     = registry.sorted_nodes();
    size_t m       = b.creators.size();

    // Reconstruct the creator-set sequence using the same exclude+remix rule
    // as check_creator_selection: at step i, pool = registry minus the first
    // i aborting_nodes, rand = prev_rand mixed with the first i abort hashes.
    std::set<std::string> excluded;
    Hash rand = prev_rand;
    for (size_t i = 0; i < b.abort_events.size(); ++i) {
        const auto& ae = b.abort_events[i];

        // committee at this step (BEFORE applying ae[i]).
        std::vector<std::string> avail;
        for (auto& nd : nodes) {
            if (excluded.count(nd.domain)) continue;
            avail.push_back(nd.domain);
        }
        if (avail.size() < m)
            return {false, "insufficient eligible nodes at abort_event[" + std::to_string(i) + "]"};
        auto indices = select_m_creators(rand, avail.size(), m);
        std::vector<std::string> domains_at_event;
        for (auto idx : indices) domains_at_event.push_back(avail[idx]);

        // missing_creator must be in the set as of this abort.
        if (std::find(domains_at_event.begin(), domains_at_event.end(),
                       ae.aborting_node) == domains_at_event.end())
            return {false, "abort_event[" + std::to_string(i)
                         + "] aborting_node not in selected set"};

        // claims_json: must be an array of M-1 valid AbortClaimMsg JSON objects.
        if (!ae.claims_json.is_array())
            return {false, "abort_event[" + std::to_string(i) + "] claims missing"};

        size_t needed = domains_at_event.size() > 0 ? domains_at_event.size() - 1 : 0;
        if (ae.claims_json.size() != needed)
            return {false, "abort_event[" + std::to_string(i)
                         + "] claim count != M-1"};

        std::set<std::string> seen_claimers;
        for (auto& cj : ae.claims_json) {
            auto m_ = node::AbortClaimMsg::from_json(cj);

            if (m_.block_index     != b.index)              return {false, "claim block_index mismatch"};
            if (m_.round           != ae.round)             return {false, "claim round mismatch"};
            if (m_.prev_hash       != prev_hash)            return {false, "claim prev_hash mismatch"};
            if (m_.missing_creator != ae.aborting_node)     return {false, "claim missing_creator mismatch"};

            // Claimer must be in the at-event set, distinct from missing.
            if (m_.claimer == m_.missing_creator)           return {false, "claimer == missing"};
            if (std::find(domains_at_event.begin(), domains_at_event.end(),
                           m_.claimer) == domains_at_event.end())
                return {false, "claimer not in at-event set"};
            if (!seen_claimers.insert(m_.claimer).second)
                return {false, "duplicate claimer in cert"};

            auto e = registry.find(m_.claimer);
            if (!e) return {false, "claimer not found in registry"};

            Hash digest = node::make_abort_claim_message(m_.block_index, m_.round,
                                                          m_.prev_hash, m_.missing_creator);
            if (!verify(e->pubkey, digest.data(), digest.size(), m_.ed_sig))
                return {false, "claim sig invalid from " + m_.claimer};
        }

        // advance: exclude aborting_node from pool, mix abort hash into rand.
        excluded.insert(ae.aborting_node);
        rand = SHA256Builder{}.append(rand).append(ae.event_hash).finalize();
    }

    return {true, ""};
}

BlockValidator::Result BlockValidator::check_delay(const Block& b) const {
    Hash expected_seed = compute_delay_seed(b.index, b.prev_hash, b.tx_root,
                                              b.creator_dh_inputs);
    if (expected_seed != b.delay_seed)
        return {false, "delay_seed mismatch"};
    if (delay_T_ == 0)
        return {false, "validator delay_T not configured"};
    if (!delay_hash_verify(b.delay_seed, delay_T_, b.delay_output))
        return {false, "delay_output invalid"};
    return {true, ""};
}

BlockValidator::Result BlockValidator::check_block_sigs(
    const Block& b, const NodeRegistry& registry) const {
    if (b.creator_block_sigs.size() != b.creators.size())
        return {false, "creator_block_sigs size != creators size"};
    if (k_block_sigs_ == 0)
        return {false, "validator k_block_sigs not configured"};
    if (k_block_sigs_ > b.creators.size())
        return {false, "k_block_sigs > M (genesis misconfigured)"};

    Hash digest = compute_block_digest(b);
    Signature zero_sig{};

    size_t signed_count = 0;
    for (size_t i = 0; i < b.creators.size(); ++i) {
        // Sentinel: all-zero sig means "did not sign in time". K-of-M weak
        // BFT permits up to (M - K) such positions. False-positive rate
        // (an Ed25519 sig happening to be all zeros) is ~2^-512, negligible.
        if (b.creator_block_sigs[i] == zero_sig) continue;

        auto e = registry.find(b.creators[i]);
        if (!e) return {false, "creator not found: " + b.creators[i]};
        if (!verify(e->pubkey, digest.data(), digest.size(), b.creator_block_sigs[i]))
            return {false, "block sig invalid: " + b.creators[i]};
        ++signed_count;
    }

    if (signed_count < k_block_sigs_)
        return {false, "block signatures " + std::to_string(signed_count)
                     + " < required " + std::to_string(k_block_sigs_)};
    return {true, ""};
}

BlockValidator::Result BlockValidator::check_cumulative_rand(
    const Block& b, const Chain& chain) const {
    Hash prev_rand = chain.empty() ? Hash{} : chain.head().cumulative_rand;
    Hash expected  = SHA256Builder{}
        .append(prev_rand)
        .append(b.delay_output)
        .finalize();
    if (expected != b.cumulative_rand)
        return {false, "cumulative_rand incorrect"};
    return {true, ""};
}

BlockValidator::Result BlockValidator::check_transactions(
    const Block& b, const Chain& chain, const NodeRegistry& registry) const {

    std::map<std::string, uint64_t> next_nonce;
    auto chain_next = [&](const std::string& from) -> uint64_t& {
        auto it = next_nonce.find(from);
        if (it == next_nonce.end())
            it = next_nonce.emplace(from, chain.next_nonce(from)).first;
        return it->second;
    };

    for (auto& tx : b.transactions) {
        // Two-tier identity (rev. 4):
        //   - Anonymous accounts (from = "0x" + 64 hex): pubkey is the address
        //     itself. Restricted to TRANSFER (cannot register / stake / etc).
        //   - Registered domains (from = anything else): pubkey from registry.
        //   - REGISTER tx is the special case where the registrant's pubkey
        //     comes from the tx payload (since they're not yet registered).
        const bool from_anon = is_anon_address(tx.from);

        PubKey pk{};
        if (tx.type == TxType::REGISTER) {
            if (from_anon)
                return {false, "REGISTER from anonymous account is not allowed"};
            if (tx.payload.size() != REGISTER_PAYLOAD_SIZE)
                return {false, "REGISTER payload size != 32"};
            std::copy_n(tx.payload.begin(), 32, pk.begin());
        } else if (from_anon) {
            // Only TRANSFER is allowed from anonymous accounts.
            if (tx.type != TxType::TRANSFER)
                return {false, "anonymous accounts may only TRANSFER (got "
                             + std::to_string(int(tx.type)) + ")"};
            pk = parse_anon_pubkey(tx.from);
        } else {
            auto e = registry.find(tx.from);
            if (!e) return {false, "tx sender not in registry: " + tx.from};
            pk = e->pubkey;
        }

        auto sb = tx.signing_bytes();
        if (!verify(pk, sb.data(), sb.size(), tx.sig))
            return {false, "tx signature invalid from: " + tx.from};

        uint64_t& n = chain_next(tx.from);
        if (tx.nonce != n)
            return {false, "nonce mismatch from " + tx.from
                         + ": expected " + std::to_string(n)
                         + " got " + std::to_string(tx.nonce)};
        n++;

        switch (tx.type) {
        case TxType::TRANSFER:
        case TxType::REGISTER:
            break;
        case TxType::DEREGISTER:
            if (!registry.find(tx.from))
                return {false, "DEREGISTER from non-registered: " + tx.from};
            break;
        case TxType::STAKE:
        case TxType::UNSTAKE:
            if (tx.payload.size() != 8)
                return {false, "STAKE/UNSTAKE payload must be 8 bytes"};
            break;
        }
    }
    return {true, ""};
}

BlockValidator::Result BlockValidator::check_timestamp(const Block& b) const {
    int64_t diff = b.timestamp - now_unix();
    if (diff > 5 || diff < -5)
        return {false, "timestamp out of +-5s window"};
    return {true, ""};
}

} // namespace dhcoin::node
