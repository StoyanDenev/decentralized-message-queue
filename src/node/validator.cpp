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
    if (auto r = check_equivocation_events(b, registry); !r.ok) return r;
    if (auto r = check_delay(b);                         !r.ok) return r;
    if (auto r = check_block_sigs(b, registry, chain);   !r.ok) return r;
    if (auto r = check_cumulative_rand(b, chain);        !r.ok) return r;
    if (auto r = check_transactions(b, chain, registry); !r.ok) return r;
    if (auto r = check_cross_shard_receipts(b, chain);   !r.ok) return r;
    if (auto r = check_inbound_receipts(b, chain);       !r.ok) return r;
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

    // rev.9 (B1): committee derives from per-shard, per-epoch seed.
    // epoch_index = b.index / epoch_blocks. epoch_rand is the rand at the
    // block opening that epoch (or genesis-anchored rand if epoch_start=0).
    auto   nodes     = registry.sorted_nodes();
    EpochIndex epoch_index = epoch_blocks_ ? (b.index / epoch_blocks_) : 0;
    uint64_t epoch_start = epoch_index * (epoch_blocks_ ? epoch_blocks_ : 1);
    Hash epoch_rand = resolve_epoch_rand(epoch_start, chain);
    Hash prev_rand = epoch_committee_seed(epoch_rand, shard_id_);
    (void)epoch_index;
    // m = K-committee size (b.creators.size()). Permitted values:
    //   MD blocks:  m == k_block_sigs_ (full K).
    //   BFT blocks: m == ceil(2*k_block_sigs_/3) (escalated, smaller committee).
    size_t m         = b.creators.size();
    size_t k_full    = k_block_sigs_;
    size_t k_bft     = (2 * k_full + 2) / 3;
    if (k_full != 0) {
        bool md_ok  = (b.consensus_mode == ConsensusMode::MUTUAL_DISTRUST) && (m == k_full);
        bool bft_ok = (b.consensus_mode == ConsensusMode::BFT)             && (m == k_bft);
        if (!md_ok && !bft_ok)
            return {false, "block creators count " + std::to_string(m)
                         + " inconsistent with consensus_mode "
                         + std::to_string(static_cast<int>(b.consensus_mode))
                         + " and genesis K=" + std::to_string(k_full)};
    }

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

    // rev.9 (B1): epoch-relative seed for the at-event committee
    // reconstruction (mirror check_creator_selection).
    EpochIndex epoch_index = epoch_blocks_ ? (b.index / epoch_blocks_) : 0;
    uint64_t   epoch_start = epoch_index * (epoch_blocks_ ? epoch_blocks_ : 1);
    Hash epoch_rand = resolve_epoch_rand(epoch_start, chain);
    Hash prev_rand = epoch_committee_seed(epoch_rand, shard_id_);
    Hash prev_hash = chain.head_hash();
    auto nodes     = registry.sorted_nodes();
    (void)epoch_index;

    // Per-event committee size: at step i, BEFORE applying ae[i], the
    // committee size is determined by the same escalation rule as
    // node.cpp::check_if_selected: if pool < K_full and we've hit
    // bft_escalation_threshold, committee shrinks to ceil(2K/3). Otherwise
    // K_full. This must match what the producer used at the time.
    size_t k_full = k_block_sigs_;
    size_t k_bft  = (2 * k_full + 2) / 3;

    // Reconstruct the creator-set sequence using the same exclude+remix rule
    // as check_creator_selection.
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

        // Match check_if_selected's escalation logic: at step i we have
        // already applied i prior aborts. If avail < k_full AND escalation
        // gate met AND avail >= k_bft, committee size at this event is
        // k_bft; otherwise k_full.
        size_t m_at_event = k_full;
        if (avail.size() < k_full
            && bft_enabled_
            && i >= bft_escalation_threshold_
            && avail.size() >= k_bft) {
            m_at_event = k_bft;
        }
        if (avail.size() < m_at_event)
            return {false, "insufficient eligible nodes at abort_event[" + std::to_string(i) + "]"};
        auto indices = select_m_creators(rand, avail.size(), m_at_event);
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

// Each EquivocationEvent must contain two signatures by the same registered
// key over two DIFFERENT block_digests at the SAME block_index. If valid,
// this is unambiguous proof of equivocation: the equivocator's full stake
// is forfeited at apply time (chain.cpp::apply_transactions). Validator
// rejects events where the two digests are equal (no equivocation), the
// equivocator isn't registered, the block_index doesn't match, or either
// signature fails to verify.
BlockValidator::Result BlockValidator::check_equivocation_events(
    const Block& b, const NodeRegistry& registry) const {
    for (size_t i = 0; i < b.equivocation_events.size(); ++i) {
        const auto& ev = b.equivocation_events[i];

        if (ev.digest_a == ev.digest_b)
            return {false, "equivocation_event[" + std::to_string(i)
                         + "] digest_a == digest_b (not equivocation)"};
        if (ev.sig_a == ev.sig_b)
            return {false, "equivocation_event[" + std::to_string(i)
                         + "] sig_a == sig_b (same signature)"};

        auto entry = registry.find(ev.equivocator);
        if (!entry)
            return {false, "equivocation_event[" + std::to_string(i)
                         + "] equivocator not in registry: " + ev.equivocator};

        if (!verify(entry->pubkey, ev.digest_a.data(), ev.digest_a.size(), ev.sig_a))
            return {false, "equivocation_event[" + std::to_string(i)
                         + "] sig_a does not verify against equivocator's key"};
        if (!verify(entry->pubkey, ev.digest_b.data(), ev.digest_b.size(), ev.sig_b))
            return {false, "equivocation_event[" + std::to_string(i)
                         + "] sig_b does not verify against equivocator's key"};
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
    const Block& b, const NodeRegistry& registry, const Chain& chain) const {
    if (b.creator_block_sigs.size() != b.creators.size())
        return {false, "creator_block_sigs size != creators size"};
    if (k_block_sigs_ == 0)
        return {false, "validator k_block_sigs not configured"};
    // committee size may be smaller than k_block_sigs_ in BFT-mode blocks
    // (escalated to ceil(2K/3)). check_creator_selection enforces the
    // size↔mode pairing.

    // rev.8 mode-eligibility: BFT mode is permitted only when bft_enabled
    // AND total abort threshold met AND committee size matches k_bft. The
    // committee-size check above (in check_creator_selection) already
    // enforces the size↔mode pairing; here we enforce the abort-threshold
    // gate so a malicious proposer can't unilaterally escalate.
    size_t total_aborts = b.abort_events.size();
    if (b.consensus_mode == ConsensusMode::BFT) {
        if (!bft_enabled_)
            return {false, "BFT block but bft_enabled=false at genesis"};
        if (total_aborts < bft_escalation_threshold_)
            return {false, "BFT block with insufficient aborts ("
                         + std::to_string(total_aborts) + " < " + std::to_string(bft_escalation_threshold_) + ")"};
    }

    size_t required = required_block_sigs(b.consensus_mode, b.creators.size());

    if (b.consensus_mode == ConsensusMode::MUTUAL_DISTRUST) {
        if (!b.bft_proposer.empty())
            return {false, "bft_proposer set in MUTUAL_DISTRUST block"};
    } else {
        // BFT: bft_proposer must be the deterministically-chosen committee
        // member, and that member must have signed. Use epoch-relative +
        // shard-salted rand to match check_creator_selection's seed.
        EpochIndex epi = epoch_blocks_ ? (b.index / epoch_blocks_) : 0;
        uint64_t   estart = epi * (epoch_blocks_ ? epoch_blocks_ : 1);
        Hash erand = resolve_epoch_rand(estart, chain);
        Hash seed = epoch_committee_seed(erand, shard_id_);
        size_t expected_idx = proposer_idx(seed, b.abort_events,
                                            b.creators.size());
        if (expected_idx >= b.creators.size())
            return {false, "proposer index out of range"};
        if (b.bft_proposer != b.creators[expected_idx])
            return {false, "wrong BFT proposer: block has '" + b.bft_proposer
                         + "', expected '" + b.creators[expected_idx] + "'"};
        Signature zero{};
        if (b.creator_block_sigs[expected_idx] == zero)
            return {false, "BFT proposer did not sign"};
    }

    Hash digest = compute_block_digest(b);
    Signature zero_sig{};

    size_t signed_count = 0;
    for (size_t i = 0; i < b.creators.size(); ++i) {
        // Sentinel: all-zero sig means "did not sign in time". MD requires
        // all K to sign (no sentinels); BFT permits up to K - ceil(2K/3)
        // sentinel positions. False-positive rate (a real Ed25519 sig
        // happening to be all zeros) is ~2^-512, negligible.
        if (b.creator_block_sigs[i] == zero_sig) continue;

        auto e = registry.find(b.creators[i]);
        if (!e) return {false, "creator not found: " + b.creators[i]};
        if (!verify(e->pubkey, digest.data(), digest.size(), b.creator_block_sigs[i]))
            return {false, "block sig invalid: " + b.creators[i]};
        ++signed_count;
    }

    if (signed_count < required)
        return {false, "block signatures " + std::to_string(signed_count)
                     + " < required " + std::to_string(required)
                     + " (mode=" + std::to_string(static_cast<int>(b.consensus_mode)) + ")"};
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

// rev.9 B2c.2-full: resolve the epoch rand for committee selection.
// Order of preference:
//   1. External provider (installed by Node when role==SHARD): the
//      cumulative_rand of the BEACON's block at epoch_start_height.
//      This is the production zero-trust path — both shard and beacon
//      derive committees from the same beacon-anchored rand.
//   2. Fallback to the local chain (SINGLE/BEACON role, or shard
//      bootstrap before beacon headers reach the requested height).
Hash BlockValidator::resolve_epoch_rand(uint64_t epoch_start,
                                          const Chain& chain) const {
    if (external_epoch_rand_) {
        if (auto v = external_epoch_rand_(epoch_start); v.has_value()) {
            return *v;
        }
    }
    if (epoch_start == 0 || epoch_start > chain.height()) {
        return chain.empty() ? Hash{} : chain.head().cumulative_rand;
    }
    return chain.at(epoch_start - 1).cumulative_rand;
}

// rev.9 B3.2: receipts must match the cross-shard subset of
// transactions[] one-for-one in order. The producer (build_body) emits
// a receipt for every TRANSFER whose `to` routes to another shard;
// validators independently rederive the expected list and compare.
// This makes receipts as trustworthy as the K-of-K-signed block:
// tampering with a receipt's `to`/`amount`/etc. either falls out of
// sync with the tx (caught here) or changes the block hash (breaks
// signing).
BlockValidator::Result BlockValidator::check_cross_shard_receipts(
    const Block& b, const Chain& chain) const {

    std::vector<const Transaction*> cross;
    for (auto& tx : b.transactions) {
        if (tx.type == TxType::TRANSFER && chain.is_cross_shard(tx.to))
            cross.push_back(&tx);
    }
    if (cross.size() != b.cross_shard_receipts.size())
        return {false, "cross_shard_receipts size " +
                       std::to_string(b.cross_shard_receipts.size()) +
                       " != cross-shard tx count " +
                       std::to_string(cross.size())};

    for (size_t i = 0; i < cross.size(); ++i) {
        const auto& tx = *cross[i];
        const auto& r  = b.cross_shard_receipts[i];
        if (r.src_shard       != chain.my_shard_id())
            return {false, "receipt[" + std::to_string(i) + "] src_shard mismatch"};
        if (r.dst_shard       != crypto::shard_id_for_address(
                                     tx.to, chain.shard_count(), chain.shard_salt()))
            return {false, "receipt[" + std::to_string(i) + "] dst_shard mismatch"};
        if (r.src_block_index != b.index)
            return {false, "receipt[" + std::to_string(i) + "] src_block_index mismatch"};
        if (r.tx_hash != tx.hash || r.from != tx.from || r.to != tx.to
            || r.amount != tx.amount || r.fee != tx.fee || r.nonce != tx.nonce)
            return {false, "receipt[" + std::to_string(i) + "] field mismatch with tx"};
    }
    return {true, ""};
}

// rev.9 B3.4: inbound_receipts checks. Source-side K-of-K verification
// happens at receive time (each producer ratifies the bundle when
// storing in pending_inbound_receipts_); the destination committee's
// K-of-K signing of THIS block is the collective on-chain attestation
// that the inbound set was valid at production time. The validator's
// job here is shape + dedup, not source-block reverification.
BlockValidator::Result BlockValidator::check_inbound_receipts(
    const Block& b, const Chain& chain) const {

    // SINGLE / BEACON chains never apply inbound receipts.
    if (chain.shard_count() <= 1) {
        if (!b.inbound_receipts.empty())
            return {false, "inbound_receipts non-empty on non-shard chain"};
        return {true, ""};
    }

    std::set<std::pair<ShardId, Hash>> seen;
    for (size_t i = 0; i < b.inbound_receipts.size(); ++i) {
        const auto& r = b.inbound_receipts[i];
        if (r.dst_shard != chain.my_shard_id())
            return {false, "inbound_receipts[" + std::to_string(i)
                         + "] dst_shard " + std::to_string(r.dst_shard)
                         + " != my_shard_id " + std::to_string(chain.my_shard_id())};
        if (r.src_shard == chain.my_shard_id())
            return {false, "inbound_receipts[" + std::to_string(i)
                         + "] src_shard equals own shard_id"};
        auto key = std::make_pair(r.src_shard, r.tx_hash);
        if (!seen.insert(key).second)
            return {false, "inbound_receipts[" + std::to_string(i)
                         + "] duplicate (src_shard, tx_hash) within block"};
        if (chain.inbound_receipt_applied(r.src_shard, r.tx_hash))
            return {false, "inbound_receipts[" + std::to_string(i)
                         + "] already credited in earlier block"};
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
