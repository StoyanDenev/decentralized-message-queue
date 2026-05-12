// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/node/validator.hpp>
#include <determ/node/producer.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/crypto/random.hpp>
#include <determ/crypto/keys.hpp>
#include <algorithm>
#include <chrono>
#include <map>
#include <set>

namespace determ::node {

using namespace determ::crypto;
using namespace determ::chain;

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
    if (auto r = check_creator_dh_secrets(b, registry);  !r.ok) return r;
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
    //
    // rev.9 R2: filter the eligible pool by this chain's
    // committee_region. Empty region (default) yields the full pool —
    // identical to pre-R2 sorted_nodes() output.
    auto   nodes     = registry.eligible_in_region(committee_region_);
    // R4 Phase 4: under-quorum stress branch. If this shard currently
    // absorbs refugee shards (per Chain::merge_state_), extend the
    // eligible pool with validators from each refugee region. Refugees
    // signing this committee's block are accepted as creators here.
    for (auto& [refugee_shard, refugee_region] :
         chain.shards_absorbed_by(shard_id_)) {
        (void)refugee_shard;
        if (refugee_region.empty() || refugee_region == committee_region_)
            continue;
        auto refugees = registry.eligible_in_region(refugee_region);
        for (auto& r : refugees) {
            bool dup = false;
            for (auto& n : nodes) if (n.domain == r.domain) { dup = true; break; }
            if (!dup) nodes.push_back(r);
        }
    }
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
    // rev.9 R2: same region filter as check_creator_selection — must
    // mirror exactly so abort-cert reconstruction sees the same pool
    // the producer committed to.
    auto nodes     = registry.eligible_in_region(committee_region_);
    // R4 Phase 4: same stress-branch extension as check_creator_selection.
    for (auto& [refugee_shard, refugee_region] :
         chain.shards_absorbed_by(shard_id_)) {
        (void)refugee_shard;
        if (refugee_region.empty() || refugee_region == committee_region_)
            continue;
        auto refugees = registry.eligible_in_region(refugee_region);
        for (auto& r : refugees) {
            bool dup = false;
            for (auto& n : nodes) if (n.domain == r.domain) { dup = true; break; }
            if (!dup) nodes.push_back(r);
        }
    }
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

// rev.9 S-009: each creator_dh_secrets[i] must hash with creators[i]'s
// pubkey to creator_dh_inputs[i] (the Phase-1 commit). This is the
// commit-reveal step that closes selective-abort defense:
//   commit_i = SHA256(secret_i || pubkey_i)
// is signed in Phase 1 (by creator_ed_sigs[i]), so any post-Phase-1
// substitution of secret_i would fail this check.
BlockValidator::Result BlockValidator::check_creator_dh_secrets(
    const Block& b, const NodeRegistry& registry) const {
    if (b.creator_dh_secrets.size() != b.creators.size())
        return {false, "creator_dh_secrets size != creators size"};
    for (size_t i = 0; i < b.creators.size(); ++i) {
        auto e = registry.find(b.creators[i]);
        if (!e) return {false, "creator not found: " + b.creators[i]};
        Hash expected = SHA256Builder{}
            .append(b.creator_dh_secrets[i])
            .append(e->pubkey.data(), e->pubkey.size())
            .finalize();
        if (expected != b.creator_dh_inputs[i])
            return {false, "creator_dh_secret[" + std::to_string(i)
                         + "] does not match commit"};
    }
    return {true, ""};
}

BlockValidator::Result BlockValidator::check_delay(const Block& b) const {
    Hash expected_seed = compute_delay_seed(b.index, b.prev_hash, b.tx_root,
                                              b.creator_dh_inputs);
    if (expected_seed != b.delay_seed)
        return {false, "delay_seed mismatch"};

    // rev.9 S-009: delay_output = SHA256(delay_seed || ordered_secrets).
    // The selective-abort defense relies on each creator_dh_secrets[i]
    // being the preimage of creator_dh_inputs[i] (= SHA256(secret||pubkey)),
    // verified in check_creator_dh_secrets. Block hash binds delay_output
    // and creator_dh_secrets via signing_bytes; sigs over block_digest
    // don't directly cover delay_output but commit-reveal binds it
    // uniquely (any tampering breaks the SHA256 commit-reveal check).
    if (b.creator_dh_secrets.size() != b.creators.size())
        return {false, "creator_dh_secrets size != creators size"};
    Hash expected_output = compute_block_rand(b.delay_seed, b.creator_dh_secrets);
    if (expected_output != b.delay_output)
        return {false, "delay_output mismatch (commit-reveal)"};
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

        // E1: explicit guard against any tx claiming `from` is the Zeroth
        // pool. The all-zero anon address encodes a low-order curve point
        // with no usable private key — signature verification should
        // fail anyway, but this fail-fast check is cheaper and unambiguous.
        if (tx.from == ZEROTH_ADDRESS)
            return {false, "Zeroth pool is a pseudo-account; no tx may "
                          "originate from " + std::string(ZEROTH_ADDRESS)};

        PubKey pk{};
        if (tx.type == TxType::REGISTER) {
            if (from_anon)
                return {false, "REGISTER from anonymous account is not allowed"};
            // rev.9 R1 wire format:
            //   [pubkey: 32B][region_len: u8][region: utf8 bytes]
            // Legacy 32-B pubkey-only payload is accepted (region absent
            // = empty pool tag). Larger payloads must declare a length
            // that exactly accounts for the trailing region bytes, with
            // region_len <= 32 and region matching the normalized
            // ASCII charset [a-z0-9-_]. Validation here mirrors what
            // genesis-load enforces, so REGISTER region is hash-stable
            // across both wire ingress paths.
            if (tx.payload.size() < REGISTER_PAYLOAD_PUBKEY_SIZE)
                return {false, "REGISTER payload size < 32"};
            if (tx.payload.size() > REGISTER_PAYLOAD_MAX_SIZE)
                return {false, "REGISTER payload size > "
                              + std::to_string(REGISTER_PAYLOAD_MAX_SIZE)};
            if (tx.payload.size() == REGISTER_PAYLOAD_PUBKEY_SIZE + 1)
                return {false, "REGISTER payload truncated (region_len without bytes)"};
            if (tx.payload.size() > REGISTER_PAYLOAD_PUBKEY_SIZE) {
                size_t rlen = tx.payload[REGISTER_PAYLOAD_PUBKEY_SIZE];
                if (rlen > REGISTER_REGION_MAX)
                    return {false, "REGISTER region length > 32"};
                if (tx.payload.size() != REGISTER_PAYLOAD_PUBKEY_SIZE + 1 + rlen)
                    return {false, "REGISTER payload size != 32 + 1 + region_len"};
                // Charset enforcement: lowercase ASCII alphanumeric +
                // '-' + '_'. Reject if any byte falls outside; this is
                // strict equality (no implicit tolower at validate time
                // — RPC paths normalize before signing so the on-wire
                // bytes are already canonical).
                for (size_t i = 0; i < rlen; ++i) {
                    unsigned char c = tx.payload[REGISTER_PAYLOAD_PUBKEY_SIZE + 1 + i];
                    bool ok = (c >= 'a' && c <= 'z')
                           || (c >= '0' && c <= '9')
                           || c == '-' || c == '_';
                    if (!ok)
                        return {false, "REGISTER region has invalid char "
                                       "(allowed [a-z0-9-_])"};
                }
                // A6 gate: REGISTER tx with a non-empty region tag is
                // only meaningful under EXTENDED. NONE rejects loudly
                // (single-chain deployment has no concept of region).
                // CURRENT silently tolerates the tag (backward-compat
                // for chains that may carry a region from a future
                // mode-switch); the registry stores it but
                // check_creator_selection ignores region under CURRENT.
                if (rlen > 0 && sharding_mode_ == ShardingMode::NONE) {
                    return {false, "REGISTER carries non-empty region under "
                                   "sharding_mode=none (region is meaningless "
                                   "in single-chain deployments)"};
                }
            }
            std::copy_n(tx.payload.begin(), 32, pk.begin());
        } else if (tx.type == TxType::REGION_CHANGE) {
            // rev.9 R1: REGION_CHANGE is reserved for v2. Reject
            // unconditionally with a clear error so wire-format slot is
            // locked but no apply path runs.
            return {false, "REGION_CHANGE tx type is reserved for future use"};
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
            // A4: TRANSFER may carry an optional application-defined
            // payload (memo, contract reference, off-chain pointer,
            // ...). Protocol guarantees integrity only — payload bytes
            // are signed (Transaction::signing_bytes binds payload) and
            // included in the block hash. Semantics are application-
            // level; see docs/PROTOCOL.md §3.
            if (tx.payload.size() > 32)
                return {false, "TRANSFER payload exceeds 32-byte cap (got "
                             + std::to_string(tx.payload.size()) + " bytes)"};
            break;
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
        case TxType::REGION_CHANGE:
            // Defensive: the early branch above already rejects
            // REGION_CHANGE before reaching this switch. Keeping the
            // case present silences -Wswitch and documents the slot.
            return {false, "REGION_CHANGE tx type is reserved for future use"};
        case TxType::PARAM_CHANGE: {
            // A5 governance: payload-shape + mode + whitelist + multisig
            // checks. Apply-side staging at effective_height is handled
            // in chain.cpp.
            if (governance_mode_ == 0) {
                return {false, "PARAM_CHANGE rejected: chain is in "
                               "uncontrolled governance mode"};
            }
            // Decode payload:
            //   [name_len: u8][name][value_len: u16 LE][value]
            //   [effective_height: u64 LE][sig_count: u8]
            //   sig_count × { [keyholder_index: u16 LE][ed_sig: 64B] }
            const auto& p = tx.payload;
            size_t off = 0;
            if (p.size() < 1) return {false, "PARAM_CHANGE payload truncated (name_len)"};
            size_t nlen = p[off++];
            if (p.size() < off + nlen)
                return {false, "PARAM_CHANGE payload truncated (name)"};
            std::string name(p.begin() + off, p.begin() + off + nlen);
            off += nlen;
            if (p.size() < off + 2) return {false, "PARAM_CHANGE payload truncated (value_len)"};
            uint16_t vlen = uint16_t(p[off]) | (uint16_t(p[off+1]) << 8);
            off += 2;
            if (p.size() < off + vlen)
                return {false, "PARAM_CHANGE payload truncated (value)"};
            std::vector<uint8_t> value(p.begin() + off, p.begin() + off + vlen);
            off += vlen;
            if (p.size() < off + 8) return {false, "PARAM_CHANGE payload truncated (effective_height)"};
            uint64_t eff = 0;
            for (int i = 0; i < 8; ++i) eff |= uint64_t(p[off + i]) << (8 * i);
            off += 8;
            if (p.size() < off + 1) return {false, "PARAM_CHANGE payload truncated (sig_count)"};
            uint8_t sigc = p[off++];
            const size_t expected_tail = size_t(sigc) * (2 + 64);
            if (p.size() != off + expected_tail)
                return {false, "PARAM_CHANGE payload size mismatch"};
            (void)eff;
            (void)value;

            // Whitelist enforcement. Off-list names rejected even with
            // full threshold.
            static const std::set<std::string> kWhitelist = {
                "tx_commit_ms", "block_sig_ms", "abort_claim_ms",
                "bft_escalation_threshold", "SUSPENSION_SLASH",
                "MIN_STAKE", "UNSTAKE_DELAY",
                "param_keyholders", "param_threshold",
            };
            if (kWhitelist.find(name) == kWhitelist.end()) {
                return {false, "PARAM_CHANGE rejected: parameter '"
                             + name + "' is not on the governance whitelist"};
            }

            // Multisig verification: each (keyholder_index, ed_sig)
            // pair signs the canonical (name ‖ value ‖ effective_height)
            // tuple, distinct indices, with index < keyholders.size().
            // Distinct-signer + threshold gate prevents replay of one
            // keyholder's signature multiple times.
            std::vector<uint8_t> sig_msg;
            sig_msg.reserve(nlen + vlen + 8 + 16);
            sig_msg.push_back(static_cast<uint8_t>(nlen));
            sig_msg.insert(sig_msg.end(), name.begin(), name.end());
            sig_msg.push_back(static_cast<uint8_t>(vlen & 0xff));
            sig_msg.push_back(static_cast<uint8_t>((vlen >> 8) & 0xff));
            sig_msg.insert(sig_msg.end(), value.begin(), value.end());
            for (int i = 0; i < 8; ++i)
                sig_msg.push_back(static_cast<uint8_t>((eff >> (8*i)) & 0xff));

            std::set<uint16_t> seen_idx;
            uint32_t good_sigs = 0;
            for (uint8_t s = 0; s < sigc; ++s) {
                uint16_t idx = uint16_t(p[off]) | (uint16_t(p[off+1]) << 8);
                off += 2;
                Signature msig{};
                std::copy_n(p.begin() + off, 64, msig.begin());
                off += 64;
                if (idx >= param_keyholders_.size())
                    return {false, "PARAM_CHANGE keyholder_index out of range"};
                if (!seen_idx.insert(idx).second)
                    return {false, "PARAM_CHANGE duplicate keyholder_index"};
                if (verify(param_keyholders_[idx], sig_msg.data(),
                           sig_msg.size(), msig)) {
                    good_sigs++;
                }
            }
            if (good_sigs < param_threshold_) {
                return {false, "PARAM_CHANGE signature threshold not met "
                               "(got " + std::to_string(good_sigs)
                             + ", need " + std::to_string(param_threshold_)
                             + ")"};
            }
            break;
        }
        case TxType::MERGE_EVENT: {
            // R4 Phase 1+2+4+6: gate + decode + region charset check +
            // S-036 partial witness-window bounds. The full historical
            // witness-window check (verify each beacon block in
            // [evidence_window_start, +merge_threshold_blocks) contains
            // no SHARD_TIP_S AND eligible_in_region < 2K) requires
            // on-chain SHARD_TIP records — a separate work item.
            // This commit ships the internal-consistency bounds that
            // can be checked without that record:
            //   * BEGIN: evidence window must end at or before the
            //     containing block's height (window is in the past).
            //   * BEGIN: evidence_window_start must be on-chain history
            //     (start >= 0, start + threshold <= current).
            //   * effective_height must be >= block.index + grace
            //     (committees observe the transition before it fires).
            if (sharding_mode_ != ShardingMode::EXTENDED) {
                return {false, "MERGE_EVENT tx requires "
                               "sharding_mode=extended"};
            }
            auto ev = MergeEvent::decode(tx.payload);
            if (!ev) {
                return {false, "MERGE_EVENT payload malformed "
                               "(canonical encoding required)"};
            }
            if (ev->partner_id == ev->shard_id)
                return {false, "MERGE_EVENT partner_id equals shard_id"};
            // Region charset rule: [a-z0-9-_], <= 32 bytes. Empty is
            // valid (refugee shard runs in CURRENT / global pool).
            for (unsigned char c : ev->merging_shard_region) {
                bool ok = (c >= 'a' && c <= 'z')
                       || (c >= '0' && c <= '9')
                       || c == '-' || c == '_';
                if (!ok) {
                    return {false, "MERGE_EVENT merging_shard_region "
                                   "violates charset [a-z0-9-_]"};
                }
            }
            // R4 Phase 6: bounds checks. Read thresholds from Chain.
            uint64_t grace     = chain.merge_grace_blocks();
            uint64_t threshold = chain.merge_threshold_blocks();
            if (ev->effective_height < b.index + grace) {
                return {false, "MERGE_EVENT effective_height "
                             + std::to_string(ev->effective_height)
                             + " is too soon (need >= "
                             + std::to_string(b.index + grace) + ")"};
            }
            if (ev->event_type == MergeEvent::BEGIN) {
                // Evidence window must lie entirely in committed
                // history. Reject obviously-forged windows (future
                // start, or window extending past the containing
                // block).
                if (threshold > 0
                    && ev->evidence_window_start + threshold > b.index) {
                    return {false, "MERGE_EVENT BEGIN evidence window "
                                   "extends past block height "
                                 + std::to_string(b.index)};
                }
            }
            // Modular arithmetic check (partner == (shard+1) mod
            // num_shards) requires Chain access — defer to apply.
            break;
        }
        case TxType::COMPOSABLE_BATCH: {
            // v2.4: validate the batch envelope + each inner tx's shape
            // and signature. Constraints:
            //   - Payload decodes as a JSON array of inner txs
            //   - Inner count in [1, MAX_COMPOSABLE_INNER]
            //   - Each inner.type == TRANSFER (v2.4 restriction)
            //   - Each inner.fee == 0 (outer pays the chain fee)
            //   - Each inner.payload.size() <= 32 (same as a standalone
            //     TRANSFER)
            //   - Each inner is independently signed by its inner.from
            //     (anon address parse for bearer; registry lookup for
            //     registered domain)
            //   - No nested COMPOSABLE_BATCH (flat only)
            //
            // Inner nonce-to-chain-state consistency is NOT checked
            // here — that depends on the live chain state at apply
            // time, and the apply path performs the check inside
            // atomic_scope (rolling back the whole batch if any inner
            // nonce mismatches). Same for balance checks.
            std::vector<Transaction> inner;
            try {
                std::string s(tx.payload.begin(), tx.payload.end());
                auto arr = nlohmann::json::parse(s);
                if (!arr.is_array()) {
                    return {false, "COMPOSABLE_BATCH payload not a JSON array"};
                }
                for (auto& j : arr) {
                    inner.push_back(Transaction::from_json(j));
                }
            } catch (std::exception& e) {
                return {false,
                    std::string("COMPOSABLE_BATCH payload malformed: ") + e.what()};
            }
            if (inner.empty()) {
                return {false, "COMPOSABLE_BATCH empty (must contain at "
                               "least 1 inner tx)"};
            }
            if (inner.size() > MAX_COMPOSABLE_INNER) {
                return {false, "COMPOSABLE_BATCH oversized (max "
                             + std::to_string(MAX_COMPOSABLE_INNER)
                             + " inner txs)"};
            }
            for (size_t ii = 0; ii < inner.size(); ++ii) {
                auto& it = inner[ii];
                if (it.type != TxType::TRANSFER) {
                    return {false, "COMPOSABLE_BATCH inner["
                                 + std::to_string(ii)
                                 + "] type must be TRANSFER in v2.4"};
                }
                if (it.fee != 0) {
                    return {false, "COMPOSABLE_BATCH inner["
                                 + std::to_string(ii)
                                 + "] fee must be 0 (outer pays)"};
                }
                if (it.payload.size() > 32) {
                    return {false, "COMPOSABLE_BATCH inner["
                                 + std::to_string(ii)
                                 + "] payload exceeds 32 bytes"};
                }
                // Inner-tx signature verification: derive the inner.from's
                // pubkey (parse_anon_pubkey for bearer / registry.find for
                // registered) and verify it.sig over it.signing_bytes().
                PubKey ipk{};
                if (is_anon_address(it.from)) {
                    ipk = parse_anon_pubkey(it.from);
                } else if (auto re = registry.find(it.from)) {
                    ipk = re->pubkey;
                } else {
                    return {false, "COMPOSABLE_BATCH inner["
                                 + std::to_string(ii)
                                 + "] sender not in registry: " + it.from};
                }
                auto sb = it.signing_bytes();
                if (!verify(ipk, sb.data(), sb.size(), it.sig)) {
                    return {false, "COMPOSABLE_BATCH inner["
                                 + std::to_string(ii)
                                 + "] signature invalid from " + it.from};
                }
            }
            break;
        }
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
    // S-003: widened from ±5s to ±30s to match the spec text (README §8
    // and PROTOCOL.md §4). The tighter window caused false-positive
    // aborts under normal cross-region NTP drift (typically 50-500 ms
    // but occasionally seconds for non-NTP'd hosts) plus in-flight
    // network latency. ±30s is conservative-but-livenessy; honest
    // committee members' clocks need only agree to within half a
    // minute, which is achievable without any NTP tuning. A median-of-
    // last-N-blocks check (Bitcoin-style) is the v2 path if drift
    // becomes a measurement concern; today the wall-clock check is
    // just a sanity bound, not a consensus-defining property.
    constexpr int64_t kTimestampWindowSec = 30;
    int64_t diff = b.timestamp - now_unix();
    if (diff > kTimestampWindowSec || diff < -kTimestampWindowSec)
        return {false, "timestamp out of +-30s window"};
    return {true, ""};
}

} // namespace determ::node
