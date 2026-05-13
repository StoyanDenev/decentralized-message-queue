// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Unchained Contributors
#include <unchained/node/producer.hpp>
#include <unchained/chain/params.hpp>
#include <unchained/crypto/keys.hpp>
#include <unchained/crypto/random.hpp>
#include <unchained/crypto/sha256.hpp>
#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>

namespace unchained::node {

using namespace unchained::crypto;
using namespace unchained::chain;
using json = nlohmann::json;

// ─── ContribMsg JSON ─────────────────────────────────────────────────────────

json ContribMsg::to_json() const {
    json arr = json::array();
    for (auto& h : tx_hashes) arr.push_back(to_hex(h));
    return {
        {"block_index", block_index},
        {"signer",      signer},
        {"prev_hash",   to_hex(prev_hash)},
        {"aborts_gen",  aborts_gen},
        {"tx_hashes",   arr},
        {"dh_input",    to_hex(dh_input)},
        {"ed_sig",      to_hex(ed_sig)}
    };
}

ContribMsg ContribMsg::from_json(const json& j) {
    ContribMsg m;
    m.block_index = j["block_index"].get<uint64_t>();
    m.signer      = j["signer"].get<std::string>();
    m.prev_hash   = from_hex_arr<32>(j["prev_hash"].get<std::string>());
    m.aborts_gen  = j.value("aborts_gen", uint64_t{0});
    if (j.contains("tx_hashes"))
        for (auto& h : j["tx_hashes"])
            m.tx_hashes.push_back(from_hex_arr<32>(h.get<std::string>()));
    m.dh_input = from_hex_arr<32>(j["dh_input"].get<std::string>());
    m.ed_sig   = from_hex_arr<64>(j["ed_sig"].get<std::string>());
    return m;
}

// ─── AbortClaimMsg JSON ──────────────────────────────────────────────────────

json AbortClaimMsg::to_json() const {
    return {
        {"block_index",     block_index},
        {"round",           round},
        {"prev_hash",       to_hex(prev_hash)},
        {"missing_creator", missing_creator},
        {"claimer",         claimer},
        {"ed_sig",          to_hex(ed_sig)}
    };
}

AbortClaimMsg AbortClaimMsg::from_json(const json& j) {
    AbortClaimMsg m;
    m.block_index     = j["block_index"].get<uint64_t>();
    m.round           = j["round"].get<uint8_t>();
    m.prev_hash       = from_hex_arr<32>(j["prev_hash"].get<std::string>());
    m.missing_creator = j["missing_creator"].get<std::string>();
    m.claimer         = j["claimer"].get<std::string>();
    m.ed_sig          = from_hex_arr<64>(j["ed_sig"].get<std::string>());
    return m;
}

Hash make_abort_claim_message(uint64_t block_index, uint8_t round,
                               const Hash& prev_hash,
                               const std::string& missing_creator) {
    SHA256Builder b;
    b.append(std::string("DTM-AbortClaim-v1"));
    b.append(block_index);
    b.append(round);
    b.append(prev_hash);
    b.append(missing_creator);
    return b.finalize();
}

AbortClaimMsg make_abort_claim(const NodeKey& key,
                                const std::string& claimer,
                                uint64_t block_index, uint8_t round,
                                const Hash& prev_hash,
                                const std::string& missing_creator) {
    AbortClaimMsg m;
    m.block_index     = block_index;
    m.round           = round;
    m.prev_hash       = prev_hash;
    m.missing_creator = missing_creator;
    m.claimer         = claimer;
    Hash msg = make_abort_claim_message(block_index, round, prev_hash, missing_creator);
    m.ed_sig = sign(key, msg.data(), msg.size());
    return m;
}

// ─── BlockSigMsg JSON ────────────────────────────────────────────────────────

json BlockSigMsg::to_json() const {
    return {
        {"block_index",  block_index},
        {"signer",       signer},
        {"delay_output", to_hex(delay_output)},
        {"dh_secret",    to_hex(dh_secret)},
        {"ed_sig",       to_hex(ed_sig)}
    };
}

BlockSigMsg BlockSigMsg::from_json(const json& j) {
    BlockSigMsg m;
    m.block_index  = j["block_index"].get<uint64_t>();
    m.signer       = j["signer"].get<std::string>();
    m.delay_output = from_hex_arr<32>(j["delay_output"].get<std::string>());
    // rev.9 S-009: dh_secret defaulted to zero for old-format messages.
    if (j.contains("dh_secret"))
        m.dh_secret = from_hex_arr<32>(j["dh_secret"].get<std::string>());
    m.ed_sig       = from_hex_arr<64>(j["ed_sig"].get<std::string>());
    return m;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

Hash make_contrib_commitment(uint64_t block_index, const Hash& prev_hash,
                              const std::vector<Hash>& sorted_tx_hashes,
                              const Hash& dh_input) {
    SHA256Builder inner;
    for (auto& h : sorted_tx_hashes) inner.append(h);
    Hash inner_root = inner.finalize();

    SHA256Builder b;
    b.append(block_index);
    b.append(prev_hash);
    b.append(inner_root);
    b.append(dh_input);
    return b.finalize();
}

Hash compute_tx_root(const std::vector<std::vector<Hash>>& creator_tx_lists) {
    std::set<Hash> u;
    for (auto& list : creator_tx_lists)
        for (auto& h : list) u.insert(h);

    SHA256Builder b;
    for (auto& h : u) b.append(h);
    return b.finalize();
}

// S-025 closure: compute_tx_root_intersection deleted as unused. The
// function was a relic of a pre-v1 design where the canonical tx set
// was the intersection of committee members' lists (every member must
// independently propose the tx). v1 settled on union semantics —
// censorship requires ALL K to omit. The intersection helper has no
// callers in the current code base and is removed to reduce confusion.
// If a future v2 mode wants intersection semantics, it can re-introduce
// the function or guard it under a feature flag.

Hash compute_delay_seed(uint64_t block_index, const Hash& prev_hash,
                         const Hash& tx_root,
                         const std::vector<Hash>& creator_dh_inputs) {
    SHA256Builder b;
    b.append(block_index);
    b.append(prev_hash);
    b.append(tx_root);
    for (auto& h : creator_dh_inputs) b.append(h);
    return b.finalize();
}

size_t proposer_idx(const Hash& prev_cum_rand,
                    const std::vector<AbortEvent>& aborts,
                    size_t committee_size) {
    if (committee_size == 0) return 0;
    SHA256Builder b;
    b.append(prev_cum_rand);
    for (auto& ae : aborts) b.append(ae.event_hash);
    b.append(std::string("bft-proposer"));
    Hash mix = b.finalize();
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i)
        v = (v << 8) | mix[i];
    return static_cast<size_t>(v % committee_size);
}

size_t count_round1_aborts(const std::vector<AbortEvent>& aborts) {
    size_t n = 0;
    for (auto& ae : aborts) if (ae.round == 1) ++n;
    return n;
}

size_t required_block_sigs(ConsensusMode mode, size_t committee_size) {
    if (mode == ConsensusMode::MUTUAL_DISTRUST) return committee_size;
    // BFT: ceil(2K/3)
    return (2 * committee_size + 2) / 3;
}

// rev.9 S-009 closure: block_digest excludes delay_output. The delay
// output is determined by Phase-2-revealed secrets which arrive after
// digest signing — we cannot include them in the digest without a
// chicken-and-egg waiting protocol. Safety holds because delay_output
// is recomputed by every node from delay_seed (Phase-1 inputs, signed)
// + creator_dh_secrets (each verifiable against the signed commit in
// creator_dh_inputs[i]). The validator's recomputation rejects any
// tampered delay_output. The block hash (via Block::signing_bytes)
// still binds delay_output and creator_dh_secrets so block identity
// is unique.
// S-030 D2 (block-digest field-coverage gap): the K-of-K committee
// signature target excludes evidence and receipt lists, leaving a
// one-block window where two valid K-of-K-signed block instances
// can differ in those fields behind the same digest. See
// docs/proofs/S030-D2-Analysis.md for the full analysis and why a
// naive digest extension does not work (gossip-async views).
//
// Status: a Phase-1-side view reconciliation mechanism (ContribMsg
// includes a hash of each member's evidence-pool view; assembly
// reconciles at Phase 1→2 transition; canonical reconciliation feeds
// the digest) is the correct fix. Tracked as a v2 work item; not in
// this v1.x release.
Hash compute_block_digest(const Block& b) {
    SHA256Builder h;
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    return h.finalize();
}

// rev.9 S-009: post-Phase-2 randomness output. Computed once K secrets
// gather. ordered_secrets[i] must correspond to creators[i] (same
// committee selection order as creator_dh_inputs).
Hash compute_block_rand(const Hash& delay_seed,
                          const std::vector<Hash>& ordered_secrets) {
    SHA256Builder h;
    h.append(delay_seed);
    for (auto& s : ordered_secrets) h.append(s);
    return h.finalize();
}

// ─── make_contrib ────────────────────────────────────────────────────────────

ContribMsg make_contrib(const NodeKey& key,
                         const std::string& domain,
                         uint64_t block_index,
                         const Hash& prev_hash,
                         uint64_t aborts_gen,
                         const std::vector<Hash>& tx_snapshot,
                         const Hash& dh_input) {
    ContribMsg m;
    m.block_index = block_index;
    m.signer      = domain;
    m.prev_hash   = prev_hash;
    m.aborts_gen  = aborts_gen;
    m.tx_hashes   = tx_snapshot;
    m.dh_input    = dh_input;
    std::sort(m.tx_hashes.begin(), m.tx_hashes.end());
    m.tx_hashes.erase(std::unique(m.tx_hashes.begin(), m.tx_hashes.end()),
                      m.tx_hashes.end());

    Hash commit = make_contrib_commitment(block_index, prev_hash, m.tx_hashes, dh_input);
    m.ed_sig = sign(key, commit.data(), commit.size());
    return m;
}

// ─── make_block_sig ──────────────────────────────────────────────────────────

BlockSigMsg make_block_sig(const NodeKey& key,
                            const std::string& domain,
                            uint64_t block_index,
                            const Hash& delay_output,
                            const Hash& block_digest,
                            const Hash& dh_secret) {
    BlockSigMsg m;
    m.block_index  = block_index;
    m.signer       = domain;
    m.delay_output = delay_output;
    m.dh_secret    = dh_secret;
    m.ed_sig       = sign(key, block_digest.data(), block_digest.size());
    return m;
}

// ─── build_body ──────────────────────────────────────────────────────────────

Block build_body(
    const std::map<Hash, Transaction>& tx_store,
    const Chain&                       chain,
    const std::vector<AbortEvent>&     aborts,
    const std::vector<std::string>&    creator_domains,
    const std::vector<ContribMsg>&     contribs,
    const Hash&                        delay_output,
    uint32_t                           m_pool_size,
    ConsensusMode                      mode,
    const std::string&                 bft_proposer_domain,
    const std::vector<EquivocationEvent>& equivocation_events,
    const std::vector<CrossShardReceipt>& inbound_receipts,
    const std::vector<Hash>&              ordered_secrets) {

    Block b;
    b.index               = chain.empty() ? 1 : chain.height();
    b.prev_hash           = chain.empty() ? Hash{} : chain.head_hash();
    b.timestamp           = now_unix();
    b.abort_events        = aborts;
    b.equivocation_events = equivocation_events;
    b.creators            = creator_domains;

    // Per-creator Phase-1 evidence in selection order.
    for (auto& c : contribs) {
        b.creator_tx_lists.push_back(c.tx_hashes);
        b.creator_ed_sigs.push_back(c.ed_sig);
        b.creator_dh_inputs.push_back(c.dh_input);
    }

    // rev.9 S-009: when ordered_secrets is provided, the block is being
    // built for finalization (try_finalize_round) — populate
    // creator_dh_secrets and recompute delay_output as
    // SHA256(delay_seed || ordered_secrets). When empty, the block is
    // being built for a Phase-2 candidate digest sign (delay_output
    // isn't in the digest, so its value at this stage is irrelevant —
    // we still set it to the caller-provided value for compatibility,
    // but signers don't bind it).
    if (!ordered_secrets.empty())
        b.creator_dh_secrets = ordered_secrets;

    // tx_root = union of K-committee tx_hashes lists. Same rule for both
    // K=M_pool (strong) and K<M_pool (hybrid). Censorship requires every
    // committee member to omit. Intersection is preserved as a helper for
    // v2 / specialized chains but is not used in v1.
    (void)m_pool_size;
    b.tx_root        = compute_tx_root(b.creator_tx_lists);
    b.delay_seed     = compute_delay_seed(b.index, b.prev_hash, b.tx_root, b.creator_dh_inputs);
    // rev.9 S-009: if secrets supplied (finalize path), derive delay_output
    // from them. Otherwise (Phase-2 candidate digest), leave delay_output as
    // caller-provided — block_digest excludes delay_output anyway.
    b.delay_output   = ordered_secrets.empty()
                        ? delay_output
                        : compute_block_rand(b.delay_seed, ordered_secrets);
    b.consensus_mode = mode;
    b.bft_proposer   = bft_proposer_domain;

    // cumulative_rand derives from the actual block delay_output (which
    // is the commit-reveal output when secrets are populated, else the
    // caller-provided value). Using b.delay_output keeps the validator
    // and producer in sync regardless of which path set it.
    Hash prev_rand = chain.empty() ? Hash{} : chain.head().cumulative_rand;
    b.cumulative_rand = SHA256Builder{}
        .append(prev_rand)
        .append(b.delay_output)
        .finalize();

    // Resolve hashes to actual txs. The canonical set is the union of K
    // committee tx_hashes lists — a tx is included if any committee member
    // has it. Censorship requires ALL K to collude (K-conjunction within
    // the committee); rotation gives liveness over the M_pool.
    std::set<Hash> selected_hashes;
    for (auto& list : b.creator_tx_lists)
        for (auto& h : list) selected_hashes.insert(h);

    std::vector<Transaction> ordered;
    ordered.reserve(selected_hashes.size());
    for (auto& h : selected_hashes) {
        auto it = tx_store.find(h);
        if (it != tx_store.end()) ordered.push_back(it->second);
    }
    std::sort(ordered.begin(), ordered.end(),
        [](const Transaction& a, const Transaction& b_) {
            if (a.from  != b_.from)  return a.from  < b_.from;
            if (a.nonce != b_.nonce) return a.nonce < b_.nonce;
            return a.hash < b_.hash;
        });

    std::map<std::string, uint64_t> bal, nonces, locked;
    auto get_bal = [&](const std::string& d) -> uint64_t& {
        auto it = bal.find(d);
        if (it == bal.end()) it = bal.emplace(d, chain.balance(d)).first;
        return it->second;
    };
    auto get_nonce = [&](const std::string& d) -> uint64_t& {
        auto it = nonces.find(d);
        if (it == nonces.end()) it = nonces.emplace(d, chain.next_nonce(d)).first;
        return it->second;
    };
    auto get_locked = [&](const std::string& d) -> uint64_t& {
        auto it = locked.find(d);
        if (it == locked.end()) it = locked.emplace(d, chain.stake(d)).first;
        return it->second;
    };

    auto decode_amount = [](const std::vector<uint8_t>& p) -> uint64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8 && i < (int)p.size(); ++i) v |= uint64_t(p[i]) << (8 * i);
        return v;
    };

    for (auto& tx : ordered) {
        uint64_t& nn = get_nonce(tx.from);
        if (tx.nonce != nn) continue;

        uint64_t& sb = get_bal(tx.from);
        switch (tx.type) {
        case TxType::TRANSFER: {
            uint64_t cost = tx.amount + tx.fee;
            if (sb < cost) continue;
            sb -= cost;
            // rev.9 B3.2: cross-shard TRANSFERs are debited locally and
            // emit a receipt for delivery to the destination shard. The
            // local credit is suppressed (the destination shard credits
            // `to` after verifying the receipt against this block in
            // Stage B3.4).
            if (chain.is_cross_shard(tx.to)) {
                CrossShardReceipt r;
                r.src_shard       = chain.my_shard_id();
                r.dst_shard       = crypto::shard_id_for_address(
                                        tx.to, chain.shard_count(), chain.shard_salt());
                r.src_block_index = b.index;
                // src_block_hash stays zero in the on-chain stored
                // receipt (it would be circular — receipts are part of
                // the block hash). Filled in by the gossip-bundle layer
                // (B3.3) at relay time, derived from the produced block.
                r.tx_hash = tx.hash;
                r.from    = tx.from;
                r.to      = tx.to;
                r.amount  = tx.amount;
                r.fee     = tx.fee;
                r.nonce   = tx.nonce;
                b.cross_shard_receipts.push_back(r);
            } else {
                get_bal(tx.to) += tx.amount;
            }
            break;
        }
        case TxType::REGISTER:
        case TxType::DEREGISTER: {
            if (sb < tx.fee) continue;
            sb -= tx.fee;
            break;
        }
        case TxType::STAKE: {
            if (tx.payload.size() != 8) continue;
            uint64_t amount = decode_amount(tx.payload);
            uint64_t cost   = amount + tx.fee;
            if (sb < cost) continue;
            sb -= cost;
            get_locked(tx.from) += amount;
            break;
        }
        case TxType::UNSTAKE: {
            if (tx.payload.size() != 8) continue;
            uint64_t amount = decode_amount(tx.payload);
            if (sb < tx.fee) continue;
            uint64_t& lk = get_locked(tx.from);
            if (lk < amount) continue;
            // S-017: skip too-early UNSTAKE so it doesn't reach validators
            // (which now also reject it — see validator.cpp UNSTAKE branch).
            // Apply-time refund branch in chain.cpp remains as a defense
            // against tx-included-by-buggy-producer paths.
            if (b.index < chain.stake_unlock_height(tx.from)) continue;
            sb -= tx.fee;
            break;
        }
        }
        nn++;
        b.transactions.push_back(tx);
    }

    // rev.9 B3.4: bake inbound receipts addressed to this shard. Skip
    // any receipt already credited (replayed bundle) or addressed to a
    // different shard (defensive — Node should pre-filter, but the
    // chain check is canonical).
    for (auto& r : inbound_receipts) {
        if (r.dst_shard != chain.my_shard_id()) continue;
        if (chain.inbound_receipt_applied(r.src_shard, r.tx_hash)) continue;
        b.inbound_receipts.push_back(r);
    }

    return b;
}

} // namespace unchained::node
