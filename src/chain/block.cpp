// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/chain/block.hpp>
#include <determ/crypto/sha256.hpp>

namespace determ::chain {

using namespace determ::crypto;
using json = nlohmann::json;

// ─── Transaction ─────────────────────────────────────────────────────────────

std::vector<uint8_t> Transaction::signing_bytes() const {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(type));
    out.insert(out.end(), from.begin(), from.end());
    out.push_back(0);
    out.insert(out.end(), to.begin(), to.end());
    out.push_back(0);
    for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

Hash Transaction::compute_hash() const {
    auto sb = signing_bytes();
    return sha256(sb.data(), sb.size());
}

json Transaction::to_json() const {
    json j;
    j["type"]    = static_cast<int>(type);
    j["from"]    = from;
    j["to"]      = to;
    j["amount"]  = amount;
    j["fee"]     = fee;
    j["nonce"]   = nonce;
    j["payload"] = to_hex(payload.data(), payload.size());
    j["sig"]     = to_hex(sig);
    j["hash"]    = to_hex(hash);
    return j;
}

Transaction Transaction::from_json(const json& j) {
    Transaction tx;
    tx.type    = static_cast<TxType>(j["type"].get<int>());
    tx.from    = j["from"].get<std::string>();
    tx.to      = j["to"].get<std::string>();
    tx.amount  = j["amount"].get<uint64_t>();
    tx.fee     = j.value("fee", uint64_t{0});
    tx.nonce   = j["nonce"].get<uint64_t>();
    tx.payload = from_hex(j["payload"].get<std::string>());
    tx.sig     = from_hex_arr<64>(j["sig"].get<std::string>());
    tx.hash    = from_hex_arr<32>(j["hash"].get<std::string>());
    return tx;
}

// ─── GenesisAlloc ────────────────────────────────────────────────────────────

json GenesisAlloc::to_json() const {
    return {
        {"domain",  domain},
        {"ed_pub",  to_hex(ed_pub)},
        {"balance", balance},
        {"stake",   stake},
        {"region",  region}
    };
}

GenesisAlloc GenesisAlloc::from_json(const json& j) {
    GenesisAlloc a;
    a.domain  = j["domain"].get<std::string>();
    a.ed_pub  = from_hex_arr<32>(j.value("ed_pub", std::string(64, '0')));
    a.balance = j.value("balance", uint64_t{0});
    a.stake   = j.value("stake",   uint64_t{0});
    // rev.9 R1: region absent on legacy genesis blocks → empty string.
    a.region  = j.value("region",  std::string{});
    return a;
}

// ─── AbortEvent ──────────────────────────────────────────────────────────────

json AbortEvent::to_json() const {
    json j;
    j["round"]         = round;
    j["aborting_node"] = aborting_node;
    j["timestamp"]     = timestamp;
    j["event_hash"]    = to_hex(event_hash);
    j["claims"]        = claims_json.is_null() ? json::array() : claims_json;
    return j;
}

AbortEvent AbortEvent::from_json(const json& j) {
    AbortEvent ae;
    ae.round         = j["round"].get<uint8_t>();
    ae.aborting_node = j["aborting_node"].get<std::string>();
    ae.timestamp     = j["timestamp"].get<int64_t>();
    ae.event_hash    = from_hex_arr<32>(j["event_hash"].get<std::string>());
    ae.claims_json   = j.value("claims", json::array());
    return ae;
}

// ─── EquivocationEvent ───────────────────────────────────────────────────────

json EquivocationEvent::to_json() const {
    json j;
    j["equivocator"]          = equivocator;
    j["block_index"]          = block_index;
    j["digest_a"]             = to_hex(digest_a);
    j["sig_a"]                = to_hex(sig_a);
    j["digest_b"]             = to_hex(digest_b);
    j["sig_b"]                = to_hex(sig_b);
    j["shard_id"]             = shard_id;
    j["beacon_anchor_height"] = beacon_anchor_height;
    return j;
}

EquivocationEvent EquivocationEvent::from_json(const json& j) {
    EquivocationEvent e;
    e.equivocator          = j["equivocator"].get<std::string>();
    e.block_index          = j["block_index"].get<uint64_t>();
    e.digest_a             = from_hex_arr<32>(j["digest_a"].get<std::string>());
    e.sig_a                = from_hex_arr<64>(j["sig_a"].get<std::string>());
    e.digest_b             = from_hex_arr<32>(j["digest_b"].get<std::string>());
    e.sig_b                = from_hex_arr<64>(j["sig_b"].get<std::string>());
    e.shard_id             = j.value("shard_id",             uint32_t{0});
    e.beacon_anchor_height = j.value("beacon_anchor_height", uint64_t{0});
    return e;
}

// ─── MergeEvent ──────────────────────────────────────────────────────────────

std::vector<uint8_t> MergeEvent::encode() const {
    std::vector<uint8_t> out;
    out.reserve(26 + merging_shard_region.size());
    out.push_back(event_type);
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((shard_id   >> (8 * i)) & 0xff));
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((partner_id >> (8 * i)) & 0xff));
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>((effective_height       >> (8 * i)) & 0xff));
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>((evidence_window_start  >> (8 * i)) & 0xff));
    out.push_back(static_cast<uint8_t>(merging_shard_region.size()));
    out.insert(out.end(),
                 merging_shard_region.begin(), merging_shard_region.end());
    return out;
}

std::optional<MergeEvent> MergeEvent::decode(const std::vector<uint8_t>& p) {
    if (p.size() < 26) return std::nullopt;
    if (p[0] > 1)      return std::nullopt;
    size_t rlen = p[25];
    if (rlen > 32)     return std::nullopt;
    if (p.size() != 26 + rlen) return std::nullopt;
    MergeEvent ev;
    ev.event_type = p[0];
    ev.shard_id = 0;
    ev.partner_id = 0;
    for (int i = 0; i < 4; ++i) {
        ev.shard_id   |= uint32_t(p[1 + i]) << (8 * i);
        ev.partner_id |= uint32_t(p[5 + i]) << (8 * i);
    }
    ev.effective_height = 0;
    ev.evidence_window_start = 0;
    for (int i = 0; i < 8; ++i) {
        ev.effective_height      |= uint64_t(p[9  + i]) << (8 * i);
        ev.evidence_window_start |= uint64_t(p[17 + i]) << (8 * i);
    }
    ev.merging_shard_region.assign(
        reinterpret_cast<const char*>(p.data() + 26), rlen);
    return ev;
}

// ─── CrossShardReceipt ───────────────────────────────────────────────────────

json CrossShardReceipt::to_json() const {
    json j;
    j["src_shard"]       = src_shard;
    j["dst_shard"]       = dst_shard;
    j["src_block_index"] = src_block_index;
    j["src_block_hash"]  = to_hex(src_block_hash);
    j["tx_hash"]         = to_hex(tx_hash);
    j["from"]            = from;
    j["to"]              = to;
    j["amount"]          = amount;
    j["fee"]             = fee;
    j["nonce"]           = nonce;
    return j;
}

CrossShardReceipt CrossShardReceipt::from_json(const json& j) {
    CrossShardReceipt r;
    r.src_shard       = j.value("src_shard",       uint32_t{0});
    r.dst_shard       = j.value("dst_shard",       uint32_t{0});
    r.src_block_index = j.value("src_block_index", uint64_t{0});
    r.src_block_hash  = from_hex_arr<32>(j.value("src_block_hash",
                                                    std::string(64, '0')));
    r.tx_hash         = from_hex_arr<32>(j.value("tx_hash",
                                                    std::string(64, '0')));
    r.from            = j.value("from",   std::string{});
    r.to              = j.value("to",     std::string{});
    r.amount          = j.value("amount", uint64_t{0});
    r.fee             = j.value("fee",    uint64_t{0});
    r.nonce           = j.value("nonce",  uint64_t{0});
    return r;
}

// ─── Block ───────────────────────────────────────────────────────────────────

std::vector<uint8_t> Block::signing_bytes() const {
    SHA256Builder b;
    b.append(static_cast<uint64_t>(index));
    b.append(prev_hash);
    b.append(timestamp);

    SHA256Builder txh;
    for (auto& tx : transactions) {
        auto sb = tx.signing_bytes();
        txh.append(sb.data(), sb.size());
    }
    b.append(txh.finalize());

    for (auto& c : creators) b.append(c);

    for (auto& list : creator_tx_lists)
        for (auto& h : list) b.append(h);
    for (auto& s : creator_ed_sigs)
        b.append(s.data(), s.size());
    for (auto& h : creator_dh_inputs) b.append(h);
    for (auto& h : creator_dh_secrets) b.append(h);

    b.append(tx_root);
    b.append(delay_seed);
    b.append(delay_output);
    b.append(static_cast<uint8_t>(consensus_mode));
    b.append(bft_proposer);
    b.append(cumulative_rand);
    for (auto& ae : abort_events) b.append(ae.event_hash);
    // Bind equivocation events into the block hash so any tampering
    // with evidence (changing equivocator, sigs, digests) changes the
    // block hash and breaks consensus on it.
    for (auto& ev : equivocation_events) {
        b.append(ev.equivocator);
        b.append(ev.block_index);
        b.append(ev.digest_a);
        b.append(ev.sig_a.data(), ev.sig_a.size());
        b.append(ev.digest_b);
        b.append(ev.sig_b.data(), ev.sig_b.size());
        b.append(static_cast<uint64_t>(ev.shard_id));
        b.append(ev.beacon_anchor_height);
    }

    // Bind cross-shard receipts into the block hash. Any tampering with
    // receipt fields (especially `to` or `amount`) would change the hash
    // and break K-of-K signing on the source side, so dst-side credits
    // remain safe even though dst doesn't re-sign receipts.
    for (auto& r : cross_shard_receipts) {
        b.append(static_cast<uint64_t>(r.src_shard));
        b.append(static_cast<uint64_t>(r.dst_shard));
        b.append(r.src_block_index);
        b.append(r.src_block_hash);
        b.append(r.tx_hash);
        b.append(r.from);
        b.append(r.to);
        b.append(r.amount);
        b.append(r.fee);
        b.append(r.nonce);
    }

    // rev.9 B3.4: bind inbound receipts (this block credits them) so
    // the destination committee's K-of-K signing certifies the exact
    // set credited. Source K-of-K verification happens at receive time
    // (each producer ratifies independently); the destination block's
    // signing is the committee's collective attestation.
    for (auto& r : inbound_receipts) {
        b.append(static_cast<uint64_t>(r.src_shard));
        b.append(static_cast<uint64_t>(r.dst_shard));
        b.append(r.src_block_index);
        b.append(r.tx_hash);
        b.append(r.to);
        b.append(r.amount);
    }

    for (auto& a : initial_state) {
        b.append(a.domain);
        b.append(a.ed_pub.data(), a.ed_pub.size());
        b.append(a.balance);
        b.append(a.stake);
        // rev.9 R1: bind region into the genesis block hash ONLY when
        // non-empty. Empty region preserves byte-identical signing
        // bytes with pre-R1 genesis blocks (backward-compat invariant).
        if (!a.region.empty()) {
            b.append(static_cast<uint8_t>(a.region.size()));
            b.append(a.region);
        }
    }

    // R4 Phase 3: bind partner_subset_hash into block signing-bytes
    // ONLY when non-zero. Default zero-hash preserves byte-identical
    // signing bytes for all pre-R4 / non-merged blocks — every existing
    // test stays hash-stable. Non-zero binds the partner shard's tx
    // subset commitment into the K-of-K committee signature, closing
    // the cross-chain merged-signing path described in the R4 design.
    {
        Hash zero{};
        if (partner_subset_hash != zero) {
            b.append(partner_subset_hash);
        }
    }

    // S-033 / v2.1: bind state_root into the block hash chain ONLY when
    // non-zero. Same backward-compat pattern as partner_subset_hash —
    // pre-S-033 blocks have zero state_root and contribute nothing to
    // signing_bytes. When the producer populates it (post-feature-toggle),
    // the K-of-K committee signatures cover the state-after-apply
    // commitment. Validator re-derives and rejects on mismatch. The
    // prev_hash chain then forward-binds the commitment so any future
    // block's verification transitively authenticates all prior state
    // roots — turning the chain into a verifiable state log.
    {
        Hash zero{};
        if (state_root != zero) {
            b.append(state_root);
        }
    }

    Hash h = b.finalize();
    return std::vector<uint8_t>(h.begin(), h.end());
}

Hash Block::compute_hash() const {
    auto sb = signing_bytes();
    SHA256Builder b;
    b.append(sb.data(), sb.size());
    // Bind per-creator block sigs into the hash so any equivocation on them
    // produces a different block hash.
    for (auto& s : creator_block_sigs)
        b.append(s.data(), s.size());
    return b.finalize();
}

json Block::to_json() const {
    json j;
    j["index"]          = index;
    j["prev_hash"]      = to_hex(prev_hash);
    j["timestamp"]      = timestamp;

    json txs = json::array();
    for (auto& tx : transactions) txs.push_back(tx.to_json());
    j["transactions"]   = txs;

    json jc = json::array();
    for (auto& c : creators) jc.push_back(c);
    j["creators"]        = jc;

    json jctl = json::array();
    for (auto& list : creator_tx_lists) {
        json one = json::array();
        for (auto& h : list) one.push_back(to_hex(h));
        jctl.push_back(one);
    }
    j["creator_tx_lists"] = jctl;

    json jeds = json::array();
    for (auto& s : creator_ed_sigs) jeds.push_back(to_hex(s));
    j["creator_ed_sigs"]  = jeds;

    json jdi = json::array();
    for (auto& h : creator_dh_inputs) jdi.push_back(to_hex(h));
    j["creator_dh_inputs"] = jdi;

    json jds = json::array();
    for (auto& h : creator_dh_secrets) jds.push_back(to_hex(h));
    j["creator_dh_secrets"] = jds;

    j["tx_root"]         = to_hex(tx_root);
    j["delay_seed"]      = to_hex(delay_seed);
    j["delay_output"]    = to_hex(delay_output);
    j["consensus_mode"]  = static_cast<uint8_t>(consensus_mode);
    j["bft_proposer"]    = bft_proposer;

    json jbs = json::array();
    for (auto& s : creator_block_sigs) jbs.push_back(to_hex(s));
    j["creator_block_sigs"] = jbs;

    j["cumulative_rand"] = to_hex(cumulative_rand);

    json aes = json::array();
    for (auto& ae : abort_events) aes.push_back(ae.to_json());
    j["abort_events"]   = aes;

    json eqs = json::array();
    for (auto& ev : equivocation_events) eqs.push_back(ev.to_json());
    j["equivocation_events"] = eqs;

    json csrs = json::array();
    for (auto& r : cross_shard_receipts) csrs.push_back(r.to_json());
    j["cross_shard_receipts"] = csrs;

    json ibrs = json::array();
    for (auto& r : inbound_receipts) ibrs.push_back(r.to_json());
    j["inbound_receipts"] = ibrs;

    json is_arr = json::array();
    for (auto& a : initial_state) is_arr.push_back(a.to_json());
    j["initial_state"]  = is_arr;

    // S-033 / v2.1: serialize state_root only when non-zero.
    {
        Hash zero{};
        if (state_root != zero)
            j["state_root"] = to_hex(state_root);
    }
    // R4 Phase 3: serialize partner_subset_hash only when non-zero.
    // Pre-R4 / non-merged blocks omit the key entirely, keeping JSON
    // byte-identical for existing chain.json files.
    {
        Hash zero{};
        if (partner_subset_hash != zero)
            j["partner_subset_hash"] = to_hex(partner_subset_hash);
    }

    return j;
}

Block Block::from_json(const json& j) {
    Block b;
    b.index         = j["index"].get<uint64_t>();
    b.prev_hash     = from_hex_arr<32>(j["prev_hash"].get<std::string>());
    b.timestamp     = j["timestamp"].get<int64_t>();

    for (auto& tx : j["transactions"])
        b.transactions.push_back(Transaction::from_json(tx));
    for (auto& c : j["creators"])
        b.creators.push_back(c.get<std::string>());

    if (j.contains("creator_tx_lists")) {
        for (auto& one : j["creator_tx_lists"]) {
            std::vector<Hash> list;
            for (auto& h : one) list.push_back(from_hex_arr<32>(h.get<std::string>()));
            b.creator_tx_lists.push_back(std::move(list));
        }
    }
    if (j.contains("creator_ed_sigs")) {
        for (auto& s : j["creator_ed_sigs"])
            b.creator_ed_sigs.push_back(from_hex_arr<64>(s.get<std::string>()));
    }
    if (j.contains("creator_dh_inputs")) {
        for (auto& h : j["creator_dh_inputs"])
            b.creator_dh_inputs.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    if (j.contains("creator_dh_secrets")) {
        for (auto& h : j["creator_dh_secrets"])
            b.creator_dh_secrets.push_back(from_hex_arr<32>(h.get<std::string>()));
    }

    if (j.contains("tx_root"))
        b.tx_root = from_hex_arr<32>(j["tx_root"].get<std::string>());
    if (j.contains("delay_seed"))
        b.delay_seed = from_hex_arr<32>(j["delay_seed"].get<std::string>());
    if (j.contains("delay_output"))
        b.delay_output = from_hex_arr<32>(j["delay_output"].get<std::string>());
    if (j.contains("consensus_mode"))
        b.consensus_mode = static_cast<ConsensusMode>(j["consensus_mode"].get<uint8_t>());
    if (j.contains("bft_proposer"))
        b.bft_proposer = j["bft_proposer"].get<std::string>();

    if (j.contains("creator_block_sigs")) {
        for (auto& s : j["creator_block_sigs"])
            b.creator_block_sigs.push_back(from_hex_arr<64>(s.get<std::string>()));
    }

    b.cumulative_rand = from_hex_arr<32>(j["cumulative_rand"].get<std::string>());
    for (auto& ae : j["abort_events"])
        b.abort_events.push_back(AbortEvent::from_json(ae));

    if (j.contains("equivocation_events")) {
        for (auto& ej : j["equivocation_events"])
            b.equivocation_events.push_back(EquivocationEvent::from_json(ej));
    }

    if (j.contains("cross_shard_receipts")) {
        for (auto& rj : j["cross_shard_receipts"])
            b.cross_shard_receipts.push_back(CrossShardReceipt::from_json(rj));
    }

    if (j.contains("inbound_receipts")) {
        for (auto& rj : j["inbound_receipts"])
            b.inbound_receipts.push_back(CrossShardReceipt::from_json(rj));
    }

    if (j.contains("initial_state"))
        for (auto& ia : j["initial_state"])
            b.initial_state.push_back(GenesisAlloc::from_json(ia));

    if (j.contains("partner_subset_hash"))
        b.partner_subset_hash =
            from_hex_arr<32>(j["partner_subset_hash"].get<std::string>());
    if (j.contains("state_root"))
        b.state_root =
            from_hex_arr<32>(j["state_root"].get<std::string>());

    return b;
}

} // namespace determ::chain
