// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verify-tx-inclusion implementation.
//
// Composite primitive: fetch block B (full body) -> verify committee
// sigs over the block digest -> recompute tx_root from the committed
// hash lists -> cross-check the returned body against that committed
// set -> answer membership of tx H. See verify_tx_inclusion.hpp for the
// full trust-model rationale (tx_root + creator_tx_lists are both inside
// the committee-signed digest, so inclusion is cryptographically
// anchored, not a daemon claim).

#include "verify_tx_inclusion.hpp"
#include "verify.hpp"
#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>

namespace determ::light {

using nlohmann::json;

// Local copy of producer.cpp::compute_tx_root (lines 262-270) — the
// light-client binary does NOT link node/producer.cpp (that pulls in
// chain.cpp + node.cpp + the consensus headers), so the small union
// commitment is reproduced here. KEEP IN SYNC: tx_root is SHA-256 over
// the sorted, deduplicated union of the K committee members' tx-hash
// lists. std::set gives both the dedup and the ascending canonical
// order the upstream relies on.
static Hash light_compute_tx_root(
    const std::vector<std::vector<Hash>>& creator_tx_lists) {
    std::set<Hash> u;
    for (auto& list : creator_tx_lists)
        for (auto& h : list) u.insert(h);
    determ::crypto::SHA256Builder b;
    for (auto& h : u) b.append(h);
    return b.finalize();
}

// Build a JSON committee shape verify_block_sigs can consume from the
// in-memory (domain -> pubkey) seed.
static json build_committee_json(
    const std::map<std::string, PubKey>& committee_seed) {
    json arr = json::array();
    for (auto& [domain, pk] : committee_seed) {
        arr.push_back({{"domain", domain}, {"ed_pub", to_hex(pk)}});
    }
    return json{{"members", arr}};
}

TxInclusionResult verify_tx_inclusion(
    RpcClient&  rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    uint64_t    height,
    const std::string& tx_hash_hex) {

    TxInclusionResult res;
    res.height      = height;
    res.tx_hash_hex = tx_hash_hex;

    // ── 0. Validate + normalize the queried hash up front ───────────────
    // 64 lowercase hex chars. We compare against to_hex(...) output which
    // is lowercase, so normalize the input the same way.
    if (tx_hash_hex.size() != 64) {
        res.verdict = InclusionVerdict::UNVERIFIABLE;
        res.detail  = "--tx-hash must be 64 hex chars (32 bytes), got "
                    + std::to_string(tx_hash_hex.size());
        return res;
    }
    std::string target_hex;
    target_hex.reserve(64);
    for (char c : tx_hash_hex) {
        if      (c >= '0' && c <= '9') target_hex.push_back(c);
        else if (c >= 'a' && c <= 'f') target_hex.push_back(c);
        else if (c >= 'A' && c <= 'F') target_hex.push_back(static_cast<char>(c - 'A' + 'a'));
        else {
            res.verdict = InclusionVerdict::UNVERIFIABLE;
            res.detail  = "--tx-hash contains a non-hex character";
            return res;
        }
    }
    res.tx_hash_hex = target_hex;

    // ── 1. Fetch block B (full body) via the `block` RPC ────────────────
    // rpc_block returns null for index >= height (out of range). A null
    // reply is a hard error (the height doesn't exist on the chain), not
    // a NOT_INCLUDED — the caller asked about a block that isn't there.
    json blk_json = rpc.call("block", {{"index", height}});
    if (blk_json.is_null()) {
        throw std::runtime_error(
            "block " + std::to_string(height)
            + " is out of range (>= daemon's chain height) — cannot prove "
              "inclusion against a block that doesn't exist");
    }
    if (blk_json.contains("error") && !blk_json["error"].is_null()) {
        throw std::runtime_error(
            "block RPC error for height " + std::to_string(height)
            + ": " + blk_json["error"].dump());
    }

    // Parse the block. A malformed block body is UNVERIFIABLE.
    determ::chain::Block b;
    try {
        b = determ::chain::Block::from_json(blk_json);
    } catch (const std::exception& e) {
        res.verdict = InclusionVerdict::UNVERIFIABLE;
        res.detail  = std::string("malformed block body: ") + e.what();
        return res;
    }
    res.committee_size  = b.creators.size();
    // Always recompute block_hash locally from the parsed block rather
    // than trusting any wire-provided field — this is a trust-minimized
    // tool. (The `block` RPC's to_json() doesn't even emit block_hash;
    // recomputing also defends against a daemon that injects a bogus one.)
    res.block_hash_hex  = to_hex(b.compute_hash());

    // ── 2. Anchor the block ─────────────────────────────────────────────
    if (height == 0) {
        // Genesis carries NO committee sigs by construction — it is the
        // deterministic GenesisConfig->Block transform. Anchor on the
        // hash instead: recompute compute_genesis_hash(genesis) and
        // require it equal block 0's recomputed hash. This is exactly
        // the genesis pin the caller already performed at startup,
        // re-derived here against the block-RPC reply (defense in depth:
        // the daemon could in principle serve a different block at index
        // 0 than at the headers endpoint). Genesis has an empty tx set,
        // so the membership step below will answer NOT_INCLUDED for any
        // H — anchored by this hash match, not by committee sigs.
        Hash expected = determ::chain::compute_genesis_hash(genesis);
        Hash actual   = b.compute_hash();
        if (expected != actual) {
            res.verdict = InclusionVerdict::UNVERIFIABLE;
            res.detail  = "genesis anchor failed: block 0 hash="
                        + to_hex(actual) + " but compute_genesis_hash="
                        + to_hex(expected);
            return res;
        }
        // Genesis is anchored (by hash). Treat as verified for reporting;
        // sigs_verified stays 0 (there are none) and committee_size is 0.
        res.committee_verified = true;
        res.sigs_verified      = 0;
    } else {
        // B > 0: the load-bearing anchor is K-of-K (MD) or ceil(2K/3)
        // (BFT) Ed25519 sigs over light_compute_block_digest(b), which
        // binds tx_root AND creator_tx_lists. Every creator must be in
        // our genesis-seeded committee (verify_block_sigs enforces this).
        json committee_json = build_committee_json(committee_seed);
        auto vbs = verify_block_sigs(blk_json, committee_json, /*bft=*/false);
        if (!vbs.ok) {
            // BFT fallback: a BFT-escalated block has up to K - ceil(2K/3)
            // sentinel-zero slots; retry once at the BFT threshold.
            vbs = verify_block_sigs(blk_json, committee_json, /*bft=*/true);
        }
        if (!vbs.ok) {
            res.verdict = InclusionVerdict::UNVERIFIABLE;
            res.detail  = "committee-sig verification failed: " + vbs.detail;
            return res;
        }
        res.committee_verified = true;
        res.sigs_verified      = vbs.count;
    }

    // ── 3. Recompute tx_root from creator_tx_lists; require match ───────
    // verify_block_sigs already proved the committee signed over the
    // block.tx_root FIELD and over the creator_tx_lists BYTES. Re-deriving
    // tx_root from creator_tx_lists and demanding it equal block.tx_root
    // confirms the two committed quantities are mutually consistent (a
    // sanity gate; a mismatch here would mean the daemon served a block
    // whose tx_root field contradicts its own hash lists — which could
    // not have been validly signed, so treat as UNVERIFIABLE).
    //
    // Skipped for genesis (height 0): genesis does NOT use the union-of-
    // lists construction — it has empty creator_tx_lists and a zero
    // tx_root by construction (genesis.cpp sets g.tx_root = {}), so
    // light_compute_tx_root (SHA-256 over an empty set != zero) would
    // spuriously mismatch. Genesis is already anchored by hash in step 2.
    if (height > 0) {
        Hash recomputed_root = light_compute_tx_root(b.creator_tx_lists);
        if (recomputed_root != b.tx_root) {
            res.verdict = InclusionVerdict::UNVERIFIABLE;
            res.detail  = "tx_root mismatch: recomputed from creator_tx_lists="
                        + to_hex(recomputed_root)
                        + " but block.tx_root=" + to_hex(b.tx_root);
            return res;
        }
    }
    res.tx_root_hex = to_hex(b.tx_root);

    // ── 4. Build the committed tx-hash SET (the canonical tx set) ───────
    // This is the union of the K committee hash lists — the same set the
    // producer resolves into transactions[]. Membership in THIS set is
    // what "included" means, and it is committee-signed (step 2).
    std::set<Hash> committed;
    for (auto& list : b.creator_tx_lists)
        for (auto& h : list) committed.insert(h);
    res.tx_count = committed.size();

    // ── 5. Cross-check the returned BODY against the committed set ──────
    // The body (transactions[]) is supplementary, but if the daemon
    // returns a body that doesn't match the committed hash set, we cannot
    // trust ANY of its contents — refuse to answer (UNVERIFIABLE) rather
    // than risk a false INCLUDED/NOT_INCLUDED. Two checks:
    //   (a) every body tx's recomputed hash is in the committed set, and
    //       the body has no duplicates;
    //   (b) the body covers the whole committed set (|body set| == |set|).
    // Together these establish a bijection body <-> committed set, so the
    // body faithfully realizes exactly the committee-signed hashes.
    std::set<Hash> body_hashes;
    for (auto& tx : b.transactions) {
        Hash h = tx.compute_hash();
        if (committed.find(h) == committed.end()) {
            res.verdict = InclusionVerdict::UNVERIFIABLE;
            res.detail  = "tampered body: tx " + to_hex(h)
                        + " in transactions[] is NOT in the committee-signed "
                          "hash set (creator_tx_lists)";
            return res;
        }
        if (!body_hashes.insert(h).second) {
            res.verdict = InclusionVerdict::UNVERIFIABLE;
            res.detail  = "tampered body: duplicate tx " + to_hex(h)
                        + " in transactions[]";
            return res;
        }
    }
    if (body_hashes.size() != committed.size()) {
        // The body omits some committed tx(s). The daemon is hiding part
        // of the block's committed contents; we can't soundly answer.
        res.verdict = InclusionVerdict::UNVERIFIABLE;
        res.detail  = "tampered body: transactions[] covers "
                    + std::to_string(body_hashes.size())
                    + " of " + std::to_string(committed.size())
                    + " committee-signed tx hashes (body is missing entries)";
        return res;
    }

    // ── 6. Membership verdict ───────────────────────────────────────────
    // committed and body_hashes are now provably the same set, so we can
    // answer against either. Check the queried hash H.
    Hash target;
    try {
        target = from_hex_arr<32>(target_hex);
    } catch (const std::exception& e) {
        res.verdict = InclusionVerdict::UNVERIFIABLE;
        res.detail  = std::string("--tx-hash parse error: ") + e.what();
        return res;
    }
    res.verdict = (committed.find(target) != committed.end())
                  ? InclusionVerdict::INCLUDED
                  : InclusionVerdict::NOT_INCLUDED;
    return res;
}

} // namespace determ::light
