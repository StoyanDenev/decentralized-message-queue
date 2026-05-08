#pragma once
#include <dhcoin/chain/block.hpp>
#include <dhcoin/chain/chain.hpp>
#include <dhcoin/crypto/keys.hpp>
#include <dhcoin/types.hpp>
#include <map>
#include <string>
#include <vector>

namespace dhcoin::node {

// ─── Phase 1 — TxCommit + DhInput (combined) ─────────────────────────────────
// Each committee member broadcasts their proposed tx_hashes plus a fresh
// dh_input (32 random bytes), Ed25519-signed. The union of K tx_hashes lists
// is the canonical tx set; the K dh_inputs combine into the delay-hash seed.
struct ContribMsg {
    uint64_t           block_index{0};
    std::string        signer;
    Hash               prev_hash{};
    // Number of AbortEvents the sender has seen so far at this height. Used
    // for runtime generation matching: peers ignore contribs from a different
    // generation than their own. Different gens never share a beacon.
    uint64_t           aborts_gen{0};
    std::vector<Hash>  tx_hashes;     // sorted ascending
    Hash               dh_input{};    // fresh 32 B
    Signature          ed_sig{};      // Ed25519 over commit message

    nlohmann::json    to_json() const;
    static ContribMsg from_json(const nlohmann::json& j);
};

// ─── S7 — AbortClaim ─────────────────────────────────────────────────────────
// When a creator's local timer fires with fewer than M valid contributions
// (Phase 1) or block-sigs (Phase 2), they sign and broadcast an AbortClaim
// naming the first missing creator in selection order. M-1 matching claims
// form a quorum certificate that can advance the round; this prevents
// unilateral abort-blame divergence across peers.
struct AbortClaimMsg {
    uint64_t    block_index{0};
    uint8_t     round{0};         // 1 = CONTRIB phase, 2 = BLOCK_SIG phase
    Hash        prev_hash{};
    std::string missing_creator;
    std::string claimer;
    Signature   ed_sig{};         // Ed25519 over the abort_claim_message digest

    nlohmann::json    to_json() const;
    static AbortClaimMsg from_json(const nlohmann::json& j);
};

// Domain-separated commitment that each AbortClaim's Ed25519 sig covers.
Hash make_abort_claim_message(uint64_t block_index, uint8_t round,
                               const Hash& prev_hash,
                               const std::string& missing_creator);

AbortClaimMsg make_abort_claim(const crypto::NodeKey& key,
                                const std::string& claimer,
                                uint64_t block_index, uint8_t round,
                                const Hash& prev_hash,
                                const std::string& missing_creator);

// ─── Phase 2 — BlockSig (after local delay-hash completes) ───────────────────
// Each committee member publishes the delay-hash output and an Ed25519 sig
// over the block digest. K parallel Ed25519 sigs authenticate the block.
struct BlockSigMsg {
    uint64_t              block_index{0};
    std::string           signer;
    Hash                  delay_output{};
    Signature             ed_sig{};      // Ed25519 over block_digest

    nlohmann::json    to_json() const;
    static BlockSigMsg from_json(const nlohmann::json& j);
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Domain-separated commitment that each creator's Ed25519 sig covers in Phase 1.
Hash make_contrib_commitment(uint64_t block_index, const Hash& prev_hash,
                              const std::vector<Hash>& sorted_tx_hashes,
                              const Hash& dh_input);

// Canonical tx_root: union of K-committee tx_hashes lists. Used in strong
// mode (K=M_pool, every creator on committee) — censorship requires every
// creator to omit a tx.
Hash compute_tx_root(const std::vector<std::vector<Hash>>& creator_tx_lists);

// Canonical tx_root: intersection of K-committee tx_hashes lists. Used in
// weak mode (K<M_pool, rotating committee). A tx is included only if EVERY
// committee member has it in their list — censorship is single-creator
// (any one of K can omit). Trade for liveness: rotating committee tolerates
// (pool_size − K) silent creators via suspension dropping them from pool.
Hash compute_tx_root_intersection(const std::vector<std::vector<Hash>>& creator_tx_lists);

// Delay-hash seed — combined DH inputs in selection order, anchored to
// (idx, prev, tx_root).
Hash compute_delay_seed(uint64_t block_index, const Hash& prev_hash,
                         const Hash& tx_root,
                         const std::vector<Hash>& creator_dh_inputs);

// Phase 2 sig domain: hash that each creator_block_sigs[i] covers. Includes
// every consensus-critical field of the block so equivocation on any of them
// produces an unverifiable sig.
Hash compute_block_digest(const chain::Block& b);

ContribMsg make_contrib(const crypto::NodeKey& key,
                         const std::string& domain,
                         uint64_t block_index,
                         const Hash& prev_hash,
                         uint64_t aborts_gen,
                         const std::vector<Hash>& tx_snapshot,
                         const Hash& dh_input);

BlockSigMsg make_block_sig(const crypto::NodeKey& key,
                            const std::string& domain,
                            uint64_t block_index,
                            const Hash& delay_output,
                            const Hash& block_digest);

// Build the canonical block body. `m_pool_size` is the chain-wide registered
// pool size from genesis (cfg_.m_creators); the K-committee is the size of
// `creator_domains`/`contribs`. tx_root is always the union of K hash lists.
chain::Block build_body(
    const std::map<Hash, chain::Transaction>& tx_store,
    const chain::Chain&                       chain,
    const std::vector<chain::AbortEvent>&     aborts,
    const std::vector<std::string>&           creator_domains,
    const std::vector<ContribMsg>&            contribs,        // K, in selection order
    const Hash&                               delay_output,
    uint32_t                                  m_pool_size);

} // namespace dhcoin::node
