// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/chain/block.hpp>
#include <determ/chain/chain.hpp>
#include <determ/node/registry.hpp>
#include <determ/time/clock.hpp>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace determ::node {

class BlockValidator {
public:
    BlockValidator() = default;

    struct Result {
        bool        ok{false};
        std::string error;
    };

    // K = committee size per round (genesis-pinned). When K = M_pool every
    // registered creator is on every committee (strong mode). When K < M_pool,
    // the committee rotates through the eligible pool (hybrid mode; v2
    // delivers the M_pool−K silent tolerance).
    void set_k_block_sigs(uint32_t K) { k_block_sigs_ = K; }
    void set_m_pool(uint32_t M)       { m_pool_ = M; }

    // rev.8 per-height BFT escalation. When `bft_enabled_` is true, validator
    // accepts BFT-mode blocks if their abort count satisfies the threshold.
    void set_bft_enabled(bool en)             { bft_enabled_ = en; }
    void set_bft_escalation_threshold(uint32_t t) { bft_escalation_threshold_ = t; }

    // rev.9 (B1): epoch-relative committee derivation parameters.
    void set_epoch_blocks(uint32_t e) { epoch_blocks_ = e; }
    void set_shard_id(ShardId s)      { shard_id_ = s; }

    // rev.9 R2: this chain's committee_region (mirrored from genesis).
    // Empty = global pool — check_creator_selection / check_abort_certs
    // see the full registry pool (pre-R2 behavior). Non-empty restricts
    // the eligible pool via NodeRegistry::eligible_in_region(region_).
    void set_committee_region(const std::string& r) { committee_region_ = r; }

    // A6: deployment-wide sharding mode (mirrored from the operator's
    // selected TimingProfile). Drives mode-incompatible-tx gates in
    // check_transactions:
    //   NONE     — REGISTER with non-empty region rejected; only
    //              SINGLE chain_role accepted at startup; MERGE_EVENT
    //              (R7, not yet defined) rejected.
    //   CURRENT  — REGISTER region tolerated but ignored (pre-R1
    //              backward compat); MERGE_EVENT rejected.
    //   EXTENDED — REGISTER region accepted (R1); MERGE_EVENT accepted
    //              (R7 will install the apply path).
    void set_sharding_mode(ShardingMode m) { sharding_mode_ = m; }

    // D3.6 / S-036: this chain's role, mirrored from GenesisConfig. MERGE_EVENT is
    // a BEACON-coordinated event (block.hpp: "valid only under BEACON chain role")
    // — the historical distress witness it needs (the `t:` records) is BEACON-only
    // state, so a shard cannot verify it. The validator fail-closes MERGE_EVENT on
    // every non-BEACON chain. Default SINGLE preserves legacy behaviour for any
    // call site that constructs BlockValidator without the setter.
    void set_chain_role(ChainRole r) { chain_role_ = r; }

    // D3.5e-7d / S-036 Layer 2: the beacon's GENESIS-COMMITTED shard→region map
    // (GenesisConfig::shard_regions), mirrored from the Node exactly like
    // set_chain_role / set_committee_region — genesis-constant, replay-safe, no
    // wire. check_shardtip_witnesses reads it to (a) region-filter the frozen
    // source-committee pool and (b) bind rec.region against the authoritative
    // map entry (a missing entry yields "" — the CURRENT-compat global pool).
    void set_beacon_shard_regions(std::map<ShardId, std::string> m) {
        beacon_shard_regions_ = std::move(m);
    }

    // D3.7 / S-036 test seam: run the per-tx admission checks (incl. the D3.6
    // MERGE_EVENT historical-witness gate) in isolation so the falsifier can drive
    // accept/reject scenarios without assembling a fully-signed committee block.
    // Const, read-only — byte-identical to the check_transactions the block
    // validator already runs; no consensus behaviour change.
    Result check_transactions_for_test(const chain::Block& b, const chain::Chain& chain,
                                        const NodeRegistry& registry) const {
        return check_transactions(b, chain, registry);
    }

    // D3.5e-7d / S-036 test seam: run the universal witness re-verification in
    // isolation (the same const-forwarder pattern as check_transactions_for_test)
    // so the falsifier can drive fabricated/forged/reuse/unpinned scenarios
    // without assembling a fully-signed beacon block.
    Result check_shardtip_witnesses_for_test(const chain::Block& b,
                                             const chain::Chain& chain,
                                             const NodeRegistry& registry) const {
        return check_shardtip_witnesses(b, chain, registry);
    }

    // STMC-4 test seam (ShardTipMergeClosureSoundness, STMC-4; gate-gap audit
    // wf_6c5a9e49): run the D3.5d-ii Layer-1 reconciliation check in isolation —
    // same const-forwarder pattern as check_shardtip_witnesses_for_test above. The
    // trailing NodeRegistry is UNNAMED and unused: check_shardtip_reconciliation
    // reads only b + chain (chain itself is (void)-reserved), but the seam mirrors
    // the witnesses seam's arity so the two shard-tip gates are driven identically.
    // The gate is wired into validate() at validator.cpp:57, AFTER check_block_sigs
    // (:51), so a hand-built EXTENDED block can never reach it live — hence the
    // subset-reject loop shipped UNTESTED (only the producer-side fold was
    // witnessed). This seam lets the falsifier drive an EXTENDED block whose
    // shard_tip_records carries a record NOT in
    // reconcile_intersection(creator_view_shardtip_lists) and assert the SPECIFIC
    // "not in committee-view intersection" reject (the mutant: delete the
    // subset-reject loop at validator.cpp ~:1547-1550), plus the
    // "does not match committed root" view-root-bind reject — without assembling a
    // fully-signed committee block whose block-sig/digest gates would otherwise
    // mask a corrupted view list.
    Result check_shardtip_reconciliation_for_test(const chain::Block& b,
                                                  const chain::Chain& chain,
                                                  const NodeRegistry&) const {
        return check_shardtip_reconciliation(b, chain);
    }

    // SR-5 test seam: run the cross-shard-receipt misroute check in isolation
    // (same const-forwarder pattern) so the falsifier can drive a receipt whose
    // dst_shard != ρ(to) without assembling a fully-signed committee block. Note
    // the 2-arg signature (no NodeRegistry) — the check reads only b + chain.
    Result check_cross_shard_receipts_for_test(const chain::Block& b,
                                               const chain::Chain& chain) const {
        return check_cross_shard_receipts(b, chain);
    }

    // VAL-inbound-f2 test seam (ConsensusValidatorGateAudit, VAL-inbound-f2-*):
    // run the F2 inbound-receipt admission check in isolation — same 2-arg
    // const-forwarder pattern as check_cross_shard_receipts_for_test (the check
    // reads only b + chain). Lets the falsifier drive an F2-active multi-shard
    // block with forged creator_view_inbound_lists / an unwitnessed inbound
    // receipt and assert the SPECIFIC reject (":1486 does not match committed
    // root" / ":1493 not in committee-view intersection") without assembling a
    // fully-signed committee block whose block-sig/digest gates would otherwise
    // mask a corrupted view list.
    Result check_inbound_receipts_for_test(const chain::Block& b,
                                           const chain::Chain& chain) const {
        return check_inbound_receipts(b, chain);
    }

    // EqAbort test seam (EqAbortViewDigestExtension.md): run the F2 eq/abort
    // view-reconciliation check in isolation — same 2-arg const-forwarder pattern
    // as check_inbound_receipts_for_test (the check reads only b + chain, using
    // chain ONLY for f2_active_from_height()). check_eqabort_reconciliation
    // authenticates each per-creator eq/abort view list against its committed root
    // (:1602) and enforces the block's eq/abort event set is a SUBSET of the
    // reconcile_union over those lists (:1608). It sits in validate() AFTER
    // check_block_sigs, so a hand-built (unsigned) F2 block dies before reaching
    // it; the seam lets the falsifier drive a root-mismatched view list or an
    // out-of-union event and assert the SPECIFIC reject without assembling a
    // fully-signed committee block. Falsifies check_eqabort_reconciliation's whole
    // body -> `return {true,""}` (accept ANY eq/abort set).
    Result check_eqabort_reconciliation_for_test(const chain::Block& b,
                                                 const chain::Chain& chain) const {
        return check_eqabort_reconciliation(b, chain);
    }

    // T-3 test seam (ConsensusPhaseStructureSoundness, derivation determinism):
    // run the commit-reveal derivation check in isolation — same const-forwarder
    // pattern as the three seams above. check_delay reads ONLY b (no chain, no
    // registry), so this isolates the gate from the other 16 validate() checks
    // and lets the falsifier tamper b.delay_seed / b.delay_output and assert the
    // SPECIFIC reject without assembling a fully-signed committee block (whose
    // later block-sig/digest gates would otherwise mask a clean positive control).
    Result check_delay_for_test(const chain::Block& b) const {
        return check_delay(b);
    }

    // T-3 cumulative_rand test seam (ConsensusPhaseStructureSoundness, T-3):
    // run the beacon-chaining check in isolation — same const-forwarder pattern.
    // check_cumulative_rand re-derives R_h = SHA256(prev_cumulative_rand ||
    // delay_output) and rejects a non-canonical stored value; it reads b + the
    // chain head's prev_cumulative_rand, so this 2-arg seam isolates gate #10
    // (which sits AFTER check_block_sigs #9 and is therefore unreachable by a
    // hand-built commit-reveal block) and lets the falsifier tamper
    // b.cumulative_rand and assert the SPECIFIC reject. Falsifies
    // validator.cpp check_cumulative_rand's compare -> `if(false)`.
    Result check_cumulative_rand_for_test(const chain::Block& b,
                                          const chain::Chain& chain) const {
        return check_cumulative_rand(b, chain);
    }

    // ── Q1 (DECISION-LOG 2026-08-12) — the beacon-header ingest binding ─────
    // PRODUCTION seam (not a *_for_test forwarder): Node::on_beacon_header
    // authenticates a gossiped beacon header with K-of-K signatures over
    // compute_block_digest. That digest covers index, prev_hash, tx_root,
    // delay_seed, creators and creator_dh_inputs — but NOT creator_dh_secrets,
    // delay_output or cumulative_rand. Without the gates below a MITM can
    // rewrite cumulative_rand on an otherwise-valid header without breaking a
    // single signature, seeding the shard's epoch-committee selection
    // (Node::current_epoch_rand / the external epoch-rand provider) with a
    // value of its choosing.
    //
    // This runs the SAME apply-path gates that already bind the field — no new
    // verifier logic (the divergence bug-class), no wire change, no digest
    // change. The binding chain, each link verified in code:
    //   1. check_creator_dh_secrets_with:
    //        SHA256(creator_dh_secrets[i] ‖ pk_i) == creator_dh_inputs[i]
    //      creator_dh_inputs IS digest-covered ⇒ the secrets are pinned by the
    //      signatures (preimage resistance). This link is LOAD-BEARING: the
    //      secrets themselves are NOT digest-covered, so without it an
    //      attacker grinds them to move delay_output and then re-derives a
    //      matching cumulative_rand — the fix would only appear to bind.
    //   2. check_delay:
    //        delay_seed   == compute_delay_seed(index, prev_hash, tx_root,
    //                                           creator_dh_inputs)   [all
    //                        four digest-covered — plus delay_seed itself is]
    //        delay_output == compute_block_rand(delay_seed,
    //                                           creator_dh_secrets)
    //      ⇒ delay_output is pinned.
    //   3. check_cumulative_rand_from:
    //        cumulative_rand == SHA256(prev_rand ‖ delay_output)
    //      ⇒ with (1) and (2), cumulative_rand is pinned.
    //
    // `prev_rand` is the PREDECESSOR header's cumulative_rand. On the
    // beacon-header path that is beacon_headers_.back().cumulative_rand — NOT
    // chain.head() (the shard's own chain is a different chain, so the
    // chain-reading check_cumulative_rand overload is the wrong tool here).
    //
    // FIRST-HEADER RULE — std::nullopt means "no tracked predecessor". The
    // first tracked header is beacon block INDEX 1, whose predecessor is the
    // BEACON GENESIS block; a shard neither holds nor pins it (beacon-genesis
    // pinning is the named B2c.5 follow-on), and its cumulative_rand is a
    // genesis-config-derived hash, NOT zero — so substituting Hash{} would
    // reject every honest bootstrap. Links (1) and (2) therefore still run
    // (delay_output stays pinned to the K-of-K-signed digest) and ONLY link
    // (3) is skipped. RESIDUAL, documented not closed: on that one header
    // cumulative_rand itself remains attacker-choosable. A tamper by a pure
    // RELAY is self-limiting — compute_hash covers cumulative_rand and the
    // next genuine header's prev_hash IS digest-signed, so header 2 fails to
    // chain (bias one epoch, then stall).
    //
    // BUT do NOT read that as "no silent long-run control": this ingress
    // never checks that b.creators IS the beacon's derived committee (it only
    // checks they are registered and signed — see on_beacon_header), so ANY
    // k_block_sigs eligible domains can mint an internally-consistent header
    // STREAM and drive the rand chain indefinitely, with every check here
    // passing. That is a separate open hole on this path, adjacent to the
    // still-unauthorized HELLO beacon-role authentication.
    // The first-header residual itself does NOT strictly require the B2c.5
    // beacon-genesis pin: a successor-confirmation rule at the two
    // consumption sites (do not let an unconfirmed first header seed epoch
    // rand until a chaining successor arrives) closes it in-tree. Both are
    // owner decisions, recorded in the DECISION-LOG.
    //
    // `resolve_key` supplies creators[i]'s Ed25519 key. The caller MUST pass
    // the SAME key source it verified the block signatures against (on the
    // beacon-header path: the member_pub map handed to verify_committee_sigs),
    // so key resolution here can never diverge from the signature check and
    // false-reject an honest header.
    using CreatorKeyResolver =
        std::function<std::optional<PubKey>(const std::string& domain)>;
    Result check_header_rand_binding(const chain::Block& b,
                                     const std::optional<Hash>& prev_rand,
                                     const CreatorKeyResolver& resolve_key) const;

    // VAL-timestamp test seam (ConsensusValidatorGateAudit, VAL-timestamp-30s-window):
    // run the wall-clock timestamp check in isolation — same 1-arg const-forwarder
    // as check_delay_for_test. check_timestamp reads ONLY b + clock_ (injected via
    // set_clock), so a VirtualClock pins "now" and lets the falsifier drive a block
    // whose timestamp is far outside the +-30s window and assert the SPECIFIC reject
    // without assembling a fully-signed committee block (whose block-sig/digest gates
    // would otherwise mask a clean positive control).
    Result check_timestamp_for_test(const chain::Block& b) const {
        return check_timestamp(b);
    }

    // EQV test seam (ConsensusValidatorGateAudit, EQV-sig-verify-forged-slash):
    // run the equivocation-evidence check in isolation — same const-forwarder
    // pattern as the seams above. Lets the falsifier drive an event with a
    // forged sig_a and assert the SPECIFIC reject without assembling a
    // fully-signed (F2-reconciled) committee block whose block-sig/digest gates
    // would otherwise mask a corrupted-sig event. Arg order matches the private
    // method: (b, registry, chain).
    Result check_equivocation_events_for_test(const chain::Block& b,
                                              const NodeRegistry& registry,
                                              const chain::Chain& chain) const {
        return check_equivocation_events(b, registry, chain);
    }

    // D1: the CONFIDENTIAL-TX (shielded-pool) master switch, mirrored from
    // GenesisConfig. Default true = SHIELD/UNSHIELD/CONFIDENTIAL_TRANSFER
    // accepted (unchanged). false = all three rejected at this (authoritative,
    // submit + block) accept-rule, so no confidential tx is ever included.
    void set_confidential_tx_enabled(bool e) { confidential_tx_enabled_ = e; }

    // A5: governance mode mirrored from genesis. 0 = uncontrolled
    // (PARAM_CHANGE rejected outright); 1 = governed (PARAM_CHANGE
    // validated against keyholder set + threshold over a whitelisted
    // parameter name set).
    void set_governance_mode(uint8_t m)            { governance_mode_ = m; }
    void set_param_keyholders(std::vector<PubKey> ks) {
        param_keyholders_ = std::move(ks);
    }
    void set_param_threshold(uint32_t t)           { param_threshold_ = t; }

    // rev.9 B2c.2-full: when the validator runs on a SHARD chain, the
    // committee-selection rand must come from the BEACON's chain, not the
    // shard's own. The Node installs this provider so the validator can
    // resolve the cumulative_rand of the beacon block at the requested
    // epoch_start_height. Returning nullopt means "no beacon header
    // available at that height yet" — the validator falls back to the
    // local chain (early-bootstrap path; shard registry mirrors beacon at
    // genesis, so behavior is identical until headers begin to land).
    using EpochRandProvider =
        std::function<std::optional<Hash>(uint64_t epoch_start_height)>;
    void set_external_epoch_rand_provider(EpochRandProvider p) {
        external_epoch_rand_ = std::move(p);
    }

    // §Q1 clock injection: the NON-digest ±30s freshness gate
    // (check_timestamp) reads wall time through this. Default RealClock ==
    // determ::now_unix() verbatim, so the default validation path is
    // byte-identical. The Node passes its own injected clock so a node
    // running on a virtual clock validates block timestamps against the
    // SAME time source it stamped them with (else a virtual-time block's
    // timestamp would fail the real-time window). Never enters a digest.
    void set_clock(const determ::time::Clock& c) { clock_ = &c; }

    Result validate(const chain::Block& b,
                    const chain::Chain& chain,
                    const NodeRegistry& registry) const;

private:
    Result check_prev_hash(const chain::Block& b, const chain::Chain& chain) const;
    // D3.3b-read: the creator POOL + IDENTITY checks below resolve committee
    // membership + pubkeys through the frozen cc: checkpoint on EXTENDED chains
    // (committee_pool.hpp), so each takes `chain`.
    Result check_creators_registered(const chain::Block& b, const NodeRegistry& registry,
                                     const chain::Chain& chain) const;
    Result check_creator_selection(const chain::Block& b, const NodeRegistry& registry,
                                   const chain::Chain& chain) const;
    Result check_creator_tx_commitments(const chain::Block& b, const NodeRegistry& registry,
                                        const chain::Chain& chain) const;
    Result check_creator_dh_secrets(const chain::Block& b, const NodeRegistry& registry,
                                    const chain::Chain& chain) const;
    // Q1 seam: the commit-reveal CORE with an explicit creator-key resolver.
    // check_creator_dh_secrets is a thin wrapper that resolves keys through the
    // frozen-committee path (chain + present-head registry); the beacon-header
    // ingest path resolves through the map it verified the sigs against. ONE
    // implementation of the commit-reveal rule, two key sources.
    Result check_creator_dh_secrets_with(const chain::Block& b,
                                         const CreatorKeyResolver& resolve_key) const;
    Result check_delay(const chain::Block& b) const;
    Result check_block_sigs(const chain::Block& b, const NodeRegistry& registry,
                             const chain::Chain& chain) const;
    Result check_abort_certs(const chain::Block& b, const chain::Chain& chain,
                              const NodeRegistry& registry) const;
    Result check_equivocation_events(const chain::Block& b,
                                       const NodeRegistry& registry,
                                       const chain::Chain& chain) const;
    // rev.9 B3.2: cross_shard_receipts must match the cross-shard
    // subset of transactions[] in order, with consistent fields.
    // SINGLE chains expect an empty receipts list.
    Result check_cross_shard_receipts(const chain::Block& b,
                                        const chain::Chain& chain) const;
    // rev.9 B3.4: inbound_receipts (this block credits them) shape +
    // dedup checks. Each entry must have dst_shard == this chain's
    // shard_id, src_shard != this chain's shard_id, tx_hash unique
    // within the block, and not previously applied. SINGLE / BEACON
    // chains expect an empty list.
    Result check_inbound_receipts(const chain::Block& b,
                                    const chain::Chain& chain) const;
    // v2.7 F2 / S-030-D2: equivocation/abort evidence must be a SUBSET of the
    // committee-wide reconcile_union of the members' committed Phase-1 views
    // (carried per-creator + authenticated against the signed roots). Closes the
    // S-030-D2 removal gap for the eq/abort dimensions together with the
    // compute_block_digest binding. See docs/proofs/EqAbortViewDigestExtension.md.
    Result check_eqabort_reconciliation(const chain::Block& b,
                                         const chain::Chain& chain) const;
    // D3.5d-ii / S-036 Layer 1: Block::shard_tip_records must be a SUBSET of the
    // committee-wide reconcile_intersection of the members' committed Phase-1
    // shard-tip views (creator_view_shardtip_lists, authenticated against the
    // signed roots). Gated on sharding_mode_==EXTENDED (the validator has no
    // chain_role; shard_count() cannot distinguish CURRENT-multishard). NO
    // source-committee re-verification — that is discharged contemporaneously in
    // Node::on_shard_tip and is not reconstructible from committed beacon state
    // (§9.6); the full-K intersection proves all K members ran it on identical
    // content. See docs/proofs/ShardTipMergeDesign.md §9.6.
    Result check_shardtip_reconciliation(const chain::Block& b,
                                          const chain::Chain& chain) const;
    // D3.5e-7d / S-036 Layer 2: the UNIVERSAL witness re-verification — the
    // CLOSED-maker. Every honest node (committee member or not) re-verifies each
    // carried ShardTipRecord against its index-aligned full-tip witness BEFORE the
    // block is accepted (and therefore before the t: fold applies it): re-derive
    // the frozen source committee from the beacon's OWN committed cc:[E_source]
    // (via the e-7b shared helper — the exact code on_shard_tip ran), recompute
    // compute_block_digest(witness) FROM THE PREIMAGE, cross-check the record's
    // height/source_shard_id/eligible_count INSIDE it (the anti-reuse binding),
    // verify the K-of-K sigs against FROZEN ed_pubs, and require the recomputed
    // committee_sig_root == rec.committee_sig_root. Runs ONCE at accept
    // (apply_block_locked / the A4 reorg path); Chain::load replay and snapshot
    // restore trust the already-gated block — identical to check_block_sigs — so
    // reject-on-unpinned cannot fork archive vs snapshot nodes. Fail-closed on an
    // unpinned cc:[E_source] (epoch-0 / pruned): an honest producer never emits
    // such a record (the e-7c emission gate evaluates the same predicate over the
    // same committed prefix), so rejection only ever denies a Byzantine beacon.
    Result check_shardtip_witnesses(const chain::Block& b,
                                    const chain::Chain& chain,
                                    const NodeRegistry& registry) const;
    Result check_cumulative_rand(const chain::Block& b, const chain::Chain& chain) const;
    // Q1 seam: the cumulative_rand CORE with an explicit predecessor rand.
    // check_cumulative_rand is a thin wrapper that sources it from the chain
    // head; the beacon-header ingest path sources it from the previous tracked
    // beacon header. ONE implementation of the chaining rule, two rand sources.
    Result check_cumulative_rand_from(const chain::Block& b,
                                      const Hash& prev_rand) const;
    Result check_transactions(const chain::Block& b, const chain::Chain& chain,
                               const NodeRegistry& registry) const;
    Result check_timestamp(const chain::Block& b) const;

public:
    // The verifier's per-transaction accept rules — the ONE definition site
    // (check_transactions walks a block through it in order). Public so the
    // producer asks the same predicate before a transaction enters a block
    // (Node::tx_admit_locked -> build_body): the assembler must never include
    // what the verifier rejects, because a rejected self-assembled block
    // evicts nothing and the chain halts (SECURITY.md S-056/S-059/S-061/S-062).
    // `expected_nonce` is the caller's simulated next nonce for tx.from; the
    // caller advances it on success. Verifies the transaction signature.
    Result check_transaction(const chain::Transaction& tx, uint64_t block_index,
                             const chain::Chain& chain, const NodeRegistry& registry,
                             uint64_t expected_nonce) const;

    // 2026-09-17 (SECURITY.md S-105): the verifier's per-EQUIVOCATION-EVENT
    // accept rules — the ONE definition site (check_equivocation_events walks a
    // block's events through it). Public for the same reason check_transaction
    // is: the producer asks the same predicate before an event enters a block
    // (Node::eq_admit_locked -> build_body). build_body used to include whatever
    // the evidence pool held, so a pooled record whose equivocator stopped
    // resolving (a DEREGISTER reaching its inactive_from, or an epoch turn) made
    // every honest block invalid for as long as it stayed pooled — the S-056
    // class on the evidence arm. `i` appears only in the reject strings;
    // `block_index` is the index of the block the event is checked FOR and picks
    // the epoch the equivocator's key resolves in. Verifies two Ed25519
    // signatures.
    Result check_equivocation_event(const chain::EquivocationEvent& ev, size_t i,
                                    uint64_t block_index, const chain::Chain& chain,
                                    const NodeRegistry& registry) const;
private:

    // Resolve the rand source at `epoch_start_height` for committee
    // selection. Consults the external provider first; on miss, falls
    // back to chain.at(epoch_start - 1).cumulative_rand or chain.head()
    // if epoch_start sits outside the chain.
    Hash resolve_epoch_rand(uint64_t epoch_start,
                              const chain::Chain& chain) const;

    uint32_t k_block_sigs_{0};
    uint32_t m_pool_{0};
    bool     bft_enabled_{true};
    uint32_t bft_escalation_threshold_{1};   // S-045: default 1 (was 5)
    uint32_t epoch_blocks_{1000};
    ShardId  shard_id_{0};
    // rev.9 R2: committee region pin for this chain (empty = global).
    std::string committee_region_{};
    // A6: sharding mode mirrored from the operator's selected
    // TimingProfile. Default CURRENT preserves legacy behavior for any
    // call site that constructs BlockValidator without an explicit setter.
    ShardingMode sharding_mode_{ShardingMode::CURRENT};
    // D3.6 / S-036: this chain's role. Default SINGLE (never BEACON) so a validator
    // constructed without set_chain_role never runs the beacon-only MERGE_EVENT
    // witness path — byte-neutral for every legacy call site.
    ChainRole chain_role_{ChainRole::SINGLE};
    // D3.5e-7d: the genesis-committed shard→region map (empty default = every
    // lookup yields "" = the CURRENT-compat global pool).
    std::map<ShardId, std::string> beacon_shard_regions_{};
    // D1: CT layer master switch, mirrored from GenesisConfig. Default true so
    // any call site that constructs BlockValidator without the setter keeps the
    // pre-D1 behaviour (CT accepted).
    bool         confidential_tx_enabled_{true};
    // A5: governance state mirrored from genesis.
    uint8_t      governance_mode_{0};
    std::vector<PubKey> param_keyholders_{};
    uint32_t     param_threshold_{0};
    EpochRandProvider external_epoch_rand_{};
    // §Q1 clock injection for the freshness gate; default = process
    // RealClock (== determ::now_unix(), byte-invariant). Non-owning.
    const determ::time::Clock* clock_{&determ::time::RealClock::instance()};
};

} // namespace determ::node
