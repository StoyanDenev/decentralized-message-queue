// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
#include <determ/chain/chain.hpp>
#include <determ/node/registry.hpp>
#include <determ/node/validator.hpp>
#include <determ/node/producer.hpp>
#include <determ/net/gossip.hpp>
#include <asio.hpp>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <shared_mutex>
#include <optional>
#include <map>
#include <nlohmann/json.hpp>

namespace determ::node {

struct Config {
    std::string              domain;
    std::string              data_dir;
    uint16_t                 listen_port{7777};
    uint16_t                 rpc_port{7778};
    // S-001 mitigation: when true (default), the RPC server binds to
    // 127.0.0.1 only — external network clients cannot connect.
    // Operators with a real authentication story (mTLS / reverse proxy
    // with auth / VPN) can flip this to false to expose RPC on all
    // interfaces. The unauthenticated all-interfaces default that
    // S-001 documented is no longer reachable through config silence.
    bool                     rpc_localhost_only{true};
    // v2.16 / S-001 full closure: HMAC-SHA-256 RPC authentication.
    // Hex-encoded shared secret. Empty (default) = auth disabled (only
    // localhost-only enforcement). Non-empty = every RPC request MUST
    // include an `auth` field that's hex(HMAC-SHA-256(secret,
    // method || "|" || params_canonical_json)). Server rejects with
    // {"error": "auth_failed"} otherwise.
    //
    // Threat model: closes the unauthenticated-RPC attack surface
    // (S-001) when localhost_only is false. With auth enabled,
    // network-reachable RPC requires possession of the shared secret;
    // without the secret, an attacker cannot forge requests.
    //
    // Replay protection: NOT included in v2.16. An MITM that captures
    // an authenticated request can replay it. Adding a per-request
    // nonce (timestamp + sequence) is a follow-on; the v2.16 ship
    // closes S-001's primary issue (unauthenticated requests) but
    // leaves replay as a documented separate concern.
    //
    // Recommended generation: 32 random bytes hex-encoded
    // (`openssl rand -hex 32`). Share with operators via secure
    // channel (env var, secrets manager, sealed config).
    std::string              rpc_auth_secret{};
    // v2.X / S-014: RPC rate-limiting. Token-bucket per peer IP.
    // `rpc_rate_per_sec` is the steady-state RPC budget per second
    // per peer; `rpc_rate_burst` is the bucket capacity (max
    // sudden-burst calls before steady-state rate kicks in). Both 0
    // disables rate limiting (default behavior, backward compat).
    // Suggested defaults for operators wanting protection:
    //   rate_per_sec = 100, burst = 200 (allows brief polling
    //   spikes from a single client without aggressive penalty).
    double                   rpc_rate_per_sec{0.0};
    double                   rpc_rate_burst{0.0};
    // S-014 (gossip side): per-peer-IP gossip rate limit. Same
    // mechanism as RPC. HELLO is exempt so newly-attached peers finish
    // handshake even under pressure. Both 0 disables (default).
    // Suggested defaults for external-bind operators:
    //   gossip_rate_per_sec = 500, gossip_rate_burst = 1000
    // (healthy consensus is a few msgs/s steady-state with bursts on
    // round transitions; 500/s with 1000 burst absorbs that headroom).
    double                   gossip_rate_per_sec{0.0};
    double                   gossip_rate_burst{0.0};
    std::vector<std::string> bootstrap_peers;
    // rev.9 B2c.5c: cross-chain peer addresses. Populated when this node
    // wants to participate in cross-chain coordination — typically a
    // SHARD-role node lists beacon nodes here, and a BEACON-role node
    // lists shard nodes. Peers are connected separately from
    // bootstrap_peers (which is intra-chain only). The role-based
    // gossip filter (B2c.5b) ensures messages from these peers don't
    // pollute intra-chain consensus state.
    std::vector<std::string> beacon_peers;       // shard-role: connect to beacons
    std::vector<std::string> shard_peers;        // beacon-role: connect to shards
    std::string              key_path;
    std::string              chain_path;
    // rev.9 B6.basic: if set and chain_path is empty/missing on
    // startup, the node bootstraps from this snapshot (state +
    // tail headers) instead of replaying every block from genesis.
    // Operators stage the snapshot file separately (e.g., download
    // from a trusted source) and point the config at it. After
    // bootstrap, normal chain.json persistence resumes.
    std::string              snapshot_path;
    // Bootstrap (M12). genesis_path is the path to the GenesisConfig JSON
    // shared by all operators of this chain. genesis_hash, if non-empty, is
    // a hex-encoded 32-byte hash that the loaded genesis must match — node
    // refuses to start on mismatch (eclipse defense).
    std::string              genesis_path;
    std::string              genesis_hash;
    // R2: beacon-role nodes load a shard manifest at startup to learn each
    // shard's committee_region. The manifest is required for BEACON-role
    // nodes whose chain runs under sharding_mode=EXTENDED (otherwise
    // on_shard_tip can't validate the region-filtered committee). Under
    // CURRENT or NONE the field is meaningful but optional (degenerate:
    // every shard has committee_region == "" so the filter is a no-op).
    // Empty string means "use default path {data_dir}/shard_manifest.json".
    std::string              shard_manifest_path;
    uint32_t                 m_creators{3};
    // K-of-M Phase 2 threshold. K = M = strong BFT (unanimity). K < M = weak
    // BFT (single non-signer tolerated). Loaded from GenesisConfig at chain
    // init; per-node override is rejected as a misconfiguration. Constraint:
    // 1 <= k_block_sigs <= m_creators.
    uint32_t                 k_block_sigs{3};
    // rev.8 per-height escalation. Loaded from GenesisConfig.
    bool                     bft_enabled{true};
    uint32_t                 bft_escalation_threshold{5};
    // rev.9 sharding role. SINGLE = today's behavior. BEACON/SHARD activate
    // sharded paths in Stage B2+. Loaded from GenesisConfig.
    ChainRole                chain_role{ChainRole::SINGLE};
    // A6: sharding mode mirrored from the operator's selected
    // TimingProfile. Persisted in node config so cmd_start can hand it
    // to the validator without re-resolving the profile (the named
    // profile is a cmd_init concern only). Default CURRENT preserves
    // pre-A6 behavior for legacy node configs (chain_role=BEACON|SHARD
    // historically meant "rev.9 current sharding").
    ShardingMode             sharding_mode{ShardingMode::CURRENT};
    ShardId                  shard_id{0};
    uint32_t                 initial_shard_count{1};
    uint32_t                 epoch_blocks{1000};
    // rev.9 R1: this validator's self-declared region tag included in the
    // REGISTER tx payload. Empty = global pool (backward-compat).
    // Normalized + charset-checked at validator. Operators set this in
    // node config so the registration matches the shard's
    // committee_region.
    std::string              region{};
    // rev.9 R1: this chain's committee_region (mirrored from the loaded
    // genesis). Empty = global pool. Used by check_if_selected to
    // filter the eligible pool before drawing K.
    std::string              committee_region{};
    // L4 / C3 — three local round timers.
    uint32_t                 tx_commit_ms{200};
    uint32_t                 block_sig_ms{200};
    uint32_t                 abort_claim_ms{100};

    nlohmann::json to_json() const;
    static Config  from_json(const nlohmann::json& j);
    static Config  load(const std::string& path);
    void           save(const std::string& path) const;
};

// Two protocol phases (CONTRIB → BLOCK_SIG). The transition is a local
// state change once K Phase-1 commits arrive; commit-reveal does the
// selective-abort defense rather than a wall-clock delay (rev.9 S-009).
enum class ConsensusPhase : uint8_t { IDLE, CONTRIB, BLOCK_SIG };

enum class SyncState : uint8_t { SYNCING, IN_SYNC };

class Node {
public:
    explicit Node(const Config& cfg);
    ~Node();

    void run();
    void stop();

    asio::io_context& io_context_access() { return io_; }

    // RPC handlers
    nlohmann::json rpc_status()                                     const;
    nlohmann::json rpc_peers()                                      const;
    // rev.9: block explorer primitive. Returns the full block at the
    // given index (block 0 = genesis). Returns null if out of range.
    nlohmann::json rpc_block(uint64_t index)                        const;
    // rev.9: chain summary — last N blocks with index, hash, mode,
    // tx_count, creators (compact). Useful for ops dashboards.
    nlohmann::json rpc_chain_summary(uint32_t last_n = 10)          const;
    // rev.9: list current validator pool (registered + active +
    // staked >= min_stake + not suspended). Each entry includes
    // domain, ed_pub (hex), staked balance, active_from height.
    nlohmann::json rpc_validators()                                 const;
    // rev.9: aggregate account state — balance, next_nonce, plus
    // registry status if the address is a registered domain. Works
    // for both registered domains and anonymous bearer-wallet
    // addresses (0x-prefixed hex). Returns null if address has no
    // on-chain state.
    nlohmann::json rpc_account(const std::string& addr)             const;
    // rev.9 B5: current epoch's committee — the K creators selected
    // by epoch_committee_seed(epoch_rand, shard_id) over the current
    // validator pool. Pure function of chain state; deterministic
    // across all nodes. Each entry: {domain, ed_pub, stake,
    // active_from}. Useful for explorers and rotation observability.
    nlohmann::json rpc_committee()                                  const;
    // rev.9: locate a transaction by its hex-encoded hash. Scans the
    // chain (head → genesis) and returns {tx, block_index, block_hash}
    // on hit, or null when the hash isn't found in any finalized block
    // (it may still be in the mempool, or simply unknown).
    nlohmann::json rpc_tx(const std::string& hash_hex)              const;
    nlohmann::json rpc_register();
    nlohmann::json rpc_send(const std::string& to, uint64_t amount, uint64_t fee = 0);
    nlohmann::json rpc_balance(const std::string& domain)           const;
    // S-033 / v2.1: expose the chain's current cryptographic state
    // commitment. Returns {"state_root": "<hex>", "height": N}. Until
    // the producer starts populating block.state_root, this surface is
    // a query-only foundation — operators can compare across nodes to
    // detect silent state divergence. Once producer-side population
    // lands (follow-on commit), Block.state_root == this for every
    // honest node applying the same block sequence.
    nlohmann::json rpc_state_root()                                 const;
    // v2.2 light-client foundation: inclusion proof for a state key.
    // Returns a JSON object with the verification-input tuple, or
    // {"error": "not_found"} if the key is not committed by the
    // current state_root. The light client receives this plus the
    // state_root from a trusted block header and verifies via
    // crypto::merkle_verify (or a pure-JS/wasm port).
    //
    // Namespace argument: "a" (accounts), "s" (stakes), "r" (registrants),
    //   "b" (abort_records), "k" (constants), "c" (counters). For
    //   "a"/"s"/"r"/"b" the key argument is the domain string; for
    //   "k"/"c" it's the constant/counter name. Other namespaces
    //   (i/m/p) need composite keys and are not yet exposed by RPC.
    nlohmann::json rpc_state_proof(const std::string& ns,
                                       const std::string& key)      const;
    nlohmann::json rpc_stake(uint64_t amount, uint64_t fee = 0);
    nlohmann::json rpc_unstake(uint64_t amount, uint64_t fee = 0);
    nlohmann::json rpc_nonce(const std::string& domain)             const;
    nlohmann::json rpc_stake_info(const std::string& domain)        const;

    // v2.18/v2.19 Theme 7: DApp registry queries. The substrate for
    // wallets and DApp-discovery tooling.
    //
    // rpc_dapp_info(domain): returns the DApp's full registry entry as
    //   JSON, or {"error": "not_found"} if no entry exists. Used by
    //   wallets before constructing a DAPP_CALL: they need the DApp's
    //   service_pubkey (for E2E encryption) and the registered topics
    //   list (to validate against locally before paying chain fees).
    //
    // rpc_dapp_list(prefix, topic): returns an array of DApp summaries
    //   matching optional filters. `prefix` matches DApp domain
    //   prefix (e.g., "chat." or empty for all); `topic` matches DApps
    //   that have registered the given topic. For lightweight clients
    //   that don't want to traverse the full registry.
    nlohmann::json rpc_dapp_info(const std::string& domain)         const;
    nlohmann::json rpc_dapp_list(const std::string& prefix,
                                    const std::string& topic)       const;

    // v2.19 Theme 7 Phase 7.4 (polling subset): retrospective query
    // for DAPP_CALL events addressed to a DApp. Scans blocks in
    // [from_height, to_height], filters tx.type == DAPP_CALL +
    // tx.to == domain, optionally filters by payload-encoded topic.
    //
    // For DApp nodes: poll this RPC every N seconds with the last
    // height they processed, get newly-arrived messages, process them,
    // bump their watermark. Lightweight; works against any Determ
    // full node.
    //
    // Streaming subscription (true push-based delivery) is Phase 7.4
    // proper — a follow-on. For v2.19 ship, polling is sufficient.
    //
    // Result limit: at most DAPP_MESSAGES_PAGE_LIMIT events per call;
    // caller paginates by adjusting from_height. Total bytes per call
    // bounded by event count × MAX_DAPP_CALL_PAYLOAD + overhead.
    nlohmann::json rpc_dapp_messages(const std::string& domain,
                                        uint64_t           from_height,
                                        uint64_t           to_height,
                                        const std::string& topic)   const;

    // Rev. 4: accept a fully-signed Transaction JSON (built externally, e.g.
    // from a CLI tool with a raw Ed25519 key) and broadcast it via gossip.
    // Used for anonymous-account TRANSFERs that aren't authored by this node.
    nlohmann::json rpc_submit_tx(const nlohmann::json& tx_json);
    // rev.9 B5: external submission of equivocation evidence. Forensics
    // tools and governance scripts can submit EquivocationEvent JSON
    // assembled off-chain (e.g., from log scraping that observed two
    // conflicting BFT blocks signed by the same proposer). The node
    // validates the two-sig proof against the equivocator's registered
    // key, then queues for inclusion + gossip — the same path internal
    // detection (apply_block_locked) takes. Returns
    //   { accepted: bool, reason: <error if rejected> }.
    // Idempotent on (equivocator, block_index) duplicates.
    nlohmann::json rpc_submit_equivocation(const nlohmann::json& ev_json);
    // rev.9 B6.basic: snapshot of chain state (accounts, stakes,
    // registrants, dedup, genesis-pinned constants, tail headers).
    // Operators host the result for fast bootstrap of new nodes.
    nlohmann::json rpc_snapshot(uint32_t header_count = 16) const;

private:
    void on_block(const chain::Block& b);
    void on_tx(const chain::Transaction& tx);

    // S-002 mitigation: verify a transaction's Ed25519 signature at
    // mempool-admission time so forged-sig floods are rejected before
    // they can consume mempool slots or amplify through gossip. The
    // full validator's check_transactions still re-verifies at block
    // apply (defense in depth). This early check is the cheap one;
    // declining bad sigs here prevents the DoS amplification path.
    //
    // Returns true if the signature verifies under the tx's claimed
    // identity (REGISTER pubkey from payload, anonymous pubkey from
    // bearer address, or registry pubkey for registered domains).
    // Returns false otherwise — including when the sender's registry
    // entry isn't available yet (a new domain submitting before its
    // own REGISTER is finalized falls through this path; this is
    // intentional and matches the validator's behavior).
    //
    // Caller must hold state_mutex_.
    bool verify_tx_signature_locked(const chain::Transaction& tx) const;
    void on_contrib(const ContribMsg& msg);
    void on_block_sig(const BlockSigMsg& msg);
    // Called by start_delay_compute when replaying buffered sigs; assumes
    // state_mutex_ is already held by the caller.
    void on_block_sig_locked(const BlockSigMsg& msg);
    // S-013: bounded per-signer admission into buffered_block_sigs_.
    // Caller must hold state_mutex_.
    void try_buffer_block_sig(const BlockSigMsg& msg);
    void on_abort_claim(const AbortClaimMsg& msg);
    void on_abort_event(uint64_t block_index, const Hash& prev_hash,
                         const chain::AbortEvent& ev);
    void on_equivocation_evidence(const chain::EquivocationEvent& ev);
    // rev.9 B2c.1: shard-side handler for gossiped beacon headers.
    // Stores in beacon_headers_; full validation (K-of-K against pool
    // derived from prior verified headers) is B2c.2.
    void on_beacon_header(const chain::Block& b);
    // rev.9 B2c.3: beacon-side handler for gossiped shard tips. Validates
    // K-of-K (or BFT) sigs against the committee the beacon derives from
    // its own pool + shard_id salt. Stores validated tips in
    // latest_shard_tips_.
    void on_shard_tip(ShardId shard_id, const chain::Block& tip);
    // rev.9 B3.3: cross-shard receipt bundle handler.
    //   * BEACON role: relay (re-broadcast) to all peers; ignores
    //     payload semantics. Bundle's natural path is shard → beacon
    //     → other shard.
    //   * SHARD role: filter receipts in src_block.cross_shard_receipts
    //     to those addressed to my_shard_id; deduplicate against
    //     pending_inbound_receipts_ + applied_inbound_receipts_; store
    //     for B3.4 (producer to bake into next block; apply to credit).
    //   * SINGLE role: drop.
    // The raw `relay` Message is used by BEACON to re-broadcast verbatim
    // (preserves the source's K-of-K signing intact).
    void on_cross_shard_receipt_bundle(ShardId src_shard,
                                          const chain::Block& src_block,
                                          const net::Message& relay);
    // rev.9 B6.basic: serve a snapshot to a requesting peer. Builds via
    // Chain::serialize_state(header_count) and sends via the peer
    // pointer.
    void on_snapshot_request(uint32_t header_count,
                                std::shared_ptr<net::Peer> peer);
    void on_get_chain(uint64_t from_index, uint16_t count,
                      std::shared_ptr<net::Peer> peer);
    void on_chain_response(const std::vector<chain::Block>& blocks,
                            bool has_more, std::shared_ptr<net::Peer> peer);
    void on_status_request(std::shared_ptr<net::Peer> peer);
    void on_status_response(uint64_t height, const std::string& genesis_hash,
                             std::shared_ptr<net::Peer> peer);

    void start_sync_if_behind();
    void request_next_chunk();
    bool in_sync() const;

    void check_if_selected();
    void start_contrib_phase();
    void enter_block_sig_phase();
    void start_block_sig_phase(const Hash& delay_output);
    void try_finalize_round();

    // rev.8 helpers. Both compute deterministic per-round state from
    // current_aborts_ + chain head; same answer on every node.
    chain::ConsensusMode current_mode() const;
    std::string          current_proposer_domain() const;     // "" in MD mode

    // rev.9 (B1): epoch-relative randomness for committee selection.
    // epoch_index = chain_.height() / epoch_blocks. epoch_rand = chain's
    // cumulative_rand at the block that opened the epoch. With S=1 this
    // does not change behavior visibly compared to rev.8; it only sets up
    // the per-shard / per-epoch seed shape that Stage B2 will use across
    // multiple chains.
    EpochIndex current_epoch_index() const;
    Hash       current_epoch_rand()  const;
    void handle_contrib_timeout();
    void handle_block_sig_timeout();
    void reset_round();
    void apply_block_locked(const chain::Block& b);

    Config                cfg_;
    crypto::NodeKey       key_;
    chain::Chain          chain_;
    NodeRegistry          registry_;
    BlockValidator        validator_;

    // Mempool keyed by tx.hash (primary) and indexed by (from, nonce) for
    // replace-by-fee: a new tx with the same (from, nonce) replaces the old
    // iff its fee is strictly higher.
    //
    // S-008 mitigation: bounded mempool. MEMPOOL_MAX_TXS is a hard cap on
    // the total tx_store_ size; MEMPOOL_MAX_PER_SENDER is a per-sender
    // quota that prevents one address from filling the mempool with
    // pipelined-nonce txs. Both checks are enforced in on_tx (gossip-
    // admission) and rpc_submit_tx (RPC admission).
    //
    // Eviction policy on global-cap overflow: lowest-fee tx in the
    // mempool is evicted, IF the incoming tx's fee is strictly higher.
    // This is "fee-priority mempool" — under sustained spam, the chain
    // economically prices out the spammer (they must pay the marginal
    // fee to evict). Per-sender quota overflow always rejects (no
    // eviction across senders for fairness).
    //
    // Suggested defaults: 10,000 total mempool slots; 100 per sender.
    // Tunable via genesis-pinned config in v2.X follow-on if needed.
    static constexpr size_t MEMPOOL_MAX_TXS         = 10000;
    static constexpr size_t MEMPOOL_MAX_PER_SENDER  = 100;
    std::map<Hash, chain::Transaction>                       tx_store_;
    std::map<std::pair<std::string, uint64_t>, Hash>         tx_by_account_nonce_;

    // S-008: count txs in the mempool from a given sender. Iterates
    // tx_by_account_nonce_ in lexicographic order; std::map's ordered
    // structure means we can range-scan from `{sender, 0}` and stop
    // when the key's `.first` changes. O(per-sender-count), bounded
    // by MEMPOOL_MAX_PER_SENDER = 100.
    size_t mempool_count_from(const std::string& sender) const;
    // S-008: shared admission policy for tx_store_ insertion. Returns
    // "" on accept; non-empty error string on reject. Used by both
    // on_tx (gossip path) and rpc_submit_tx (RPC path) so the policy
    // is the same regardless of admission channel.
    //
    // Caller is responsible for the sig-verify check BEFORE calling
    // this — admission gates apply only to authenticated txs (else
    // an unauth flood would consume admission-evaluation budget).
    std::string mempool_admit_check(const chain::Transaction& tx) const;
    // S-008: evict the lowest-fee tx if the new one has strictly
    // higher fee than the current minimum. Returns true if eviction
    // happened OR if no eviction was needed (cap not exceeded).
    // Returns false if cap is hit AND the new tx's fee isn't high
    // enough to displace anything — caller should reject the tx.
    bool mempool_make_room_for(const chain::Transaction& tx);

    net::GossipNet                  gossip_;
    asio::io_context                io_;
    std::vector<chain::AbortEvent>  current_aborts_;
    std::vector<size_t>             current_creator_indices_;
    std::vector<std::string>        current_creator_domains_;

    ConsensusPhase                  phase_{ConsensusPhase::IDLE};

    // Phase 1 — Contrib accumulation. Equivocation (same signer at the
    // same generation with two different commitments) is now routed
    // through the shared `pending_equivocation_evidence_` buffer used by
    // BlockSigMsg-level equivocation (S-006 closure). The legacy
    // `contrib_equivocations_` map that sat here unused was removed
    // alongside that closure.
    std::map<std::string, ContribMsg>                       pending_contribs_;

    // Per-round canonical inputs. tx_root + delay_seed are derived from
    // the K Phase-1 contribs and used as the seed for the commit-reveal
    // randomness (S-009 rev.9). No worker thread, no wall-clock delay —
    // the transition Phase-1 → Phase-2 is immediate.
    Hash                                                     current_tx_root_{};
    Hash                                                     current_delay_seed_{};

    // rev.9 S-009: this node's fresh Phase-1 secret for the current
    // round. Generated in start_contrib_phase, committed via
    // SHA256(secret || pubkey) as ContribMsg.dh_input, revealed in
    // Phase-2 BlockSigMsg.dh_secret. Reset on each round.
    Hash                                                     current_round_secret_{};
    // rev.9 S-009: peers' revealed secrets, gathered in Phase 2 via
    // BlockSigMsg.dh_secret. Indexed by signer (committee member's
    // domain). Verified against commit in pending_contribs_[signer].
    // dh_input on receipt; aggregated at finalize into block.
    // creator_dh_secrets in committee selection order.
    std::map<std::string, Hash>                              pending_secrets_;

    // Phase 2 — BlockSig accumulation, gated to current round's delay_output.
    Hash                                                     current_delay_output_{};
    std::map<std::string, BlockSigMsg>                       pending_block_sigs_;
    // Buffer for BlockSigMsgs that arrive before this node has assembled
    // its own K Phase-1 contribs. Drained when the round transitions into
    // Phase-2.
    std::vector<BlockSigMsg>                                 buffered_block_sigs_;

    // rev.8 mode of the current round. Set by check_if_selected when the
    // committee is chosen (MD with full K, or BFT with reduced ceil(2K/3)).
    chain::ConsensusMode current_round_mode_{chain::ConsensusMode::MUTUAL_DISTRUST};

    // rev.8 follow-on: equivocation evidence pool. Populated by
    // apply_block_locked when a duplicate-height BFT block with a
    // different hash is observed (the bft_proposer signed two block
    // digests). Drained into the next produced block's
    // equivocation_events; entries deduped by equivocator after a block
    // baking the proof is applied (slashing zeros their stake).
    std::vector<chain::EquivocationEvent> pending_equivocation_evidence_;

    // rev.9 B2c.1: shard-only. Light header chain of the beacon. Shards
    // populate this by receiving BEACON_HEADER gossip messages from
    // beacon nodes. B2c.2 added validation (K-of-K sigs against pool
    // derived from prior headers); B2c.2-full adds committee derivation
    // from this chain. For now this is a verified-append receive buffer.
    std::vector<chain::Block> beacon_headers_;

    // rev.9 B2c.3: beacon-only. Latest validated tip per shard. Beacon
    // populates this by receiving SHARD_TIP gossip messages from shard
    // nodes and verifying K-of-K (or BFT) sigs against the shard's
    // committee derived from beacon's own validator pool + shard_id
    // salt. Used to populate BeaconBlock.shard_summaries (B3+).
    std::map<ShardId, chain::Block> latest_shard_tips_;

    // R2: beacon-only. Per-shard committee_region loaded from the
    // shard manifest at startup. Used by on_shard_tip to filter the
    // pool before deriving the expected committee. Absent shard_id
    // means committee_region == "" (global pool — backward-compat
    // with CURRENT-mode chains that have no regional grouping).
    std::map<ShardId, std::string>  shard_committee_regions_;

    // rev.9 B3.3: shard-only. Inbound cross-shard receipts addressed to
    // this shard. Populated when a CROSS_SHARD_RECEIPT_BUNDLE arrives
    // from another shard (via beacon relay) and the bundle's receipts
    // include entries with dst_shard == my_shard_id. Keyed by
    // (src_shard, tx_hash) for idempotent dedup; B3.4 dequeues these
    // when producing a destination-shard block (which carries them as
    // applied receipts and credits `to`).
    std::map<std::pair<ShardId, Hash>, chain::CrossShardReceipt>
        pending_inbound_receipts_;

    asio::steady_timer              contrib_timer_;
    asio::steady_timer              block_sig_timer_;

    // S7: AbortClaim accumulation. Keyed by (round, missing_creator) so
    // multiple competing claim sets don't conflict. M-1 matching claims
    // (one per claimer) advance the abort.
    std::map<std::pair<uint8_t, std::string>,
             std::map<std::string, AbortClaimMsg>> pending_claims_;

    // Sync state. peer_heights_ is a best-effort view of each peer's reported
    // tip; max(peer_heights_) drives the SYNCING/IN_SYNC transition. The
    // sync_peer_ pointer holds the peer we're currently chunking from (if any).
    SyncState                                state_{SyncState::SYNCING};
    std::map<std::string, uint64_t>          peer_heights_;
    std::shared_ptr<net::Peer>               sync_peer_;

    std::atomic<bool>               running_{false};
    // S-031 partial mitigation: shared_mutex permits N concurrent readers
    // (read-only RPCs taking std::shared_lock) while serializing writes
    // (mutations + consensus state transitions taking std::unique_lock).
    // Full A9 overlay/delta state model (the audit's structural fix) is
    // a deeper refactor; this is the high-leverage subset that lifts
    // the throughput ceiling for the common read-heavy workload
    // (status/balance/account/block lookups dominate operational queries).
    mutable std::shared_mutex       state_mutex_;
    std::vector<std::thread>        threads_;

    // A9 / S-031 follow-on: async chain.save() worker.
    //
    // Pre-fix: after every block apply, Node::on_block_finalized called
    // chain_.save(cfg_.chain_path) synchronously while holding
    // state_mutex_'s unique_lock. The save serializes the full chain
    // JSON and writes it to disk — O(N) work per block where N is
    // chain height. On long-lived chains this is the dominant cost in
    // the apply hot path AND it blocks the next apply from acquiring
    // unique_lock until the disk write finishes.
    //
    // Post-fix: enqueue_save() sets save_pending_ and notifies. The
    // worker thread takes state_mutex_ shared_lock (concurrent with
    // RPC readers, only contends with the NEXT writer), serializes,
    // releases the lock, writes atomically. Multiple pending saves
    // coalesce: while a save is running the flag may be re-set; one
    // additional save fires after the running one completes. Burst
    // applies → at most one save lagging behind the head.
    //
    // Crash semantics: between block apply and save completion, the
    // block is in memory but not on disk. Node crash in this window =
    // chain.json contains a slightly older head. Peers gossip the
    // missing block(s) on restart; node catches up via normal sync.
    // No worse than pre-fix's window-after-apply-pre-save.
    //
    // Stop semantics: stop() sets save_stop_, notifies, joins the
    // worker. After join, performs one final synchronous save to
    // ensure the latest state is on disk before process exit.
    std::thread                     save_thread_;
    std::mutex                      save_mutex_;
    std::condition_variable         save_cv_;
    std::atomic<bool>               save_pending_{false};
    std::atomic<bool>               save_stop_{false};
    void save_worker_loop();
    void enqueue_save();
};

} // namespace determ::node
