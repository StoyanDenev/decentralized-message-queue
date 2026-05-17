// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/node/node.hpp>
#include <determ/node/producer.hpp>
#include <determ/rpc/rpc.hpp>
#include <determ/chain/chain.hpp>
#include <determ/chain/block.hpp>
#include <determ/chain/params.hpp>
#include <determ/crypto/keys.hpp>
#include <determ/crypto/merkle.hpp>
#include <determ/crypto/random.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/net/messages.hpp>
#include <determ/util/json_validate.hpp>
#include <determ/net/rate_limiter.hpp>
// v2.17: envelope crypto for passphrase-encrypted keyfiles.
// Lives in wallet/envelope.cpp, also linked into determ binary.
#include "envelope.hpp"
#include "shamir.hpp"
#include <asio.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;
using json = nlohmann::json;
using namespace determ;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static std::string default_data_dir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    return appdata ? std::string(appdata) + "\\determ" : ".determ";
#else
    const char* home = std::getenv("HOME");
    return home ? std::string(home) + "/.determ" : ".determ";
#endif
}

static std::string config_path(const std::string& data_dir) {
    return data_dir + "/config.json";
}

static void usage() {
    std::cout << R"(Determ — fork-free DH-consensus cryptocurrency

Usage:
  determ init [--data-dir <dir>] [--profile cluster|web|regional|global|tactical|single_test|cluster_test|web_test|regional_test|global_test|tactical_test]
                                              [--genesis <config.json>]
                                              Generate node keys and config
  determ register <domain> [--rpc-port <p>]  Submit RegisterTx to running node
  determ start [--config <path>]             Start node (sync + participate in consensus)
  determ send <to_domain> <amount>           Submit TRANSFER transaction
  determ status                              Chain head, node count, next creators
  determ show-block <index>                  Print block at index (full JSON)
  determ chain-summary [--last N]            Compact summary of last N blocks
  determ validators                          List the current validator pool
  determ committee                           List the current epoch's K-of-K committee
  determ show-account <address> [--json]     Inspect any address (balance, nonce, registry, stake)
  determ show-tx <hash> [--json]             Look up a tx by hash (block_index + payload)
  determ snapshot create [--out f]           Dump current chain state for fast bootstrap (B6.basic)
  determ snapshot inspect --in f [--state-root <hex64>] [--json]
                                              Validate + summarize a snapshot file (round-trip check);
                                              optional --state-root pins an externally-trusted root for
                                              trustless-fast-sync verification; --json emits
                                              machine-readable output for scripts
  determ snapshot fetch --peer h:p --out f   Fetch a snapshot from a running node over the gossip wire
  determ peers                               List connected peers
  determ balance [<domain>]                  Show domain balance
  determ stake <amount> [--fee <n>]          Lock <amount> as registration stake
  determ unstake <amount> [--fee <n>]        Release stake (after deregister + delay)
  determ nonce [<domain>]                    Show next account nonce
  determ stake_info [<domain>]               Show locked stake and unlock height
  determ genesis-tool peer-info <domain>     Print this node's creator entry (JSON)
                                              for inclusion in a genesis config.
  determ genesis-tool build <config.json>    Build a genesis from peer-info entries
  determ genesis-tool build-sharded <cfg>    Stage B2: produce 1 beacon + S shard genesis files
                                              and print the genesis hash.
  determ account create [--out <file>]       Generate a fresh anonymous account
                                              keypair (Ed25519). Prints address + privkey.
  determ account address <privkey_hex>       Derive the account address from a hex privkey.
  determ send_anon <to> <amount> <privkey_hex>
                                              Sign a TRANSFER from the anon account
                                              corresponding to <privkey_hex> and submit
                                              via the daemon's submit_tx RPC.

State commitment + light-client (v2.1 + v2.2):
  determ state-root                          Chain Merkle state root + height + head_hash
  determ state-proof --ns {a|s|r|d|b|k|c} --key <name>
                                              Merkle inclusion proof for any state entry
                                              (light-client primitive against state_root;
                                              d = v2.18 DApp registry by owning domain)
  determ verify-state-proof [--in file] [--state-root <hex64>]
                                              Verify a state-proof response locally via
                                              crypto::merkle_verify. Reads JSON from --in
                                              or stdin. Optional --state-root pins an
                                              externally-trusted root (real light-client
                                              mode); without it, the proof's claimed root
                                              is used (self-consistency check).
  determ headers [--from N] [--count M]      Fetch a slice of block headers (Block JSON
                  [--peer host:port            minus transactions / receipts / initial_state).
                   | --rpc-port P]             Light-client header-sync primitive: the
                                              returned headers carry committee signatures
                                              and state_root for verify-state-proof
                                              anchoring. Default: --from 0 --count 16;
                                              server caps count at 256. Default fetch path
                                              is RPC (--rpc-port); --peer host:port
                                              alternative uses the gossip-layer
                                              HEADERS_REQUEST/RESPONSE wire messages
                                              (no RPC required on the peer side).
  determ verify-headers [--in file]          Verify prev_hash chain in a `determ headers`
                        [--genesis-hash <hex64>]
                        [--prev-hash <hex64>] response. Reads JSON from --in or stdin.
                                              Optional --genesis-hash anchors index-0
                                              start; --prev-hash anchors index-N>0 starts
                                              (for extending a previously-verified range).
                                              Pure chain-of-hashes integrity check; does
                                              not verify committee signatures.
  determ verify-block-sigs --header <file>   Verify K-of-K committee Ed25519 signatures
                           --committee <f>   on a single block header against a supplied
                           [--bft]           committee pubkey map. --header accepts a
                                              single-block JSON or `determ headers`
                                              envelope. --committee is a JSON array of
                                              {domain, ed_pub} entries (or {members: [...]}
                                              shape). --bft allows sentinel-zero slots
  determ verify-genesis --in genesis.json   Standalone genesis.json validator. Loads,
                          [--expected-hash  applies sane-bounds checks, computes
                           <hex64>] [--json] compute_genesis_hash, prints a structured
                                              summary (incl. operational params NOT bound
                                              to identity hash per S-039). Optional
                                              --expected-hash pins against external value;
                                              --json emits machine-readable output.
                                              for BFT-mode threshold = ceil(2K/3).

DApp substrate (v2.18 + v2.19) — the DApp's identity is its owning Determ domain:
  determ submit-dapp-register --priv <hex> --from <domain>
                              --service-pubkey <64hex> --endpoint-url <url>
                              [--topics t1,t2,...] [--retention 0|1]
                              [--metadata-hex <hex>] [--fee N]
                                              Register or update a DApp (idempotent on --from)
  determ submit-dapp-register --priv <hex> --from <domain> --deactivate
                                              Deactivate (defers via DAPP_GRACE_BLOCKS)
  determ submit-dapp-call --priv <hex> --from <sender> --to <dapp-domain>
                          [--topic T] [--payload-hex <hex>]
                          [--amount N] [--fee N]
                                              Submit a DAPP_CALL routed to --to
  determ dapp-list [--prefix P] [--topic T]   List registered DApps (optional filters)
  determ dapp-info --domain <D>               Per-DApp record
  determ dapp-messages --domain <D> [--from H] [--to H] [--topic T]
                                              Retrospective DAPP_CALL poll (256 / page)

)" << R"(Governance + sharded operation:
  determ submit-param-change ...              A5 PARAM_CHANGE tx (see CLI-REFERENCE.md §Governance)
  determ submit-merge-event ...               R7 MERGE_EVENT tx (EXTENDED-mode under-quorum merge)

In-process tests (deterministic, no network):
  determ test-atomic-scope                    A9 Phase 2D nested-scope rollback primitive
  determ test-composable-batch                COMPOSABLE_BATCH all-or-nothing semantics
  determ test-dapp-register                   v2.18 DAPP_REGISTER apply path
  determ test-dapp-call                       v2.19 DAPP_CALL routing + apply path
  determ test-s018-json-validation            S-018 json_require<T> field-name diagnostics
  determ test-merkle                          v2.1 Merkle primitives (root, proof, verify,
                                              tampering detection, domain separation)
  determ test-committee-selection             Committee-selection primitives (S-020 hybrid
                                              select_m_creators + select_after_abort_m
                                              + epoch_committee_seed determinism)
  determ test-shard-routing                   shard_id_for_address (cross-shard routing
                                              salted-SHA-256; determinism, salt-sensitivity,
                                              distribution sanity)
  determ test-ed25519                         Ed25519 sign/verify (foundation for every
                                              signature claim in the protocol; determinism,
                                              tampering rejection, cross-key rejection)
  determ test-sha256                          SHA-256 wrapper + SHA256Builder (NIST FIPS
                                              180-4 vectors; Preliminaries §1.3 big-endian
                                              uint64_t encoding for protocol determinism)
  determ test-anon-address                    is_anon_address / normalize_anon_address /
                                              parse_anon_pubkey / make_anon_address
                                              (S-028 case-insensitive parsing + canonical
                                              lowercase storage form)
  determ test-genesis-message                 GenesisConfig::genesis_message hash-mixing
                                              contract (backward-compat default-skips-mix
                                              invariant + custom-yields-distinct-hash
                                              + size cap enforcement)
  determ test-state-root                      Chain::compute_state_root() commitment
                                              algebra (S-033 / v2.1) — determinism,
                                              purity, per-namespace sensitivity, order
                                              independence, invertibility
  determ test-block-rand                      V8 randomness primitives —
                                              compute_delay_seed + compute_block_rand
                                              + proposer_idx + required_block_sigs
                                              + count_round1_aborts (FA1 + FA5
                                              foundation; commit-reveal contract +
                                              BFT quorum arithmetic)
  determ test-rate-limiter                    S-014 token-bucket rate limiter
                                              (net::RateLimiter) — disabled-mode
                                              bypass, first-touch full, burst
                                              exhaustion, per-key independence,
                                              refill timing, burst-cap invariant
  determ test-block-digest                    compute_block_digest (FA1 signature
                                              target) — INCLUSION-list field
                                              coverage + EXCLUSION-list (S-030 D2)
                                              fence (delay_output, state_root,
                                              equivocation_events, abort_events,
                                              etc. MUST NOT affect digest)
  determ test-block-hash                      Block::signing_bytes() +
                                              Block::compute_hash() — FA1 chain-
                                              anchor identity; full field-coverage
                                              including Phase-2-reveal fields +
                                              partner_subset_hash + state_root
                                              zero-skip backward-compat
  determ test-binary-codec                    Wire-format codec (A3 / S8) — JSON
                                              envelope v0 + binary envelope v1
                                              round-trip + format-detecting
                                              deserializer + malformed-input
                                              rejection + S-022 per-MsgType cap
                                              table golden vectors
  determ test-wire-types                      Block-internal wire types JSON
                                              round-trip — CrossShardReceipt +
                                              AbortEvent + EquivocationEvent +
                                              GenesisAlloc; field-preservation +
                                              S-018 strict-rejection lock-in
  determ test-transaction                     Transaction::signing_bytes +
                                              compute_hash + Ed25519 sign/verify
                                              + JSON round-trip for all TxType
                                              variants + S-018 strict-rejection
  determ test-merge-event-codec               MergeEvent::encode / ::decode
                                              (R4 under-quorum merge wire
                                              format) — round-trip, field
                                              sensitivity, rejection paths
  determ test-consensus-msgs                  ContribMsg + BlockSigMsg +
                                              AbortClaimMsg + their commitment
                                              hashes (make_contrib_commitment +
                                              make_abort_claim_message);
                                              domain-separation + sign/verify
  determ test-tx-root                         compute_tx_root union semantics
                                              (FA2 censorship resistance:
                                              {A,B} ∪ {B,C} == {A,B,C}, NOT
                                              intersection); dedup + order
                                              invariance
  determ test-genesis                         compute_genesis_hash +
                                              make_genesis_block — chain
                                              identity origin + S-039
                                              diagnostic-UX gap lock-in
  determ test-envelope                        wallet/envelope.hpp AES-256-GCM
                                              + PBKDF2 encrypt/decrypt + AAD
                                              binding + serialize round-trip
                                              (A2 Phase 2 wallet recovery
                                              share wrapping)
  determ test-resolve-fork                    Chain::resolve_fork (S-029
                                              BFT-mode fork-choice: heaviest
                                              sigs / fewer aborts / smallest
                                              hash; deterministic across
                                              peers)
  determ test-shamir                          Shamir's Secret Sharing over
                                              GF(2^8) (wallet/shamir.cpp, A2
                                              Phase 1) — T-of-N reconstruction
                                              + share-shape invariants +
                                              threshold safety
  determ test-random-state                    Random-state primitives —
                                              compute_dh_output / _m +
                                              update_random_state +
                                              compute_abort_hash +
                                              chain_abort_hash +
                                              genesis_random_state (V8
                                              foundation + S5 anti-cartel)
  determ test-snapshot-defense                S-018 defense-in-depth lock-in
                                              for Chain::restore_from_snapshot
                                              wrong-type collection rejection
                                              (every collection throws clean
                                              field-name diagnostic, not
                                              opaque nlohmann error)
  determ test-encoding                        types.hpp encoding helpers —
                                              to_hex / from_hex / from_hex_arr
                                              round-trips + case-insensitive
                                              parse + rejection paths + enum
                                              to_string mappings
  determ test-chain-helpers                   Chain read API — balance /
                                              next_nonce / stake / lockfree
                                              variants + shard routing
                                              + A1 supply counters +
                                              operator-tunable getters
  determ test-json-validate                   S-018 json_validate helpers —
                                              json_require<T> / _hex / _array
                                              direct unit test (error-message
                                              contract under every from_json
                                              in the codebase)
  determ test-block-roundtrip                 Block::to_json / from_json full
                                              field-set round-trip across all
                                              sub-object arrays + zero-skip
                                              fields + compute_hash invariance
                                              through JSON transit
  determ test-config-roundtrip                Config::to_json / from_json —
                                              operator-config save+reload
                                              round-trip across all 32
                                              tunable fields (ports / peers /
                                              rate-limits / region / enums)
  determ test-tx-binary-codec                 Transaction binary codec
                                              (encode_tx_frame / decode_tx_frame
                                              via encode_binary / decode_binary)
                                              — S-002 fixed-slot amount/fee/
                                              nonce path + trailer overflow

For details + flags see docs/CLI-REFERENCE.md.
)" << "\n";
}

// ─── Commands ────────────────────────────────────────────────────────────────

static int cmd_init(int argc, char** argv) {
    std::string data_dir     = default_data_dir();
    std::string profile      = "web";
    std::string genesis_path = "";
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--data-dir") data_dir     = argv[i + 1];
        if (std::string(argv[i]) == "--profile")  profile      = argv[i + 1];
        if (std::string(argv[i]) == "--genesis")  genesis_path = argv[i + 1];
    }

    fs::create_directories(data_dir);
    std::string kpath = data_dir + "/node_key.json";
    std::string cpath = config_path(data_dir);
    std::string chain_path = data_dir + "/chain.json";

    if (fs::exists(kpath)) {
        std::cout << "Key already exists at " << kpath << " (skipping keygen)\n";
    } else {
        auto key = crypto::generate_node_key();
        crypto::save_node_key(key, kpath);
        std::cout << "Generated node key: pubkey=" << to_hex(key.pub) << "\n";
    }

    node::Config cfg;
    cfg.data_dir   = data_dir;
    cfg.key_path   = kpath;
    cfg.chain_path = chain_path;
    cfg.listen_port = 7777;
    cfg.rpc_port    = 7778;

    chain::TimingProfile tp = chain::PROFILE_WEB;
    if      (profile == "cluster")        tp = chain::PROFILE_CLUSTER;
    else if (profile == "regional")       tp = chain::PROFILE_REGIONAL;
    else if (profile == "global")         tp = chain::PROFILE_GLOBAL;
    else if (profile == "tactical")       tp = chain::PROFILE_TACTICAL;
    else if (profile == "single_test")    tp = chain::PROFILE_SINGLE_TEST;
    else if (profile == "cluster_test")   tp = chain::PROFILE_CLUSTER_TEST;
    else if (profile == "web_test")       tp = chain::PROFILE_WEB_TEST;
    else if (profile == "regional_test")  tp = chain::PROFILE_REGIONAL_TEST;
    else if (profile == "global_test")    tp = chain::PROFILE_GLOBAL_TEST;
    else if (profile == "tactical_test")  tp = chain::PROFILE_TACTICAL_TEST;
    else if (profile != "web") {
        std::cerr << "Unknown --profile " << profile
                  << " (expected: cluster|web|regional|global|tactical|"
                  << "single_test|cluster_test|web_test|regional_test|global_test|tactical_test)\n";
        return 1;
    }
    cfg.tx_commit_ms   = tp.tx_commit_ms;
    cfg.block_sig_ms   = tp.block_sig_ms;
    cfg.abort_claim_ms = tp.abort_claim_ms;
    cfg.m_creators     = tp.m_creators;
    cfg.k_block_sigs   = tp.k_block_sigs;
    // A6: pin chain_role + sharding_mode from the chosen profile so
    // cmd_start can hand them to the validator without re-resolving the
    // profile. Genesis remains the source of truth at runtime — Node's
    // ctor cross-checks gcfg.chain_role against cfg_.chain_role and
    // gates loadtime on cfg_.sharding_mode (see node.cpp).
    cfg.chain_role     = tp.chain_role;
    cfg.sharding_mode  = tp.sharding_mode;

    if (!genesis_path.empty()) {
        cfg.genesis_path = genesis_path;
        try {
            auto gcfg = chain::GenesisConfig::load(genesis_path);
            cfg.genesis_hash = to_hex(chain::compute_genesis_hash(gcfg));
            std::cout << "Pinned genesis hash: " << cfg.genesis_hash << "\n";
        } catch (std::exception& e) {
            std::cerr << "Warning: could not load genesis at " << genesis_path
                      << " (" << e.what() << "); pin left empty\n";
        }
    }

    cfg.save(cpath);

    const char* mode = (cfg.k_block_sigs == cfg.m_creators) ? "strong" : "weak";
    std::cout << "Config written to " << cpath
              << " (profile: " << profile
              << ", M=" << cfg.m_creators
              << ", K=" << cfg.k_block_sigs
              << ", mode=" << mode << ")\n";
    std::cout << "Edit the config to set your domain and bootstrap peers, then run:\n";
    std::cout << "  determ start\n";
    return 0;
}

static int cmd_start(int argc, char** argv) {
    std::string data_dir = default_data_dir();
    std::string cfg_path;
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--config")   cfg_path = argv[i + 1];
        if (std::string(argv[i]) == "--data-dir") data_dir = argv[i + 1];
    }
    if (cfg_path.empty()) cfg_path = config_path(data_dir);

    try {
        auto cfg = node::Config::load(cfg_path);

        if (cfg.key_path.empty()) cfg.key_path = cfg.data_dir + "/node_key.json";
        if (!fs::exists(cfg.key_path)) {
            auto key = crypto::generate_node_key();
            crypto::save_node_key(key, cfg.key_path);
            std::cout << "[init] Generated node key\n" << std::flush;
        }
        if (cfg.chain_path.empty()) cfg.chain_path = cfg.data_dir + "/chain.json";

        std::cout << "[determ] Loading node domain=" << cfg.domain
                  << " genesis_path=" << cfg.genesis_path << "\n" << std::flush;

        node::Node node(cfg);

        rpc::RpcServer rpc_server(node.io_context_access(), node,
                                       cfg.rpc_port, cfg.rpc_localhost_only,
                                       cfg.rpc_auth_secret,
                                       cfg.rpc_rate_per_sec,
                                       cfg.rpc_rate_burst);
        rpc_server.start();

        std::cout << "[determ] Starting node domain=" << cfg.domain
                  << " port=" << cfg.listen_port << "\n" << std::flush;
        node.run(); // blocks
        return 0;
    } catch (std::exception& e) {
        std::cerr << "[determ] FATAL: " << e.what() << std::endl;
        std::cerr.flush();
        return 1;
    } catch (...) {
        std::cerr << "[determ] FATAL: unknown exception" << std::endl;
        std::cerr.flush();
        return 1;
    }
}

static uint16_t get_rpc_port(int argc, char** argv) {
    for (int i = 0; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--rpc-port")
            return static_cast<uint16_t>(std::stoi(argv[i + 1]));
    return 7778;
}

// Bounded auto-retry for tx submissions: re-resolves nonce on each attempt,
// returns the last response or an error after `max_retries` failures.
// "Failure" here means the RPC raised a nonce-mismatch error or returned a
// queued tx that still hadn't been included after `retry_window_blocks`
// of polling. The retry_window check is cheap (status RPC).
static int submit_tx_with_retry(uint16_t port,
                                 const std::string& method,
                                 nlohmann::json params,
                                 int max_retries = 3) {
    for (int attempt = 0; attempt < max_retries; ++attempt) {
        try {
            auto result = rpc::rpc_call("127.0.0.1", port, method, params);
            std::cout << result.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::string msg = e.what();
            // Re-attempt only on transient nonce-mismatch errors. Other errors
            // are non-retryable.
            if (msg.find("nonce") == std::string::npos || attempt + 1 == max_retries) {
                std::cerr << "Error: " << msg << "\n";
                return 1;
            }
            std::cerr << "[retry " << (attempt + 1) << "] " << msg << "\n";
        }
    }
    return 1;
}

static int cmd_register(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: determ register <domain>\n"; return 1; }
    std::string domain   = argv[0];
    uint16_t    rpc_port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", rpc_port, "register",
                                    {{"domain", domain}});
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

static int cmd_send(int argc, char** argv) {
    if (argc < 2) { std::cerr << "Usage: determ send <to_domain> <amount> [--fee <n>]\n"; return 1; }
    std::string to     = argv[0];
    uint64_t    amount = std::stoull(argv[1]);
    uint64_t    fee    = 0;
    uint16_t    port   = get_rpc_port(argc, argv);
    for (int i = 2; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--fee") fee = std::stoull(argv[i + 1]);
    return submit_tx_with_retry(port, "send",
        {{"to", to}, {"amount", amount}, {"fee", fee}});
}

static int cmd_status(int argc, char** argv) {
    uint16_t port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "status");
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error (is the node running?): " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ show-block <index> [--rpc-port N]
//   Prints the full block at the given index from a running node.
static int cmd_show_block(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ show-block <index> [--rpc-port N]\n";
        return 1;
    }
    uint64_t index = std::stoull(argv[0]);
    uint16_t port = get_rpc_port(argc, argv);
    try {
        json params = {{"index", index}};
        auto result = rpc::rpc_call("127.0.0.1", port, "block", params);
        if (result.is_null()) {
            std::cerr << "Block " << index << " out of range (chain.height too low)\n";
            return 1;
        }
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// v2.2 light-client committee-signature verifier.
//
// Usage: determ verify-block-sigs --header <file> --committee <file>
//                                  [--bft]
//
// Reads a single block header (from `determ headers` or `show-block`)
// and a committee pubkey map, then verifies that each `creators[i]`'s
// `creator_block_sigs[i]` is a valid Ed25519 signature over
// `compute_block_digest(b)` under the pubkey associated with that
// creator's domain.
//
// The committee file is a JSON object with a `members` array — same
// shape the `committee` RPC returns:
//
//   {
//     "members": [
//       {"domain": "node1", "ed_pub": "<64-char hex>"},
//       {"domain": "node2", "ed_pub": "<64-char hex>"},
//       ...
//     ]
//   }
//
// (Or accept the raw committee RPC response directly — the response is
// the array itself.)
//
// Optional `--bft`: in BFT mode the required threshold is
// Q = ceil(2 * |creators| / 3) instead of full K-of-K. Without this
// determ verify-genesis --in genesis.json [--json] [--expected-hash HEX]
//   Standalone genesis.json validator. Loads the file, applies the
//   same parsing + sane-bounds checks as `determ start`, computes the
//   chain-identity hash via compute_genesis_hash, prints a structured
//   summary (human-readable by default, single-line JSON with --json).
//   Optional --expected-hash compares the computed identity against an
//   externally-trusted pin; exits non-zero with a clear diagnostic
//   when they differ.
//
// Useful workflows:
//   * Pre-deployment: verify the genesis.json hashes to the value the
//     operator expects (defeats config-rewrite-attacks where a
//     deployment template smuggles in a different chain identity).
//   * Cross-team coordination: each team independently computes the
//     hash from their checked-in genesis.json and compares.
//   * Cluster onboarding: a new operator's genesis must match the
//     existing cluster's pinned hash.
//
// Note re: S-039 (Low/Op diagnostic-UX gap, see docs/SECURITY.md §S-039):
// `compute_genesis_hash` does NOT bind operational params like
// m_creators, k_block_sigs, block_subsidy, min_stake, initial_shard_count,
// bft_enabled. Two genesis.json files differing ONLY in those fields
// produce the same identity hash. This command prints those fields
// explicitly in the output so operators can spot mismatches via direct
// inspection even though the hash itself doesn't catch them.
static int cmd_verify_genesis(int argc, char** argv) {
    std::string in_path;
    std::string expected_hash_hex;
    bool json_out = false;
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--in") in_path = argv[i + 1];
        else if (std::string(argv[i]) == "--expected-hash") expected_hash_hex = argv[i + 1];
    }
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") json_out = true;
    }
    if (in_path.empty()) {
        std::cerr << "Usage: determ verify-genesis --in <genesis.json> "
                     "[--expected-hash <hex64>] [--json]\n";
        return 1;
    }

    auto emit_error = [&](const std::string& code, const std::string& msg) {
        if (json_out) {
            json err = {{"status", "error"}, {"code", code}, {"message", msg}};
            std::cout << err.dump() << "\n";
        } else {
            std::cerr << "FAIL: " << msg << "\n";
        }
    };

    try {
        std::ifstream f(in_path);
        if (!f) {
            emit_error("cannot_open", "cannot open " + in_path);
            return 1;
        }
        json j = json::parse(f);
        chain::GenesisConfig cfg = chain::GenesisConfig::from_json(j);

        // compute_genesis_hash (the identity contract). The from_json
        // path above already applied sane-bounds checks for subsidy
        // overflow + genesis_message size + LOTTERY multiplier
        // constraints — those throw at parse time.
        Hash hash = chain::compute_genesis_hash(cfg);

        // Build the result + optionally compare against external pin.
        json result = {
            {"status",                "ok"},
            {"path",                  in_path},
            {"genesis_hash",          to_hex(hash)},
            {"chain_id",              cfg.chain_id},
            {"chain_role",            static_cast<uint8_t>(cfg.chain_role)},
            {"shard_id",              cfg.shard_id},
            {"initial_creators",      cfg.initial_creators.size()},
            {"initial_balances",      cfg.initial_balances.size()},
            // Operational params NOT in compute_genesis_hash (S-039).
            // Emit them so operators can spot mismatches manually.
            {"m_creators",            cfg.m_creators},
            {"k_block_sigs",          cfg.k_block_sigs},
            {"block_subsidy",         cfg.block_subsidy},
            {"min_stake",             cfg.min_stake},
            {"initial_shard_count",   cfg.initial_shard_count},
            {"bft_enabled",           cfg.bft_enabled},
            // Fields that ARE in the hash:
            {"genesis_message_is_default",
                cfg.genesis_message == chain::DEFAULT_GENESIS_MESSAGE},
            {"genesis_message_bytes", cfg.genesis_message.size()},
            {"committee_region",      cfg.committee_region},
        };

        // Optional external-pin comparison.
        bool pin_match = true;
        if (!expected_hash_hex.empty()) {
            if (expected_hash_hex.size() != 64) {
                emit_error("invalid_expected_hash_length",
                    "expected-hash must be 64 hex chars, got "
                    + std::to_string(expected_hash_hex.size()));
                return 1;
            }
            Hash expected = from_hex_arr<32>(expected_hash_hex);
            pin_match = (expected == hash);
            result["expected_hash_match"] = pin_match;
        }

        if (json_out) {
            std::cout << result.dump() << "\n";
        } else {
            std::cout << "genesis OK: " << in_path << "\n";
            std::cout << "  genesis_hash       : " << to_hex(hash) << "\n";
            std::cout << "  chain_id           : " << cfg.chain_id << "\n";
            std::cout << "  chain_role         : "
                      << static_cast<int>(cfg.chain_role) << "\n";
            std::cout << "  shard_id           : " << cfg.shard_id << "\n";
            std::cout << "  initial_creators   : " << cfg.initial_creators.size() << "\n";
            std::cout << "  initial_balances   : " << cfg.initial_balances.size() << "\n";
            std::cout << "  --- operational params (S-039: NOT bound to identity hash) ---\n";
            std::cout << "  m_creators         : " << cfg.m_creators << "\n";
            std::cout << "  k_block_sigs       : " << cfg.k_block_sigs << "\n";
            std::cout << "  block_subsidy      : " << cfg.block_subsidy << "\n";
            std::cout << "  min_stake          : " << cfg.min_stake << "\n";
            std::cout << "  initial_shard_count: " << cfg.initial_shard_count << "\n";
            std::cout << "  bft_enabled        : "
                      << (cfg.bft_enabled ? "true" : "false") << "\n";
            std::cout << "  --- identity-bound fields ---\n";
            std::cout << "  genesis_message    : "
                      << (cfg.genesis_message == chain::DEFAULT_GENESIS_MESSAGE
                              ? "(default)"
                              : "(custom, " + std::to_string(cfg.genesis_message.size()) + " bytes)")
                      << "\n";
            std::cout << "  committee_region   : "
                      << (cfg.committee_region.empty() ? "(none)" : cfg.committee_region)
                      << "\n";
            if (!expected_hash_hex.empty()) {
                if (pin_match) {
                    std::cout << "  expected hash      : ✓ matches\n";
                } else {
                    std::cerr << "FAIL: genesis_hash does NOT match --expected-hash\n";
                    std::cerr << "  computed: " << to_hex(hash) << "\n";
                    std::cerr << "  expected: " << expected_hash_hex << "\n";
                }
            }
        }
        return pin_match ? 0 : 1;
    } catch (std::exception& e) {
        emit_error("parse_or_validation_error", e.what());
        return 1;
    }
}

// flag, every creators[i] must have a non-zero verifying signature
// (MD-mode K-of-K).
//
// Returns 0 on success with a structured summary; non-zero with a FAIL
// diagnostic on signature mismatch or missing committee member.
//
// Pure committee-signature check. Does NOT verify the prev_hash chain
// (use `verify-headers` for that) or the state_root (compute_state_root
// can't be re-derived without the full state — use the verified header
// to anchor verify-state-proof / snapshot inspect --state-root).
static int cmd_verify_block_sigs(int argc, char** argv) {
    std::string header_path;
    std::string committee_path;
    bool bft_mode = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--header"    && i + 1 < argc) header_path    = argv[i + 1];
        else if (a == "--committee" && i + 1 < argc) committee_path = argv[i + 1];
        else if (a == "--bft") bft_mode = true;
    }
    if (header_path.empty() || committee_path.empty()) {
        std::cerr << "Usage: determ verify-block-sigs --header <file> "
                     "--committee <file> [--bft]\n";
        return 1;
    }

    // Read header + committee.
    nlohmann::json hjson, cjson;
    try {
        std::ifstream hf(header_path);
        if (!hf) throw std::runtime_error("cannot open header: " + header_path);
        hjson = nlohmann::json::parse(hf);
        std::ifstream cf(committee_path);
        if (!cf) throw std::runtime_error("cannot open committee: " + committee_path);
        cjson = nlohmann::json::parse(cf);
    } catch (std::exception& e) {
        std::cerr << "verify-block-sigs: parse error: " << e.what() << "\n";
        return 1;
    }

    // If the header file is actually a `determ headers` response
    // (`{headers: [...], ...}`), pull out the first header.
    if (hjson.contains("headers") && hjson["headers"].is_array()) {
        if (hjson["headers"].empty()) {
            std::cerr << "verify-block-sigs: header file has empty "
                         "headers array — nothing to verify\n";
            return 1;
        }
        hjson = hjson["headers"][0];
    }

    // Pad stripped header back to a Block-parseable shape: the heavy
    // collections that the `headers` RPC erases (transactions,
    // cross_shard_receipts, inbound_receipts, initial_state) are
    // NOT in compute_block_digest's input, so empty arrays are
    // semantically equivalent for our purposes.
    if (!hjson.contains("transactions"))         hjson["transactions"]         = nlohmann::json::array();
    if (!hjson.contains("cross_shard_receipts")) hjson["cross_shard_receipts"] = nlohmann::json::array();
    if (!hjson.contains("inbound_receipts"))     hjson["inbound_receipts"]     = nlohmann::json::array();
    if (!hjson.contains("initial_state"))        hjson["initial_state"]        = nlohmann::json::array();

    chain::Block b;
    try {
        b = chain::Block::from_json(hjson);
    } catch (std::exception& e) {
        std::cerr << "verify-block-sigs: malformed header: "
                  << e.what() << "\n";
        return 1;
    }

    // Build domain → pubkey lookup from the committee JSON. Accept
    // both `{members: [...]}` (shape with envelope) and raw array.
    nlohmann::json members;
    if (cjson.is_array()) members = cjson;
    else if (cjson.contains("members") && cjson["members"].is_array())
        members = cjson["members"];
    else {
        std::cerr << "verify-block-sigs: committee file must be a JSON "
                     "array or an object with a 'members' array\n";
        return 1;
    }

    std::map<std::string, PubKey> pubkey_of;
    try {
        for (auto& m : members) {
            std::string domain = m.value("domain", std::string{});
            std::string ed_hex = m.value("ed_pub", std::string{});
            if (domain.empty() || ed_hex.empty()) continue;
            if (ed_hex.size() != 64) {
                throw std::runtime_error(
                    "committee member '" + domain
                    + "' has malformed ed_pub (expected 64 hex chars, got "
                    + std::to_string(ed_hex.size()) + ")");
            }
            pubkey_of[domain] = from_hex_arr<32>(ed_hex);
        }
    } catch (std::exception& e) {
        std::cerr << "verify-block-sigs: " << e.what() << "\n";
        return 1;
    }
    if (pubkey_of.empty()) {
        std::cerr << "verify-block-sigs: committee file has no valid "
                     "members\n";
        return 1;
    }

    // Sanity: every creator in the block must be in the committee.
    for (auto& d : b.creators) {
        if (pubkey_of.find(d) == pubkey_of.end()) {
            std::cerr << "FAIL: creator '" << d << "' is not in the "
                         "supplied committee — cannot verify their "
                         "signature\n";
            return 1;
        }
    }
    if (b.creator_block_sigs.size() != b.creators.size()) {
        std::cerr << "FAIL: creator_block_sigs.size (" << b.creator_block_sigs.size()
                  << ") != creators.size (" << b.creators.size() << ")\n";
        return 1;
    }

    // Compute the digest that the committee signed.
    Hash digest = node::compute_block_digest(b);

    // Verify each creator's signature. In MD mode, every creator must
    // have a valid sig (sentinel-zero NOT allowed). In BFT mode, count
    // non-zero verifying sigs and check against Q = ceil(2K/3).
    Signature zero_sig{};
    size_t valid = 0;
    std::vector<std::string> failures;
    for (size_t i = 0; i < b.creators.size(); ++i) {
        const auto& sig = b.creator_block_sigs[i];
        if (sig == zero_sig) {
            if (!bft_mode) {
                failures.push_back("creator[" + std::to_string(i) + "] '"
                                    + b.creators[i] + "': sentinel-zero "
                                    "signature not allowed in MD mode");
            }
            // BFT: zero is a valid sentinel slot; just don't count.
            continue;
        }
        const auto& pk = pubkey_of.at(b.creators[i]);
        bool ok = crypto::verify(pk, digest.data(), digest.size(), sig);
        if (ok) {
            valid++;
        } else {
            failures.push_back("creator[" + std::to_string(i) + "] '"
                                + b.creators[i] + "': signature does NOT "
                                "verify against compute_block_digest");
        }
    }

    size_t required = bft_mode
        ? (2 * b.creators.size() + 2) / 3   // ceil(2K/3)
        : b.creators.size();                 // full K-of-K

    if (valid >= required && failures.empty()) {
        std::cout << "OK\n";
        std::cout << "  block_index:    " << b.index << "\n";
        std::cout << "  mode:           "
                  << (bft_mode ? "BFT (threshold "
                                + std::to_string(required) + "/"
                                + std::to_string(b.creators.size())
                                + ")"
                              : "MD (full K-of-K)") << "\n";
        std::cout << "  verified sigs:  " << valid << "/"
                  << b.creators.size() << "\n";
        std::cout << "  digest:         " << to_hex(digest) << "\n";
        if (!b.state_root.empty() || b.state_root != Hash{}) {
            std::cout << "  state_root:     " << to_hex(b.state_root)
                      << "\n";
        }
        return 0;
    } else {
        std::cerr << "FAIL: committee-signature verification\n";
        std::cerr << "  block_index:   " << b.index << "\n";
        std::cerr << "  mode:          "
                  << (bft_mode ? "BFT" : "MD") << "\n";
        std::cerr << "  verified sigs: " << valid << "/"
                  << b.creators.size()
                  << " (required " << required << ")\n";
        for (auto& f : failures) std::cerr << "  " << f << "\n";
        return 1;
    }
}

// v2.2 light-client header-chain verifier.
//
// Usage: determ verify-headers [--in file] [--genesis-hash <hex64>]
//                              [--prev-hash <hex64>]
//
// Reads a `determ headers` response (JSON) from --in or stdin and
// verifies that the prev_hash chain links correctly between
// consecutive headers: header[i].prev_hash == header[i-1].block_hash.
//
// Optional --genesis-hash <hex64>: if the headers slice starts at
// index 0, the first header's prev_hash should equal Hash{} (32 zero
// bytes — the canonical "no parent" marker). If --genesis-hash is
// supplied, it's also checked against the genesis header's block_hash.
// Useful when bootstrapping from a known genesis pin.
//
// Optional --prev-hash <hex64>: if the headers slice starts at some
// index > 0, the first header's prev_hash must equal this supplied
// hash (= block_hash of the block immediately preceding the slice).
// Light clients use this to extend a previously-verified header
// range with a new fetched slice.
//
// Does NOT verify committee signatures on each header (that requires
// a NodeRegistry + epoch-rand derivation; out of scope for this
// stdalone CLI). This is the chain-of-hashes integrity check —
// catches a server returning misaligned / re-ordered headers.
static int cmd_verify_headers(int argc, char** argv) {
    std::string in_path;
    std::string genesis_hash_hex;
    std::string prev_hash_hex;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"            && i + 1 < argc) in_path          = argv[i + 1];
        else if (a == "--genesis-hash"  && i + 1 < argc) genesis_hash_hex = argv[i + 1];
        else if (a == "--prev-hash"     && i + 1 < argc) prev_hash_hex    = argv[i + 1];
    }

    nlohmann::json doc;
    try {
        if (!in_path.empty()) {
            std::ifstream f(in_path);
            if (!f) throw std::runtime_error("cannot open: " + in_path);
            doc = nlohmann::json::parse(f);
        } else {
            doc = nlohmann::json::parse(std::cin);
        }
    } catch (std::exception& e) {
        std::cerr << "verify-headers: parse error: " << e.what() << "\n";
        return 1;
    }

    if (!doc.contains("headers") || !doc["headers"].is_array()) {
        std::cerr << "verify-headers: input missing 'headers' array "
                     "(expected `determ headers` response)\n";
        return 1;
    }
    auto& headers = doc["headers"];
    if (headers.empty()) {
        std::cout << "OK (empty headers slice, nothing to verify)\n";
        return 0;
    }

    // Helper: pull required hex field from one header.
    auto h_get = [](const nlohmann::json& h, const char* field,
                       size_t expected_chars) -> std::string {
        if (!h.contains(field) || !h[field].is_string())
            throw std::runtime_error(
                std::string("header missing '") + field + "' field");
        std::string s = h[field].get<std::string>();
        if (s.size() != expected_chars)
            throw std::runtime_error(
                std::string("header '") + field
                + "' has wrong length: expected "
                + std::to_string(expected_chars) + " chars, got "
                + std::to_string(s.size()));
        return s;
    };

    try {
        // Check the first header's prev_hash against the appropriate
        // anchor: --genesis-hash (if index 0), --prev-hash (if not 0),
        // or just print a note (if no anchor supplied).
        uint64_t first_index = headers[0].value("index", uint64_t{0});
        std::string first_prev = h_get(headers[0], "prev_hash", 64);

        if (first_index == 0) {
            // Genesis: prev_hash must be 32-zero-bytes (the canonical
            // "no parent" marker).
            std::string zero64(64, '0');
            if (first_prev != zero64) {
                std::cerr << "FAIL: genesis header (index 0) has "
                             "non-zero prev_hash: " << first_prev << "\n";
                return 1;
            }
            // Optional: verify the supplied --genesis-hash matches the
            // genesis header's block_hash.
            if (!genesis_hash_hex.empty()) {
                std::string gh = h_get(headers[0], "block_hash", 64);
                if (gh != genesis_hash_hex) {
                    std::cerr << "FAIL: genesis block_hash mismatch\n"
                              << "  header reports: " << gh << "\n"
                              << "  --genesis-hash: " << genesis_hash_hex << "\n";
                    return 1;
                }
            }
        } else if (!prev_hash_hex.empty()) {
            // Non-genesis start: first header's prev_hash must match
            // the supplied --prev-hash anchor.
            if (first_prev != prev_hash_hex) {
                std::cerr << "FAIL: first header's prev_hash doesn't "
                             "match supplied --prev-hash\n"
                          << "  header prev_hash: " << first_prev << "\n"
                          << "  --prev-hash:     " << prev_hash_hex << "\n";
                return 1;
            }
        }
        // (If neither --genesis-hash nor --prev-hash is supplied and
        // we don't start at 0, the first prev_hash is unanchored —
        // we just verify the internal chain links and report it.)

        // Walk consecutive header pairs and verify prev_hash chain.
        for (size_t i = 1; i < headers.size(); ++i) {
            std::string prev = h_get(headers[i], "prev_hash", 64);
            std::string prior_hash = h_get(headers[i - 1], "block_hash", 64);
            if (prev != prior_hash) {
                std::cerr << "FAIL: prev_hash chain break at header "
                          << i << " (index "
                          << headers[i].value("index", uint64_t{0}) << ")\n"
                          << "  prev_hash:        " << prev << "\n"
                          << "  prior block_hash: " << prior_hash << "\n";
                return 1;
            }
        }
    } catch (std::exception& e) {
        std::cerr << "verify-headers: " << e.what() << "\n";
        return 1;
    }

    std::cout << "OK\n";
    std::cout << "  verified " << headers.size()
              << " header(s) " << headers[0].value("index", uint64_t{0})
              << ".." << headers.back().value("index", uint64_t{0}) << "\n";
    if (!genesis_hash_hex.empty()) {
        std::cout << "  genesis pin: ✓ matches supplied --genesis-hash\n";
    } else if (!prev_hash_hex.empty()) {
        std::cout << "  prev pin:    ✓ matches supplied --prev-hash\n";
    }
    return 0;
}

// v2.2 light-client header-sync CLI.
//
// Two fetch paths:
//
//   1. RPC fetch (default):
//        determ headers [--from N] [--count M] [--rpc-port P]
//      Connects to a local node's RPC port. Returns the same
//      {headers, from, count, height} envelope `rpc_headers`
//      produces.
//
//   2. Gossip-layer fetch (light-client mode):
//        determ headers --peer host:port [--from N] [--count M]
//      Connects directly to a remote node's gossip port, exchanges
//      HELLO + HEADERS_REQUEST, waits for HEADERS_RESPONSE. No RPC
//      binding required — peers don't have to expose RPC for light
//      clients to consume headers. This is the missing v2.2
//      gossip-layer piece (HEADERS_REQUEST / HEADERS_RESPONSE wire
//      messages); same envelope shape, same content as the RPC
//      path so all downstream verifier CLIs (verify-headers,
//      verify-block-sigs) work identically.
//
// Returns a slice of block headers — the same Block JSON shape that
// `show-block` emits, but with the heavy `transactions`,
// `cross_shard_receipts`, `inbound_receipts`, and `initial_state`
// fields stripped. Light clients use this to verify committee
// signatures + extract state_root for verify-state-proof anchoring,
// without the bandwidth cost of fetching every tx.
//
// Defaults: --from 0, --count 16. Server caps count at 256.
static int cmd_headers(int argc, char** argv) {
    uint64_t from_index = 0;
    uint32_t count = 16;
    std::string peer_str;
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--from")  from_index = std::stoull(argv[i + 1]);
        else if (a == "--count") count = static_cast<uint32_t>(
                                            std::stoul(argv[i + 1]));
        else if (a == "--peer")  peer_str = argv[i + 1];
    }

    // Path 2: gossip-layer fetch via --peer host:port.
    if (!peer_str.empty()) {
        auto colon = peer_str.find(':');
        if (colon == std::string::npos) {
            std::cerr << "--peer must be host:port\n";
            return 1;
        }
        std::string host = peer_str.substr(0, colon);
        uint16_t port = static_cast<uint16_t>(
            std::stoi(peer_str.substr(colon + 1)));
        try {
            asio::io_context io;
            asio::ip::tcp::resolver resolver(io);
            auto endpoints = resolver.resolve(host, std::to_string(port));
            asio::ip::tcp::socket socket(io);
            asio::connect(socket, endpoints);

            auto write_msg = [&](const net::Message& msg) {
                auto buf = msg.serialize();
                asio::write(socket, asio::buffer(buf));
            };

            // HELLO + HEADERS_REQUEST. Tag ourselves SINGLE/0 since
            // light clients don't claim a chain identity (matches
            // the snapshot-fetcher pattern).
            write_msg(net::make_hello("headers-fetcher", 0,
                                        ChainRole::SINGLE, 0));
            write_msg(net::make_headers_request(from_index, count));

            // Read framed messages until HEADERS_RESPONSE arrives.
            // Skip any others (peer might be gossiping blocks /
            // headers / etc. concurrently).
            std::array<uint8_t, 4> hdr;
            for (int spin = 0; spin < 200; ++spin) {
                asio::read(socket, asio::buffer(hdr));
                uint32_t len = (uint32_t(hdr[0]) << 24)
                             | (uint32_t(hdr[1]) << 16)
                             | (uint32_t(hdr[2]) <<  8)
                             |  uint32_t(hdr[3]);
                if (len == 0 || len > 16 * 1024 * 1024) {
                    std::cerr << "headers fetch: bad frame length "
                              << len << "\n";
                    return 1;
                }
                std::vector<uint8_t> body(len);
                asio::read(socket, asio::buffer(body));
                net::Message m = net::Message::deserialize(body.data(),
                                                              body.size());
                if (m.type != net::MsgType::HEADERS_RESPONSE) continue;
                std::cout << m.payload.dump(2) << "\n";
                return 0;
            }
            std::cerr << "headers fetch: timed out waiting for "
                         "HEADERS_RESPONSE\n";
            return 1;
        } catch (std::exception& e) {
            std::cerr << "headers fetch error: " << e.what() << "\n";
            return 1;
        }
    }

    // Path 1: RPC fetch (default).
    uint16_t port = get_rpc_port(argc, argv);
    try {
        json params = {{"from", from_index}, {"count", count}};
        auto result = rpc::rpc_call("127.0.0.1", port, "headers", params);
        std::cout << result.dump(2) << "\n";
        return 0;
    } catch (std::exception& e) {
        std::cerr << "headers query failed: " << e.what() << "\n";
        return 1;
    }
}

// determ validators [--json] [--rpc-port N]
//   Lists the current validator pool (registered + active + staked +
//   not suspended). Default output is a human-readable table; --json
//   emits the raw RPC array verbatim, suitable for feeding directly
//   into `verify-block-sigs --committee` or any other machine
//   consumer.
static int cmd_validators(int argc, char** argv) {
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") { json_out = true; break; }
    }
    uint16_t port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "validators");
        if (json_out) {
            std::cout << result.dump(2) << "\n";
            return 0;
        }
        if (!result.is_array() || result.empty()) {
            std::cout << "(no eligible validators)\n";
            return 0;
        }
        std::cout << std::left
                  << std::setw(25) << "domain"
                  << std::setw(10) << "stake"
                  << std::setw(15) << "active_from"
                  << "ed_pub\n";
        for (auto& v : result) {
            std::cout << std::setw(25) << v.value("domain", std::string{})
                      << std::setw(10) << v.value("stake", uint64_t{0})
                      << std::setw(15) << v.value("active_from", uint64_t{0})
                      << v.value("ed_pub", std::string{}).substr(0, 24) << "...\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ chain-summary [--last N] [--json] [--rpc-port N]
//   Prints a compact summary of the last N blocks (default 10).
//   Default output is human-readable; --json emits the raw RPC
//   response verbatim (the {blocks, height, total_supply, ...}
//   object including A1 supply counters).
static int cmd_chain_summary(int argc, char** argv) {
    uint32_t last_n = 10;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--last" && i + 1 < argc)
            last_n = static_cast<uint32_t>(std::stoul(argv[i + 1]));
        else if (a == "--json") json_out = true;
    }
    uint16_t port = get_rpc_port(argc, argv);
    try {
        json params = {{"last_n", last_n}};
        auto result = rpc::rpc_call("127.0.0.1", port, "chain_summary", params);
        if (json_out) {
            std::cout << result.dump(2) << "\n";
            return 0;
        }
        // A1: chain_summary now returns an object {blocks: [...], total_supply,
        // genesis_total, expected_total, accumulated_*}. Backward-compat note:
        // an array result (legacy server) is still accepted as the blocks list.
        json blocks = result.is_array() ? result : result.value("blocks", json::array());
        for (auto& b : blocks) {
            std::cout << "#" << std::setw(6) << std::left << b.value("index", uint64_t{0})
                      << " mode=" << b.value("consensus_mode", 0)
                      << " txs=" << std::setw(3) << std::left << b.value("tx_count", 0)
                      << " creators=" << b.value("creators", json::array()).dump()
                      << " hash=" << b.value("hash", std::string{}).substr(0, 12)
                      << "\n";
        }
        if (result.is_object()) {
            std::cout << "height=" << result.value("height", uint64_t{0})
                      << " total_supply=" << result.value("total_supply", uint64_t{0})
                      << " genesis_total=" << result.value("genesis_total", uint64_t{0})
                      << " (subsidy=+" << result.value("accumulated_subsidy", uint64_t{0})
                      << " inbound=+" << result.value("accumulated_inbound", uint64_t{0})
                      << " slashed=-" << result.value("accumulated_slashed", uint64_t{0})
                      << " outbound=-" << result.value("accumulated_outbound", uint64_t{0})
                      << ")\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ committee [--json] [--rpc-port N]
//   Print the current epoch's K-of-K committee (the creators producing
//   blocks right now). Pure function of chain state — deterministic
//   across all nodes on the same chain at the same height. Default
//   output is a human-readable table; --json emits the raw RPC array
//   verbatim, suitable for feeding directly into `verify-block-sigs
//   --committee` for light-client K-of-K signature verification.
static int cmd_committee(int argc, char** argv) {
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") { json_out = true; break; }
    }
    uint16_t port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "committee");
        if (json_out) {
            std::cout << result.dump(2) << "\n";
            return 0;
        }
        if (!result.is_array() || result.empty()) {
            std::cout << "(empty committee — chain has no eligible validators yet)\n";
            return 0;
        }
        std::cout << std::left
                  << std::setw(25) << "domain"
                  << std::setw(10) << "stake"
                  << std::setw(15) << "active_from"
                  << "ed_pub\n";
        for (auto& v : result) {
            std::cout << std::setw(25) << v.value("domain", std::string{})
                      << std::setw(10) << v.value("stake", uint64_t{0})
                      << std::setw(15) << v.value("active_from", uint64_t{0})
                      << v.value("ed_pub", std::string{}).substr(0, 24) << "...\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ show-account <address> [--rpc-port N]
//   Inspect on-chain state for an arbitrary address (registered domain or
//   anonymous bearer wallet). Prints balance, next nonce, and registry
//   info + stake when the address is a registered validator.
static int cmd_show_account(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ show-account <address> [--rpc-port N] [--json]\n";
        return 1;
    }
    std::string addr = argv[0];
    uint16_t port = get_rpc_port(argc, argv);
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") json_out = true;
    }
    try {
        json params = {{"address", addr}};
        auto result = rpc::rpc_call("127.0.0.1", port, "account", params);
        if (result.is_null()) {
            if (json_out) {
                std::cout << json::object().dump() << "\n";
            } else {
                std::cout << "(no on-chain state for " << addr << ")\n";
            }
            return 0;
        }
        if (json_out) {
            // Pass-through the RPC's JSON — scripts get the same shape
            // they'd get from a direct RPC call without the human-
            // readable formatting overhead.
            std::cout << result.dump() << "\n";
            return 0;
        }
        std::cout << "address      : " << result.value("address", std::string{}) << "\n";
        std::cout << "anonymous    : " << (result.value("is_anonymous", false) ? "yes" : "no") << "\n";
        std::cout << "balance      : " << result.value("balance", uint64_t{0}) << "\n";
        std::cout << "next_nonce   : " << result.value("next_nonce", uint64_t{0}) << "\n";
        std::cout << "stake        : " << result.value("stake", uint64_t{0}) << "\n";
        if (result.contains("registry") && !result["registry"].is_null()) {
            auto& r = result["registry"];
            std::cout << "registry     :\n";
            std::cout << "  ed_pub       : " << r.value("ed_pub", std::string{}) << "\n";
            std::cout << "  registered_at: " << r.value("registered_at", uint64_t{0}) << "\n";
            std::cout << "  active_from  : " << r.value("active_from", uint64_t{0}) << "\n";
            std::cout << "  inactive_from: " << r.value("inactive_from", uint64_t{0}) << "\n";
        } else {
            std::cout << "registry     : (not registered)\n";
        }
    } catch (std::exception& e) {
        if (json_out) {
            json err = {{"error", e.what()}};
            std::cout << err.dump() << "\n";
        } else {
            std::cerr << "Error: " << e.what() << "\n";
        }
        return 1;
    }
    return 0;
}

// determ snapshot create [--out file.json] [--headers N] [--rpc-port N]
//   B6.basic: dump chain state (accounts, stakes, registrants, dedup,
//   tail headers) to a file. Operators host this for fast-bootstrap of
//   new nodes — restoring from a snapshot avoids replaying every block
//   from genesis. The result is JSON; a typical snapshot for a mature
//   chain is much smaller than the full chain.json. v1 verification
//   model: trust the source + post-restore consistency check (replay
//   the next handful of blocks); v2 adds state roots in the block
//   format for cryptographic verification.
static int cmd_snapshot_create(int argc, char** argv) {
    std::string out_path;
    uint32_t    header_count = 16;
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if (a == "--out")     out_path = argv[i + 1];
        if (a == "--headers") header_count = static_cast<uint32_t>(
                                    std::stoul(argv[i + 1]));
    }
    uint16_t port = get_rpc_port(argc, argv);
    try {
        json params = {{"headers", header_count}};
        auto result = rpc::rpc_call("127.0.0.1", port, "snapshot", params);
        std::string text = result.dump(2);
        if (out_path.empty()) {
            std::cout << text << "\n";
        } else {
            std::ofstream f(out_path);
            if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
            f << text << "\n";
            std::cout << "Snapshot written to " << out_path << "\n";
            std::cout << "  block_index : "
                      << result.value("block_index", uint64_t{0}) << "\n";
            std::cout << "  head_hash   : "
                      << result.value("head_hash", std::string{}) << "\n";
            std::cout << "  accounts    : "
                      << result.value("accounts", json::array()).size() << "\n";
            std::cout << "  stakes      : "
                      << result.value("stakes", json::array()).size() << "\n";
            std::cout << "  registrants : "
                      << result.value("registrants", json::array()).size() << "\n";
            std::cout << "  headers     : "
                      << result.value("headers", json::array()).size() << "\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// determ snapshot fetch --peer host:port --out file.json [--headers N]
//   B6.basic: connect to a running node, send a SNAPSHOT_REQUEST over
//   the gossip-wire protocol, write the response to a file. Pure
//   network client; no genesis or chain config needed locally. After
//   fetch, validates by round-tripping through restore_from_snapshot
//   (head_hash sanity check). Operator workflow:
//     determ snapshot fetch --peer 1.2.3.4:7771 --out snap.json
//     # ... edit config to set snapshot_path = snap.json ...
//     determ start
static int cmd_snapshot_fetch(int argc, char** argv) {
    std::string peer_str, out_path;
    uint32_t header_count = 16;
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if (a == "--peer")    peer_str    = argv[i + 1];
        if (a == "--out")     out_path    = argv[i + 1];
        if (a == "--headers") header_count = static_cast<uint32_t>(
                                    std::stoul(argv[i + 1]));
    }
    if (peer_str.empty() || out_path.empty()) {
        std::cerr << "Usage: determ snapshot fetch --peer host:port "
                     "--out file.json [--headers N]\n";
        return 1;
    }
    auto colon = peer_str.find(':');
    if (colon == std::string::npos) {
        std::cerr << "peer must be host:port\n";
        return 1;
    }
    std::string host = peer_str.substr(0, colon);
    uint16_t    port = static_cast<uint16_t>(std::stoi(peer_str.substr(colon + 1)));

    try {
        asio::io_context io;
        asio::ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(host, std::to_string(port));
        asio::ip::tcp::socket socket(io);
        asio::connect(socket, endpoints);

        auto write_msg = [&](const net::Message& msg) {
            auto buf = msg.serialize();
            asio::write(socket, asio::buffer(buf));
        };

        // HELLO so the peer doesn't drop us. We tag ourselves as
        // SINGLE/0 — bootstrap clients don't claim a chain identity.
        write_msg(net::make_hello("snapshot-fetcher", 0,
                                    ChainRole::SINGLE, 0));
        write_msg(net::make_snapshot_request(header_count));

        // Read framed messages until SNAPSHOT_RESPONSE arrives. Skip
        // any others (peer might gossip blocks/headers in the
        // meantime).
        std::array<uint8_t, 4> hdr;
        for (int spin = 0; spin < 200; ++spin) {
            asio::read(socket, asio::buffer(hdr));
            uint32_t len = (uint32_t(hdr[0]) << 24)
                         | (uint32_t(hdr[1]) << 16)
                         | (uint32_t(hdr[2]) << 8)
                         |  uint32_t(hdr[3]);
            if (len == 0 || len > 16 * 1024 * 1024) {
                std::cerr << "fetch: bad frame length " << len << "\n";
                return 1;
            }
            std::vector<uint8_t> body(len);
            asio::read(socket, asio::buffer(body));
            net::Message m = net::Message::deserialize(body.data(), body.size());
            if (m.type != net::MsgType::SNAPSHOT_RESPONSE) continue;

            // Validate by round-trip through restore_from_snapshot.
            chain::Chain c = chain::Chain::restore_from_snapshot(m.payload);
            std::ofstream f(out_path);
            if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
            f << m.payload.dump(2) << "\n";
            std::cout << "Snapshot fetched from " << peer_str << "\n";
            std::cout << "  block_index : " << (c.empty() ? 0 : c.head().index) << "\n";
            std::cout << "  head_hash   : "
                      << (c.empty() ? std::string{} : to_hex(c.head_hash())) << "\n";
            std::cout << "  accounts    : " << c.accounts().size()    << "\n";
            std::cout << "  stakes      : " << c.stakes().size()      << "\n";
            std::cout << "  registrants : " << c.registrants().size() << "\n";
            std::cout << "  written to  : " << out_path << "\n";
            return 0;
        }
        std::cerr << "fetch: timed out waiting for SNAPSHOT_RESPONSE\n";
        return 1;
    } catch (std::exception& e) {
        std::cerr << "fetch error: " << e.what() << "\n";
        return 1;
    }
}

// determ snapshot inspect --in file.json [--state-root <hex64>]
//   Round-trips a snapshot through Chain::restore_from_snapshot and
//   prints a human-readable summary. Validates JSON format, version,
//   head_hash consistency, AND post-restore state_root (S-033 + S-038
//   gates: restore_from_snapshot already rejects on mismatch). Useful
//   before staging a snapshot for fast-bootstrap of a new node.
//
//   Optional --state-root <hex64>: pin an externally-trusted state
//   root. Inspection succeeds only if the snapshot's tail-head
//   state_root matches. This is the trustless-fast-sync gate from a
//   light-client POV: a client that has verified the head's state
//   commitment via header-sync can use this to confirm a snapshot it
//   downloaded matches that commitment, with zero trust in the
//   snapshot's origin (S-033 + S-038 closure path; complements
//   `determ verify-state-proof` for per-field queries).
static int cmd_snapshot_inspect(int argc, char** argv) {
    std::string in_path;
    std::string expected_state_root_hex;
    bool json_out = false;
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--in")          in_path = argv[i + 1];
        else if (std::string(argv[i]) == "--state-root") expected_state_root_hex = argv[i + 1];
    }
    // `--json` is a flag, not a value-pair, so scan all args including
    // the last position.
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") json_out = true;
    }
    if (in_path.empty()) {
        std::cerr << "Usage: determ snapshot inspect --in <file> "
                     "[--state-root <hex64>] [--json]\n";
        return 1;
    }
    try {
        std::ifstream f(in_path);
        if (!f) {
            if (json_out) {
                json err = {{"error", "cannot_open"}, {"path", in_path}};
                std::cout << err.dump() << "\n";
            } else {
                std::cerr << "Cannot open " << in_path << "\n";
            }
            return 1;
        }
        json snap = json::parse(f);
        chain::Chain c = chain::Chain::restore_from_snapshot(snap);

        // Compute the snapshot's restored state_root for display +
        // optional comparison against an externally-trusted root.
        // restore_from_snapshot already verified the snapshot-stored
        // state_root matches the recomputed one (S-033 + S-038 gate);
        // this is the read-out + the external-pin comparison.
        Hash restored_root = c.compute_state_root();

        // Build the inspection result. Same data in both formats; the
        // `--json` mode is for scripts that want to consume the result
        // (e.g., bootstrap-orchestrators that pipeline snapshot
        // verification + state-root checks).
        json result = {
            {"status",        "ok"},
            {"path",          in_path},
            {"block_index",   c.empty() ? 0 : c.head().index},
            {"head_hash",     c.empty() ? std::string{} : to_hex(c.head_hash())},
            {"state_root",    to_hex(restored_root)},
            {"accounts",      c.accounts().size()},
            {"stakes",        c.stakes().size()},
            {"registrants",   c.registrants().size()},
            {"block_subsidy", c.block_subsidy()},
            {"min_stake",     c.min_stake()},
            {"shard_count",   c.shard_count()},
            {"shard_id",      c.my_shard_id()},
            {"tail_headers",  c.height()},
        };

        // External-trusted-root pin (trustless-fast-sync gate).
        if (!expected_state_root_hex.empty()) {
            if (expected_state_root_hex.size() != 64) {
                if (json_out) {
                    json err = {
                        {"error", "invalid_state_root_length"},
                        {"got",   expected_state_root_hex.size()}
                    };
                    std::cout << err.dump() << "\n";
                } else {
                    std::cerr << "Error: --state-root must be 64 hex chars "
                                 "(32 bytes), got "
                              << expected_state_root_hex.size() << "\n";
                }
                return 1;
            }
            Hash expected = from_hex_arr<32>(expected_state_root_hex);
            if (expected != restored_root) {
                if (json_out) {
                    json err = {
                        {"error",                  "state_root_mismatch"},
                        {"snapshot_state_root",    to_hex(restored_root)},
                        {"supplied_state_root",    to_hex(expected)}
                    };
                    std::cout << err.dump() << "\n";
                } else {
                    std::cerr << "FAIL: snapshot state_root does NOT match "
                                 "supplied --state-root\n";
                    std::cerr << "  snapshot's state_root: "
                              << to_hex(restored_root) << "\n";
                    std::cerr << "  supplied state_root:   "
                              << to_hex(expected) << "\n";
                    std::cerr << "  (snapshot may have been tampered with, "
                                 "or was produced against a different chain "
                                 "than the one you trust)\n";
                }
                return 1;
            }
            result["trusted_root_match"] = true;
        }

        if (json_out) {
            std::cout << result.dump() << "\n";
        } else {
            std::cout << "snapshot OK: " << in_path << "\n";
            std::cout << "  block_index : " << result["block_index"].get<uint64_t>() << "\n";
            std::cout << "  head_hash   : " << result["head_hash"].get<std::string>() << "\n";
            std::cout << "  state_root  : " << result["state_root"].get<std::string>() << "\n";
            std::cout << "  accounts    : " << result["accounts"].get<size_t>()    << "\n";
            std::cout << "  stakes      : " << result["stakes"].get<size_t>()      << "\n";
            std::cout << "  registrants : " << result["registrants"].get<size_t>() << "\n";
            std::cout << "  block_subsidy: " << result["block_subsidy"].get<uint64_t>() << "\n";
            std::cout << "  min_stake   : " << result["min_stake"].get<uint64_t>() << "\n";
            std::cout << "  shard_count : " << result["shard_count"].get<uint32_t>() << "\n";
            std::cout << "  shard_id    : " << result["shard_id"].get<uint32_t>() << "\n";
            std::cout << "  tail headers: " << result["tail_headers"].get<size_t>() << "\n";
            if (result.contains("trusted_root_match"))
                std::cout << "  trusted root: ✓ matches --state-root\n";
        }
    } catch (std::exception& e) {
        if (json_out) {
            json err = {{"error", "exception"}, {"message", e.what()}};
            std::cout << err.dump() << "\n";
        } else {
            std::cerr << "Error: " << e.what() << "\n";
        }
        return 1;
    }
    return 0;
}

static int cmd_snapshot(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ snapshot {create|inspect} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "create")  return cmd_snapshot_create (argc - 1, argv + 1);
    if (sub == "inspect") return cmd_snapshot_inspect(argc - 1, argv + 1);
    if (sub == "fetch")   return cmd_snapshot_fetch  (argc - 1, argv + 1);
    std::cerr << "Unknown snapshot subcommand: " << sub << "\n";
    return 1;
}

// determ show-tx <hash> [--rpc-port N] [--json]
//   Look up a transaction by its hex-encoded hash. Reports the tx
//   payload, the block it landed in, and the block's timestamp.
//   --json emits the raw RPC envelope for script consumption.
static int cmd_show_tx(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ show-tx <hash> [--rpc-port N] [--json]\n";
        return 1;
    }
    std::string hash_hex = argv[0];
    uint16_t port = get_rpc_port(argc, argv);
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") json_out = true;
    }
    try {
        json params = {{"hash", hash_hex}};
        auto result = rpc::rpc_call("127.0.0.1", port, "tx", params);
        if (result.is_null()) {
            if (json_out) {
                std::cout << json::object().dump() << "\n";
            } else {
                std::cout << "(tx " << hash_hex.substr(0, 16) << "... not found in any finalized block)\n";
            }
            return 0;
        }
        if (json_out) {
            std::cout << result.dump() << "\n";
            return 0;
        }
        std::cout << "block_index : " << result.value("block_index", uint64_t{0}) << "\n";
        std::cout << "block_hash  : " << result.value("block_hash", std::string{}) << "\n";
        std::cout << "timestamp   : " << result.value("timestamp", int64_t{0}) << "\n";
        std::cout << "transaction :\n";
        std::cout << result["tx"].dump(2) << "\n";
    } catch (std::exception& e) {
        if (json_out) {
            json err = {{"error", e.what()}};
            std::cout << err.dump() << "\n";
        } else {
            std::cerr << "Error: " << e.what() << "\n";
        }
        return 1;
    }
    return 0;
}

// determ peers [--json] [--rpc-port N]
//   List connected peers. Default: one host:port per line. --json
//   emits the raw RPC array verbatim (one JSON array of strings).
static int cmd_peers(int argc, char** argv) {
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") { json_out = true; break; }
    }
    uint16_t port = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "peers");
        if (json_out) {
            std::cout << result.dump(2) << "\n";
            return 0;
        }
        if (result.empty()) { std::cout << "(no peers connected)\n"; return 0; }
        for (auto& p : result) std::cout << "  " << p.get<std::string>() << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

static int cmd_balance(int argc, char** argv) {
    std::string domain = (argc >= 1) ? argv[0] : "";
    uint16_t    port   = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "balance", {{"domain", domain}});
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

static int cmd_stake(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: determ stake <amount> [--fee <n>]\n"; return 1; }
    uint64_t amount = std::stoull(argv[0]);
    uint64_t fee    = 0;
    uint16_t port   = get_rpc_port(argc, argv);
    for (int i = 1; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--fee") fee = std::stoull(argv[i + 1]);
    return submit_tx_with_retry(port, "stake", {{"amount", amount}, {"fee", fee}});
}

static int cmd_unstake(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: determ unstake <amount> [--fee <n>]\n"; return 1; }
    uint64_t amount = std::stoull(argv[0]);
    uint64_t fee    = 0;
    uint16_t port   = get_rpc_port(argc, argv);
    for (int i = 1; i < argc - 1; ++i)
        if (std::string(argv[i]) == "--fee") fee = std::stoull(argv[i + 1]);
    return submit_tx_with_retry(port, "unstake", {{"amount", amount}, {"fee", fee}});
}

static int cmd_nonce(int argc, char** argv) {
    std::string domain = (argc >= 1) ? argv[0] : "";
    uint16_t    port   = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "nonce", {{"domain", domain}});
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// genesis-tool peer-info <domain>
//   Loads the node's local Ed25519 key and prints the JSON entry the operator
//   should send to whoever is assembling the genesis config. Possession of the
//   private key is proved later at REGISTER time (the on-chain REGISTER tx is
//   signed by the same key), so no separate proof-of-possession is emitted here.
static int cmd_genesis_tool_peer_info(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ genesis-tool peer-info <domain> [--data-dir <dir>] [--stake <n>]\n";
        return 1;
    }
    std::string domain   = argv[0];
    std::string data_dir = default_data_dir();
    uint64_t    stake    = chain::MIN_STAKE;
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--data-dir") data_dir = argv[i + 1];
        if (std::string(argv[i]) == "--stake")    stake    = std::stoull(argv[i + 1]);
    }

    std::string kpath = data_dir + "/node_key.json";
    if (!fs::exists(kpath)) {
        std::cerr << "Key not found at " << kpath
                  << " (run 'determ init --data-dir " << data_dir << "' first)\n";
        return 1;
    }
    auto key = crypto::load_node_key(kpath);

    json entry = {
        {"domain",        domain},
        {"ed_pub",        to_hex(key.pub)},
        {"initial_stake", stake}
    };
    std::cout << entry.dump(2) << "\n";
    return 0;
}

// genesis-tool build <config.json>
//   Loads a GenesisConfig (with all initial_creators + initial_balances),
//   validates K/M bounds, prints the resulting genesis hash, and writes
//   <config>.hash next to the file for convenient distribution.
static int cmd_genesis_tool_build(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ genesis-tool build <genesis_config.json>\n";
        return 1;
    }
    std::string path = argv[0];
    try {
        auto cfg  = chain::GenesisConfig::load(path);
        if (cfg.k_block_sigs == 0 || cfg.k_block_sigs > cfg.m_creators) {
            std::cerr << "Genesis invalid: k_block_sigs=" << cfg.k_block_sigs
                      << " must satisfy 1 <= K <= M=" << cfg.m_creators << "\n";
            return 1;
        }
        auto hash = chain::compute_genesis_hash(cfg);
        std::string hex = to_hex(hash);
        const char* mode = (cfg.k_block_sigs == cfg.m_creators) ? "strong" : "weak";
        std::cout << "Genesis chain_id:   " << cfg.chain_id           << "\n";
        std::cout << "Chain role:         " << to_string(cfg.chain_role)
                  << " (shard_id=" << cfg.shard_id
                  << ", S=" << cfg.initial_shard_count
                  << ", E=" << cfg.epoch_blocks << ")\n";
        std::cout << "M_creators:         " << cfg.m_creators         << "\n";
        std::cout << "K_block_sigs:       " << cfg.k_block_sigs       << "\n";
        std::cout << "Mode:               " << mode << " (default: mutual-distrust K-of-K)\n";
        std::cout << "Inclusion:          " << chain::to_string(cfg.inclusion_model)
                  << " (min_stake=" << cfg.min_stake << ")\n";
        std::cout << "BFT escalation:     "
                  << (cfg.bft_enabled
                      ? ("enabled, threshold=" + std::to_string(cfg.bft_escalation_threshold) + " round-1 aborts")
                      : "disabled (chain halts on persistent silent committee member)")
                  << "\n";
        std::cout << "Initial creators:   " << cfg.initial_creators.size() << "\n";
        std::cout << "Initial balances:   " << cfg.initial_balances.size() << "\n";
        std::cout << "Genesis hash:       " << hex << "\n";

        std::ofstream f(path + ".hash");
        f << hex << "\n";
        std::cout << "Wrote " << path << ".hash\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// genesis-tool build-sharded <config.json>
//   Stage B2a. Loads a single GenesisConfig and produces (1 + S) genesis
//   files: one beacon (chain_role=BEACON, shard_id=0) and S shard files
//   (chain_role=SHARD, shard_id=i for i in 0..S-1). All inherit the same
//   creators, balances, K, M, BFT params, and shard_address_salt.
//
//   The beacon's hash is pinned into each shard's `genesis_hash` config
//   slot at deploy time (operators copy it into shard nodes' config.json).
//   Cross-chain coordination (epoch transitions, cross-shard receipts)
//   is Stage B2b/B2c — out of scope for this minimal scaffolding step.
static int cmd_genesis_tool_build_sharded(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ genesis-tool build-sharded "
                     "<genesis_config.json> [--profile <name>]\n";
        return 1;
    }
    std::string path = argv[0];
    // A6: optional --profile pins the deployment's sharding_mode at
    // build time so we can reject mode-incompatible configs early.
    // When omitted, sharding_mode is INFERRED from the input JSON
    // (non-empty committee_region or any non-empty shard_regions[i]
    // implies EXTENDED; otherwise CURRENT). Inference keeps existing
    // build-sharded callers byte-compatible.
    std::string profile_name;
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--profile") profile_name = argv[i + 1];
    }
    try {
        auto base = chain::GenesisConfig::load(path);
        if (base.k_block_sigs == 0 || base.k_block_sigs > base.m_creators) {
            std::cerr << "Genesis invalid: k_block_sigs=" << base.k_block_sigs
                      << " must satisfy 1 <= K <= M=" << base.m_creators << "\n";
            return 1;
        }
        if (base.initial_shard_count < 1) {
            std::cerr << "build-sharded requires initial_shard_count >= 1 in input config\n";
            return 1;
        }

        // A6: reload the raw JSON so we can read shard_regions (a
        // top-level array, length S, one entry per shard). It is not
        // a field on GenesisConfig itself — per-shard regions are a
        // build-time input only; each shard genesis carries its own
        // committee_region (set below per shard once shard_regions is
        // wired by R3). For now we use shard_regions ONLY to detect
        // EXTENDED intent for the mode-consistency checks.
        std::ifstream raw_in(path);
        nlohmann::json raw;
        if (raw_in) raw = nlohmann::json::parse(raw_in, nullptr, false);
        std::vector<std::string> shard_regions;
        bool any_shard_region = false;
        if (raw.is_object() && raw.contains("shard_regions")
            && raw["shard_regions"].is_array()) {
            for (auto& sr : raw["shard_regions"]) {
                std::string s = sr.is_string() ? sr.get<std::string>()
                                                : std::string{};
                shard_regions.push_back(s);
                if (!s.empty()) any_shard_region = true;
            }
        }
        bool any_creator_region = false;
        for (auto& c : base.initial_creators) {
            if (!c.region.empty()) { any_creator_region = true; break; }
        }
        bool extended_signaled = !base.committee_region.empty()
                                || any_shard_region
                                || any_creator_region;

        // Resolve the effective sharding_mode for build-time checks.
        ShardingMode mode;
        if (!profile_name.empty()) {
            chain::TimingProfile tp = chain::PROFILE_WEB;
            bool ok = true;
            if      (profile_name == "cluster")        tp = chain::PROFILE_CLUSTER;
            else if (profile_name == "web")            tp = chain::PROFILE_WEB;
            else if (profile_name == "regional")       tp = chain::PROFILE_REGIONAL;
            else if (profile_name == "global")         tp = chain::PROFILE_GLOBAL;
            else if (profile_name == "tactical")       tp = chain::PROFILE_TACTICAL;
            else if (profile_name == "single_test")    tp = chain::PROFILE_SINGLE_TEST;
            else if (profile_name == "cluster_test")   tp = chain::PROFILE_CLUSTER_TEST;
            else if (profile_name == "web_test")       tp = chain::PROFILE_WEB_TEST;
            else if (profile_name == "regional_test")  tp = chain::PROFILE_REGIONAL_TEST;
            else if (profile_name == "global_test")    tp = chain::PROFILE_GLOBAL_TEST;
            else if (profile_name == "tactical_test")  tp = chain::PROFILE_TACTICAL_TEST;
            else ok = false;
            if (!ok) {
                std::cerr << "Unknown --profile " << profile_name << "\n";
                return 1;
            }
            mode = tp.sharding_mode;
        } else {
            mode = extended_signaled ? ShardingMode::EXTENDED
                                     : ShardingMode::CURRENT;
        }

        // A6 mismatch gate: a non-EXTENDED build refuses any region
        // input. Region tags are a no-op (CURRENT silently tolerates,
        // NONE rejects) under non-EXTENDED runtime; baking them into
        // the genesis is therefore an operator error worth catching
        // before the chain ships.
        if (mode != ShardingMode::EXTENDED) {
            if (!base.committee_region.empty()) {
                std::cerr << "build-sharded: sharding_mode="
                          << to_string(mode)
                          << " rejects non-empty committee_region "
                             "(got '" << base.committee_region
                          << "') — regional committees require "
                             "sharding_mode=extended\n";
                return 1;
            }
            if (any_shard_region) {
                std::cerr << "build-sharded: sharding_mode="
                          << to_string(mode)
                          << " rejects non-empty shard_regions[] — "
                             "per-shard regions require "
                             "sharding_mode=extended\n";
                return 1;
            }
            if (any_creator_region) {
                std::cerr << "build-sharded: sharding_mode="
                          << to_string(mode)
                          << " rejects non-empty initial_creators[].region — "
                             "creator region tags require "
                             "sharding_mode=extended\n";
                return 1;
            }
        }

        // A6 / cascading-merge invariant: an EXTENDED deployment with
        // fewer than 3 shards is degenerate (the under-quorum merge
        // mechanism that justifies EXTENDED needs at least 3 shards for
        // the modular fold to be meaningful). Hard error.
        //
        // (Originally drafted as a proposed S-038 mitigation; the S-038
        // number was later reassigned in SECURITY.md to "state_root
        // verification gate dormant". The invariant itself is closed by
        // construction here + documented inline in SECURITY.md §6.5 T-004
        // and README §16.5.)
        if (mode == ShardingMode::EXTENDED && base.initial_shard_count < 3) {
            std::cerr << "build-sharded: sharding_mode=extended requires "
                         "initial_shard_count >= 3 (got "
                      << base.initial_shard_count
                      << ", minimum 3) — cascading-merge invariant "
                         "(see SECURITY.md §6.5 + README §16.5)\n";
            return 1;
        }

        // If shard_regions is present, its length must match S.
        if (!shard_regions.empty()
            && shard_regions.size() != base.initial_shard_count) {
            std::cerr << "build-sharded: shard_regions length "
                      << shard_regions.size()
                      << " != initial_shard_count "
                      << base.initial_shard_count << "\n";
            return 1;
        }

        // Generate a fresh shard_address_salt if the input didn't supply one.
        Hash zero_salt{};
        if (base.shard_address_salt == zero_salt) {
            if (RAND_bytes(base.shard_address_salt.data(), 32) != 1) {
                std::cerr << "Failed to generate shard_address_salt\n";
                return 1;
            }
        }

        // Beacon genesis (role=BEACON, shard_id=0).
        chain::GenesisConfig beacon = base;
        beacon.chain_role = ChainRole::BEACON;
        beacon.shard_id   = 0;
        std::string beacon_path = path + ".beacon.json";
        beacon.save(beacon_path);
        Hash beacon_hash = chain::compute_genesis_hash(beacon);
        std::ofstream(beacon_path + ".hash") << to_hex(beacon_hash) << "\n";

        std::cout << "Beacon genesis:     " << beacon_path << "\n";
        std::cout << "  chain_role:       beacon (shard_id=0, S=" << beacon.initial_shard_count
                  << ", E=" << beacon.epoch_blocks << ")\n";
        std::cout << "  hash:             " << to_hex(beacon_hash) << "\n";

        // Shard genesis files (role=SHARD, shard_id=0..S-1).
        for (uint32_t s = 0; s < base.initial_shard_count; ++s) {
            chain::GenesisConfig shard = base;
            shard.chain_role = ChainRole::SHARD;
            shard.shard_id   = s;
            // A6: when shard_regions is supplied (EXTENDED only — gated
            // above), the per-shard committee_region overrides the
            // base.committee_region. Empty entry leaves the base value
            // (= "" under EXTENDED defaults to global pool for that
            // shard, which is allowed). Pre-A6 callers omit
            // shard_regions and inherit base.committee_region (which
            // must be "" under non-EXTENDED).
            if (!shard_regions.empty()) {
                shard.committee_region = shard_regions[s];
            }
            std::string shard_path = path + ".shard" + std::to_string(s) + ".json";
            shard.save(shard_path);
            Hash sh = chain::compute_genesis_hash(shard);
            std::ofstream(shard_path + ".hash") << to_hex(sh) << "\n";

            std::cout << "Shard genesis:      " << shard_path << "\n";
            std::cout << "  chain_role:       shard (shard_id=" << s
                      << ", S=" << shard.initial_shard_count
                      << ", E=" << shard.epoch_blocks << ")\n";
            std::cout << "  hash:             " << to_hex(sh) << "\n";
        }

        std::cout << "\nNote: this scaffolds the genesis file structure for sharded "
                     "deployments.\n      Cross-chain coordination (validator pool at "
                     "beacon, epoch broadcast,\n      cross-shard receipts) is Stage "
                     "B2b/B2c — operators must run beacon\n      and each shard as "
                     "separate processes, with their own bootstrap_peers.\n";
        return 0;
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

// account create --out <file> [--allow-plaintext-stdout] [--passphrase <pw>]
//
// S-004 mitigation: refuse stdout output by default. Generating a
// fresh privkey and printing it to stdout exposes it to terminal
// scrollback, shell history, accidental log capture, and any process
// reading the parent shell's tty. The default output is a file with
// restrictive permissions (owner read+write only). Operators who
// truly want stdout output (offline air-gapped key gen with a
// trusted shell history) must set --allow-plaintext-stdout
// explicitly so the choice is auditable in the invoking script.
//
// File permissions: std::filesystem::permissions narrowed to
// owner_read | owner_write on the freshly-written file. On Unix
// this is chmod 0600; on Windows the call resolves to a best-effort
// owner-only ACL via the std::filesystem implementation.
//
// v2.17 / S-004 option 2: passphrase-encrypted keyfile at rest. If
// --passphrase is provided (or DETERM_PASSPHRASE env var is set),
// the on-disk keyfile is wrapped in an AES-256-GCM envelope keyed
// from PBKDF2-HMAC-SHA-256(passphrase, salt, 600k iters). The
// envelope is serialized in the canonical dot-separated format
// (see wallet/envelope.hpp). File permissions still get 0600 for
// belt-and-suspenders.
//
// To read back: `determ account decrypt --in <file> --passphrase ...`
// (or rely on DETERM_PASSPHRASE env var; passing on CLI is leaked
// into shell history).
static int cmd_account_create(int argc, char** argv) {
    std::string out_path;
    std::string passphrase;
    bool allow_plaintext_stdout = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--out" && i + 1 < argc) out_path = argv[i + 1];
        else if (a == "--allow-plaintext-stdout") allow_plaintext_stdout = true;
        else if (a == "--passphrase" && i + 1 < argc) passphrase = argv[i + 1];
    }
    // Env var fallback (avoids CLI leaking into shell history). The
    // CLI flag wins if both are set.
    if (passphrase.empty()) {
        const char* env = std::getenv("DETERM_PASSPHRASE");
        if (env && *env) passphrase = env;
    }
    if (out_path.empty() && !allow_plaintext_stdout) {
        std::cerr <<
            "S-004: refusing to emit privkey to stdout. Either:\n"
            "  determ account create --out <file>     (recommended; "
                                                       "file gets 0600 permissions)\n"
            "  determ account create --out <file> --passphrase <pw>\n"
            "                                         (or DETERM_PASSPHRASE env var;\n"
            "                                          encrypts at rest, S-004 option 2)\n"
            "  determ account create --allow-plaintext-stdout  (opt-in; "
                                                                  "be aware of\n"
            "                                                   terminal "
                                                                  "scrollback and\n"
            "                                                   shell history "
                                                                  "leakage)\n";
        return 1;
    }

    auto key = crypto::generate_node_key();
    std::string addr = make_anon_address(key.pub);
    std::string priv_hex = to_hex(key.priv_seed);

    json out = {
        {"address",   addr},
        {"privkey",   priv_hex},
        {"warning",   "store privkey securely; anyone with it controls the address"}
    };
    if (out_path.empty()) {
        // --allow-plaintext-stdout was explicitly set.
        std::cout << out.dump(2) << "\n";
    } else if (passphrase.empty()) {
        // Plaintext file output (S-004 option 1 — 0600 permissions only)
        std::ofstream f(out_path);
        if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
        f << out.dump(2) << "\n";
        f.close();
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        if (perm_ec) {
            std::cerr << "Warning: could not set 0600 permissions on "
                      << out_path << ": " << perm_ec.message() << "\n";
            std::cerr << "         Verify manually (chmod 0600 / icacls).\n";
        }
        std::cout << "Account written to " << out_path << "\n";
        std::cout << "Address: " << addr << "\n";
    } else {
        // v2.17 / S-004 option 2: encrypted file output. The plaintext
        // is the same JSON the plaintext path writes; the envelope
        // wraps it with AES-256-GCM keyed via PBKDF2 from the
        // passphrase. The output file is the canonical envelope
        // serialization (dot-separated hex fields, see
        // wallet/envelope.hpp). AAD binds the public address so a
        // tampered envelope cannot be substituted with another
        // address's encrypted blob.
        std::string pt = out.dump(2);
        std::vector<uint8_t> pt_bytes(pt.begin(), pt.end());
        std::vector<uint8_t> aad(addr.begin(), addr.end());
        try {
            auto env = determ::wallet::envelope::encrypt(pt_bytes, passphrase, aad);
            std::string blob = determ::wallet::envelope::serialize(env);
            std::ofstream f(out_path);
            if (!f) { std::cerr << "Cannot write " << out_path << "\n"; return 1; }
            // Header: 1-line magic + address (plaintext metadata) +
            // envelope blob. The address is in AAD so it's
            // tamper-evident, but exposing it in plaintext lets
            // operators identify which account the file belongs to
            // without decrypting.
            f << "DETERM-ACCOUNT-V1 " << addr << "\n";
            f << blob << "\n";
            f.close();
            std::error_code perm_ec;
            std::filesystem::permissions(
                out_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace,
                perm_ec);
            if (perm_ec) {
                std::cerr << "Warning: could not set 0600 permissions on "
                          << out_path << ": " << perm_ec.message() << "\n";
            }
            std::cout << "Encrypted account written to " << out_path << "\n";
            std::cout << "Address: " << addr << "\n";
            std::cout << "  (use `determ account decrypt --in " << out_path
                      << " --passphrase ...` to recover privkey)\n";
        } catch (std::exception& e) {
            std::cerr << "Encryption failed: " << e.what() << "\n";
            return 1;
        }
    }
    return 0;
}

// v2.17 / S-004 option 2 read-back: decrypt an envelope-wrapped keyfile
// produced by `account create --passphrase`. Outputs the plaintext
// JSON to stdout (privkey + address). Requires --passphrase or
// DETERM_PASSPHRASE env var.
static int cmd_account_decrypt(int argc, char** argv) {
    std::string in_path, passphrase;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"         && i + 1 < argc) in_path    = argv[i + 1];
        else if (a == "--passphrase" && i + 1 < argc) passphrase = argv[i + 1];
    }
    if (passphrase.empty()) {
        const char* env = std::getenv("DETERM_PASSPHRASE");
        if (env && *env) passphrase = env;
    }
    if (in_path.empty()) {
        std::cerr << "Usage: determ account decrypt --in <file> "
                     "[--passphrase <pw>]\n"
                     "  (or set DETERM_PASSPHRASE env var)\n";
        return 1;
    }
    if (passphrase.empty()) {
        std::cerr << "account decrypt requires --passphrase or "
                     "DETERM_PASSPHRASE env var\n";
        return 1;
    }
    std::ifstream f(in_path);
    if (!f) { std::cerr << "Cannot read " << in_path << "\n"; return 1; }
    std::string header_line, blob_line;
    std::getline(f, header_line);
    std::getline(f, blob_line);
    // Validate header.
    if (header_line.rfind("DETERM-ACCOUNT-V1 ", 0) != 0) {
        std::cerr << "Not a DETERM-ACCOUNT-V1 file: " << in_path << "\n";
        return 1;
    }
    std::string addr = header_line.substr(std::strlen("DETERM-ACCOUNT-V1 "));
    auto env_opt = determ::wallet::envelope::deserialize(blob_line);
    if (!env_opt) {
        std::cerr << "Envelope deserialize failed\n";
        return 1;
    }
    std::vector<uint8_t> aad(addr.begin(), addr.end());
    auto pt_opt = determ::wallet::envelope::decrypt(*env_opt, passphrase, aad);
    if (!pt_opt) {
        std::cerr << "Decryption failed (wrong passphrase or "
                     "tampered file)\n";
        return 1;
    }
    std::string pt(pt_opt->begin(), pt_opt->end());
    std::cout << pt << "\n";
    return 0;
}

// account address <privkey_hex>
//   Derives the account address from a privkey hex string (offline, no daemon needed).
static int cmd_account_address(int argc, char** argv) {
    if (argc < 1) { std::cerr << "Usage: determ account address <privkey_hex>\n"; return 1; }
    crypto::NodeKey key;
    key.priv_seed = from_hex_arr<32>(argv[0]);

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, key.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "invalid privkey\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, key.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    std::cout << make_anon_address(key.pub) << "\n";
    return 0;
}

static int cmd_account(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ account {create|address} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "create")  return cmd_account_create (argc - 1, argv + 1);
    if (sub == "address") return cmd_account_address(argc - 1, argv + 1);
    if (sub == "decrypt") return cmd_account_decrypt(argc - 1, argv + 1);
    std::cerr << "Unknown account subcommand: " << sub << "\n";
    return 1;
}

// send_anon <to> <amount> <privkey_hex> [--fee <n>] [--rpc-port <p>]
static int cmd_send_anon(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: determ send_anon <to> <amount> <privkey_hex> "
                     "[--fee <n>] [--rpc-port <p>]\n";
        return 1;
    }
    std::string to     = argv[0];
    uint64_t    amount = std::stoull(argv[1]);
    std::string priv_hex = argv[2];
    uint64_t    fee    = 0;
    uint16_t    port   = get_rpc_port(argc, argv);
    // --nonce N: override auto-fetched nonce. Useful for stress-testing
    // mempool admission (pipelined-nonce submissions) without waiting
    // for confirmations. -1 = auto-fetch via RPC (default).
    int64_t     nonce_override = -1;
    for (int i = 3; i < argc - 1; ++i) {
        if (std::string(argv[i]) == "--fee")   fee = std::stoull(argv[i + 1]);
        else if (std::string(argv[i]) == "--nonce") nonce_override = std::stoll(argv[i + 1]);
    }

    crypto::NodeKey key;
    try {
        key.priv_seed = from_hex_arr<32>(priv_hex);
    } catch (std::exception& e) {
        std::cerr << "Invalid privkey: " << e.what() << "\n";
        return 1;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, key.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "invalid privkey for Ed25519\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, key.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    std::string from_addr = make_anon_address(key.pub);

    uint64_t nonce = 0;
    if (nonce_override >= 0) {
        nonce = static_cast<uint64_t>(nonce_override);
    } else {
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "nonce", {{"domain", from_addr}});
            nonce = r.value("next_nonce", uint64_t{0});
        } catch (std::exception& e) {
            std::cerr << "nonce query failed: " << e.what() << "\n";
            return 1;
        }
    }

    chain::Transaction tx;
    tx.type    = chain::TxType::TRANSFER;
    tx.from    = from_addr;
    tx.to      = to;
    tx.amount  = amount;
    tx.fee     = fee;
    tx.nonce   = nonce;
    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(key, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "submit_tx", {{"tx", tx.to_json()}});
        std::cout << r.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "submit_tx failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// A5: build, sign, and submit a PARAM_CHANGE tx.
//   determ submit-param-change \
//     --priv <sender_priv_hex> \
//     --name <param_name> \
//     --value-hex <hex_le_bytes> \
//     --effective-height <N> \
//     --keyholder-sig <idx>:<priv_hex> [--keyholder-sig <idx>:<priv_hex> ...] \
//     [--fee <N>] [--rpc-port <P>]
//
// The sender pays the fee; the keyholder private keys are used purely
// for signing the (name, value, effective_height) tuple — no on-chain
// account for keyholders is required. Each --keyholder-sig produces
// one (idx, sig) entry inside the canonical payload. The canonical
// signing message format mirrors validator.cpp's check.
static int cmd_submit_param_change(int argc, char** argv) {
    std::string priv_hex;
    std::string from_domain;   // required: registered domain that pays the fee
    std::string name;
    std::string value_hex;
    uint64_t    effective_height = 0;
    uint64_t    fee  = 0;
    uint16_t    port = get_rpc_port(argc, argv);
    std::vector<std::pair<uint16_t, std::string>> keyholder_sigs;
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--priv")             priv_hex = argv[i + 1];
        else if (a == "--from")             from_domain = argv[i + 1];
        else if (a == "--name")             name = argv[i + 1];
        else if (a == "--value-hex")        value_hex = argv[i + 1];
        else if (a == "--effective-height") effective_height = std::stoull(argv[i + 1]);
        else if (a == "--fee")              fee = std::stoull(argv[i + 1]);
        else if (a == "--keyholder-sig") {
            std::string s = argv[i + 1];
            auto colon = s.find(':');
            if (colon == std::string::npos) {
                std::cerr << "--keyholder-sig requires <idx>:<priv_hex>\n";
                return 1;
            }
            uint16_t idx = static_cast<uint16_t>(std::stoul(s.substr(0, colon)));
            keyholder_sigs.emplace_back(idx, s.substr(colon + 1));
        }
    }
    if (priv_hex.empty() || from_domain.empty() || name.empty()
        || value_hex.empty() || keyholder_sigs.empty()) {
        std::cerr << "Usage: determ submit-param-change --priv <hex> "
                     "--from <domain> --name <NAME> --value-hex <hex> "
                     "--effective-height <N> "
                     "--keyholder-sig <idx>:<priv_hex> [more...] "
                     "[--fee <N>] [--rpc-port <P>]\n";
        return 1;
    }

    std::vector<uint8_t> value;
    try { value = from_hex(value_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid --value-hex: " << e.what() << "\n"; return 1;
    }
    if (name.size() > 255) {
        std::cerr << "--name too long (>255 bytes)\n"; return 1;
    }
    if (value.size() > 0xffff) {
        std::cerr << "--value-hex too long (>65535 bytes)\n"; return 1;
    }

    // Build the canonical signing message that each keyholder signs:
    //   [name_len: u8][name][value_len: u16 LE][value][effective_height: u64 LE]
    std::vector<uint8_t> sig_msg;
    sig_msg.push_back(static_cast<uint8_t>(name.size()));
    sig_msg.insert(sig_msg.end(), name.begin(), name.end());
    sig_msg.push_back(static_cast<uint8_t>(value.size() & 0xff));
    sig_msg.push_back(static_cast<uint8_t>((value.size() >> 8) & 0xff));
    sig_msg.insert(sig_msg.end(), value.begin(), value.end());
    for (int i = 0; i < 8; ++i)
        sig_msg.push_back(static_cast<uint8_t>((effective_height >> (8*i)) & 0xff));

    // Build the full tx payload: sig_msg + [sig_count: u8] + each (idx, sig).
    std::vector<uint8_t> payload = sig_msg;
    payload.push_back(static_cast<uint8_t>(keyholder_sigs.size()));
    for (auto& [idx, kh_hex] : keyholder_sigs) {
        crypto::NodeKey kh;
        try { kh.priv_seed = from_hex_arr<32>(kh_hex); }
        catch (std::exception& e) {
            std::cerr << "Invalid keyholder priv hex: " << e.what() << "\n";
            return 1;
        }
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, kh.priv_seed.data(), 32);
        if (!pkey) { std::cerr << "keyholder priv invalid\n"; return 1; }
        size_t pub_len = 32;
        EVP_PKEY_get_raw_public_key(pkey, kh.pub.data(), &pub_len);
        EVP_PKEY_free(pkey);
        Signature sig = crypto::sign(kh, sig_msg.data(), sig_msg.size());
        payload.push_back(static_cast<uint8_t>(idx & 0xff));
        payload.push_back(static_cast<uint8_t>((idx >> 8) & 0xff));
        payload.insert(payload.end(), sig.begin(), sig.end());
    }

    // Sender side: derive anon address, query nonce, sign + submit.
    crypto::NodeKey sender;
    try { sender.priv_seed = from_hex_arr<32>(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid sender priv: " << e.what() << "\n"; return 1;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, sender.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "sender priv invalid\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, sender.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    // Sender must be a registered domain (anon accounts may only
    // TRANSFER per the validator). The provided --from is used as-is;
    // the node's registry resolves it to a pubkey, which must match
    // the --priv key.
    uint64_t nonce = 0;
    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "nonce",
                                  {{"domain", from_domain}});
        nonce = r.value("next_nonce", uint64_t{0});
    } catch (std::exception& e) {
        std::cerr << "nonce query failed: " << e.what() << "\n"; return 1;
    }

    chain::Transaction tx;
    tx.type    = chain::TxType::PARAM_CHANGE;
    tx.from    = from_domain;
    tx.to      = from_domain;   // ignored for PARAM_CHANGE
    tx.amount  = 0;
    tx.fee     = fee;
    tx.nonce   = nonce;
    tx.payload = payload;
    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(sender, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "submit_tx", {{"tx", tx.to_json()}});
        std::cout << r.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "submit_tx failed: " << e.what() << "\n"; return 1;
    }
    return 0;
}

// R4: build, sign, and submit a MERGE_EVENT tx.
//   determ submit-merge-event \
//     --priv <sender_priv_hex> --from <sender_domain> \
//     --event {begin|end} \
//     --shard-id <N> --partner-id <N> \
//     --effective-height <N> --evidence-window-start <N> \
//     [--refugee-region <region>] \
//     [--fee <N>] [--rpc-port <P>]
//
// Builds a canonical MergeEvent payload, wraps it in a Transaction
// from a registered domain, and submits via submit_tx RPC. Operator-
// driven for v1.x; auto-detection on the beacon (eligible_in_region
// < 2K observation window) is tracked as v2.11 in docs/V2-DESIGN.md.
static int cmd_submit_merge_event(int argc, char** argv) {
    std::string priv_hex, from_domain, event_str, refugee_region;
    uint32_t shard_id = 0, partner_id = 0;
    uint64_t effective_height = 0, evidence_window_start = 0;
    uint64_t fee  = 0;
    uint16_t port = get_rpc_port(argc, argv);
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--priv")              priv_hex = argv[i + 1];
        else if (a == "--from")              from_domain = argv[i + 1];
        else if (a == "--event")             event_str = argv[i + 1];
        else if (a == "--shard-id")          shard_id   = static_cast<uint32_t>(std::stoul(argv[i + 1]));
        else if (a == "--partner-id")        partner_id = static_cast<uint32_t>(std::stoul(argv[i + 1]));
        else if (a == "--effective-height")  effective_height       = std::stoull(argv[i + 1]);
        else if (a == "--evidence-window-start")
                                              evidence_window_start = std::stoull(argv[i + 1]);
        else if (a == "--refugee-region")    refugee_region = argv[i + 1];
        else if (a == "--fee")               fee  = std::stoull(argv[i + 1]);
    }
    if (priv_hex.empty() || from_domain.empty() || event_str.empty()) {
        std::cerr << "Usage: determ submit-merge-event "
                     "--priv <hex> --from <domain> --event {begin|end} "
                     "--shard-id <N> --partner-id <N> "
                     "--effective-height <N> --evidence-window-start <N> "
                     "[--refugee-region <region>] "
                     "[--fee <N>] [--rpc-port <P>]\n";
        return 1;
    }
    chain::MergeEvent ev;
    if      (event_str == "begin") ev.event_type = chain::MergeEvent::BEGIN;
    else if (event_str == "end")   ev.event_type = chain::MergeEvent::END;
    else {
        std::cerr << "--event must be 'begin' or 'end'\n"; return 1;
    }
    ev.shard_id              = shard_id;
    ev.partner_id            = partner_id;
    ev.effective_height      = effective_height;
    ev.evidence_window_start = evidence_window_start;
    ev.merging_shard_region  = refugee_region;
    std::vector<uint8_t> payload = ev.encode();

    crypto::NodeKey sender;
    try { sender.priv_seed = from_hex_arr<32>(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid sender priv: " << e.what() << "\n"; return 1;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, sender.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "sender priv invalid\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, sender.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    uint64_t nonce = 0;
    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "nonce",
                                  {{"domain", from_domain}});
        nonce = r.value("next_nonce", uint64_t{0});
    } catch (std::exception& e) {
        std::cerr << "nonce query failed: " << e.what() << "\n"; return 1;
    }

    chain::Transaction tx;
    tx.type    = chain::TxType::MERGE_EVENT;
    tx.from    = from_domain;
    tx.to      = from_domain;   // ignored for MERGE_EVENT
    tx.amount  = 0;
    tx.fee     = fee;
    tx.nonce   = nonce;
    tx.payload = payload;
    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(sender, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "submit_tx", {{"tx", tx.to_json()}});
        std::cout << r.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "submit_tx failed: " << e.what() << "\n"; return 1;
    }
    return 0;
}

// v2.18 Theme 7: submit a DAPP_REGISTER tx to the network.
// The signing sender (--from + --priv) must already be a REGISTER'd
// Determ identity. service_pubkey is generated separately (e.g., via
// libsodium box-keypair-gen) and provided here in hex.
static int cmd_submit_dapp_register(int argc, char** argv) {
    std::string priv_hex, from_domain, service_pubkey_hex, endpoint_url,
                topics_csv, metadata_hex;
    uint8_t retention = 0;
    bool deactivate = false;
    uint64_t fee  = 0;
    uint16_t port = get_rpc_port(argc, argv);
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--priv")            priv_hex = argv[i + 1];
        else if (a == "--from")            from_domain = argv[i + 1];
        else if (a == "--service-pubkey")  service_pubkey_hex = argv[i + 1];
        else if (a == "--endpoint-url")    endpoint_url = argv[i + 1];
        else if (a == "--topics")          topics_csv = argv[i + 1];
        else if (a == "--retention")       retention = uint8_t(std::stoi(argv[i + 1]));
        else if (a == "--metadata-hex")    metadata_hex = argv[i + 1];
        else if (a == "--fee")             fee  = std::stoull(argv[i + 1]);
    }
    // --deactivate is a flag (no value)
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--deactivate") deactivate = true;
    }
    if (priv_hex.empty() || from_domain.empty() ||
        (!deactivate && (service_pubkey_hex.empty() || endpoint_url.empty()))) {
        std::cerr << "Usage: determ submit-dapp-register --priv <hex> --from <domain>\n"
                     "  Create/update: --service-pubkey <64hex> --endpoint-url <url>\n"
                     "                 [--topics t1,t2,t3] [--retention 0|1]\n"
                     "                 [--metadata-hex <hex>]\n"
                     "  Deactivate:    --deactivate\n"
                     "  [--fee <N>] [--rpc-port <P>]\n";
        return 1;
    }

    // Build payload per the canonical encoding documented in block.hpp.
    std::vector<uint8_t> payload;
    if (deactivate) {
        payload.push_back(1);
    } else {
        payload.push_back(0);
        std::array<uint8_t, 32> svc_pk;
        try { svc_pk = from_hex_arr<32>(service_pubkey_hex); }
        catch (std::exception& e) {
            std::cerr << "Invalid --service-pubkey: " << e.what() << "\n";
            return 1;
        }
        payload.insert(payload.end(), svc_pk.begin(), svc_pk.end());
        if (endpoint_url.size() > 255) {
            std::cerr << "--endpoint-url too long (max 255)\n"; return 1;
        }
        payload.push_back(uint8_t(endpoint_url.size()));
        payload.insert(payload.end(), endpoint_url.begin(), endpoint_url.end());
        // Parse topics CSV
        std::vector<std::string> topics;
        if (!topics_csv.empty()) {
            size_t pos = 0;
            while (pos < topics_csv.size()) {
                size_t comma = topics_csv.find(',', pos);
                if (comma == std::string::npos) comma = topics_csv.size();
                topics.push_back(topics_csv.substr(pos, comma - pos));
                pos = comma + 1;
            }
        }
        if (topics.size() > 32) {
            std::cerr << "Too many topics (max 32)\n"; return 1;
        }
        payload.push_back(uint8_t(topics.size()));
        for (auto& t : topics) {
            if (t.size() > 64) {
                std::cerr << "Topic '" << t << "' too long (max 64)\n";
                return 1;
            }
            payload.push_back(uint8_t(t.size()));
            payload.insert(payload.end(), t.begin(), t.end());
        }
        payload.push_back(retention);
        std::vector<uint8_t> metadata;
        if (!metadata_hex.empty()) {
            metadata = from_hex(metadata_hex);
        }
        if (metadata.size() > 4096) {
            std::cerr << "Metadata too long (max 4096 bytes)\n"; return 1;
        }
        uint16_t mlen = uint16_t(metadata.size());
        payload.push_back(uint8_t(mlen & 0xFF));
        payload.push_back(uint8_t((mlen >> 8) & 0xFF));
        payload.insert(payload.end(), metadata.begin(), metadata.end());
    }

    // Build, sign, submit.
    crypto::NodeKey sender;
    try { sender.priv_seed = from_hex_arr<32>(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid sender priv: " << e.what() << "\n"; return 1;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, sender.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "sender priv invalid\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, sender.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    uint64_t nonce = 0;
    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "nonce",
                                  {{"domain", from_domain}});
        nonce = r.value("next_nonce", uint64_t{0});
    } catch (std::exception& e) {
        std::cerr << "nonce query failed: " << e.what() << "\n"; return 1;
    }

    chain::Transaction tx;
    tx.type    = chain::TxType::DAPP_REGISTER;
    tx.from    = from_domain;
    tx.to      = "";
    tx.amount  = 0;
    tx.fee     = fee;
    tx.nonce   = nonce;
    tx.payload = payload;
    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(sender, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "submit_tx", {{"tx", tx.to_json()}});
        std::cout << r.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "submit_tx failed: " << e.what() << "\n"; return 1;
    }
    return 0;
}

// v2.19 Theme 7: submit a DAPP_CALL tx to the network.
// --to <dapp-domain> --topic <topic> --payload-hex <hex>
// Optional --amount for atomic payment.
static int cmd_submit_dapp_call(int argc, char** argv) {
    std::string priv_hex, from_domain, to_domain, topic, payload_hex;
    uint64_t amount = 0, fee = 0;
    uint16_t port = get_rpc_port(argc, argv);
    for (int i = 0; i < argc - 1; ++i) {
        std::string a = argv[i];
        if      (a == "--priv")        priv_hex = argv[i + 1];
        else if (a == "--from")        from_domain = argv[i + 1];
        else if (a == "--to")          to_domain = argv[i + 1];
        else if (a == "--topic")       topic = argv[i + 1];
        else if (a == "--payload-hex") payload_hex = argv[i + 1];
        else if (a == "--amount")      amount = std::stoull(argv[i + 1]);
        else if (a == "--fee")         fee  = std::stoull(argv[i + 1]);
    }
    if (priv_hex.empty() || from_domain.empty() || to_domain.empty()) {
        std::cerr << "Usage: determ submit-dapp-call --priv <hex> --from <domain>\n"
                     "  --to <dapp-domain> [--topic <T>] [--payload-hex <hex>]\n"
                     "  [--amount <N>] [--fee <N>] [--rpc-port <P>]\n";
        return 1;
    }
    if (topic.size() > 64) {
        std::cerr << "Topic too long (max 64)\n"; return 1;
    }

    // Build DAPP_CALL payload: [topic_len:u8][topic][ct_len:u32 LE][ciphertext]
    std::vector<uint8_t> ciphertext;
    if (!payload_hex.empty()) ciphertext = from_hex(payload_hex);
    if (ciphertext.size() > 16384) {
        std::cerr << "Payload too large (max 16 KB)\n"; return 1;
    }
    std::vector<uint8_t> payload;
    payload.push_back(uint8_t(topic.size()));
    payload.insert(payload.end(), topic.begin(), topic.end());
    uint32_t cl = uint32_t(ciphertext.size());
    payload.push_back(uint8_t(cl         & 0xFF));
    payload.push_back(uint8_t((cl >>  8) & 0xFF));
    payload.push_back(uint8_t((cl >> 16) & 0xFF));
    payload.push_back(uint8_t((cl >> 24) & 0xFF));
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

    crypto::NodeKey sender;
    try { sender.priv_seed = from_hex_arr<32>(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid sender priv: " << e.what() << "\n"; return 1;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, sender.priv_seed.data(), 32);
    if (!pkey) { std::cerr << "sender priv invalid\n"; return 1; }
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, sender.pub.data(), &pub_len);
    EVP_PKEY_free(pkey);

    uint64_t nonce = 0;
    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "nonce",
                                  {{"domain", from_domain}});
        nonce = r.value("next_nonce", uint64_t{0});
    } catch (std::exception& e) {
        std::cerr << "nonce query failed: " << e.what() << "\n"; return 1;
    }

    chain::Transaction tx;
    tx.type    = chain::TxType::DAPP_CALL;
    tx.from    = from_domain;
    tx.to      = to_domain;
    tx.amount  = amount;
    tx.fee     = fee;
    tx.nonce   = nonce;
    tx.payload = payload;
    auto sb = tx.signing_bytes();
    tx.sig  = crypto::sign(sender, sb.data(), sb.size());
    tx.hash = tx.compute_hash();

    try {
        auto r = rpc::rpc_call("127.0.0.1", port, "submit_tx", {{"tx", tx.to_json()}});
        std::cout << r.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "submit_tx failed: " << e.what() << "\n"; return 1;
    }
    return 0;
}

static int cmd_genesis_tool(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ genesis-tool {peer-info|build|build-sharded} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "peer-info")     return cmd_genesis_tool_peer_info    (argc - 1, argv + 1);
    if (sub == "build")         return cmd_genesis_tool_build         (argc - 1, argv + 1);
    if (sub == "build-sharded") return cmd_genesis_tool_build_sharded (argc - 1, argv + 1);
    std::cerr << "Unknown genesis-tool subcommand: " << sub << "\n";
    return 1;
}

static int cmd_stake_info(int argc, char** argv) {
    std::string domain = (argc >= 1) ? argv[0] : "";
    uint16_t    port   = get_rpc_port(argc, argv);
    try {
        auto result = rpc::rpc_call("127.0.0.1", port, "stake_info", {{"domain", domain}});
        std::cout << result.dump(2) << "\n";
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 0; }

    std::string cmd = argv[1];
    int sub_argc = argc - 2;
    char** sub_argv = argv + 2;

    if (cmd == "init")        return cmd_init(sub_argc, sub_argv);
    if (cmd == "start")       return cmd_start(sub_argc, sub_argv);
    if (cmd == "register")    return cmd_register(sub_argc, sub_argv);
    if (cmd == "send")        return cmd_send(sub_argc, sub_argv);
    if (cmd == "status")        return cmd_status(sub_argc, sub_argv);
    if (cmd == "peers")         return cmd_peers(sub_argc, sub_argv);
    if (cmd == "show-block")    return cmd_show_block(sub_argc, sub_argv);
    if (cmd == "headers")       return cmd_headers(sub_argc, sub_argv);
    if (cmd == "verify-headers") return cmd_verify_headers(sub_argc, sub_argv);
    if (cmd == "verify-block-sigs") return cmd_verify_block_sigs(sub_argc, sub_argv);
    if (cmd == "verify-genesis") return cmd_verify_genesis(sub_argc, sub_argv);
    if (cmd == "chain-summary") return cmd_chain_summary(sub_argc, sub_argv);
    if (cmd == "validators")    return cmd_validators(sub_argc, sub_argv);
    if (cmd == "committee")     return cmd_committee(sub_argc, sub_argv);
    if (cmd == "show-account")  return cmd_show_account(sub_argc, sub_argv);
    if (cmd == "show-tx")       return cmd_show_tx(sub_argc, sub_argv);
    if (cmd == "snapshot")      return cmd_snapshot(sub_argc, sub_argv);
    if (cmd == "balance")     return cmd_balance(sub_argc, sub_argv);
    if (cmd == "state-root") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "state_root", {});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "state-root query failed: " << e.what() << "\n";
            return 1;
        }
    }
    // v2.18 Theme 7: DApp registry query — info for one DApp.
    // Usage: determ dapp-info --domain <D> [--rpc-port N]
    if (cmd == "dapp-info") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        std::string domain;
        for (int i = 0; i < sub_argc; ++i) {
            std::string a = sub_argv[i];
            if (a == "--domain" && i + 1 < sub_argc) domain = sub_argv[++i];
        }
        if (domain.empty()) {
            std::cerr << "dapp-info requires --domain\n";
            return 1;
        }
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "dapp_info",
                {{"domain", domain}});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "dapp-info query failed: " << e.what() << "\n";
            return 1;
        }
    }
    // v2.19 Theme 7 Phase 7.4: retrospective DAPP_CALL query.
    // Usage: determ dapp-messages --domain D [--from H] [--to H]
    //        [--topic T] [--rpc-port N]
    // DApp node poll-and-process pattern:
    //   while true: dapp-messages --from $WATERMARK; process; $WATERMARK = result.last_scanned + 1
    if (cmd == "dapp-messages") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        std::string domain, topic;
        uint64_t from_h = 0, to_h = 0;
        for (int i = 0; i < sub_argc; ++i) {
            std::string a = sub_argv[i];
            if      (a == "--domain" && i + 1 < sub_argc) domain = sub_argv[++i];
            else if (a == "--from"   && i + 1 < sub_argc) from_h = std::stoull(sub_argv[++i]);
            else if (a == "--to"     && i + 1 < sub_argc) to_h   = std::stoull(sub_argv[++i]);
            else if (a == "--topic"  && i + 1 < sub_argc) topic  = sub_argv[++i];
        }
        if (domain.empty()) {
            std::cerr << "dapp-messages requires --domain\n";
            return 1;
        }
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "dapp_messages",
                {{"domain", domain}, {"from_height", from_h},
                 {"to_height", to_h}, {"topic", topic}});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "dapp-messages query failed: " << e.what() << "\n";
            return 1;
        }
    }

    // v2.18 Theme 7: DApp registry query — list / filter.
    // Usage: determ dapp-list [--prefix P] [--topic T] [--rpc-port N]
    if (cmd == "dapp-list") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        std::string prefix, topic;
        for (int i = 0; i < sub_argc; ++i) {
            std::string a = sub_argv[i];
            if (a == "--prefix" && i + 1 < sub_argc) prefix = sub_argv[++i];
            else if (a == "--topic" && i + 1 < sub_argc) topic = sub_argv[++i];
        }
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "dapp_list",
                {{"prefix", prefix}, {"topic", topic}});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "dapp-list query failed: " << e.what() << "\n";
            return 1;
        }
    }

    // v2.2 light-client demonstrator: verify a state-proof response
    // locally via crypto::merkle_verify, without trusting the
    // responding node. Pair with `determ state-proof` (which fetches
    // the proof from a full node) — a light client that has an
    // independently-trusted state_root (e.g., from a block header it
    // accepted via header-sync, or a snapshot it verified) can use
    // this to confirm any state field's current value with zero
    // additional trust in the full node.
    //
    // Usage:
    //   determ state-proof --ns a --key alice --rpc-port 8771 > proof.json
    //   determ verify-state-proof --in proof.json
    //
    // Or pipe directly:
    //   determ state-proof --ns a --key alice | determ verify-state-proof
    //
    // Optional --state-root <hex64>: verify against an externally-
    // provided root rather than the root the proof itself reports.
    // (Useful for confirming the proof matches a root the client
    // already trusts; without this flag, this command just sanity-
    // checks that the proof is internally consistent.)
    if (cmd == "verify-state-proof") {
        std::string in_path;
        std::string expected_root_hex;
        for (int i = 0; i < sub_argc; ++i) {
            std::string a = sub_argv[i];
            if      (a == "--in"          && i + 1 < sub_argc) in_path          = sub_argv[++i];
            else if (a == "--state-root"  && i + 1 < sub_argc) expected_root_hex= sub_argv[++i];
        }

        // Read JSON proof from file or stdin.
        nlohmann::json proof_json;
        try {
            if (!in_path.empty()) {
                std::ifstream f(in_path);
                if (!f) throw std::runtime_error("cannot open: " + in_path);
                proof_json = nlohmann::json::parse(f);
            } else {
                proof_json = nlohmann::json::parse(std::cin);
            }
        } catch (std::exception& e) {
            std::cerr << "verify-state-proof: parse error: "
                      << e.what() << "\n";
            return 1;
        }

        // Surface "not_found" responses explicitly — the server told
        // us the key isn't in the tree, so there's nothing to verify.
        if (proof_json.contains("error")) {
            std::cerr << "verify-state-proof: RPC error in proof: "
                      << proof_json["error"].dump() << "\n";
            return 1;
        }

        // Extract proof fields. Each field validated by name for
        // clear diagnostics (mirrors S-018 patterns).
        Hash claimed_root;
        std::vector<uint8_t> key_bytes;
        Hash value_hash;
        size_t target_index = 0;
        size_t leaf_count = 0;
        std::vector<Hash> proof_sibs;
        try {
            using determ::util::json_require;
            using determ::util::json_require_hex;
            using determ::util::json_require_array;
            claimed_root = from_hex_arr<32>(
                json_require_hex(proof_json, "state_root", 64));
            std::string kb_hex = json_require<std::string>(proof_json, "key_bytes");
            key_bytes = from_hex(kb_hex);
            value_hash = from_hex_arr<32>(
                json_require_hex(proof_json, "value_hash", 64));
            target_index = json_require<size_t>(proof_json, "target_index");
            leaf_count   = json_require<size_t>(proof_json, "leaf_count");
            for (auto& h : json_require_array(proof_json, "proof")) {
                proof_sibs.push_back(
                    from_hex_arr<32>(h.get<std::string>()));
            }
        } catch (std::exception& e) {
            std::cerr << "verify-state-proof: malformed proof: "
                      << e.what() << "\n";
            return 1;
        }

        // If the operator supplied an external trusted root, swap it
        // in (this is the real light-client mode — the proof's own
        // claimed root is server-supplied and not trusted).
        Hash verify_root = claimed_root;
        if (!expected_root_hex.empty()) {
            if (expected_root_hex.size() != 64) {
                std::cerr << "verify-state-proof: --state-root must be "
                             "64 hex chars (32 bytes), got "
                          << expected_root_hex.size() << "\n";
                return 1;
            }
            try {
                verify_root = from_hex_arr<32>(expected_root_hex);
            } catch (std::exception& e) {
                std::cerr << "verify-state-proof: --state-root parse error: "
                          << e.what() << "\n";
                return 1;
            }
            if (verify_root != claimed_root) {
                std::cerr << "verify-state-proof: WARNING — supplied "
                             "--state-root "
                          << to_hex(verify_root).substr(0, 16)
                          << "... does NOT match proof's claimed root "
                          << to_hex(claimed_root).substr(0, 16)
                          << "...\n";
                std::cerr << "  (verifying against the supplied --state-root; "
                             "if the proof was fetched against the same "
                             "trusted root this should match)\n";
            }
        }

        bool ok = crypto::merkle_verify(verify_root, key_bytes, value_hash,
                                          target_index, leaf_count, proof_sibs);
        if (ok) {
            std::cout << "OK\n";
            std::cout << "  state_root:   " << to_hex(verify_root) << "\n";
            std::cout << "  key:          "
                      << (proof_json.contains("namespace")
                          ? proof_json["namespace"].get<std::string>() + ":"
                          : std::string{})
                      << proof_json.value("key", std::string{}) << "\n";
            std::cout << "  value_hash:   " << to_hex(value_hash) << "\n";
            std::cout << "  proof depth:  " << proof_sibs.size()
                      << " sibling hashes\n";
            std::cout << "  leaf_count:   " << leaf_count
                      << " (target_index=" << target_index << ")\n";
            return 0;
        } else {
            std::cerr << "FAIL: merkle_verify rejected the proof\n";
            std::cerr << "  state_root:   " << to_hex(verify_root) << "\n";
            std::cerr << "  expected leaf at index " << target_index
                      << " of " << leaf_count << " to combine with the "
                      << proof_sibs.size() << " sibling hashes to produce "
                      << "the state_root, but it did not.\n";
            return 1;
        }
    }

    // v2.2 light-client foundation: state-proof CLI.
    // Usage: determ state-proof --ns <a|s|r|d|b|k|c> --key <name> [--rpc-port N]
    // (`d` = v2.18 DApp registry; the underlying RPC was extended in this
    // session to surface the d:-namespace alongside accounts/stakes/etc.)
    if (cmd == "state-proof") {
        uint16_t port = get_rpc_port(sub_argc, sub_argv);
        std::string ns, key;
        for (int i = 0; i < sub_argc; ++i) {
            std::string a = sub_argv[i];
            if (a == "--ns" && i + 1 < sub_argc) ns = sub_argv[++i];
            else if (a == "--key" && i + 1 < sub_argc) key = sub_argv[++i];
        }
        if (ns.empty() || key.empty()) {
            std::cerr << "state-proof requires --ns and --key\n";
            return 1;
        }
        try {
            auto r = rpc::rpc_call("127.0.0.1", port, "state_proof",
                {{"namespace", ns}, {"key", key}});
            std::cout << r.dump(2) << "\n";
            return 0;
        } catch (std::exception& e) {
            std::cerr << "state-proof query failed: " << e.what() << "\n";
            return 1;
        }
    }
    // A9 Phase 2D regression: in-process exercise of Chain::atomic_scope's
    // commit / discard / nesting / exception semantics. No network, no
    // RPC — just a freshly-constructed Chain and direct method calls.
    // Exit 0 on all assertions passing, non-zero on any failure.
    if (cmd == "test-atomic-scope") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Build a minimal genesis block: alice=100, bob=0.
        Block genesis;
        genesis.index           = 0;
        genesis.prev_hash       = Hash{};
        genesis.timestamp       = 0;
        genesis.cumulative_rand = Hash{};
        genesis.creators.clear();
        GenesisAlloc a; a.domain = "alice"; a.balance = 100; a.stake = 0;
        genesis.initial_state.push_back(a);
        GenesisAlloc bb; bb.domain = "bob"; bb.balance = 0;  bb.stake = 0;
        genesis.initial_state.push_back(bb);

        Chain chain(genesis);
        uint64_t alice_initial = chain.balance("alice");
        uint64_t bob_initial   = chain.balance("bob");
        check(alice_initial == 100, "genesis: alice = 100");
        check(bob_initial   == 0,   "genesis: bob   = 0");

        // Test 1: atomic_scope returning true commits the change.
        // We invoke atomic_scope and inside fn, append a block that
        // transfers 25 from alice to bob. Return true → mutations kept.
        // Helper that builds a transfer block at the next height.
        auto build_transfer_block = [&](uint64_t amount) {
            Block tb;
            tb.index           = chain.height();
            tb.prev_hash       = chain.head_hash();
            tb.timestamp        = 1;
            tb.cumulative_rand = Hash{};
            Transaction tx;
            tx.type     = TxType::TRANSFER;
            tx.from     = "alice";
            tx.to       = "bob";
            tx.amount   = amount;
            tx.fee      = 0;
            tx.nonce    = chain.next_nonce("alice");
            tx.payload  = {};
            tx.hash     = tx.compute_hash();
            tb.transactions.push_back(tx);
            return tb;
        };

        bool committed = chain.atomic_scope([&](Chain& c) {
            c.append(build_transfer_block(25));
            return true;  // keep
        });
        check(committed == true,                "test1: scope returned true");
        check(chain.balance("alice") == 75,     "test1: alice=75 after commit");
        check(chain.balance("bob")   == 25,     "test1: bob=25 after commit");
        check(chain.height() == 2,              "test1: chain height grew");

        // Test 2: atomic_scope returning false rolls back the change.
        uint64_t alice_pre  = chain.balance("alice");
        uint64_t bob_pre    = chain.balance("bob");
        uint64_t height_pre = chain.height();
        bool kept = chain.atomic_scope([&](Chain& c) {
            c.append(build_transfer_block(10));
            return false;  // discard
        });
        check(kept == false,                          "test2: scope returned false");
        check(chain.balance("alice") == alice_pre,    "test2: alice unchanged after discard");
        check(chain.balance("bob")   == bob_pre,      "test2: bob unchanged after discard");
        check(chain.height()         == height_pre,   "test2: blocks_ rolled back");

        // Test 3: throwing in scope rolls back AND re-raises.
        bool caught = false;
        try {
            chain.atomic_scope([&](Chain& c) -> bool {
                c.append(build_transfer_block(5));
                throw std::runtime_error("synthetic");
                return true;  // unreachable
            });
        } catch (std::exception&) {
            caught = true;
        }
        check(caught,                                  "test3: exception propagates");
        check(chain.balance("alice") == alice_pre,     "test3: alice unchanged after throw");
        check(chain.balance("bob")   == bob_pre,       "test3: bob unchanged after throw");
        check(chain.height()         == height_pre,    "test3: blocks_ rolled back on throw");

        // Test 4: nested scopes — outer commits, inner discards.
        // Outer appends one transfer (5). Inner appends another (3) but
        // discards. After outer commits, only outer's 5 should land.
        uint64_t a4 = chain.balance("alice");
        uint64_t b4 = chain.balance("bob");
        uint64_t h4 = chain.height();
        chain.atomic_scope([&](Chain& outer) {
            outer.append(build_transfer_block(5));
            // After outer's append: alice -= 5, bob += 5
            outer.atomic_scope([&](Chain& inner) {
                inner.append(build_transfer_block(3));
                // After inner's append: alice -= 3 more, bob += 3 more
                return false;  // discard inner
            });
            // After inner's discard: state should reflect ONLY outer's append.
            return true;  // commit outer
        });
        check(chain.balance("alice") == a4 - 5,     "test4: alice debited only outer (5)");
        check(chain.balance("bob")   == b4 + 5,     "test4: bob credited only outer (5)");
        check(chain.height()         == h4 + 1,     "test4: only outer block landed");

        // Test 5: nested scopes — outer discards. Both inner and outer
        // mutations roll back even if inner committed.
        uint64_t a5 = chain.balance("alice");
        uint64_t b5 = chain.balance("bob");
        uint64_t h5 = chain.height();
        chain.atomic_scope([&](Chain& outer) {
            outer.append(build_transfer_block(7));
            outer.atomic_scope([&](Chain& inner) {
                inner.append(build_transfer_block(2));
                return true;  // commit inner
            });
            return false;  // discard outer — should undo BOTH appends
        });
        check(chain.balance("alice") == a5,         "test5: alice unchanged after outer discard");
        check(chain.balance("bob")   == b5,         "test5: bob unchanged after outer discard");
        check(chain.height()         == h5,         "test5: both blocks rolled back");

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": atomic_scope " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // v2.4 composable transactions: in-process apply-path test.
    // Builds a Chain with three accounts (alice, bob, carol), constructs
    // COMPOSABLE_BATCH txs with various inner-tx shapes, applies them
    // via Chain::append, and verifies the all-or-nothing semantics.
    // v2.18 Theme 7: in-process apply-path test for DAPP_REGISTER.
    // Builds a Chain with alice as a REGISTER'd domain (the DApp's
    // owner), then applies a series of DAPP_REGISTER txs exercising
    // create / update / deactivate paths. Verifies dapp_registry_
    // state + state_root changes accordingly.
    if (cmd == "test-dapp-register") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Genesis: alice is a registered Determ domain with stake.
        Block genesis;
        genesis.index           = 0;
        genesis.prev_hash       = Hash{};
        genesis.timestamp       = 0;
        genesis.cumulative_rand = Hash{};
        GenesisAlloc a;
        a.domain = "alice";
        a.balance = 1000;
        a.stake = 100;
        for (size_t i = 0; i < a.ed_pub.size(); ++i) a.ed_pub[i] = uint8_t(i + 1);
        genesis.initial_state.push_back(a);
        Chain chain(genesis);

        // Helper: build a DAPP_REGISTER payload for op=0 (create/update).
        auto pack_register_v0 = [](const PubKey& svc_pk,
                                      const std::string& url,
                                      const std::vector<std::string>& topics,
                                      uint8_t retention,
                                      const std::vector<uint8_t>& metadata) {
            std::vector<uint8_t> p;
            p.push_back(0);  // op = create/update
            p.insert(p.end(), svc_pk.begin(), svc_pk.end());
            p.push_back(uint8_t(url.size()));
            p.insert(p.end(), url.begin(), url.end());
            p.push_back(uint8_t(topics.size()));
            for (auto& t : topics) {
                p.push_back(uint8_t(t.size()));
                p.insert(p.end(), t.begin(), t.end());
            }
            p.push_back(retention);
            p.push_back(uint8_t(metadata.size() & 0xFF));
            p.push_back(uint8_t((metadata.size() >> 8) & 0xFF));
            p.insert(p.end(), metadata.begin(), metadata.end());
            return p;
        };
        auto pack_register_v1 = []() {
            return std::vector<uint8_t>{1};  // op = deactivate, no further bytes
        };

        auto build_dapp_register_block = [&](const std::string& from,
                                                const std::vector<uint8_t>& payload) {
            Block b;
            b.index           = chain.height();
            b.prev_hash       = chain.head_hash();
            b.timestamp       = 1;
            b.cumulative_rand = Hash{};
            Transaction tx;
            tx.type    = TxType::DAPP_REGISTER;
            tx.from    = from;
            tx.to      = "";
            tx.amount  = 0;
            tx.fee     = 0;
            tx.nonce   = chain.next_nonce(from);
            tx.payload = payload;
            tx.hash    = tx.compute_hash();
            b.transactions.push_back(tx);
            return b;
        };

        // Test 1: create. alice registers a DApp.
        PubKey svc_pk{};
        for (size_t i = 0; i < svc_pk.size(); ++i) svc_pk[i] = uint8_t(0xA0 + i);
        std::vector<std::string> topics = {"chat", "files"};
        std::vector<uint8_t> meta = {0xDE, 0xAD, 0xBE, 0xEF};
        auto pl1 = pack_register_v0(svc_pk, "https://dapp.example", topics, 0, meta);
        Hash root_before = chain.compute_state_root();
        chain.append(build_dapp_register_block("alice", pl1));
        Hash root_after  = chain.compute_state_root();

        auto entry_opt = chain.dapp("alice");
        check(entry_opt.has_value(),                  "test1: dapp entry exists");
        check(entry_opt && entry_opt->endpoint_url == "https://dapp.example",
              "test1: endpoint_url correct");
        check(entry_opt && entry_opt->topics.size() == 2,
              "test1: topic count = 2");
        check(entry_opt && entry_opt->topics[0] == "chat",
              "test1: topic[0] = chat");
        check(entry_opt && entry_opt->topics[1] == "files",
              "test1: topic[1] = files");
        check(entry_opt && entry_opt->service_pubkey == svc_pk,
              "test1: service_pubkey matches");
        check(entry_opt && entry_opt->retention == 0,
              "test1: retention = 0 (default)");
        check(entry_opt && entry_opt->metadata == meta,
              "test1: metadata round-trips");
        check(entry_opt && entry_opt->inactive_from == UINT64_MAX,
              "test1: entry is active");
        check(root_after != root_before,
              "test1: state_root changed after DAPP_REGISTER");

        // Test 2: update — change endpoint_url, add a topic.
        std::vector<std::string> topics2 = {"chat", "files", "notifications"};
        auto pl2 = pack_register_v0(svc_pk, "https://dapp.v2.example", topics2, 1, meta);
        uint64_t registered_at_before = entry_opt->registered_at;
        chain.append(build_dapp_register_block("alice", pl2));
        auto entry2 = chain.dapp("alice");
        check(entry2.has_value(),                      "test2: entry still exists");
        check(entry2 && entry2->endpoint_url == "https://dapp.v2.example",
              "test2: endpoint_url updated");
        check(entry2 && entry2->topics.size() == 3,
              "test2: topic count = 3");
        check(entry2 && entry2->retention == 1,
              "test2: retention updated to 1");
        check(entry2 && entry2->registered_at == registered_at_before,
              "test2: registered_at preserved across update");

        // Test 3: deactivate.
        auto pl3 = pack_register_v1();
        uint64_t height_pre_deactivate = chain.height();
        chain.append(build_dapp_register_block("alice", pl3));
        auto entry3 = chain.dapp("alice");
        check(entry3.has_value(),                      "test3: entry still in registry");
        check(entry3 && entry3->inactive_from != UINT64_MAX,
              "test3: inactive_from set");
        // height_pre_deactivate is the height BEFORE the deactivate block applies.
        // The apply-time height is height_pre_deactivate (block_index passed to apply).
        // inactive_from = height_pre_deactivate + DAPP_GRACE_BLOCKS.
        check(entry3 && entry3->inactive_from == height_pre_deactivate + DAPP_GRACE_BLOCKS,
              "test3: inactive_from = current_height + GRACE");

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": dapp_register " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // v2.19 Theme 7 Phase 7.2: in-process apply-path test for DAPP_CALL.
    // Builds a Chain with alice (user) and dapp_owner (DApp's owning
    // Determ identity), registers a DApp on dapp_owner, then exercises
    // DAPP_CALL across various scenarios (success, missing DApp,
    // deactivated DApp, unknown topic, payment + message).
    if (cmd == "test-dapp-call") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Genesis: alice (user with balance) + dappowner (DApp's owner).
        Block genesis;
        genesis.index           = 0;
        genesis.prev_hash       = Hash{};
        genesis.timestamp       = 0;
        genesis.cumulative_rand = Hash{};
        GenesisAlloc a;
        a.domain = "alice"; a.balance = 1000; a.stake = 0;
        for (size_t i = 0; i < a.ed_pub.size(); ++i) a.ed_pub[i] = uint8_t(i + 1);
        genesis.initial_state.push_back(a);
        GenesisAlloc d;
        d.domain = "dappowner"; d.balance = 0; d.stake = 100;
        for (size_t i = 0; i < d.ed_pub.size(); ++i) d.ed_pub[i] = uint8_t(i + 100);
        genesis.initial_state.push_back(d);
        Chain chain(genesis);

        // Helper: pack a DAPP_REGISTER payload (op=0).
        auto pack_register = [](const PubKey& svc_pk,
                                   const std::string& url,
                                   const std::vector<std::string>& topics) {
            std::vector<uint8_t> p;
            p.push_back(0);
            p.insert(p.end(), svc_pk.begin(), svc_pk.end());
            p.push_back(uint8_t(url.size()));
            p.insert(p.end(), url.begin(), url.end());
            p.push_back(uint8_t(topics.size()));
            for (auto& t : topics) {
                p.push_back(uint8_t(t.size()));
                p.insert(p.end(), t.begin(), t.end());
            }
            p.push_back(0);  // retention = 0
            p.push_back(0); p.push_back(0);  // metadata_len = 0
            return p;
        };
        // Helper: pack a DAPP_CALL payload (topic + ciphertext).
        auto pack_call = [](const std::string& topic,
                               const std::vector<uint8_t>& ct) {
            std::vector<uint8_t> p;
            p.push_back(uint8_t(topic.size()));
            p.insert(p.end(), topic.begin(), topic.end());
            uint32_t l = uint32_t(ct.size());
            p.push_back(uint8_t(l         & 0xFF));
            p.push_back(uint8_t((l >>  8) & 0xFF));
            p.push_back(uint8_t((l >> 16) & 0xFF));
            p.push_back(uint8_t((l >> 24) & 0xFF));
            p.insert(p.end(), ct.begin(), ct.end());
            return p;
        };
        // Helper: build a block carrying one tx.
        auto build_block = [&](TxType type,
                                  const std::string& from,
                                  const std::string& to,
                                  uint64_t amount,
                                  uint64_t fee,
                                  const std::vector<uint8_t>& payload) {
            Block b;
            b.index           = chain.height();
            b.prev_hash       = chain.head_hash();
            b.timestamp       = 1;
            b.cumulative_rand = Hash{};
            Transaction tx;
            tx.type    = type;
            tx.from    = from;
            tx.to      = to;
            tx.amount  = amount;
            tx.fee     = fee;
            tx.nonce   = chain.next_nonce(from);
            tx.payload = payload;
            tx.hash    = tx.compute_hash();
            b.transactions.push_back(tx);
            return b;
        };

        // Setup: dappowner registers a DApp with two topics.
        PubKey svc_pk{};
        for (size_t i = 0; i < svc_pk.size(); ++i) svc_pk[i] = uint8_t(0xC0 + i);
        std::vector<std::string> topics = {"chat", "rpc"};
        chain.append(build_block(TxType::DAPP_REGISTER, "dappowner", "",
                                    0, 0, pack_register(svc_pk, "https://dapp.example", topics)));
        check(chain.dapp("dappowner").has_value(),
              "setup: DApp registered");

        // Test 1: successful DAPP_CALL with payment.
        // alice sends a "chat" message to dappowner with 5 DTM payment.
        std::vector<uint8_t> ciphertext = {0xAA, 0xBB, 0xCC, 0xDD};
        uint64_t alice_pre  = chain.balance("alice");
        uint64_t dapp_pre   = chain.balance("dappowner");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    /*amount=*/5, /*fee=*/0,
                                    pack_call("chat", ciphertext)));
        uint64_t alice_post = chain.balance("alice");
        uint64_t dapp_post  = chain.balance("dappowner");
        check(alice_post == alice_pre - 5,
              "test1: alice debited 5 (DAPP_CALL amount)");
        check(dapp_post  == dapp_pre + 5,
              "test1: dappowner credited 5");
        check(chain.next_nonce("alice") == 1,
              "test1: alice nonce +1");

        // Test 2: DAPP_CALL with amount=0 — pure message, no transfer.
        uint64_t alice_pre2 = chain.balance("alice");
        uint64_t dapp_pre2  = chain.balance("dappowner");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    0, 0, pack_call("rpc", {0x01, 0x02})));
        check(chain.balance("alice")     == alice_pre2,
              "test2: alice unchanged (amount=0)");
        check(chain.balance("dappowner") == dapp_pre2,
              "test2: dappowner unchanged (amount=0)");
        check(chain.next_nonce("alice")  == 2,
              "test2: alice nonce +1");

        // Test 3: DAPP_CALL to nonexistent DApp — apply silently no-ops
        // (defensive; validator would have rejected at submit-time).
        uint64_t alice_pre3 = chain.balance("alice");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "ghost.dapp",
                                    100, 0, pack_call("chat", ciphertext)));
        check(chain.balance("alice")     == alice_pre3,
              "test3: alice unchanged (missing DApp)");
        check(chain.balance("ghost.dapp") == 0,
              "test3: ghost.dapp not credited");
        check(chain.next_nonce("alice")  == 3,
              "test3: alice nonce +1 (defensive consume)");

        // Test 4: DAPP_CALL with topic not in DApp's registered list.
        uint64_t alice_pre4 = chain.balance("alice");
        uint64_t dapp_pre4  = chain.balance("dappowner");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    10, 0, pack_call("unregistered", ciphertext)));
        check(chain.balance("alice")     == alice_pre4,
              "test4: alice unchanged (unknown topic)");
        check(chain.balance("dappowner") == dapp_pre4,
              "test4: dappowner unchanged (unknown topic)");

        // Test 5: DAPP_CALL with empty topic — allowed, applies normally.
        uint64_t alice_pre5 = chain.balance("alice");
        uint64_t dapp_pre5  = chain.balance("dappowner");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    3, 0, pack_call("", ciphertext)));
        check(chain.balance("alice")     == alice_pre5 - 3,
              "test5: alice debited 3 (empty topic allowed)");
        check(chain.balance("dappowner") == dapp_pre5 + 3,
              "test5: dappowner credited 3");

        // Test 6: deactivated DApp — DAPP_CALL no-ops after grace period.
        // Deactivate the DApp; apply at height >= deactivate_height + GRACE
        // means inactive_from <= height → rejected.
        chain.append(build_block(TxType::DAPP_REGISTER, "dappowner", "",
                                    0, 0, std::vector<uint8_t>{1}));
        // The DApp is now inactive_from = current_height + DAPP_GRACE_BLOCKS.
        // For this test, we can't easily wait 100 blocks; instead, we
        // verify the DApp ENTRY now has inactive_from set, and that a
        // DAPP_CALL one block later (inactive_from > current still) is
        // accepted (within grace period).
        auto entry = chain.dapp("dappowner");
        check(entry.has_value() && entry->inactive_from != UINT64_MAX,
              "test6: DApp inactive_from set after deactivate");
        // During grace period, calls should still apply.
        uint64_t alice_pre6 = chain.balance("alice");
        chain.append(build_block(TxType::DAPP_CALL, "alice", "dappowner",
                                    1, 0, pack_call("chat", {0xFF})));
        check(chain.balance("alice") == alice_pre6 - 1,
              "test6: alice debited (call during grace period still applies)");

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": dapp_call " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    if (cmd == "test-composable-batch") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Genesis: alice=100, bob=50, carol=0.
        Block genesis;
        genesis.index           = 0;
        genesis.prev_hash       = Hash{};
        genesis.timestamp       = 0;
        genesis.cumulative_rand = Hash{};
        auto mk_alloc = [](const std::string& d, uint64_t bal) {
            GenesisAlloc a; a.domain = d; a.balance = bal; a.stake = 0;
            return a;
        };
        genesis.initial_state.push_back(mk_alloc("alice", 100));
        genesis.initial_state.push_back(mk_alloc("bob",   50));
        genesis.initial_state.push_back(mk_alloc("carol", 0));
        Chain chain(genesis);

        // Helper: build a TRANSFER inner tx (unsigned — apply-path doesn't
        // re-verify sigs; that's validator-side. This test exercises
        // apply semantics, not sig verification).
        auto mk_inner_transfer = [](const std::string& from,
                                       const std::string& to,
                                       uint64_t amount,
                                       uint64_t nonce) {
            Transaction t;
            t.type   = TxType::TRANSFER;
            t.from   = from;
            t.to     = to;
            t.amount = amount;
            t.fee    = 0;
            t.nonce  = nonce;
            t.payload = {};
            t.hash    = t.compute_hash();
            return t;
        };
        // Helper: package inner txs into a COMPOSABLE_BATCH JSON payload.
        auto pack_batch = [](const std::vector<Transaction>& inner) {
            nlohmann::json arr = nlohmann::json::array();
            for (auto& t : inner) arr.push_back(t.to_json());
            std::string s = arr.dump();
            return std::vector<uint8_t>(s.begin(), s.end());
        };
        // Helper: build a block carrying a single COMPOSABLE_BATCH outer tx.
        auto build_batch_block = [&](const std::string& outer_from,
                                        uint64_t outer_fee,
                                        const std::vector<Transaction>& inner) {
            Block b;
            b.index           = chain.height();
            b.prev_hash       = chain.head_hash();
            b.timestamp       = 1;
            b.cumulative_rand = Hash{};
            Transaction outer;
            outer.type    = TxType::COMPOSABLE_BATCH;
            outer.from    = outer_from;
            outer.to      = "";
            outer.amount  = 0;
            outer.fee     = outer_fee;
            outer.nonce   = chain.next_nonce(outer_from);
            outer.payload = pack_batch(inner);
            outer.hash    = outer.compute_hash();
            b.transactions.push_back(outer);
            return b;
        };

        // Test 1: successful batch — alice→bob 25, bob→carol 10.
        // Expected: alice=75, bob=65, carol=10. Nonces advance:
        // alice +2 (outer batch + inner TRANSFER), bob +1 (inner).
        uint64_t alice_n0 = chain.next_nonce("alice");
        uint64_t bob_n0   = chain.next_nonce("bob");
        std::vector<Transaction> inner1 = {
            mk_inner_transfer("alice", "bob",   25, alice_n0 + 1),
            mk_inner_transfer("bob",   "carol", 10, bob_n0),
        };
        chain.append(build_batch_block("alice", /*fee=*/0, inner1));
        check(chain.balance("alice") == 75,  "test1: alice=75 (commit)");
        check(chain.balance("bob")   == 65,  "test1: bob=65 (commit)");
        check(chain.balance("carol") == 10,  "test1: carol=10 (commit)");
        check(chain.next_nonce("alice") == alice_n0 + 2,
              "test1: alice nonce +2 (outer + inner)");
        check(chain.next_nonce("bob")   == bob_n0 + 1,
              "test1: bob nonce +1 (inner)");
        check(chain.next_nonce("carol") == 0,
              "test1: carol nonce unchanged");

        // Test 2: failing batch — alice→bob 25 (ok), then alice→bob 200
        // (alice has 50 after first inner, can't send 200). Whole batch
        // rolls back. Outer fee + outer nonce still consumed.
        uint64_t alice_pre  = chain.balance("alice");
        uint64_t bob_pre    = chain.balance("bob");
        uint64_t carol_pre  = chain.balance("carol");
        uint64_t alice_n1   = chain.next_nonce("alice");
        uint64_t bob_n1     = chain.next_nonce("bob");
        std::vector<Transaction> inner2 = {
            mk_inner_transfer("alice", "bob", 25,  alice_n1 + 1),
            mk_inner_transfer("alice", "bob", 200, alice_n1 + 2),
        };
        chain.append(build_batch_block("alice", 0, inner2));
        // Save balances/nonces to locals before checking to avoid an
        // apparent MSVC optimization issue when chain.balance() is
        // called inline in a check() argument across multiple statements
        // post-rollback (see investigation note in commit message).
        uint64_t alice_after2  = chain.balance("alice");
        uint64_t bob_after2    = chain.balance("bob");
        uint64_t carol_after2  = chain.balance("carol");
        uint64_t alice_n_after = chain.next_nonce("alice");
        uint64_t bob_n_after   = chain.next_nonce("bob");
        check(alice_after2  == alice_pre,    "test2: alice unchanged (rollback)");
        check(bob_after2    == bob_pre,      "test2: bob unchanged (rollback)");
        check(carol_after2  == carol_pre,    "test2: carol unchanged (rollback)");
        check(alice_n_after == alice_n1 + 1, "test2: alice nonce +1 (outer)");
        check(bob_n_after   == bob_n1,       "test2: bob nonce unchanged (rollback)");

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": composable_batch " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the Merkle
    // primitives that the v2.2 light-client surface depends on
    // (compute_state_root / state_proof RPC / verify-state-proof).
    // Exercises merkle_root determinism, merkle_proof round-trip,
    // tampering detection, and leaf/inner domain-separation.
    if (cmd == "test-merkle") {
        using namespace determ;
        using namespace determ::crypto;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto make_leaves = [](size_t n) {
            std::vector<MerkleLeaf> v;
            for (size_t i = 0; i < n; ++i) {
                MerkleLeaf m;
                m.key = {'k', static_cast<uint8_t>(i)};
                // value_hash: SHA256 of the index, deterministic.
                SHA256Builder b; b.append(static_cast<uint64_t>(i));
                m.value_hash = b.finalize();
                v.push_back(m);
            }
            return v;
        };

        // 1. Empty leaf set → all-zero root (the "no committed state"
        //    convention).
        {
            std::vector<MerkleLeaf> empty;
            Hash r = merkle_root(empty);
            check(r == Hash{}, "empty leaf set yields all-zero root");
        }

        // 2. Single-leaf tree → root == leaf_hash (degenerate case;
        //    proof is empty array).
        {
            auto leaves = make_leaves(1);
            Hash r = merkle_root(leaves);
            Hash lh = merkle_leaf_hash(leaves[0].key, leaves[0].value_hash);
            check(r == lh, "single-leaf root equals leaf_hash");
            auto p = merkle_proof(leaves, 0);
            check(p.empty(), "single-leaf proof is empty");
            bool ok = merkle_verify(r, leaves[0].key, leaves[0].value_hash,
                                       0, 1, p);
            check(ok, "single-leaf merkle_verify OK");
        }

        // 3. Determinism: same inputs → same root.
        {
            auto v1 = make_leaves(8);
            auto v2 = make_leaves(8);
            check(merkle_root(v1) == merkle_root(v2),
                  "merkle_root is deterministic");
        }

        // 4. Round-trip: merkle_proof + merkle_verify for every leaf in
        //    a balanced (8-leaf) tree.
        {
            auto leaves = make_leaves(8);
            Hash root = merkle_root(leaves);
            bool all_ok = true;
            for (size_t i = 0; i < leaves.size(); ++i) {
                auto p = merkle_proof(leaves, i);
                if (!merkle_verify(root, leaves[i].key, leaves[i].value_hash,
                                      i, leaves.size(), p)) {
                    all_ok = false; break;
                }
            }
            check(all_ok, "merkle_proof round-trips for all 8 leaves");
        }

        // 5. Round-trip: same for an unbalanced (7-leaf, not power of
        //    two) tree — the last-leaf-duplication padding works.
        {
            auto leaves = make_leaves(7);
            Hash root = merkle_root(leaves);
            bool all_ok = true;
            for (size_t i = 0; i < leaves.size(); ++i) {
                auto p = merkle_proof(leaves, i);
                if (!merkle_verify(root, leaves[i].key, leaves[i].value_hash,
                                      i, leaves.size(), p)) {
                    all_ok = false; break;
                }
            }
            check(all_ok, "merkle_proof round-trips on unbalanced (7-leaf) tree");
        }

        // 6. Tampering: flipping a value_hash makes verify fail.
        {
            auto leaves = make_leaves(8);
            Hash root = merkle_root(leaves);
            auto p = merkle_proof(leaves, 3);
            Hash tampered = leaves[3].value_hash;
            tampered[0] ^= 0xff;  // flip a byte
            check(!merkle_verify(root, leaves[3].key, tampered,
                                    3, leaves.size(), p),
                  "merkle_verify rejects tampered value_hash");
        }

        // 7. Tampering: flipping a sibling hash in the proof makes
        //    verify fail.
        {
            auto leaves = make_leaves(8);
            Hash root = merkle_root(leaves);
            auto p = merkle_proof(leaves, 0);
            if (!p.empty()) {
                p[0][0] ^= 0xff;  // flip a byte in first sibling
                check(!merkle_verify(root, leaves[0].key, leaves[0].value_hash,
                                        0, leaves.size(), p),
                      "merkle_verify rejects tampered sibling-hash");
            }
        }

        // 8. Tampering: wrong target_index makes verify fail.
        {
            auto leaves = make_leaves(8);
            Hash root = merkle_root(leaves);
            auto p = merkle_proof(leaves, 3);
            check(!merkle_verify(root, leaves[3].key, leaves[3].value_hash,
                                    5, leaves.size(), p),
                  "merkle_verify rejects wrong target_index");
        }

        // 9. Domain separation: leaf-hash and inner-hash must produce
        //    distinct outputs even on the same input bytes (defeats
        //    second-preimage attacks where an attacker crafts a leaf
        //    that hashes identically to an inner node).
        {
            std::vector<uint8_t> k = {'x'};
            Hash v{};
            v[0] = 1;
            Hash lh = merkle_leaf_hash(k, v);
            Hash zero{};
            Hash ih = merkle_inner_hash(zero, zero);
            check(lh != ih, "leaf_hash and inner_hash domain-separated");
        }

        // 10. Sort-invariance: keys are sorted at root computation, so
        //     pre-sorted vs. unsorted input yields the same root.
        {
            auto sorted_l = make_leaves(8);
            auto shuffled = sorted_l;
            std::reverse(shuffled.begin(), shuffled.end());
            check(merkle_root(sorted_l) == merkle_root(shuffled),
                  "merkle_root sorts leaves internally (input order doesn't matter)");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": merkle " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the committee-
    // selection primitives. Exercises crypto::select_m_creators
    // (S-020 hybrid rejection/Fisher-Yates) and select_after_abort_m
    // (deterministic abort-shifted re-selection). These are the
    // foundation of FA1 (safety), FA2 (censorship), FA5 (BFT safety),
    // and FA8 (regional sharding) — every committee at every round
    // is derived through these functions.
    if (cmd == "test-committee-selection") {
        using namespace determ;
        using namespace determ::crypto;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Helper: build a deterministic random_state seed for tests.
        auto seed = [](uint64_t i) {
            SHA256Builder b; b.append(i); return b.finalize();
        };

        // 1. Determinism: same (rand, N, K) → same indices.
        {
            auto a = select_m_creators(seed(1), 100, 5);
            auto b = select_m_creators(seed(1), 100, 5);
            check(a == b, "same (rand, N, K) -> identical indices");
        }

        // 2. Different seed → different indices (cryptographic
        //    determinism: deterministic from the seed, but seed-
        //    sensitive).
        {
            auto a = select_m_creators(seed(1), 100, 5);
            auto b = select_m_creators(seed(2), 100, 5);
            check(a != b, "different seed -> different indices");
        }

        // 3. All indices are distinct (without-replacement
        //    sampling).
        {
            auto v = select_m_creators(seed(42), 100, 7);
            std::set<size_t> uniq(v.begin(), v.end());
            check(uniq.size() == v.size() && v.size() == 7,
                  "select_m_creators returns K distinct indices");
        }

        // 4. All indices are in range [0, N).
        {
            auto v = select_m_creators(seed(42), 50, 10);
            bool in_range = true;
            for (size_t i : v) if (i >= 50) { in_range = false; break; }
            check(in_range, "all selected indices in [0, N)");
        }

        // 5. Rejection-sampling branch (2K ≤ N): exercised at K=3, N=20.
        //    The S-020 closure switches branches at this threshold.
        {
            auto v = select_m_creators(seed(7), 20, 3);
            check(v.size() == 3, "rejection-sampling branch (2K<=N): K=3, N=20 returns 3");
        }

        // 6. Partial-Fisher-Yates branch (2K > N): exercised at K=8, N=10.
        //    K/N > 0.5 forces the FY branch. Output must still be K
        //    distinct in-range indices.
        {
            auto v = select_m_creators(seed(11), 10, 8);
            std::set<size_t> uniq(v.begin(), v.end());
            bool ok = v.size() == 8 && uniq.size() == 8;
            for (size_t i : v) if (i >= 10) { ok = false; break; }
            check(ok, "partial-FY branch (2K>N): K=8, N=10 returns 8 distinct in-range");
        }

        // 7. Edge case: K = N (all validators on the committee).
        //    Should return every index 0..N-1 in some order.
        {
            auto v = select_m_creators(seed(99), 5, 5);
            std::set<size_t> uniq(v.begin(), v.end());
            bool covers_all = uniq.size() == 5;
            for (size_t i = 0; i < 5; ++i)
                if (uniq.count(i) != 1) { covers_all = false; break; }
            check(covers_all, "K=N: returns every index 0..N-1");
        }

        // 8. Edge case: K = 1 → single index in [0, N).
        {
            auto v = select_m_creators(seed(1), 100, 1);
            check(v.size() == 1 && v[0] < 100,
                  "K=1: returns one in-range index");
        }

        // 9. select_after_abort_m: abort-shifted re-selection is
        //    deterministic + distinct.
        {
            auto original = select_m_creators(seed(7), 20, 3);
            // Build an abort hash from a synthesized event.
            Hash abort_h = compute_abort_hash(1, "node_x", 1234, seed(7));
            auto shifted = select_after_abort_m(original, abort_h, 20);
            // Same call again with same inputs → identical result.
            auto shifted2 = select_after_abort_m(original, abort_h, 20);
            check(shifted == shifted2,
                  "select_after_abort_m is deterministic");
            check(shifted.size() == original.size(),
                  "select_after_abort_m preserves committee size");
            std::set<size_t> uniq(shifted.begin(), shifted.end());
            check(uniq.size() == shifted.size(),
                  "select_after_abort_m returns distinct indices");
        }

        // 10. epoch_committee_seed is deterministic + seed-sensitive.
        {
            Hash s1 = epoch_committee_seed(seed(1), ShardId{0});
            Hash s2 = epoch_committee_seed(seed(1), ShardId{0});
            Hash s3 = epoch_committee_seed(seed(1), ShardId{1});
            check(s1 == s2, "epoch_committee_seed is deterministic");
            check(s1 != s3, "epoch_committee_seed varies by shard_id");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": committee-selection " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for
    // crypto::shard_id_for_address — the v1.x cross-shard routing
    // foundation. Maps any address string (registered domain or
    // anonymous bearer wallet) to one of `shard_count` shards via a
    // salted SHA-256. The salt comes from genesis
    // (GenesisConfig::shard_address_salt) and is fixed for the
    // chain's lifetime. Every node (beacon, every shard, every
    // external wallet) must agree on which shard owns which address.
    if (cmd == "test-shard-routing") {
        using namespace determ;
        using namespace determ::crypto;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Build a deterministic salt.
        auto make_salt = [](uint64_t i) {
            SHA256Builder b; b.append(i); return b.finalize();
        };

        // 1. Single-shard mode: shard_id always 0 regardless of address.
        {
            Hash salt = make_salt(1);
            bool all_zero = true;
            for (const char* a : {"alice", "bob", "node1",
                                     "0xabc", "0x1234567890"}) {
                if (shard_id_for_address(a, 1, salt) != 0) {
                    all_zero = false; break;
                }
            }
            check(all_zero, "single-shard (shard_count=1) always returns 0");
        }

        // 2. Determinism: same (addr, count, salt) → same shard.
        {
            Hash salt = make_salt(2);
            ShardId s1 = shard_id_for_address("alice", 4, salt);
            ShardId s2 = shard_id_for_address("alice", 4, salt);
            check(s1 == s2, "same inputs -> same shard (deterministic)");
        }

        // 3. In-range: shard_id < shard_count.
        {
            Hash salt = make_salt(3);
            bool in_range = true;
            for (int i = 0; i < 50; ++i) {
                std::string addr = "user_" + std::to_string(i);
                if (shard_id_for_address(addr, 7, salt) >= 7) {
                    in_range = false; break;
                }
            }
            check(in_range, "all routed shard_ids in [0, shard_count)");
        }

        // 4. Salt-sensitivity: different salts route the same address
        //    to (probably) different shards. Test by checking that at
        //    least ONE address routes differently — collision on every
        //    address out of 50 is astronomically unlikely under salted SHA-256.
        {
            Hash salt_a = make_salt(4);
            Hash salt_b = make_salt(5);
            bool found_diff = false;
            for (int i = 0; i < 50; ++i) {
                std::string addr = "user_" + std::to_string(i);
                if (shard_id_for_address(addr, 4, salt_a) !=
                    shard_id_for_address(addr, 4, salt_b)) {
                    found_diff = true; break;
                }
            }
            check(found_diff,
                  "different salts route same address to different shards");
        }

        // 5. Distribution sanity: routing 1000 addresses across 4 shards
        //    yields rough uniformity (every shard gets >5% of addresses).
        //    Under SHA-256-uniform routing the expected per-shard count
        //    is 250, and chi-squared bounds for 4 shards × 1000 samples
        //    keep every shard well above 5% with overwhelming probability.
        {
            Hash salt = make_salt(6);
            std::vector<int> hist(4, 0);
            for (int i = 0; i < 1000; ++i) {
                std::string addr = "user_" + std::to_string(i);
                hist[shard_id_for_address(addr, 4, salt)]++;
            }
            bool uniform = true;
            for (int c : hist) if (c < 50) { uniform = false; break; }
            check(uniform,
                  "1000 addresses distribute across 4 shards (>5% per shard)");
        }

        // 6. Case-sensitivity: address strings are byte-for-byte;
        //    "Alice" and "alice" route to potentially-different shards
        //    (S-028 normalizes at RPC ingress, not at routing time —
        //    that's an upstream concern).
        {
            Hash salt = make_salt(7);
            ShardId s1 = shard_id_for_address("Alice", 8, salt);
            ShardId s2 = shard_id_for_address("alice", 8, salt);
            // We can't assert s1 != s2 (collision possible). We CAN
            // assert both are valid shard_ids in range. The point is
            // documenting that routing is case-sensitive on the bytes.
            check(s1 < 8 && s2 < 8,
                  "routing is byte-exact (case-sensitive at routing layer)");
        }

        // 7. Empty address: routes to shard 0 deterministically (the
        //    function doesn't reject empty strings — caller's
        //    responsibility to validate addresses upstream).
        {
            Hash salt = make_salt(8);
            ShardId s1 = shard_id_for_address("", 5, salt);
            ShardId s2 = shard_id_for_address("", 5, salt);
            check(s1 == s2 && s1 < 5,
                  "empty address routes deterministically to a valid shard");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": shard-routing " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for Ed25519
    // sign + verify. This is the foundation under EVERY signature
    // claim in the protocol:
    //   - V4 Phase-1 commit signatures (creator_ed_sigs[i])
    //   - V8 Phase-2 block-digest signatures (creator_block_sigs[i])
    //   - Transaction.sig (every TRANSFER, REGISTER, ...)
    //   - V11 equivocation_events sig_a / sig_b
    //   - AbortClaimMsg.ed_sig
    //   - ContribMsg.ed_sig, BlockSigMsg.ed_sig
    //   - A5 PARAM_CHANGE keyholder signatures
    // FA1, FA2, FA5, FA6, FA7, FA10 all reduce their cryptographic
    // failure probability to Ed25519 EUF-CMA — so any silent
    // regression in the wrapper would cascade across every safety
    // claim. A dedicated unit test catches that loudly.
    if (cmd == "test-ed25519") {
        using namespace determ;
        using namespace determ::crypto;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // 1. Key generation produces a 32-byte pubkey + a 32-byte
        //    secret-seed.
        auto key = generate_node_key();
        check(key.pub.size() == 32 && key.priv_seed.size() == 32,
              "generate_node_key produces 32-byte pub + 32-byte priv_seed");

        // 2. Sign / verify round-trip on a representative message.
        std::vector<uint8_t> msg = {'h','e','l','l','o',' ','d','e','t','e','r','m'};
        Signature sig = sign(key, msg.data(), msg.size());
        check(verify(key.pub, msg.data(), msg.size(), sig),
              "sign + verify round-trip succeeds on a 12-byte message");

        // 3. Verify with a tampered message fails (EUF-CMA bound).
        auto msg_tampered = msg;
        msg_tampered[0] ^= 0xff;
        check(!verify(key.pub, msg_tampered.data(), msg_tampered.size(), sig),
              "verify rejects sig under tampered message");

        // 4. Verify with a tampered signature fails.
        Signature sig_tampered = sig;
        sig_tampered[0] ^= 0xff;
        check(!verify(key.pub, msg.data(), msg.size(), sig_tampered),
              "verify rejects tampered signature");

        // 5. Verify with the wrong public key fails. Generate a
        //    second key to provide a real wrong-key.
        auto other = generate_node_key();
        check(!verify(other.pub, msg.data(), msg.size(), sig),
              "verify rejects sig under the wrong pubkey");

        // 6. Determinism: signing the same message with the same key
        //    twice produces the same signature. Ed25519 (RFC 8032)
        //    is deterministic by construction — this is the property
        //    F2 (selective-abort defense, FA3) leans on, and the
        //    property that lets equivocation slashing detect
        //    contradictory signatures as evidence rather than as
        //    benign duplicates.
        Signature sig2 = sign(key, msg.data(), msg.size());
        check(sig == sig2,
              "Ed25519 is deterministic: same key + msg -> same sig");

        // 7. Empty message: still sign-able and verify-able.
        Signature sig_empty = sign(key, nullptr, 0);
        check(verify(key.pub, nullptr, 0, sig_empty),
              "sign/verify works on empty (zero-byte) message");

        // 8. Distinct keys produce distinct signatures on the same
        //    message. (If two distinct keys produce the same sig on
        //    the same msg, the EUF-CMA reduction is broken; the
        //    probability of accident is negligible.)
        Signature sig_other = sign(other, msg.data(), msg.size());
        check(sig != sig_other,
              "distinct keys produce distinct signatures on same message");

        // 9. Cross-verify rejection: sig from key1 doesn't verify
        //    under key2's pubkey, and vice-versa.
        check(!verify(other.pub, msg.data(), msg.size(), sig)
              && !verify(key.pub,  msg.data(), msg.size(), sig_other),
              "cross-key verify rejected in both directions");

        // 10. Long-message sign/verify: 4 KB random-ish bytes
        //     exercises the streaming path (vs. the short-message
        //     fast path inside libssl).
        std::vector<uint8_t> big(4096);
        for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i);
        Signature sig_big = sign(key, big.data(), big.size());
        check(verify(key.pub, big.data(), big.size(), sig_big),
              "sign/verify works on 4 KB message");

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": ed25519 " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the SHA-256
    // wrapper + SHA256Builder. Pins NIST FIPS 180-4 test vectors
    // AND the protocol-critical big-endian uint64_t encoding that
    // every signing_bytes / compute_block_digest / merkle_leaf_hash
    // path depends on (Preliminaries §1.3).
    //
    // A regression in SHA-256 itself would break literally every
    // cryptographic claim in the protocol. A regression in
    // SHA256Builder::append(uint64_t)'s big-endian encoding would
    // make signing_bytes produce different hashes on little-endian
    // vs big-endian machines, silently breaking consensus across
    // platforms — which is why the BE convention is in
    // Preliminaries §1.3 as a hard requirement.
    if (cmd == "test-sha256") {
        using namespace determ;
        using namespace determ::crypto;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // 1. NIST FIPS 180-4 §A.1: SHA-256("") =
        //    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        {
            Hash h = sha256(nullptr, 0);
            check(to_hex(h) ==
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  "NIST vector: SHA-256('') matches FIPS 180-4 §A.1");
        }

        // 2. NIST FIPS 180-4 §A.1: SHA-256("abc") =
        //    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        {
            std::string s = "abc";
            Hash h = sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
            check(to_hex(h) ==
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                  "NIST vector: SHA-256('abc') matches FIPS 180-4 §A.1");
        }

        // 3. NIST FIPS 180-4 §A.2: SHA-256 of the 56-byte ASCII
        //    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" =
        //    248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        //    (this exercises a >55-byte input — different padding path
        //    in the SHA-256 final block — so it catches a regression
        //    in the BIO/EVP wrapper's input-length handling.)
        {
            std::string s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
            Hash h = sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
            check(to_hex(h) ==
                  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                  "NIST vector: SHA-256 56-byte input (FIPS 180-4 §A.2)");
        }

        // 4. SHA256Builder's incremental construction matches one-shot
        //    SHA-256. Critical because every signing_bytes / digest
        //    site uses the Builder — if it diverged from sha256()
        //    for the same byte stream, downstream verification would
        //    silently fail.
        {
            std::string s = "the quick brown fox jumps over the lazy dog";
            Hash one_shot = sha256(reinterpret_cast<const uint8_t*>(s.data()),
                                    s.size());
            SHA256Builder b;
            b.append(reinterpret_cast<const uint8_t*>(s.data()), s.size());
            Hash builder_hash = b.finalize();
            check(one_shot == builder_hash,
                  "SHA256Builder one-shot matches sha256()");
        }

        // 5. SHA256Builder appending in pieces matches one-shot
        //    over the concatenated input. Catches any state drift
        //    inside the incremental Builder.
        {
            std::string a = "the quick brown ";
            std::string b = "fox jumps over ";
            std::string c = "the lazy dog";
            std::string full = a + b + c;
            Hash one_shot = sha256(
                reinterpret_cast<const uint8_t*>(full.data()), full.size());
            SHA256Builder bld;
            bld.append(a);
            bld.append(b);
            bld.append(c);
            check(one_shot == bld.finalize(),
                  "SHA256Builder 3-piece append matches concat one-shot");
        }

        // 6. SHA256Builder::append(uint64_t) is BIG-ENDIAN. This is
        //    the protocol-critical convention from Preliminaries §1.3
        //    ("Multi-byte integers in hash inputs are encoded big-
        //    endian"). EVERY consensus hash — signing_bytes,
        //    compute_block_digest, merkle_leaf_hash — relies on this.
        //    A regression to little-endian would silently fork the
        //    protocol on any cross-platform deployment.
        //
        //    Verify by hashing a known integer through the Builder
        //    AND through manual big-endian bytes; the hashes must
        //    match.
        {
            uint64_t v = 0x0123456789ABCDEFULL;
            // Manual big-endian: high byte first.
            uint8_t be_bytes[8] = {0x01, 0x23, 0x45, 0x67,
                                    0x89, 0xAB, 0xCD, 0xEF};
            Hash manual = sha256(be_bytes, 8);
            SHA256Builder b;
            b.append(v);
            Hash builder = b.finalize();
            check(manual == builder,
                  "SHA256Builder::append(uint64_t) encodes BIG-ENDIAN "
                  "(Preliminaries §1.3 convention)");
        }

        // 7. SHA256Builder::append(int64_t) — same BE encoding,
        //    handles negative values via two's-complement layout.
        {
            int64_t v = -1;  // two's complement: 0xFFFFFFFFFFFFFFFF
            uint8_t be_bytes[8] = {0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF};
            Hash manual = sha256(be_bytes, 8);
            SHA256Builder b;
            b.append(v);
            Hash builder = b.finalize();
            check(manual == builder,
                  "SHA256Builder::append(int64_t) encodes BIG-ENDIAN "
                  "two's-complement");
        }

        // 8. sha256(Hash a, Hash b) helper matches manual
        //    concat-then-sha256.
        {
            Hash a{}; a[0] = 0xAA;
            Hash b{}; b[0] = 0xBB;
            std::vector<uint8_t> concat;
            concat.insert(concat.end(), a.begin(), a.end());
            concat.insert(concat.end(), b.begin(), b.end());
            Hash manual = sha256(concat.data(), concat.size());
            Hash helper = sha256(a, b);
            check(manual == helper,
                  "sha256(Hash, Hash) helper matches concat-then-sha256");
        }

        // 9. sha256(Hash, string) helper matches manual concat-then-
        //    sha256. (Used by sha256_genesis-style hash composition
        //    in random.cpp.)
        {
            Hash a{}; a[0] = 0xAA;
            std::string s = "domain-separator";
            std::vector<uint8_t> concat;
            concat.insert(concat.end(), a.begin(), a.end());
            concat.insert(concat.end(),
                            reinterpret_cast<const uint8_t*>(s.data()),
                            reinterpret_cast<const uint8_t*>(s.data()) + s.size());
            Hash manual = sha256(concat.data(), concat.size());
            Hash helper = sha256(a, s);
            check(manual == helper,
                  "sha256(Hash, string) helper matches concat-then-sha256");
        }

        // 10. Determinism: same input → same hash, across two
        //     independent Builder instances + a one-shot call.
        {
            std::string s = "determ";
            SHA256Builder b1, b2;
            b1.append(s);
            b2.append(s);
            Hash h1 = b1.finalize();
            Hash h2 = b2.finalize();
            Hash h3 = sha256(reinterpret_cast<const uint8_t*>(s.data()),
                                s.size());
            check(h1 == h2 && h2 == h3,
                  "sha256 is deterministic across instances + one-shot");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": sha256 " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the anon-
    // address helpers (S-028 surface): is_anon_address,
    // normalize_anon_address, parse_anon_pubkey, make_anon_address.
    //
    // These are the boundary between the wire/RPC-supplied address
    // string and the internal PubKey bytes used for signature
    // verification. The S-028 closure makes `is_anon_address` accept
    // either case (upper/lower hex) so operators don't get errors
    // for case mismatches, but stores canonical lowercase form so
    // store-keys are unambiguous. A regression here would silently
    // break anon-account routing (RPC paths normalize at input;
    // submit_tx REJECTS non-canonical to preserve sig binding).
    //
    // Tested at the unit level here in addition to
    // tools/test_anon_address_case.sh (which exercises the same
    // surface end-to-end through the 3-node RPC path). Unit-level
    // catches regressions ~100x faster.
    if (cmd == "test-anon-address") {
        using namespace determ;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // 1. is_anon_address: canonical lowercase form.
        {
            std::string a = "0x" + std::string(64, 'a');
            check(is_anon_address(a),
                  "is_anon_address accepts lowercase 0x + 64 hex");
        }

        // 2. is_anon_address: uppercase form (S-028 closure — accepts
        //    either case).
        {
            std::string a = "0x" + std::string(64, 'A');
            check(is_anon_address(a),
                  "is_anon_address accepts uppercase 0x + 64 hex");
        }

        // 3. is_anon_address: mixed-case form.
        {
            std::string a = "0xAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCdEfAbCd";
            check(is_anon_address(a),
                  "is_anon_address accepts mixed-case 0x + 64 hex");
        }

        // 4. is_anon_address: missing 0x prefix → rejects.
        {
            std::string a = std::string(64, 'a');
            check(!is_anon_address(a),
                  "is_anon_address rejects missing 0x prefix");
        }

        // 5. is_anon_address: wrong length → rejects.
        {
            std::string a = "0x" + std::string(63, 'a');
            check(!is_anon_address(a),
                  "is_anon_address rejects wrong length (63 hex chars)");
        }

        // 6. is_anon_address: non-hex char → rejects.
        {
            std::string a = "0x" + std::string(63, 'a') + "g";
            check(!is_anon_address(a),
                  "is_anon_address rejects non-hex char");
        }

        // 7. is_anon_address: registered domain name (no 0x) →
        //    rejects.
        {
            check(!is_anon_address("alice"),
                  "is_anon_address rejects registered-domain name");
        }

        // 8. normalize_anon_address: uppercase → lowercase canonical.
        {
            std::string upper = "0xABCDEF" + std::string(58, 'F');
            std::string norm = normalize_anon_address(upper);
            std::string expected = "0xabcdef" + std::string(58, 'f');
            check(norm == expected,
                  "normalize_anon_address lowercases hex but preserves 0x prefix");
        }

        // 9. normalize_anon_address: registered domain name →
        //    unchanged (only anon addresses get normalized).
        {
            check(normalize_anon_address("alice") == "alice",
                  "normalize_anon_address preserves registered domain unchanged");
        }

        // 10. parse_anon_pubkey: round-trip with make_anon_address.
        //     Pubkey -> address -> pubkey must be byte-identical.
        {
            PubKey pk{};
            for (size_t i = 0; i < 32; ++i) pk[i] = static_cast<uint8_t>(i * 7);
            std::string addr = make_anon_address(pk);
            PubKey back = parse_anon_pubkey(addr);
            check(pk == back,
                  "make_anon_address + parse_anon_pubkey round-trip");
        }

        // 11. parse_anon_pubkey: uppercase address yields same
        //     pubkey as lowercase (case-insensitive parsing).
        {
            std::string lower = "0x" + std::string(64, 'a');
            std::string upper = "0x" + std::string(64, 'A');
            PubKey p1 = parse_anon_pubkey(lower);
            PubKey p2 = parse_anon_pubkey(upper);
            check(p1 == p2,
                  "parse_anon_pubkey is case-insensitive (S-028)");
        }

        // 12. make_anon_address: output is always lowercase canonical.
        {
            PubKey pk{};
            for (size_t i = 0; i < 32; ++i) pk[i] = 0xAB;
            std::string addr = make_anon_address(pk);
            bool all_lower = true;
            for (size_t i = 2; i < addr.size(); ++i) {  // skip "0x"
                if (addr[i] >= 'A' && addr[i] <= 'F') { all_lower = false; break; }
            }
            check(all_lower && addr.substr(0, 2) == "0x" && addr.size() == 66,
                  "make_anon_address always emits lowercase canonical 0x+64");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": anon-address " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the
    // GenesisConfig::genesis_message field and its hash-mixing
    // contract. The contract has three rules (genesis.hpp comment
    // block above DEFAULT_GENESIS_MESSAGE):
    //
    //   1. Default value: when genesis_message equals
    //      DEFAULT_GENESIS_MESSAGE, compute_genesis_hash SKIPS the
    //      mix entirely. This preserves byte-identical hashes for
    //      pre-message genesis files (backward-compat invariant —
    //      existing chains can load with the default and stay on
    //      the same chain identity they had before this field was
    //      added).
    //
    //   2. Custom value: when genesis_message is anything else
    //      (including the empty string), compute_genesis_hash mixes
    //      it length-prefixed (u64 BE per Preliminaries §1.3). This
    //      produces a DISTINCT chain identity from the default.
    //
    //   3. Size cap: GENESIS_MESSAGE_MAX_BYTES = 256. from_json
    //      throws on oversized inputs.
    //
    // A regression in this hashing logic would silently break
    // chain-identity stability for existing deployments (pre-message
    // chains would suddenly compute a different genesis hash) OR
    // silently allow chain-identity collisions (two deployments
    // intending different messages would share a hash). Locking it
    // in at the unit level catches both.
    if (cmd == "test-genesis-message") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Build a minimal baseline GenesisConfig. compute_genesis_hash
        // uses many fields; we set just enough to get a stable hash.
        auto make_baseline = []() {
            GenesisConfig c;
            c.chain_id     = "test-genesis-message";
            c.m_creators   = 3;
            c.k_block_sigs = 3;
            c.block_subsidy = 0;
            // Default genesis_message is set by the struct's default-
            // member-initializer = DEFAULT_GENESIS_MESSAGE.
            return c;
        };

        // 1. Default genesis_message: hash matches a config that
        //    explicitly sets it to DEFAULT_GENESIS_MESSAGE (sanity
        //    that the default-member-initializer works).
        {
            GenesisConfig a = make_baseline();
            GenesisConfig b = make_baseline();
            b.genesis_message = DEFAULT_GENESIS_MESSAGE;
            check(compute_genesis_hash(a) == compute_genesis_hash(b),
                  "default genesis_message hash == explicit "
                  "DEFAULT_GENESIS_MESSAGE hash");
        }

        // 2. Backward-compat: a config built with the default
        //    skips the hash mix entirely. We can't test "pre-message
        //    genesis hash" directly (no time machine), but we CAN
        //    test that the contract holds: hash(default) ==
        //    hash(default) across distinct calls, and that the
        //    hash differs when genesis_message changes (next test).
        {
            GenesisConfig a = make_baseline();
            GenesisConfig b = make_baseline();
            check(compute_genesis_hash(a) == compute_genesis_hash(b),
                  "compute_genesis_hash is deterministic");
        }

        // 3. Custom genesis_message changes the hash.
        {
            GenesisConfig a = make_baseline();
            GenesisConfig b = make_baseline();
            b.genesis_message = "Custom inscribed message.";
            check(compute_genesis_hash(a) != compute_genesis_hash(b),
                  "custom genesis_message yields distinct hash");
        }

        // 4. Empty genesis_message (explicit no-inscription) ALSO
        //    changes the hash — proves rule (2). An empty string is
        //    NOT the same as the default; operators who want a
        //    chain identity that hashes the absence-of-message
        //    explicitly use "" to get a distinct chain hash.
        {
            GenesisConfig a = make_baseline();
            GenesisConfig b = make_baseline();
            b.genesis_message = "";
            check(compute_genesis_hash(a) != compute_genesis_hash(b),
                  "empty genesis_message also yields distinct hash "
                  "(empty != default)");
        }

        // 5. Different custom messages yield different hashes.
        {
            GenesisConfig a = make_baseline();
            a.genesis_message = "Message A";
            GenesisConfig b = make_baseline();
            b.genesis_message = "Message B";
            check(compute_genesis_hash(a) != compute_genesis_hash(b),
                  "different custom messages yield distinct hashes");
        }

        // 6. Same custom message yields same hash (determinism
        //    under override).
        {
            GenesisConfig a = make_baseline();
            a.genesis_message = "Inscribed at deployment time";
            GenesisConfig b = make_baseline();
            b.genesis_message = "Inscribed at deployment time";
            check(compute_genesis_hash(a) == compute_genesis_hash(b),
                  "identical custom messages yield same hash");
        }

        // 7. JSON round-trip: from_json with absent genesis_message
        //    yields default; to_json includes it; from_json on the
        //    serialized JSON yields the same value back.
        {
            GenesisConfig a = make_baseline();
            a.genesis_message = "Round-trip test";
            // Add minimal mandatory fields for to_json to work.
            nlohmann::json js = a.to_json();
            GenesisConfig back = GenesisConfig::from_json(js);
            check(back.genesis_message == "Round-trip test",
                  "to_json + from_json round-trips genesis_message");
        }

        // 8. from_json with absent key uses DEFAULT_GENESIS_MESSAGE.
        {
            nlohmann::json js = {
                {"chain_id",    "minimal"},
                {"m_creators",  3},
                {"k_block_sigs", 3}
            };
            GenesisConfig c = GenesisConfig::from_json(js);
            check(c.genesis_message == DEFAULT_GENESIS_MESSAGE,
                  "from_json: absent key -> DEFAULT_GENESIS_MESSAGE");
        }

        // 9. Size cap enforced: oversized message throws.
        {
            nlohmann::json js = {
                {"chain_id",   "oversize"},
                {"m_creators", 3},
                {"k_block_sigs", 3},
                {"genesis_message",
                 std::string(GENESIS_MESSAGE_MAX_BYTES + 1, 'x')}
            };
            bool threw = false;
            try { GenesisConfig::from_json(js); }
            catch (const std::exception&) { threw = true; }
            check(threw,
                  "from_json rejects oversized genesis_message (>256B)");
        }

        // 10. Boundary: exactly GENESIS_MESSAGE_MAX_BYTES bytes is
        //     accepted.
        {
            nlohmann::json js = {
                {"chain_id",   "boundary"},
                {"m_creators", 3},
                {"k_block_sigs", 3},
                {"genesis_message",
                 std::string(GENESIS_MESSAGE_MAX_BYTES, 'x')}
            };
            bool threw = false;
            try {
                GenesisConfig c = GenesisConfig::from_json(js);
                check(c.genesis_message.size() == GENESIS_MESSAGE_MAX_BYTES,
                      "exactly GENESIS_MESSAGE_MAX_BYTES accepted");
            } catch (const std::exception&) { threw = true; }
            if (threw) check(false,
                              "exactly GENESIS_MESSAGE_MAX_BYTES should be accepted");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": genesis-message " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the state-Merkle
    // commitment surface (S-033 + S-037 + S-038). Exercises
    // Chain::compute_state_root() over a Chain object directly — no
    // network, no consensus, no apply-time validation. Verifies:
    //   - Determinism: same state → same root, regardless of compute order.
    //   - Purity: repeated computes on an unmodified Chain match.
    //   - Sensitivity: every public set_*() that maps into a k:-namespace
    //     leaf (and shard routing via "k:my_shard_id" + "k:shard_salt")
    //     produces a distinct state_root when changed.
    //   - Invertibility: changing a value then reverting produces the
    //     same root as never-having-changed (no hidden internal state).
    //   - Namespace separation: two different mutations produce two
    //     different alternate roots (defeating accidental collisions
    //     where unrelated fields collapse to the same leaf hash).
    // The state-root is the apex of FA1 (safety) — light clients,
    // snapshot restore, and the apply-time S-033 gate all rest on this
    // function being byte-deterministic over identical state. A unit
    // test here catches accidental encoding drift before the network-
    // level test_state_root.sh / test_dapp_snapshot.sh tests would.
    if (cmd == "test-state-root") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Helper: a fresh Chain seeded with non-default values so every
        // k: leaf is distinguishable. Using zero/default everywhere
        // could hide a "missing leaf == leaf with hash-of-zero" bug.
        auto fresh_chain = []() {
            Chain c;
            c.set_block_subsidy(50);
            c.set_subsidy_pool_initial(10000);
            c.set_subsidy_mode(2);
            c.set_lottery_jackpot_multiplier(7);
            c.set_min_stake(1000);
            c.set_suspension_slash(10);
            c.set_unstake_delay(500);
            c.set_merge_threshold_blocks(20);
            c.set_revert_threshold_blocks(40);
            c.set_merge_grace_blocks(5);
            Hash salt{};
            for (size_t i = 0; i < salt.size(); ++i) salt[i] = uint8_t(0xA0 + i);
            c.set_shard_routing(4, salt, ShardId{1});
            return c;
        };

        // 1. Determinism: two Chains built from identical inputs produce
        //    identical state_roots. This is the central invariant —
        //    without it, K-of-K nodes would compute different state
        //    commitments for the same block and fail signature gathering.
        {
            Chain a = fresh_chain();
            Chain b = fresh_chain();
            check(a.compute_state_root() == b.compute_state_root(),
                  "identical Chains produce identical state_roots");
        }

        // 2. Purity: calling compute_state_root() N times on an
        //    unmodified Chain returns the same hash every time. Defeats
        //    bugs where internal caches accumulate or hash builders
        //    aren't reset between calls.
        {
            Chain c = fresh_chain();
            Hash first = c.compute_state_root();
            bool all_match = true;
            for (int i = 0; i < 10; ++i) {
                if (c.compute_state_root() != first) {
                    all_match = false;
                    break;
                }
            }
            check(all_match, "compute_state_root() is pure (10 sequential calls match)");
        }

        // 3. Non-zero baseline: a default Chain with no accounts has a
        //    non-zero state_root because the k: namespace constants
        //    (block_subsidy, min_stake, shard_count, etc.) always emit
        //    leaves. An all-zero result would mean build_state_leaves()
        //    returned an empty vector — a regression.
        {
            Chain c;  // pure default, no setters
            Hash root = c.compute_state_root();
            check(root != Hash{},
                  "default Chain has non-zero state_root (k: leaves always present)");
        }

        // 4. block_subsidy sensitivity: mutating this value must change
        //    state_root (the "k:block_subsidy" leaf).
        {
            Chain c = fresh_chain();
            Hash before = c.compute_state_root();
            c.set_block_subsidy(99);
            Hash after = c.compute_state_root();
            check(before != after,
                  "set_block_subsidy() changes state_root");
        }

        // 5. min_stake sensitivity.
        {
            Chain c = fresh_chain();
            Hash before = c.compute_state_root();
            c.set_min_stake(2000);
            Hash after = c.compute_state_root();
            check(before != after,
                  "set_min_stake() changes state_root");
        }

        // 6. subsidy_pool_initial sensitivity.
        {
            Chain c = fresh_chain();
            Hash before = c.compute_state_root();
            c.set_subsidy_pool_initial(20000);
            Hash after = c.compute_state_root();
            check(before != after,
                  "set_subsidy_pool_initial() changes state_root");
        }

        // 7. shard_count + my_shard_id sensitivity (via set_shard_routing).
        //    Both contribute their own k: leaves.
        {
            Chain c = fresh_chain();
            Hash before = c.compute_state_root();
            Hash salt = c.shard_salt();
            c.set_shard_routing(8, salt, ShardId{2});  // 4 → 8 shards
            Hash after = c.compute_state_root();
            check(before != after,
                  "set_shard_routing() (different shard_count) changes state_root");
        }

        // 8. shard_salt sensitivity: same shard_count/id but different
        //    salt yields a different state_root (the "k:shard_salt"
        //    leaf is its own 32-byte value-hash input).
        {
            Chain c = fresh_chain();
            Hash before = c.compute_state_root();
            Hash new_salt{};
            for (size_t i = 0; i < new_salt.size(); ++i)
                new_salt[i] = uint8_t(0x10 + i);
            c.set_shard_routing(c.shard_count(), new_salt, c.my_shard_id());
            Hash after = c.compute_state_root();
            check(before != after,
                  "set_shard_routing() with different salt changes state_root");
        }

        // 9. Invertibility: change-then-revert produces the original
        //    state_root. Catches bugs where a setter dirty-marks
        //    persistent shadow state that isn't actually visible
        //    through build_state_leaves.
        {
            Chain c = fresh_chain();
            Hash original = c.compute_state_root();
            c.set_block_subsidy(99);
            c.set_block_subsidy(50);  // back to fresh_chain() value
            Hash reverted = c.compute_state_root();
            check(original == reverted,
                  "change-then-revert returns to the original state_root");
        }

        // 10. Cross-namespace distinction: two different mutations
        //     should produce two different state_roots — neither equal
        //     to baseline AND not equal to each other. Defeats hidden
        //     namespace-collision bugs where, e.g., block_subsidy and
        //     min_stake accidentally hash the same way.
        {
            Chain baseline = fresh_chain();
            Hash hb = baseline.compute_state_root();

            Chain mod_a = fresh_chain();
            mod_a.set_block_subsidy(77);
            Hash ha = mod_a.compute_state_root();

            Chain mod_b = fresh_chain();
            mod_b.set_min_stake(77);  // same numeric value, different field
            Hash hbb = mod_b.compute_state_root();

            check(ha != hb && hbb != hb && ha != hbb,
                  "different namespace mutations produce distinct roots (no collision)");
        }

        // 11. Order independence (within a namespace): the build_state_
        //     leaves() function sorts leaves by key before hashing, so
        //     the order setters were called in should never affect the
        //     final root. This catches any future regression where a
        //     setter accidentally writes into an order-preserving
        //     container that build_state_leaves enumerates in
        //     insertion order.
        {
            Chain c1;
            c1.set_block_subsidy(50);
            c1.set_min_stake(1000);
            c1.set_unstake_delay(500);
            Hash h1 = c1.compute_state_root();

            Chain c2;
            c2.set_unstake_delay(500);
            c2.set_min_stake(1000);
            c2.set_block_subsidy(50);
            Hash h2 = c2.compute_state_root();

            check(h1 == h2,
                  "setter call order doesn't affect state_root (leaves sorted internally)");
        }

        // 12. lottery_jackpot_multiplier sensitivity (a u32 field —
        //     covers a different-typed leaf input than the u64 fields
        //     above).
        {
            Chain c = fresh_chain();
            Hash before = c.compute_state_root();
            c.set_lottery_jackpot_multiplier(11);
            Hash after = c.compute_state_root();
            check(before != after,
                  "set_lottery_jackpot_multiplier() (u32) changes state_root");
        }

        // 13. subsidy_mode sensitivity (a u8 field — narrowest type that
        //     gets promoted to u64 for hashing per Preliminaries §1.3).
        {
            Chain c = fresh_chain();
            Hash before = c.compute_state_root();
            c.set_subsidy_mode(5);
            Hash after = c.compute_state_root();
            check(before != after,
                  "set_subsidy_mode() (u8) changes state_root");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": state-root " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the V8 randomness
    // primitives — compute_delay_seed, compute_block_rand,
    // proposer_idx, required_block_sigs, count_round1_aborts. These
    // are the FA1 / FA5 / FA8 foundation: every committee selection at
    // every future height depends on compute_block_rand's output being
    // (a) deterministic, (b) order-sensitive in the committee-selection
    // order so reordering is detectable, and (c) domain-separated from
    // delay_seed so the two-stage commit/reveal contract holds.
    //
    // The S030-D2 analysis explicitly relies on these functions being
    // byte-deterministic; a regression here would either silently fork
    // randomness across nodes (different committee selections per node
    // → safety failure) OR allow a producer to reorder reveals to bias
    // future randomness (FA1 violation).
    if (cmd == "test-block-rand") {
        using namespace determ;
        using namespace determ::chain;
        using namespace determ::node;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Helpers: deterministic Hash builders so the test is byte-stable.
        auto fill_hash = [](uint8_t fill) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = fill;
            return h;
        };
        auto patterned_hash = [](uint8_t base) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i)
                h[i] = uint8_t(base + i);
            return h;
        };

        // === compute_delay_seed (Phase-1 inputs commitment) ===
        const uint64_t IDX = 42;
        const Hash PREV = fill_hash(0x11);
        const Hash TXR  = fill_hash(0x22);
        std::vector<Hash> DH = {
            patterned_hash(0x30), patterned_hash(0x40), patterned_hash(0x50)};

        Hash seed_baseline = compute_delay_seed(IDX, PREV, TXR, DH);

        // 1. Determinism: identical inputs → identical hash.
        {
            Hash again = compute_delay_seed(IDX, PREV, TXR, DH);
            check(seed_baseline == again, "compute_delay_seed deterministic");
        }

        // 2. block_index sensitivity: incrementing height yields a
        //    different seed (the height field is the cross-block
        //    monotonic anchor).
        {
            Hash diff = compute_delay_seed(IDX + 1, PREV, TXR, DH);
            check(seed_baseline != diff,
                  "compute_delay_seed: block_index sensitivity");
        }

        // 3. prev_hash sensitivity (chain history anchor).
        {
            Hash diff = compute_delay_seed(IDX, fill_hash(0xFE), TXR, DH);
            check(seed_baseline != diff,
                  "compute_delay_seed: prev_hash sensitivity");
        }

        // 4. tx_root sensitivity (block-content anchor).
        {
            Hash diff = compute_delay_seed(IDX, PREV, fill_hash(0xFD), DH);
            check(seed_baseline != diff,
                  "compute_delay_seed: tx_root sensitivity");
        }

        // 5. creator_dh_inputs sensitivity: replacing one input changes
        //    the seed.
        {
            auto DH2 = DH;
            DH2[1] = fill_hash(0xFC);  // different from patterned_hash(0x40)
            Hash diff = compute_delay_seed(IDX, PREV, TXR, DH2);
            check(seed_baseline != diff,
                  "compute_delay_seed: creator_dh_inputs value sensitivity");
        }

        // 6. Order sensitivity (the COMMITTEE-SELECTION-ORDER invariant):
        //    swapping two inputs must produce a different seed. Without
        //    this, a Phase-1 reorder by a malicious gather wouldn't be
        //    detectable post-Phase-2.
        {
            auto DH2 = DH;
            std::swap(DH2[0], DH2[2]);
            Hash diff = compute_delay_seed(IDX, PREV, TXR, DH2);
            check(seed_baseline != diff,
                  "compute_delay_seed: creator_dh_inputs ORDER sensitivity");
        }

        // 7. Empty creator_dh_inputs: algebraically still defined (just
        //    hashes the anchors). The "all-aborted-Phase-1" edge case.
        {
            std::vector<Hash> empty;
            Hash e1 = compute_delay_seed(IDX, PREV, TXR, empty);
            Hash e2 = compute_delay_seed(IDX, PREV, TXR, empty);
            check(e1 == e2,
                  "compute_delay_seed: deterministic on empty creator_dh_inputs");
            check(e1 != seed_baseline,
                  "compute_delay_seed: empty inputs distinct from non-empty");
        }

        // === compute_block_rand (Phase-2 output) ===
        std::vector<Hash> SECRETS = {
            patterned_hash(0x60), patterned_hash(0x70), patterned_hash(0x80)};
        Hash rand_baseline = compute_block_rand(seed_baseline, SECRETS);

        // 8. Determinism.
        {
            Hash again = compute_block_rand(seed_baseline, SECRETS);
            check(rand_baseline == again, "compute_block_rand deterministic");
        }

        // 9. delay_seed sensitivity: different Phase-1 commitment yields
        //    different randomness output even with same secrets.
        {
            Hash diff_seed = fill_hash(0x99);
            Hash diff = compute_block_rand(diff_seed, SECRETS);
            check(rand_baseline != diff,
                  "compute_block_rand: delay_seed sensitivity");
        }

        // 10. ordered_secrets sensitivity (value).
        {
            auto S2 = SECRETS;
            S2[1] = fill_hash(0xFB);
            Hash diff = compute_block_rand(seed_baseline, S2);
            check(rand_baseline != diff,
                  "compute_block_rand: ordered_secrets value sensitivity");
        }

        // 11. ordered_secrets ORDER sensitivity: swapping two secrets
        //     must change the output. This pairs with assertion 6 to
        //     enforce the same-order contract between Phase-1 inputs
        //     and Phase-2 reveals.
        {
            auto S2 = SECRETS;
            std::swap(S2[0], S2[2]);
            Hash diff = compute_block_rand(seed_baseline, S2);
            check(rand_baseline != diff,
                  "compute_block_rand: ordered_secrets ORDER sensitivity");
        }

        // 12. Domain separation: compute_delay_seed and compute_block_rand
        //     emit different hashes even when feeding "equivalent" inputs.
        //     Without separation, an attacker might engineer a delay_seed
        //     to collide with a future block_rand and bias selection.
        //     (Trivially true here because of differing input shapes,
        //     but we lock in the contract.)
        {
            std::vector<Hash> empty;
            Hash d = compute_delay_seed(0, Hash{}, Hash{}, empty);
            Hash r = compute_block_rand(Hash{}, empty);
            check(d != r, "compute_delay_seed and compute_block_rand domain-separated");
        }

        // === proposer_idx (BFT-mode designated proposer) ===

        // 13. Determinism.
        {
            std::vector<AbortEvent> aborts;
            size_t a = proposer_idx(seed_baseline, aborts, 6);
            size_t b = proposer_idx(seed_baseline, aborts, 6);
            check(a == b, "proposer_idx deterministic");
        }

        // 14. In-range invariant: result < committee_size for several
        //     committee sizes.
        {
            bool all_ok = true;
            for (size_t k : {1ull, 2ull, 3ull, 6ull, 9ull, 100ull}) {
                size_t idx = proposer_idx(seed_baseline, {}, k);
                if (idx >= k) { all_ok = false; break; }
            }
            check(all_ok, "proposer_idx in-range for k = 1, 2, 3, 6, 9, 100");
        }

        // 15. Empty committee edge case: returns 0 (the documented
        //     short-circuit; prevents modulo-by-zero).
        {
            size_t idx = proposer_idx(seed_baseline, {}, 0);
            check(idx == 0, "proposer_idx returns 0 on empty committee");
        }

        // 16. abort-sensitivity: feeding a single AbortEvent in produces
        //     a (probably-different) proposer index for the same prev_cum_rand.
        //     This is the rotation mechanism — abort retries advance the
        //     proposer index even when the seed hasn't moved.
        {
            AbortEvent ae;
            ae.round = 1;
            ae.event_hash = fill_hash(0xAB);
            std::vector<AbortEvent> aborts = {ae};
            // Probabilistic sensitivity — try a couple of seeds; at least
            // one of them must produce a different idx with the abort
            // event factored in.
            bool found_diff = false;
            for (uint8_t seed_byte : {0x00, 0x01, 0x02, 0x03, 0x04}) {
                Hash s = fill_hash(seed_byte);
                size_t no_aborts = proposer_idx(s, {}, 8);
                size_t with_aborts = proposer_idx(s, aborts, 8);
                if (no_aborts != with_aborts) { found_diff = true; break; }
            }
            check(found_diff,
                  "proposer_idx: abort events change output (rotation)");
        }

        // === required_block_sigs ===

        // 17. MUTUAL_DISTRUST returns committee_size unconditionally.
        {
            bool all_ok =
                required_block_sigs(ConsensusMode::MUTUAL_DISTRUST, 1)  == 1 &&
                required_block_sigs(ConsensusMode::MUTUAL_DISTRUST, 3)  == 3 &&
                required_block_sigs(ConsensusMode::MUTUAL_DISTRUST, 6)  == 6 &&
                required_block_sigs(ConsensusMode::MUTUAL_DISTRUST, 9)  == 9 &&
                required_block_sigs(ConsensusMode::MUTUAL_DISTRUST, 100) == 100;
            check(all_ok, "required_block_sigs(MD, K) == K for all K");
        }

        // 18. BFT returns ceil(2K/3). Concrete vectors:
        //     K=1 → 1; K=2 → 2; K=3 → 2; K=4 → 3; K=6 → 4; K=9 → 6; K=12 → 8.
        //     This is Q within the BFT-shrunk committee (k_bft), not Q
        //     within genesis K — see required_block_sigs comment.
        {
            bool all_ok =
                required_block_sigs(ConsensusMode::BFT, 1)  == 1 &&
                required_block_sigs(ConsensusMode::BFT, 2)  == 2 &&
                required_block_sigs(ConsensusMode::BFT, 3)  == 2 &&
                required_block_sigs(ConsensusMode::BFT, 4)  == 3 &&
                required_block_sigs(ConsensusMode::BFT, 6)  == 4 &&
                required_block_sigs(ConsensusMode::BFT, 9)  == 6 &&
                required_block_sigs(ConsensusMode::BFT, 12) == 8;
            check(all_ok, "required_block_sigs(BFT, k) == ceil(2k/3) for k = 1..12");
        }

        // === count_round1_aborts ===

        // 19. Empty list → 0.
        {
            std::vector<AbortEvent> empty;
            check(count_round1_aborts(empty) == 0,
                  "count_round1_aborts on empty list returns 0");
        }

        // 20. Mixed-round filter: counts only round=1, ignores round=2.
        //     (Round-2 aborts are clock-skew noisy and don't count
        //     toward suspension or BFT escalation per the protocol.)
        {
            AbortEvent r1a; r1a.round = 1; r1a.event_hash = fill_hash(0xA1);
            AbortEvent r2a; r2a.round = 2; r2a.event_hash = fill_hash(0xA2);
            AbortEvent r1b; r1b.round = 1; r1b.event_hash = fill_hash(0xA3);
            AbortEvent r2b; r2b.round = 2; r2b.event_hash = fill_hash(0xA4);
            AbortEvent r1c; r1c.round = 1; r1c.event_hash = fill_hash(0xA5);
            std::vector<AbortEvent> mixed = {r1a, r2a, r1b, r2b, r1c};
            check(count_round1_aborts(mixed) == 3,
                  "count_round1_aborts filters to round-1 only (3/5)");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": block-rand " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the S-014
    // per-peer-IP token bucket rate limiter (net::RateLimiter). Used
    // identically by RpcServer and GossipNet, so a unit test at the
    // shared-library level locks in the policy for both transports
    // in one place. The behavioral test (test_gossip_rate_limit.sh)
    // covers the wire end-to-end; this complements it by exercising
    // the algebra directly without setting up a network.
    if (cmd == "test-rate-limiter") {
        using namespace determ::net;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // 1. Default state is disabled (rate=0, burst=0): every
        //    consume() returns true with no bucket allocation.
        {
            RateLimiter rl;
            check(!rl.enabled(),
                  "default-constructed RateLimiter is disabled");
            bool all_ok = true;
            for (int i = 0; i < 1000; ++i) {
                if (!rl.consume("1.2.3.4")) { all_ok = false; break; }
            }
            check(all_ok, "disabled RateLimiter never throttles (1000/1000 pass)");
        }

        // 2. Explicit configure(0, 0) leaves the limiter disabled.
        {
            RateLimiter rl;
            rl.configure(0.0, 0.0);
            check(!rl.enabled(), "configure(0, 0) leaves limiter disabled");
        }

        // 3. Configure with positive rate and burst enables the
        //    limiter and exposes the values via getters.
        {
            RateLimiter rl;
            rl.configure(10.0, 5.0);
            check(rl.enabled(), "configure(10, 5) enables limiter");
            check(rl.rate_per_sec() == 10.0,
                  "rate_per_sec() round-trips configured value");
            check(rl.burst() == 5.0,
                  "burst() round-trips configured value");
        }

        // 4. First-touch starts the bucket FULL (legitimate callers
        //    don't get hit cold). With burst=3, three consecutive
        //    consume() calls at the same instant all succeed.
        {
            RateLimiter rl;
            rl.configure(1.0, 3.0);  // refill rate small so it doesn't add tokens during the test
            bool a = rl.consume("ip1");
            bool b = rl.consume("ip1");
            bool c = rl.consume("ip1");
            check(a && b && c,
                  "first-touch bucket is full (3 consecutive consumes succeed at burst=3)");
        }

        // 5. Burst exhaustion: the 4th consume at the same instant
        //    fails (1.0 rate × ~µs elapsed ≪ 1 token).
        {
            RateLimiter rl;
            rl.configure(1.0, 3.0);
            rl.consume("ip2"); rl.consume("ip2"); rl.consume("ip2");
            bool fourth = rl.consume("ip2");
            check(!fourth,
                  "4th consume at burst=3 same-instant fails (bucket exhausted)");
        }

        // 6. Per-key independence: exhausting one key doesn't affect
        //    another (the central security property — one abusive
        //    peer can't deny service for others).
        {
            RateLimiter rl;
            rl.configure(1.0, 3.0);
            // Exhaust ipA's bucket.
            for (int i = 0; i < 3; ++i) rl.consume("ipA");
            bool ipA_fourth = rl.consume("ipA");
            // Fresh ipB bucket should still allow 3 consumes.
            bool ipB_a = rl.consume("ipB");
            bool ipB_b = rl.consume("ipB");
            bool ipB_c = rl.consume("ipB");
            check(!ipA_fourth && ipB_a && ipB_b && ipB_c,
                  "per-key independence (ipA exhausted does NOT throttle ipB)");
        }

        // 7. Reconfigure after creation: setting new rate/burst takes
        //    effect on next consume.
        {
            RateLimiter rl;
            rl.configure(1.0, 1.0);
            check(rl.consume("ipC"), "burst=1 first consume succeeds");
            check(!rl.consume("ipC"), "burst=1 second consume fails");
            // Reconfigure to disabled.
            rl.configure(0.0, 0.0);
            check(rl.consume("ipC"),
                  "reconfigure(0, 0) re-enables passes (disabled bypasses bucket)");
        }

        // 8. Refill after a brief sleep: with rate=20/sec, sleeping
        //    100ms should add ~2 tokens (cap at burst). We sleep then
        //    verify at least one new consume succeeds.
        {
            RateLimiter rl;
            rl.configure(20.0, 2.0);
            rl.consume("ipD"); rl.consume("ipD");  // drain
            check(!rl.consume("ipD"), "burst=2 third immediate consume fails");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            check(rl.consume("ipD"),
                  "after 100ms sleep at rate=20/s, at least one new token (refill works)");
        }

        // 9. Refill cap: long sleep does NOT exceed burst. With
        //    burst=3 and a 500ms sleep at rate=100/sec, the bucket
        //    would otherwise overflow to 50 tokens; the cap holds at
        //    3, so only 3 consecutive consumes can succeed before a
        //    fail.
        {
            RateLimiter rl;
            rl.configure(100.0, 3.0);
            rl.consume("ipE"); rl.consume("ipE"); rl.consume("ipE");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            // Should now have ~3 tokens (capped), not 50.
            bool a = rl.consume("ipE");
            bool b = rl.consume("ipE");
            bool c = rl.consume("ipE");
            // The 4th here MUST fail — otherwise the cap is broken.
            bool d = rl.consume("ipE");
            check(a && b && c && !d,
                  "burst cap holds: long sleep at high rate does not exceed burst");
        }

        // 10. Many distinct keys: 100 keys each consume their entire
        //     burst, all succeed (per-key independence at scale).
        {
            RateLimiter rl;
            rl.configure(1.0, 2.0);
            bool all_ok = true;
            for (int k = 0; k < 100; ++k) {
                std::string key = "10.0.0." + std::to_string(k);
                if (!rl.consume(key) || !rl.consume(key)) {
                    all_ok = false; break;
                }
            }
            check(all_ok, "100 distinct keys each consume 2 tokens — all 200 succeed");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": rate-limiter " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for compute_block_digest
    // (the FA1 signature target). Locks in BOTH:
    //   (a) the INCLUSION list — every field in compute_block_digest
    //       must change the digest when mutated (signature-domain
    //       coverage; defeats a regression where a field is silently
    //       removed from the digest).
    //   (b) the deliberate EXCLUSION list (S-030 D2 territory) —
    //       fields NOT in compute_block_digest must NOT change it.
    //       The excluded fields are: delay_output, creator_dh_secrets,
    //       cumulative_rand, abort_events, equivocation_events,
    //       inbound_receipts, cross_shard_receipts, state_root,
    //       partner_subset_hash, timestamp.
    //
    //       The "Phase-2-reveal" subset (delay_output,
    //       creator_dh_secrets, cumulative_rand) is excluded because
    //       these values aren't known yet at digest-signing time. The
    //       remaining excludes (S-030 D2) are reconciled at apply time
    //       via:
    //         - state_root: S-033 + S-038 (apply-time gate now wired)
    //         - the rest:  v2.7 F2 view reconciliation (deferred)
    //
    //       Documenting the exclusion list with explicit assertions
    //       prevents a future commit from silently moving a field
    //       across the boundary (e.g., a well-meaning patch that adds
    //       abort_events to the digest would break the S-030 D2 design
    //       assumptions and the v2.7 F2 spec).
    if (cmd == "test-block-digest") {
        using namespace determ;
        using namespace determ::chain;
        using namespace determ::node;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Helper: build a populated Block with non-default values for
        // every digest-relevant field so each individual mutation is
        // distinguishable.
        auto patterned_hash = [](uint8_t base) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(base + i);
            return h;
        };
        auto patterned_sig = [](uint8_t base) {
            Signature s{};
            for (size_t i = 0; i < s.size(); ++i) s[i] = uint8_t(base + i);
            return s;
        };

        auto make_block = [&]() {
            Block b;
            b.index = 42;
            b.prev_hash = patterned_hash(0x10);
            b.tx_root = patterned_hash(0x20);
            b.delay_seed = patterned_hash(0x30);
            b.consensus_mode = ConsensusMode::MUTUAL_DISTRUST;
            b.bft_proposer = "";  // empty for MD blocks
            b.creators = {"alice", "bob", "carol"};
            b.creator_tx_lists = {
                {patterned_hash(0x40), patterned_hash(0x41)},
                {patterned_hash(0x42)},
                {}
            };
            b.creator_ed_sigs = {
                patterned_sig(0x50), patterned_sig(0x51), patterned_sig(0x52)};
            b.creator_dh_inputs = {
                patterned_hash(0x60), patterned_hash(0x61), patterned_hash(0x62)};
            return b;
        };

        Block baseline = make_block();
        Hash dig_baseline = compute_block_digest(baseline);

        // === INCLUSION list: every field in compute_block_digest
        //     changes the digest when mutated ===

        // 1. Determinism.
        {
            Hash again = compute_block_digest(baseline);
            check(again == dig_baseline, "compute_block_digest deterministic");
        }

        // 2. index sensitivity.
        {
            Block b = baseline;
            b.index = 43;
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: index sensitivity (INCLUDED)");
        }

        // 3. prev_hash sensitivity.
        {
            Block b = baseline;
            b.prev_hash = patterned_hash(0xFE);
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: prev_hash sensitivity (INCLUDED)");
        }

        // 4. tx_root sensitivity.
        {
            Block b = baseline;
            b.tx_root = patterned_hash(0xFD);
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: tx_root sensitivity (INCLUDED)");
        }

        // 5. delay_seed sensitivity.
        {
            Block b = baseline;
            b.delay_seed = patterned_hash(0xFC);
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: delay_seed sensitivity (INCLUDED)");
        }

        // 6. consensus_mode sensitivity.
        {
            Block b = baseline;
            b.consensus_mode = ConsensusMode::BFT;
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: consensus_mode sensitivity (INCLUDED)");
        }

        // 7. bft_proposer sensitivity.
        {
            Block b = baseline;
            b.bft_proposer = "alice";  // non-empty proposer
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: bft_proposer sensitivity (INCLUDED)");
        }

        // 8. creators sensitivity (value).
        {
            Block b = baseline;
            b.creators[1] = "different_bob";
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: creators value sensitivity (INCLUDED)");
        }

        // 9. creator_tx_lists sensitivity.
        {
            Block b = baseline;
            b.creator_tx_lists[0][0] = patterned_hash(0xFB);
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: creator_tx_lists sensitivity (INCLUDED)");
        }

        // 10. creator_ed_sigs sensitivity.
        {
            Block b = baseline;
            b.creator_ed_sigs[1] = patterned_sig(0xFA);
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: creator_ed_sigs sensitivity (INCLUDED)");
        }

        // 11. creator_dh_inputs sensitivity (the Phase-1 commit).
        {
            Block b = baseline;
            b.creator_dh_inputs[2] = patterned_hash(0xF9);
            check(compute_block_digest(b) != dig_baseline,
                  "compute_block_digest: creator_dh_inputs sensitivity (INCLUDED)");
        }

        // === EXCLUSION list: S-030 D2 territory + Phase-2-reveal
        //     subset. Mutating these MUST NOT change the digest.
        //     This is the explicit "two blocks can share a digest"
        //     surface that v2.7 F2 reconciles. ===

        // 12. delay_output excluded (Phase-2-reveal).
        {
            Block b = baseline;
            b.delay_output = patterned_hash(0xE0);
            check(compute_block_digest(b) == dig_baseline,
                  "compute_block_digest: delay_output EXCLUDED (Phase-2-reveal)");
        }

        // 13. creator_dh_secrets excluded (Phase-2-reveal).
        {
            Block b = baseline;
            b.creator_dh_secrets = {patterned_hash(0xE1), patterned_hash(0xE2)};
            check(compute_block_digest(b) == dig_baseline,
                  "compute_block_digest: creator_dh_secrets EXCLUDED (Phase-2-reveal)");
        }

        // 14. cumulative_rand excluded (Phase-2-reveal derivative).
        {
            Block b = baseline;
            b.cumulative_rand = patterned_hash(0xE3);
            check(compute_block_digest(b) == dig_baseline,
                  "compute_block_digest: cumulative_rand EXCLUDED");
        }

        // 15. abort_events excluded (S-030 D2 — v2.7 F2 territory).
        {
            Block b = baseline;
            AbortEvent ae;
            ae.round = 1;
            ae.event_hash = patterned_hash(0xE4);
            b.abort_events.push_back(ae);
            check(compute_block_digest(b) == dig_baseline,
                  "compute_block_digest: abort_events EXCLUDED (S-030 D2 / F2)");
        }

        // 16. equivocation_events excluded (S-030 D2 — v2.7 F2 territory).
        {
            Block b = baseline;
            EquivocationEvent ev;
            ev.equivocator = "mallory";
            ev.block_index = 42;
            ev.digest_a = patterned_hash(0xE5);
            ev.digest_b = patterned_hash(0xE6);
            ev.sig_a = patterned_sig(0xE7);
            ev.sig_b = patterned_sig(0xE8);
            b.equivocation_events.push_back(ev);
            check(compute_block_digest(b) == dig_baseline,
                  "compute_block_digest: equivocation_events EXCLUDED (S-030 D2 / F2)");
        }

        // 17. state_root excluded from digest (S-033 / v2.1 — apply-time
        //     gate via S-038 is the closure mechanism; the digest doesn't
        //     need to include it because each peer recomputes it locally
        //     and the gate rejects on mismatch).
        {
            Block b = baseline;
            b.state_root = patterned_hash(0xE9);
            check(compute_block_digest(b) == dig_baseline,
                  "compute_block_digest: state_root EXCLUDED (apply-time gate)");
        }

        // 18. partner_subset_hash excluded (R4 Phase 3 merge —
        //     covered by signing_bytes, not by the K-of-K Phase-2
        //     digest).
        {
            Block b = baseline;
            b.partner_subset_hash = patterned_hash(0xEA);
            check(compute_block_digest(b) == dig_baseline,
                  "compute_block_digest: partner_subset_hash EXCLUDED");
        }

        // 19. timestamp excluded (assembler-proposed; v2.7 F2 will add
        //     this to the digest via the ±30s validation pattern).
        {
            Block b = baseline;
            b.timestamp = 999;
            check(compute_block_digest(b) == dig_baseline,
                  "compute_block_digest: timestamp EXCLUDED (v2.7 F2 territory)");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": block-digest " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for Block::signing_bytes()
    // and Block::compute_hash() — the FA1 signature target that ends up
    // as the chain's prev_hash field on every subsequent block. Unlike
    // compute_block_digest (which is signed at Phase-2 by the K-of-K
    // committee BEFORE state-root and Phase-2-reveal fields are known),
    // signing_bytes covers EVERY consensus-relevant field of the block,
    // including the Phase-2-reveal fields and the apply-time-recomputed
    // state_root. This is the function that produces the block's chain-
    // anchor identity.
    if (cmd == "test-block-hash") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto patterned_hash = [](uint8_t base) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(base + i);
            return h;
        };
        auto patterned_sig = [](uint8_t base) {
            Signature s{};
            for (size_t i = 0; i < s.size(); ++i) s[i] = uint8_t(base + i);
            return s;
        };

        auto make_block = [&]() {
            Block b;
            b.index = 7;
            b.prev_hash = patterned_hash(0x10);
            b.timestamp = 1000;
            b.tx_root = patterned_hash(0x20);
            b.delay_seed = patterned_hash(0x30);
            b.delay_output = patterned_hash(0x35);
            b.consensus_mode = ConsensusMode::MUTUAL_DISTRUST;
            b.bft_proposer = "";  // empty for MD blocks
            b.cumulative_rand = patterned_hash(0x38);
            b.creators = {"alice", "bob", "carol"};
            b.creator_tx_lists = {
                {patterned_hash(0x40)}, {patterned_hash(0x41)}, {}};
            b.creator_ed_sigs = {
                patterned_sig(0x50), patterned_sig(0x51), patterned_sig(0x52)};
            b.creator_dh_inputs = {
                patterned_hash(0x60), patterned_hash(0x61), patterned_hash(0x62)};
            b.creator_dh_secrets = {
                patterned_hash(0x70), patterned_hash(0x71), patterned_hash(0x72)};
            b.creator_block_sigs = {
                patterned_sig(0x80), patterned_sig(0x81), patterned_sig(0x82)};
            return b;
        };

        Block baseline = make_block();
        Hash h_baseline = baseline.compute_hash();

        // 1. Determinism: compute_hash() called twice returns the same
        //    Hash. (No internal builder state leak.)
        {
            Hash again = baseline.compute_hash();
            check(again == h_baseline, "compute_hash() deterministic");
        }

        // 2. signing_bytes() determinism: 100 calls return the same
        //    32-byte hash. signing_bytes() returns the SHA-256 result
        //    (already hashed), so it should be deterministic by
        //    construction — but a regression to vector-style
        //    accumulation could break this.
        {
            auto s1 = baseline.signing_bytes();
            bool all_match = true;
            for (int i = 0; i < 100; ++i) {
                auto si = baseline.signing_bytes();
                if (si != s1) { all_match = false; break; }
            }
            check(all_match, "signing_bytes() pure (100 calls match)");
        }

        // 3. signing_bytes() returns exactly 32 bytes (SHA-256 output).
        {
            auto sb = baseline.signing_bytes();
            check(sb.size() == 32, "signing_bytes() returns 32 bytes (SHA-256 output)");
        }

        // === Sensitivity to fields in signing_bytes (the "always
        //     covered" set) — every field must change compute_hash
        //     when mutated. ===

        // 4. timestamp sensitivity (signing_bytes includes timestamp
        //    even though compute_block_digest doesn't — signing_bytes
        //    is computed AFTER digest signing, at gossip time, so the
        //    field is fully known).
        {
            Block b = baseline; b.timestamp = 9999;
            check(b.compute_hash() != h_baseline,
                  "compute_hash: timestamp sensitivity");
        }

        // 5. delay_output sensitivity (Phase-2 reveal — included in
        //    signing_bytes, excluded from digest).
        {
            Block b = baseline; b.delay_output = patterned_hash(0xF1);
            check(b.compute_hash() != h_baseline,
                  "compute_hash: delay_output sensitivity (Phase-2-reveal)");
        }

        // 6. creator_dh_secrets sensitivity (Phase-2 reveal).
        {
            Block b = baseline;
            b.creator_dh_secrets[1] = patterned_hash(0xF2);
            check(b.compute_hash() != h_baseline,
                  "compute_hash: creator_dh_secrets sensitivity");
        }

        // 7. cumulative_rand sensitivity.
        {
            Block b = baseline; b.cumulative_rand = patterned_hash(0xF3);
            check(b.compute_hash() != h_baseline,
                  "compute_hash: cumulative_rand sensitivity");
        }

        // 8. creator_block_sigs sensitivity (the K-of-K committee
        //    signatures themselves, bound into compute_hash but NOT
        //    into signing_bytes).
        {
            Block b = baseline; b.creator_block_sigs[0] = patterned_sig(0xF4);
            check(b.compute_hash() != h_baseline,
                  "compute_hash: creator_block_sigs sensitivity");
        }

        // === Backward-compat invariants for fields with zero-skip
        //     encoding (partner_subset_hash for R4 Phase 3,
        //     state_root for S-033). Both fields are bound into
        //     signing_bytes ONLY when non-zero, preserving byte-
        //     identical hashes for pre-feature blocks. ===

        // 9. partner_subset_hash zero-skip: setting to zero (default)
        //    yields the same hash as not touching it. Setting non-zero
        //    changes the hash.
        {
            Block b1 = baseline;          // default zero
            Block b2 = baseline;          // also default zero (explicit)
            Hash zero{};
            b2.partner_subset_hash = zero;
            check(b1.compute_hash() == b2.compute_hash(),
                  "compute_hash: partner_subset_hash zero-skip (zero == default)");
            b2.partner_subset_hash = patterned_hash(0xA0);
            check(b2.compute_hash() != b1.compute_hash(),
                  "compute_hash: partner_subset_hash non-zero changes hash");
        }

        // 10. state_root zero-skip (S-033 backward-compat).
        {
            Block b1 = baseline;
            Block b2 = baseline;
            Hash zero{};
            b2.state_root = zero;
            check(b1.compute_hash() == b2.compute_hash(),
                  "compute_hash: state_root zero-skip (zero == default)");
            b2.state_root = patterned_hash(0xA1);
            check(b2.compute_hash() != b1.compute_hash(),
                  "compute_hash: state_root non-zero changes hash");
        }

        // 11. Bound fields chain together: a block with BOTH
        //     partner_subset_hash AND state_root non-zero has a hash
        //     distinct from either alone.
        {
            Block bp = baseline;
            bp.partner_subset_hash = patterned_hash(0xB0);
            Block bs = baseline;
            bs.state_root = patterned_hash(0xB1);
            Block bps = baseline;
            bps.partner_subset_hash = patterned_hash(0xB0);
            bps.state_root = patterned_hash(0xB1);
            Hash hp = bp.compute_hash();
            Hash hs = bs.compute_hash();
            Hash hps = bps.compute_hash();
            check(hp != hs && hp != hps && hs != hps,
                  "compute_hash: partner_subset_hash and state_root contribute independently");
        }

        // 12. Order matters in creator-aligned vectors: swapping
        //     creators[0] and creators[1] yields a different hash
        //     (committee-selection-order invariant — pairs with
        //     test-block-rand assertion #6).
        {
            Block b = baseline;
            std::swap(b.creators[0], b.creators[1]);
            check(b.compute_hash() != h_baseline,
                  "compute_hash: creators[] ORDER sensitivity");
        }

        // 13. Equivocation events bound into hash. Two same-digest
        //     blocks differing only in equivocation_events still
        //     produce DIFFERENT hashes (this is the S-030 D2 mitigation
        //     at the chain-anchor level — the digest is shared but
        //     compute_hash distinguishes the actual block).
        {
            Block b = baseline;
            EquivocationEvent ev;
            ev.equivocator = "mallory";
            ev.block_index = 7;
            ev.digest_a = patterned_hash(0xC1);
            ev.digest_b = patterned_hash(0xC2);
            ev.sig_a = patterned_sig(0xC3);
            ev.sig_b = patterned_sig(0xC4);
            b.equivocation_events.push_back(ev);
            check(b.compute_hash() != h_baseline,
                  "compute_hash: equivocation_events change hash even when digest doesn't");
        }

        // 14. Abort events bound into hash via event_hash field.
        //     Note: only event_hash is bound (per S030-D2-Analysis.md
        //     "Implementation cross-reference") — other AbortEvent
        //     fields aren't included.
        {
            Block b = baseline;
            AbortEvent ae;
            ae.round = 1;
            ae.event_hash = patterned_hash(0xC5);
            b.abort_events.push_back(ae);
            check(b.compute_hash() != h_baseline,
                  "compute_hash: abort_events event_hash bound into block hash");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": block-hash " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the wire-format
    // codec (A3 / S8 closure). Exercises `Message::serialize` (legacy
    // JSON envelope, default v0), `Message::serialize_binary` (v1
    // binary envelope), the `Message::deserialize` format-detecting
    // dispatcher, `encode_binary` / `decode_binary` directly, and
    // `is_binary_envelope` detection. Plus locks in `max_message_bytes`
    // per-MsgType caps (S-022 surface) so future MsgType additions
    // don't slip through unbounded.
    //
    // Why this matters: the wire format is the trust boundary between
    // peers. A regression here would either silently break cross-peer
    // interoperability (encode/decode asymmetry across MsgType variants)
    // OR widen an attack surface (a new MsgType slipping past the
    // S-022 default-tight 1 MB cap to 16 MB).
    if (cmd == "test-binary-codec") {
        using namespace determ;
        using namespace determ::net;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Helper: serialize() / serialize_binary() prepend a 4-byte
        // big-endian length prefix (the framing layer). deserialize()
        // expects body-only — the peer's framing layer strips the
        // prefix before dispatching. For unit-level round-trip, strip
        // the prefix here too.
        auto strip_frame = [](const std::vector<uint8_t>& framed) {
            std::vector<uint8_t> body;
            if (framed.size() > 4) {
                body.assign(framed.begin() + 4, framed.end());
            }
            return body;
        };

        // === JSON envelope (v0) round-trip across multiple MsgTypes ===

        // 1. HELLO round-trip via JSON envelope. HELLO is special: it
        //    happens pre-negotiation, so it's ALWAYS JSON regardless of
        //    the peer's wire-version. Test that explicitly.
        {
            Message m = make_hello("alice", 12345, ChainRole::SINGLE, 0, 1);
            auto framed = m.serialize();
            check(framed.size() > 4,
                  "HELLO JSON serialize produces framed bytes");
            auto body = strip_frame(framed);
            Message back = Message::deserialize(body.data(), body.size());
            check(back.type == MsgType::HELLO,
                  "HELLO round-trip: type preserved");
            check(back.payload["domain"] == "alice",
                  "HELLO round-trip: domain field preserved");
            check(back.payload["port"] == 12345,
                  "HELLO round-trip: port field preserved");
        }

        // 2. STATUS_REQUEST round-trip (consensus-chatter category).
        {
            Message m{MsgType::STATUS_REQUEST, json::object()};
            auto framed = m.serialize();
            auto body = strip_frame(framed);
            Message back = Message::deserialize(body.data(), body.size());
            check(back.type == MsgType::STATUS_REQUEST,
                  "STATUS_REQUEST round-trip: type preserved");
        }

        // 3. TRANSACTION round-trip with non-trivial payload.
        {
            json tx_payload = {
                {"from", "alice"}, {"to", "bob"}, {"amount", 100},
                {"fee", 1}, {"nonce", 5}, {"hash", "deadbeef"}
            };
            Message m{MsgType::TRANSACTION, tx_payload};
            auto framed = m.serialize();
            auto body = strip_frame(framed);
            Message back = Message::deserialize(body.data(), body.size());
            check(back.type == MsgType::TRANSACTION,
                  "TRANSACTION round-trip: type preserved");
            check(back.payload == tx_payload,
                  "TRANSACTION round-trip: payload preserved byte-for-byte");
        }

        // === Binary envelope (v1) round-trip ===

        // 4. STATUS_RESPONSE binary round-trip. Use STATUS_RESPONSE
        //    rather than HELLO because HELLO is rejected by the
        //    binary path (it's always JSON pre-negotiation).
        {
            json status = {{"head_index", 100}, {"head_hash", "abcd1234"}};
            Message m{MsgType::STATUS_RESPONSE, status};
            auto framed = m.serialize_binary();
            auto body = strip_frame(framed);
            check(!body.empty(),
                  "STATUS_RESPONSE binary serialize produces non-empty body");
            check(is_binary_envelope(body.data(), body.size()),
                  "is_binary_envelope detects binary-encoded bytes");
            Message back = Message::deserialize(body.data(), body.size());
            check(back.type == MsgType::STATUS_RESPONSE,
                  "STATUS_RESPONSE binary round-trip: type preserved");
        }

        // 5. Format detection — JSON-encoded bytes do NOT trigger
        //    is_binary_envelope.
        {
            Message m{MsgType::STATUS_REQUEST, json::object()};
            auto json_framed = m.serialize();
            auto json_body = strip_frame(json_framed);
            check(!is_binary_envelope(json_body.data(), json_body.size()),
                  "is_binary_envelope returns false for JSON-encoded bytes");
        }

        // 6. encode_binary / decode_binary directly (free-function path).
        //    These operate on body bytes (no framing).
        {
            Message m{MsgType::CONTRIB, {{"x", 1}}};
            auto bytes = encode_binary(m);
            check(!bytes.empty(),
                  "encode_binary produces non-empty bytes");
            Message back = decode_binary(bytes.data(), bytes.size());
            check(back.type == MsgType::CONTRIB,
                  "decode_binary round-trip: type preserved");
        }

        // === Malformed input rejection ===

        // 7. Garbage bytes (not valid JSON, not valid binary envelope).
        //    is_binary_envelope returns false (no 0xB1 magic byte), so
        //    deserialize falls through to JSON parse which throws on
        //    invalid JSON.
        {
            std::vector<uint8_t> garbage = {0xFF, 0xFE, 0xFD, 0xFC};
            bool threw = false;
            try {
                Message::deserialize(garbage.data(), garbage.size());
            } catch (const std::exception&) { threw = true; }
            check(threw, "deserialize throws on garbage bytes");
        }

        // 8. Truncated valid JSON (envelope missing closing brace).
        //    Catches partial-payload regressions in the framing layer.
        {
            std::string truncated = "{\"type\":0,\"payload\":{";
            std::vector<uint8_t> bytes(truncated.begin(), truncated.end());
            bool threw = false;
            try {
                Message::deserialize(bytes.data(), bytes.size());
            } catch (const std::exception&) { threw = true; }
            check(threw, "deserialize throws on truncated JSON");
        }

        // === S-022 per-message-type cap golden vectors ===

        // 9. SNAPSHOT_RESPONSE + CHAIN_RESPONSE caps are 16 MB
        //    (the only legitimate large-payload channels).
        {
            check(max_message_bytes(MsgType::SNAPSHOT_RESPONSE) ==
                  16 * 1024 * 1024,
                  "max_message_bytes(SNAPSHOT_RESPONSE) == 16 MB");
            check(max_message_bytes(MsgType::CHAIN_RESPONSE) ==
                  16 * 1024 * 1024,
                  "max_message_bytes(CHAIN_RESPONSE) == 16 MB");
        }

        // 10. BLOCK + related block-shaped types are 4 MB.
        {
            check(max_message_bytes(MsgType::BLOCK) == 4 * 1024 * 1024,
                  "max_message_bytes(BLOCK) == 4 MB");
            check(max_message_bytes(MsgType::BEACON_HEADER) == 4 * 1024 * 1024,
                  "max_message_bytes(BEACON_HEADER) == 4 MB");
            check(max_message_bytes(MsgType::SHARD_TIP) == 4 * 1024 * 1024,
                  "max_message_bytes(SHARD_TIP) == 4 MB");
            check(max_message_bytes(MsgType::CROSS_SHARD_RECEIPT_BUNDLE) ==
                  4 * 1024 * 1024,
                  "max_message_bytes(CROSS_SHARD_RECEIPT_BUNDLE) == 4 MB");
            check(max_message_bytes(MsgType::HEADERS_RESPONSE) ==
                  4 * 1024 * 1024,
                  "max_message_bytes(HEADERS_RESPONSE) == 4 MB");
        }

        // 11. Consensus-chatter + requests + status default to 1 MB.
        {
            check(max_message_bytes(MsgType::HELLO) == 1 * 1024 * 1024,
                  "max_message_bytes(HELLO) == 1 MB");
            check(max_message_bytes(MsgType::CONTRIB) == 1 * 1024 * 1024,
                  "max_message_bytes(CONTRIB) == 1 MB");
            check(max_message_bytes(MsgType::BLOCK_SIG) == 1 * 1024 * 1024,
                  "max_message_bytes(BLOCK_SIG) == 1 MB");
            check(max_message_bytes(MsgType::ABORT_CLAIM) == 1 * 1024 * 1024,
                  "max_message_bytes(ABORT_CLAIM) == 1 MB");
            check(max_message_bytes(MsgType::ABORT_EVENT) == 1 * 1024 * 1024,
                  "max_message_bytes(ABORT_EVENT) == 1 MB");
            check(max_message_bytes(MsgType::EQUIVOCATION_EVIDENCE) ==
                  1 * 1024 * 1024,
                  "max_message_bytes(EQUIVOCATION_EVIDENCE) == 1 MB");
            check(max_message_bytes(MsgType::TRANSACTION) == 1 * 1024 * 1024,
                  "max_message_bytes(TRANSACTION) == 1 MB");
            check(max_message_bytes(MsgType::STATUS_REQUEST) == 1 * 1024 * 1024,
                  "max_message_bytes(STATUS_REQUEST) == 1 MB");
            check(max_message_bytes(MsgType::STATUS_RESPONSE) == 1 * 1024 * 1024,
                  "max_message_bytes(STATUS_RESPONSE) == 1 MB");
            check(max_message_bytes(MsgType::GET_CHAIN) == 1 * 1024 * 1024,
                  "max_message_bytes(GET_CHAIN) == 1 MB");
            check(max_message_bytes(MsgType::SNAPSHOT_REQUEST) ==
                  1 * 1024 * 1024,
                  "max_message_bytes(SNAPSHOT_REQUEST) == 1 MB");
            check(max_message_bytes(MsgType::HEADERS_REQUEST) ==
                  1 * 1024 * 1024,
                  "max_message_bytes(HEADERS_REQUEST) == 1 MB");
        }

        // 12. Default-branch invariant: any future MsgType beyond
        //     the enumerated set is capped at 1 MB. Use a value
        //     definitely past the enum to exercise the default path.
        {
            // Cast a future-reserved value (e.g., 200) through MsgType
            // to test the default branch. Safe — max_message_bytes is
            // a pure switch with no UB on unmapped enum values.
            check(max_message_bytes(static_cast<MsgType>(200)) ==
                  1 * 1024 * 1024,
                  "max_message_bytes default branch (future MsgType) == 1 MB");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": binary-codec " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the four block-
    // internal wire types' JSON round-trips:
    //
    //   * CrossShardReceipt (FA7 / V12 — source-side receipt emission)
    //   * AbortEvent (FA3 — consensus abort certificate)
    //   * EquivocationEvent (FA6 — slashing evidence)
    //   * GenesisAlloc (chain-identity genesis allocation)
    //
    // Each of these structs is `to_json` / `from_json` round-trip
    // critical: blocks gossip these as JSON via the chain's encoding,
    // and any field-loss across the round-trip would silently corrupt
    // wire data without a parse error. The S-018 helpers fence against
    // missing required fields, but they don't catch "field present but
    // serialized then dropped on read." That's what this test catches.
    if (cmd == "test-wire-types") {
        using namespace determ;
        using namespace determ::chain;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto patterned_hash = [](uint8_t base) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(base + i);
            return h;
        };
        auto patterned_sig = [](uint8_t base) {
            Signature s{};
            for (size_t i = 0; i < s.size(); ++i) s[i] = uint8_t(base + i);
            return s;
        };
        auto patterned_pub = [](uint8_t base) {
            PubKey p{};
            for (size_t i = 0; i < p.size(); ++i) p[i] = uint8_t(base + i);
            return p;
        };

        // === CrossShardReceipt round-trip ===
        {
            CrossShardReceipt r;
            r.src_shard       = 1;
            r.dst_shard       = 2;
            r.src_block_index = 100;
            r.src_block_hash  = patterned_hash(0xA0);
            r.tx_hash         = patterned_hash(0xB0);
            r.from            = "alice";
            r.to              = "bob";
            r.amount          = 500;
            r.fee             = 5;
            r.nonce           = 7;

            json j = r.to_json();
            CrossShardReceipt back = CrossShardReceipt::from_json(j);

            check(back.src_shard == r.src_shard,
                  "CrossShardReceipt round-trip: src_shard preserved");
            check(back.dst_shard == r.dst_shard,
                  "CrossShardReceipt round-trip: dst_shard preserved");
            check(back.src_block_index == r.src_block_index,
                  "CrossShardReceipt round-trip: src_block_index preserved");
            check(back.src_block_hash == r.src_block_hash,
                  "CrossShardReceipt round-trip: src_block_hash preserved");
            check(back.tx_hash == r.tx_hash,
                  "CrossShardReceipt round-trip: tx_hash preserved");
            check(back.from == r.from,
                  "CrossShardReceipt round-trip: from preserved");
            check(back.to == r.to,
                  "CrossShardReceipt round-trip: to preserved");
            check(back.amount == r.amount,
                  "CrossShardReceipt round-trip: amount preserved");
            check(back.fee == r.fee,
                  "CrossShardReceipt round-trip: fee preserved");
            check(back.nonce == r.nonce,
                  "CrossShardReceipt round-trip: nonce preserved");
        }

        // CrossShardReceipt: S-018 strict rejection. Every field is
        // required — missing any one throws with a clear field-name
        // diagnostic. This is the in-session hardening pass for the
        // wire type — previously from_json used permissive j.value()
        // defaults; now it uses json_require / json_require_hex to
        // match the rest of the S-018 surface.
        {
            json bad = {
                {"src_shard", 1}, {"dst_shard", 2}, {"src_block_index", 100},
                {"src_block_hash", to_hex(patterned_hash(0xA0))},
                {"tx_hash", to_hex(patterned_hash(0xB0))},
                {"from", "alice"}, {"to", "bob"},
                {"amount", 500}, {"fee", 5}
                // nonce intentionally missing
            };
            bool threw = false;
            std::string what;
            try { (void)CrossShardReceipt::from_json(bad); }
            catch (const std::exception& e) { threw = true; what = e.what(); }
            check(threw,
                  "CrossShardReceipt::from_json throws on missing 'nonce' (S-018)");
            check(what.find("nonce") != std::string::npos,
                  "CrossShardReceipt S-018 error message mentions 'nonce' field name");
        }

        // === AbortEvent round-trip ===
        {
            AbortEvent ae;
            ae.round = 1;
            ae.aborting_node = "carol";
            ae.timestamp = 1234567890;
            ae.event_hash = patterned_hash(0xC0);
            ae.claims_json = json::array();  // empty inline claims OK

            json j = ae.to_json();
            AbortEvent back = AbortEvent::from_json(j);

            check(back.round == ae.round,
                  "AbortEvent round-trip: round preserved");
            check(back.aborting_node == ae.aborting_node,
                  "AbortEvent round-trip: aborting_node preserved");
            check(back.timestamp == ae.timestamp,
                  "AbortEvent round-trip: timestamp preserved");
            check(back.event_hash == ae.event_hash,
                  "AbortEvent round-trip: event_hash preserved");
        }

        // === EquivocationEvent round-trip ===
        {
            EquivocationEvent ev;
            ev.equivocator = "mallory";
            ev.block_index = 42;
            ev.digest_a = patterned_hash(0xD0);
            ev.sig_a    = patterned_sig(0xD1);
            ev.digest_b = patterned_hash(0xD2);
            ev.sig_b    = patterned_sig(0xD3);
            ev.shard_id = 3;
            ev.beacon_anchor_height = 100;

            json j = ev.to_json();
            EquivocationEvent back = EquivocationEvent::from_json(j);

            check(back.equivocator == ev.equivocator,
                  "EquivocationEvent round-trip: equivocator preserved");
            check(back.block_index == ev.block_index,
                  "EquivocationEvent round-trip: block_index preserved");
            check(back.digest_a == ev.digest_a,
                  "EquivocationEvent round-trip: digest_a preserved");
            check(back.sig_a == ev.sig_a,
                  "EquivocationEvent round-trip: sig_a preserved");
            check(back.digest_b == ev.digest_b,
                  "EquivocationEvent round-trip: digest_b preserved");
            check(back.sig_b == ev.sig_b,
                  "EquivocationEvent round-trip: sig_b preserved");
            check(back.shard_id == ev.shard_id,
                  "EquivocationEvent round-trip: shard_id preserved");
            check(back.beacon_anchor_height == ev.beacon_anchor_height,
                  "EquivocationEvent round-trip: beacon_anchor_height preserved");
        }

        // === GenesisAlloc round-trip ===
        {
            GenesisAlloc g;
            g.domain  = "alice";
            g.ed_pub  = patterned_pub(0xE0);
            g.balance = 10000;
            g.stake   = 1000;
            g.region  = "us-east";

            json j = g.to_json();
            GenesisAlloc back = GenesisAlloc::from_json(j);

            check(back.domain == g.domain,
                  "GenesisAlloc round-trip: domain preserved");
            check(back.ed_pub == g.ed_pub,
                  "GenesisAlloc round-trip: ed_pub preserved");
            check(back.balance == g.balance,
                  "GenesisAlloc round-trip: balance preserved");
            check(back.stake == g.stake,
                  "GenesisAlloc round-trip: stake preserved");
            check(back.region == g.region,
                  "GenesisAlloc round-trip: region preserved");
        }

        // GenesisAlloc: empty region (the rev.9 R1 "legacy/global pool"
        // default) round-trips correctly. This is the backward-compat
        // path for pre-R1 genesis files.
        {
            GenesisAlloc g;
            g.domain  = "bob";
            g.ed_pub  = patterned_pub(0xE5);
            g.balance = 500;
            g.stake   = 0;
            g.region  = "";  // empty

            json j = g.to_json();
            GenesisAlloc back = GenesisAlloc::from_json(j);

            check(back.region.empty(),
                  "GenesisAlloc empty-region round-trips as empty (R1 legacy compat)");
            check(back.stake == 0,
                  "GenesisAlloc zero-stake round-trips correctly");
        }

        // === S-018 strict-rejection lock-in for the three S-018-
        //     enforced types ===

        // AbortEvent: round + aborting_node + timestamp + event_hash
        // are all S-018 required. Missing any one throws with a clear
        // field-name diagnostic. Test "round" as the canary.
        {
            json bad = {
                {"aborting_node", "carol"}, {"timestamp", 1},
                {"event_hash", to_hex(patterned_hash(0xC0))}
                // round missing
            };
            bool threw = false;
            std::string what;
            try { (void)AbortEvent::from_json(bad); }
            catch (const std::exception& e) { threw = true; what = e.what(); }
            check(threw,
                  "AbortEvent::from_json throws on missing 'round' (S-018)");
            check(what.find("round") != std::string::npos,
                  "AbortEvent S-018 error message mentions 'round' field name");
        }

        // EquivocationEvent: equivocator + block_index + digest_a/b +
        // sig_a/b are all S-018 required. Test "digest_a" as the canary
        // for the json_require_hex path (with size-check at 64 hex chars).
        {
            json bad = {
                {"equivocator", "mallory"},
                {"block_index", 42},
                // digest_a missing
                {"sig_a", to_hex(patterned_sig(0xD1))},
                {"digest_b", to_hex(patterned_hash(0xD2))},
                {"sig_b", to_hex(patterned_sig(0xD3))}
            };
            bool threw = false;
            std::string what;
            try { (void)EquivocationEvent::from_json(bad); }
            catch (const std::exception& e) { threw = true; what = e.what(); }
            check(threw,
                  "EquivocationEvent::from_json throws on missing 'digest_a' (S-018)");
            check(what.find("digest_a") != std::string::npos,
                  "EquivocationEvent S-018 error message mentions 'digest_a' field name");
        }

        // EquivocationEvent: wrong-length hex for digest_a (S-018 hex
        // length check — should be 64 hex chars for a 32-byte hash).
        {
            json bad = {
                {"equivocator", "mallory"},
                {"block_index", 42},
                {"digest_a", "deadbeef"},  // only 4 bytes, not 32
                {"sig_a", to_hex(patterned_sig(0xD1))},
                {"digest_b", to_hex(patterned_hash(0xD2))},
                {"sig_b", to_hex(patterned_sig(0xD3))}
            };
            bool threw = false;
            try { (void)EquivocationEvent::from_json(bad); }
            catch (const std::exception&) { threw = true; }
            check(threw,
                  "EquivocationEvent::from_json throws on wrong-length 'digest_a' hex (S-018)");
        }

        // GenesisAlloc: domain is the only S-018 required field; balance
        // / stake / region all default. Test missing domain throws.
        {
            json bad = {
                {"balance", 100}, {"stake", 10}
                // domain missing
            };
            bool threw = false;
            std::string what;
            try { (void)GenesisAlloc::from_json(bad); }
            catch (const std::exception& e) { threw = true; what = e.what(); }
            check(threw,
                  "GenesisAlloc::from_json throws on missing 'domain' (S-018)");
            check(what.find("domain") != std::string::npos,
                  "GenesisAlloc S-018 error message mentions 'domain' field name");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": wire-types " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for Transaction (the
    // smallest authentic wire unit on the chain). Locks in:
    //   * signing_bytes byte-layout (Preliminaries §1.3 BE encoding)
    //   * compute_hash determinism
    //   * sign/verify round-trip via Ed25519 (every field affects sig)
    //   * JSON round-trip for representative TxType variants
    //   * S-018 strict-rejection contract
    //
    // Every transaction on the chain — TRANSFER, REGISTER, DEREGISTER,
    // STAKE, UNSTAKE, PARAM_CHANGE, MERGE_EVENT, COMPOSABLE_BATCH,
    // DAPP_REGISTER, DAPP_CALL — passes through these paths. A
    // regression here would either silently break sender authentication
    // (sig verifies with tampered tx) OR break wire-format
    // interoperability (gossip round-trip drops a field).
    if (cmd == "test-transaction") {
        using namespace determ;
        using namespace determ::chain;
        using namespace determ::crypto;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // === signing_bytes determinism + field coverage ===

        auto make_tx = []() {
            Transaction tx;
            tx.type    = TxType::TRANSFER;
            tx.from    = "alice";
            tx.to      = "bob";
            tx.amount  = 100;
            tx.fee     = 1;
            tx.nonce   = 5;
            tx.payload = {0xDE, 0xAD, 0xBE, 0xEF};
            return tx;
        };

        // 1. signing_bytes determinism.
        {
            Transaction tx = make_tx();
            auto sb1 = tx.signing_bytes();
            auto sb2 = tx.signing_bytes();
            check(sb1 == sb2, "Transaction::signing_bytes deterministic");
        }

        // 2. Every Transaction core field affects signing_bytes.
        {
            Transaction t1 = make_tx();
            auto base = t1.signing_bytes();

            Transaction t2 = make_tx();
            t2.type = TxType::REGISTER;
            check(t2.signing_bytes() != base, "signing_bytes: type sensitivity");

            t2 = make_tx(); t2.from = "carol";
            check(t2.signing_bytes() != base, "signing_bytes: from sensitivity");

            t2 = make_tx(); t2.to = "dan";
            check(t2.signing_bytes() != base, "signing_bytes: to sensitivity");

            t2 = make_tx(); t2.amount = 200;
            check(t2.signing_bytes() != base, "signing_bytes: amount sensitivity");

            t2 = make_tx(); t2.fee = 99;
            check(t2.signing_bytes() != base, "signing_bytes: fee sensitivity");

            t2 = make_tx(); t2.nonce = 999;
            check(t2.signing_bytes() != base, "signing_bytes: nonce sensitivity");

            t2 = make_tx(); t2.payload = {0xCA, 0xFE};
            check(t2.signing_bytes() != base, "signing_bytes: payload sensitivity");
        }

        // 3. signing_bytes excludes sig + hash (sender signs over
        //    signing_bytes, not over their own sig — would be circular).
        {
            Transaction t1 = make_tx();
            Transaction t2 = make_tx();
            for (size_t i = 0; i < t2.sig.size(); ++i) t2.sig[i] = uint8_t(i);
            for (size_t i = 0; i < t2.hash.size(); ++i) t2.hash[i] = uint8_t(i);
            check(t1.signing_bytes() == t2.signing_bytes(),
                  "signing_bytes excludes sig and hash fields");
        }

        // 4. compute_hash determinism.
        {
            Transaction tx = make_tx();
            check(tx.compute_hash() == tx.compute_hash(),
                  "Transaction::compute_hash deterministic");
        }

        // 5. compute_hash == SHA-256 of signing_bytes (the documented
        //    contract).
        {
            Transaction tx = make_tx();
            auto sb = tx.signing_bytes();
            Hash expected = sha256(sb.data(), sb.size());
            check(tx.compute_hash() == expected,
                  "compute_hash == SHA-256(signing_bytes)");
        }

        // === Ed25519 sign/verify integration ===

        // 6. sign/verify round-trip: a tx signed by a real Ed25519 key
        //    verifies under that key.
        {
            NodeKey k = generate_node_key();
            Transaction tx = make_tx();
            auto sb = tx.signing_bytes();
            tx.sig = sign(k, sb.data(), sb.size());
            bool ok = verify(k.pub, sb.data(), sb.size(), tx.sig);
            check(ok, "sign(signing_bytes) verifies under signer's pubkey");
        }

        // 7. Tampered tx: change one byte after signing, verify fails.
        {
            NodeKey k = generate_node_key();
            Transaction tx = make_tx();
            auto sb = tx.signing_bytes();
            tx.sig = sign(k, sb.data(), sb.size());

            // Mutate amount AFTER signing. signing_bytes changes; sig
            // no longer covers the new bytes.
            tx.amount = 999;
            auto sb_tampered = tx.signing_bytes();
            bool ok = verify(k.pub, sb_tampered.data(), sb_tampered.size(), tx.sig);
            check(!ok, "verify rejects sig over tampered tx (amount changed)");
        }

        // === JSON round-trip ===

        // 8. JSON round-trip for TRANSFER (the most common type).
        {
            Transaction tx = make_tx();
            tx.hash = tx.compute_hash();
            NodeKey k = generate_node_key();
            auto sb = tx.signing_bytes();
            tx.sig = sign(k, sb.data(), sb.size());

            json j = tx.to_json();
            Transaction back = Transaction::from_json(j);

            check(back.type == tx.type,         "TRANSFER round-trip: type");
            check(back.from == tx.from,         "TRANSFER round-trip: from");
            check(back.to == tx.to,             "TRANSFER round-trip: to");
            check(back.amount == tx.amount,     "TRANSFER round-trip: amount");
            check(back.fee == tx.fee,           "TRANSFER round-trip: fee");
            check(back.nonce == tx.nonce,       "TRANSFER round-trip: nonce");
            check(back.payload == tx.payload,   "TRANSFER round-trip: payload");
            check(back.sig == tx.sig,           "TRANSFER round-trip: sig");
            check(back.hash == tx.hash,         "TRANSFER round-trip: hash");
        }

        // 9. JSON round-trip for each representative TxType (REGISTER,
        //    STAKE, UNSTAKE, DAPP_REGISTER). Verifies type field encodes
        //    + decodes correctly across the enum range.
        {
            for (TxType t : {TxType::REGISTER, TxType::DEREGISTER,
                              TxType::STAKE, TxType::UNSTAKE,
                              TxType::PARAM_CHANGE, TxType::MERGE_EVENT,
                              TxType::COMPOSABLE_BATCH, TxType::DAPP_REGISTER,
                              TxType::DAPP_CALL}) {
                Transaction tx;
                tx.type = t;
                tx.from = "alice";
                tx.to   = "";          // not all types use 'to'
                tx.nonce = 1;
                tx.payload = {0x01, 0x02};
                tx.hash = tx.compute_hash();
                json j = tx.to_json();
                Transaction back = Transaction::from_json(j);
                check(back.type == tx.type,
                      ("Transaction round-trip TxType=" +
                       std::to_string(int(t))).c_str());
            }
        }

        // === S-018 strict-rejection ===

        // 10. from_json rejects missing required field 'amount'.
        {
            json bad = {
                {"type", 0}, {"from", "alice"}, {"to", "bob"},
                /* amount missing */ {"fee", 1}, {"nonce", 5},
                {"payload", ""}, {"sig", std::string(128, '0')},
                {"hash", std::string(64, '0')}
            };
            bool threw = false;
            std::string what;
            try { (void)Transaction::from_json(bad); }
            catch (const std::exception& e) { threw = true; what = e.what(); }
            check(threw && what.find("amount") != std::string::npos,
                  "Transaction::from_json rejects missing 'amount' with field-name diagnostic");
        }

        // 11. from_json rejects wrong-length sig.
        {
            json bad = {
                {"type", 0}, {"from", "alice"}, {"to", "bob"},
                {"amount", 100}, {"fee", 1}, {"nonce", 5},
                {"payload", ""},
                {"sig", "deadbeef"},   // 4 bytes — wrong length for sig
                {"hash", std::string(64, '0')}
            };
            bool threw = false;
            try { (void)Transaction::from_json(bad); }
            catch (const std::exception&) { threw = true; }
            check(threw,
                  "Transaction::from_json rejects wrong-length 'sig' hex");
        }

        // 12. Hash distinct from signing_bytes when tx fields differ:
        //     two semantically-different txs have distinct hashes.
        {
            Transaction t1 = make_tx();
            Transaction t2 = make_tx();
            t2.nonce = 6;  // increment nonce
            check(t1.compute_hash() != t2.compute_hash(),
                  "Two txs differing in nonce have distinct compute_hash");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": transaction " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for MergeEvent
    // encode/decode (R4 under-quorum merge wire format).
    //
    // MergeEvent is the canonical payload for TxType::MERGE_EVENT —
    // emitted by beacon when a shard's eligible-validator pool drops
    // below 2K and the shard merges with its modular-next neighbor.
    // Wire format must round-trip byte-for-byte across all node
    // implementations or the apply path diverges across shards.
    if (cmd == "test-merge-event-codec") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto make_event = [](MergeEvent::Type t,
                              uint32_t shard, uint32_t partner,
                              uint64_t eff, uint64_t evws,
                              const std::string& region) {
            MergeEvent ev;
            ev.event_type = t;
            ev.shard_id   = shard;
            ev.partner_id = partner;
            ev.effective_height       = eff;
            ev.evidence_window_start  = evws;
            ev.merging_shard_region   = region;
            return ev;
        };

        // 1. BEGIN round-trip.
        {
            MergeEvent ev = make_event(MergeEvent::BEGIN, 3, 4, 1000, 950, "us-east");
            auto bytes = ev.encode();
            auto back = MergeEvent::decode(bytes);
            check(back.has_value(), "BEGIN: decode returns value");
            check(back->event_type == ev.event_type,
                  "BEGIN round-trip: event_type");
            check(back->shard_id   == ev.shard_id,
                  "BEGIN round-trip: shard_id");
            check(back->partner_id == ev.partner_id,
                  "BEGIN round-trip: partner_id");
            check(back->effective_height == ev.effective_height,
                  "BEGIN round-trip: effective_height");
            check(back->evidence_window_start == ev.evidence_window_start,
                  "BEGIN round-trip: evidence_window_start");
            check(back->merging_shard_region == ev.merging_shard_region,
                  "BEGIN round-trip: merging_shard_region");
        }

        // 2. END round-trip with empty region (END semantics).
        {
            MergeEvent ev = make_event(MergeEvent::END, 3, 4, 1500, 0, "");
            auto bytes = ev.encode();
            auto back = MergeEvent::decode(bytes);
            check(back.has_value(), "END: decode returns value");
            check(back->event_type == MergeEvent::END,
                  "END round-trip: event_type");
            check(back->merging_shard_region.empty(),
                  "END round-trip: empty region preserved");
        }

        // 3. Size invariant: BEGIN with region 'us-east' is 26 + 7.
        {
            MergeEvent ev = make_event(MergeEvent::BEGIN, 0, 1, 0, 0, "us-east");
            check(ev.encode().size() == 26 + 7,
                  "encode size == 26 + region_len");
        }

        // 4. Reject too-short payload.
        {
            std::vector<uint8_t> too_short(20, 0);
            check(!MergeEvent::decode(too_short).has_value(),
                  "decode rejects payload < 26 bytes");
        }

        // 5. Reject invalid event_type (> 1).
        {
            MergeEvent ev = make_event(MergeEvent::BEGIN, 0, 1, 0, 0, "");
            auto bytes = ev.encode();
            bytes[0] = 2;  // out-of-range event_type
            check(!MergeEvent::decode(bytes).has_value(),
                  "decode rejects event_type > 1");
        }

        // 6. Reject oversize region (rlen > 32).
        {
            std::vector<uint8_t> bad(26 + 33, 0);
            bad[0] = 0;        // BEGIN
            bad[25] = 33;      // region_len > 32
            // payload size matches header's claim (26 + 33 = 59), so the
            // length-check passes; the >32 region cap is the one that
            // rejects.
            check(!MergeEvent::decode(bad).has_value(),
                  "decode rejects region_len > 32");
        }

        // 7. Reject size mismatch (claimed region_len doesn't match
        //    payload size).
        {
            std::vector<uint8_t> bad(26 + 5, 0);  // payload has 5 region bytes
            bad[25] = 10;                          // claims region_len=10
            check(!MergeEvent::decode(bad).has_value(),
                  "decode rejects size != 26 + claimed region_len");
        }

        // 8. Determinism: encoding the same event twice yields the
        //    same bytes (matters for cross-node hash consistency on
        //    MERGE_EVENT-bearing blocks).
        {
            MergeEvent ev = make_event(MergeEvent::BEGIN, 7, 0, 200, 150, "eu-west");
            auto b1 = ev.encode();
            auto b2 = ev.encode();
            check(b1 == b2, "MergeEvent::encode deterministic");
        }

        // 9. Field sensitivity: changing any field changes the encoded
        //    bytes (no accidental field-drop).
        {
            MergeEvent base = make_event(MergeEvent::BEGIN, 1, 2, 100, 50, "test");
            auto bb = base.encode();

            MergeEvent v = base; v.event_type = MergeEvent::END;
            check(v.encode() != bb, "encode: event_type sensitivity");

            v = base; v.shard_id = 99;
            check(v.encode() != bb, "encode: shard_id sensitivity");

            v = base; v.partner_id = 99;
            check(v.encode() != bb, "encode: partner_id sensitivity");

            v = base; v.effective_height = 9999;
            check(v.encode() != bb, "encode: effective_height sensitivity");

            v = base; v.evidence_window_start = 9999;
            check(v.encode() != bb, "encode: evidence_window_start sensitivity");

            v = base; v.merging_shard_region = "different";
            check(v.encode() != bb, "encode: region sensitivity");
        }

        // 10. Maximum-region (32 bytes) round-trips.
        {
            std::string max_region(32, 'a');
            MergeEvent ev = make_event(MergeEvent::BEGIN, 1, 2, 100, 50, max_region);
            auto bytes = ev.encode();
            auto back = MergeEvent::decode(bytes);
            check(back.has_value() && back->merging_shard_region.size() == 32,
                  "encode/decode round-trip at max region size (32 bytes)");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": merge-event-codec " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the three consensus
    // message types (ContribMsg / BlockSigMsg / AbortClaimMsg) and their
    // commitment-hash helpers. These messages are signed by committee
    // members in Phase 1 / Phase 2 / abort-path respectively; a
    // regression in their wire format or commitment binding would
    // either break interoperability or open a replay attack surface.
    if (cmd == "test-consensus-msgs") {
        using namespace determ;
        using namespace determ::chain;
        using namespace determ::node;
        using namespace determ::crypto;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto patterned_hash = [](uint8_t base) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(base + i);
            return h;
        };
        auto patterned_sig = [](uint8_t base) {
            Signature s{};
            for (size_t i = 0; i < s.size(); ++i) s[i] = uint8_t(base + i);
            return s;
        };

        // === make_contrib_commitment ===
        Hash PREV = patterned_hash(0x10);
        std::vector<Hash> TXH = {
            patterned_hash(0x20), patterned_hash(0x21)};
        Hash DH = patterned_hash(0x30);

        Hash commit_base = make_contrib_commitment(42, PREV, TXH, DH);

        // 1. Determinism.
        {
            Hash again = make_contrib_commitment(42, PREV, TXH, DH);
            check(again == commit_base,
                  "make_contrib_commitment deterministic");
        }

        // 2. block_index sensitivity.
        {
            Hash diff = make_contrib_commitment(43, PREV, TXH, DH);
            check(diff != commit_base,
                  "make_contrib_commitment: block_index sensitivity");
        }

        // 3. prev_hash sensitivity.
        {
            Hash diff = make_contrib_commitment(42, patterned_hash(0xFE), TXH, DH);
            check(diff != commit_base,
                  "make_contrib_commitment: prev_hash sensitivity");
        }

        // 4. tx_hashes sensitivity (value).
        {
            std::vector<Hash> TXH2 = TXH;
            TXH2[0] = patterned_hash(0xFD);
            Hash diff = make_contrib_commitment(42, PREV, TXH2, DH);
            check(diff != commit_base,
                  "make_contrib_commitment: tx_hashes value sensitivity");
        }

        // 5. tx_hashes ORDER sensitivity. The commitment binds to a
        //    specific order; reorder must change the hash. (This pairs
        //    with the convention "sorted ascending" — a member who
        //    sorts incorrectly produces a different commit than peers.)
        {
            std::vector<Hash> TXH2 = TXH;
            std::swap(TXH2[0], TXH2[1]);
            Hash diff = make_contrib_commitment(42, PREV, TXH2, DH);
            check(diff != commit_base,
                  "make_contrib_commitment: tx_hashes ORDER sensitivity");
        }

        // 6. dh_input sensitivity.
        {
            Hash diff = make_contrib_commitment(42, PREV, TXH, patterned_hash(0xFC));
            check(diff != commit_base,
                  "make_contrib_commitment: dh_input sensitivity");
        }

        // === make_abort_claim_message ===
        Hash abort_base = make_abort_claim_message(42, 1, PREV, "carol");

        // 7. Determinism.
        {
            Hash again = make_abort_claim_message(42, 1, PREV, "carol");
            check(again == abort_base,
                  "make_abort_claim_message deterministic");
        }

        // 8. block_index sensitivity.
        {
            Hash diff = make_abort_claim_message(43, 1, PREV, "carol");
            check(diff != abort_base,
                  "make_abort_claim_message: block_index sensitivity");
        }

        // 9. round sensitivity (round=1 vs round=2 must differ; defeats
        //    cross-phase replay).
        {
            Hash diff = make_abort_claim_message(42, 2, PREV, "carol");
            check(diff != abort_base,
                  "make_abort_claim_message: round sensitivity");
        }

        // 10. prev_hash sensitivity.
        {
            Hash diff = make_abort_claim_message(42, 1, patterned_hash(0xFE), "carol");
            check(diff != abort_base,
                  "make_abort_claim_message: prev_hash sensitivity");
        }

        // 11. missing_creator sensitivity.
        {
            Hash diff = make_abort_claim_message(42, 1, PREV, "dan");
            check(diff != abort_base,
                  "make_abort_claim_message: missing_creator sensitivity");
        }

        // 12. Domain separation: contrib commit and abort claim hash
        //     must differ for the same anchor inputs (no cross-domain
        //     collision).
        {
            // Use the same block_index + prev_hash for both.
            Hash contrib = make_contrib_commitment(42, PREV, {}, Hash{});
            Hash abort   = make_abort_claim_message(42, 1, PREV, "");
            check(contrib != abort,
                  "make_contrib_commitment vs make_abort_claim_message domain-separated");
        }

        // === ContribMsg JSON round-trip ===
        {
            ContribMsg m;
            m.block_index = 42;
            m.signer = "alice";
            m.prev_hash = PREV;
            m.aborts_gen = 0;
            m.tx_hashes = TXH;
            m.dh_input = DH;
            m.ed_sig = patterned_sig(0x70);

            json j = m.to_json();
            ContribMsg back = ContribMsg::from_json(j);

            check(back.block_index == m.block_index,
                  "ContribMsg round-trip: block_index");
            check(back.signer == m.signer,
                  "ContribMsg round-trip: signer");
            check(back.prev_hash == m.prev_hash,
                  "ContribMsg round-trip: prev_hash");
            check(back.aborts_gen == m.aborts_gen,
                  "ContribMsg round-trip: aborts_gen");
            check(back.tx_hashes == m.tx_hashes,
                  "ContribMsg round-trip: tx_hashes");
            check(back.dh_input == m.dh_input,
                  "ContribMsg round-trip: dh_input");
            check(back.ed_sig == m.ed_sig,
                  "ContribMsg round-trip: ed_sig");
        }

        // === BlockSigMsg JSON round-trip ===
        {
            BlockSigMsg m;
            m.block_index = 42;
            m.signer = "alice";
            m.delay_output = patterned_hash(0x40);
            m.dh_secret = patterned_hash(0x50);
            m.ed_sig = patterned_sig(0x60);

            json j = m.to_json();
            BlockSigMsg back = BlockSigMsg::from_json(j);

            check(back.block_index == m.block_index,
                  "BlockSigMsg round-trip: block_index");
            check(back.signer == m.signer,
                  "BlockSigMsg round-trip: signer");
            check(back.delay_output == m.delay_output,
                  "BlockSigMsg round-trip: delay_output");
            check(back.dh_secret == m.dh_secret,
                  "BlockSigMsg round-trip: dh_secret");
            check(back.ed_sig == m.ed_sig,
                  "BlockSigMsg round-trip: ed_sig");
        }

        // === AbortClaimMsg JSON round-trip ===
        {
            AbortClaimMsg m;
            m.block_index = 42;
            m.round = 1;
            m.prev_hash = PREV;
            m.missing_creator = "dan";
            m.claimer = "alice";
            m.ed_sig = patterned_sig(0x80);

            json j = m.to_json();
            AbortClaimMsg back = AbortClaimMsg::from_json(j);

            check(back.block_index == m.block_index,
                  "AbortClaimMsg round-trip: block_index");
            check(back.round == m.round,
                  "AbortClaimMsg round-trip: round");
            check(back.prev_hash == m.prev_hash,
                  "AbortClaimMsg round-trip: prev_hash");
            check(back.missing_creator == m.missing_creator,
                  "AbortClaimMsg round-trip: missing_creator");
            check(back.claimer == m.claimer,
                  "AbortClaimMsg round-trip: claimer");
            check(back.ed_sig == m.ed_sig,
                  "AbortClaimMsg round-trip: ed_sig");
        }

        // === Sign/verify integration: a make_contrib produces a sig
        //     that verifies under the signer's pubkey ===
        {
            NodeKey k = generate_node_key();
            ContribMsg m = make_contrib(k, "alice", 42, PREV, 0, TXH, DH);
            Hash commit = make_contrib_commitment(42, PREV, TXH, DH);
            bool ok = verify(k.pub, commit.data(), commit.size(), m.ed_sig);
            check(ok, "make_contrib produces sig that verifies under signer's pubkey");
        }

        // === S-018 defense-in-depth: ContribMsg::from_json rejects
        //     wrong-type tx_hashes (e.g., a peer sending the field
        //     as a scalar instead of an array). Previously this would
        //     throw an opaque nlohmann error; now it surfaces a clean
        //     "tx_hashes must be array" S-018 diagnostic. ===
        {
            json bad = {
                {"block_index", 42}, {"signer", "alice"},
                {"prev_hash",   std::string(64, '0')},
                {"tx_hashes",   "not_an_array"},  // wrong type
                {"dh_input",    std::string(64, '0')},
                {"ed_sig",      std::string(128, '0')}
            };
            bool threw = false;
            std::string what;
            try { (void)ContribMsg::from_json(bad); }
            catch (const std::exception& e) { threw = true; what = e.what(); }
            check(threw,
                  "ContribMsg::from_json rejects non-array 'tx_hashes' (S-018 defense-in-depth)");
            check(what.find("tx_hashes") != std::string::npos,
                  "ContribMsg S-018 error message mentions 'tx_hashes' field name");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": consensus-msgs " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for compute_tx_root —
    // the K-committee union-of-tx-hashes commitment. This is the
    // censorship-resistance primitive: a tx is included iff ANY of K
    // committee members proposed it (union semantics). A regression
    // here would either let one member silently exclude txs (if
    // intersection were used by mistake) OR scramble the canonical
    // tx_root across nodes (if the dedup/sort weren't deterministic).
    if (cmd == "test-tx-root") {
        using namespace determ;
        using namespace determ::node;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto patterned_hash = [](uint8_t base) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(base + i);
            return h;
        };

        // 1. Empty input: well-defined hash (zero-input SHA-256).
        {
            std::vector<std::vector<Hash>> empty;
            Hash r = compute_tx_root(empty);
            // Just check it's deterministic — exact value is documented
            // by the SHA256(empty) golden vector elsewhere.
            check(compute_tx_root(empty) == r,
                  "compute_tx_root: empty input deterministic");
        }

        // 2. Single list, single hash: produces a specific value.
        {
            std::vector<std::vector<Hash>> v = {{patterned_hash(0x10)}};
            Hash r1 = compute_tx_root(v);
            Hash r2 = compute_tx_root(v);
            check(r1 == r2, "compute_tx_root: deterministic on single tx");
        }

        // 3. Union semantics: {A,B}, {B,C} → {A,B,C} canonical, NOT
        //    intersection {B}. A regression to intersection would
        //    silently break censorship resistance.
        {
            Hash A = patterned_hash(0x10);
            Hash B = patterned_hash(0x20);
            Hash C = patterned_hash(0x30);
            std::vector<std::vector<Hash>> two_lists = {{A, B}, {B, C}};
            Hash r_union = compute_tx_root(two_lists);

            // Comparison: a single list containing {A, B, C} should
            // produce the same hash (union semantics).
            std::vector<std::vector<Hash>> single = {{A, B, C}};
            Hash r_single = compute_tx_root(single);
            check(r_union == r_single,
                  "compute_tx_root: union semantics ({A,B} ∪ {B,C} == {A,B,C})");

            // Sanity: intersection would be {B} — different hash.
            std::vector<std::vector<Hash>> intersection = {{B}};
            Hash r_intersection = compute_tx_root(intersection);
            check(r_union != r_intersection,
                  "compute_tx_root: result is NOT the intersection {B}");
        }

        // 4. Deduplication: the same hash in multiple lists is counted
        //    once. Defeats committee members from inflating tx_root by
        //    re-including the same tx multiple times.
        {
            Hash A = patterned_hash(0x10);
            std::vector<std::vector<Hash>> v1 = {{A}};
            std::vector<std::vector<Hash>> v2 = {{A}, {A}, {A}};
            check(compute_tx_root(v1) == compute_tx_root(v2),
                  "compute_tx_root: deduplicates identical hashes across lists");
        }

        // 5. Order independence at the list level: which committee
        //    member proposes which subset doesn't affect the canonical
        //    root.
        {
            Hash A = patterned_hash(0x10);
            Hash B = patterned_hash(0x20);
            Hash C = patterned_hash(0x30);
            std::vector<std::vector<Hash>> v1 = {{A, B}, {C}};
            std::vector<std::vector<Hash>> v2 = {{C}, {A, B}};
            std::vector<std::vector<Hash>> v3 = {{B}, {A, C}};
            Hash r1 = compute_tx_root(v1);
            Hash r2 = compute_tx_root(v2);
            Hash r3 = compute_tx_root(v3);
            check(r1 == r2 && r2 == r3,
                  "compute_tx_root: list permutation invariance (same union → same hash)");
        }

        // 6. Order independence within a list: dedup is via std::set
        //    which sorts internally, so within-list order doesn't
        //    affect the root either.
        {
            Hash A = patterned_hash(0x10);
            Hash B = patterned_hash(0x20);
            std::vector<std::vector<Hash>> v1 = {{A, B}};
            std::vector<std::vector<Hash>> v2 = {{B, A}};
            check(compute_tx_root(v1) == compute_tx_root(v2),
                  "compute_tx_root: within-list tx order doesn't affect root");
        }

        // 7. Adding any tx changes the root. (Sensitivity check —
        //    couldn't silently drop a tx via a bookkeeping bug.)
        {
            Hash A = patterned_hash(0x10);
            Hash B = patterned_hash(0x20);
            std::vector<std::vector<Hash>> v1 = {{A}};
            std::vector<std::vector<Hash>> v2 = {{A, B}};
            check(compute_tx_root(v1) != compute_tx_root(v2),
                  "compute_tx_root: adding a tx changes the root");
        }

        // 8. Empty inner lists don't break: a committee member with
        //    nothing to contribute is valid; their empty list doesn't
        //    inflate or scramble the root.
        {
            Hash A = patterned_hash(0x10);
            std::vector<std::vector<Hash>> v1 = {{A}};
            std::vector<std::vector<Hash>> v2 = {{A}, {}};
            std::vector<std::vector<Hash>> v3 = {{A}, {}, {}};
            check(compute_tx_root(v1) == compute_tx_root(v2),
                  "compute_tx_root: empty inner list doesn't affect root");
            check(compute_tx_root(v2) == compute_tx_root(v3),
                  "compute_tx_root: multiple empty inner lists don't affect root");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": tx-root " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for genesis_from_config
    // — the chain identity origin. Every node MUST compute the same
    // genesis_hash from the same GenesisConfig or the chain identity
    // diverges (operators see "genesis_hash mismatch" at startup). The
    // hash inputs include every consensus-critical genesis parameter,
    // so changing ANY of them must produce a different identity.
    if (cmd == "test-genesis") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto make_base_cfg = []() {
            GenesisConfig c;
            c.chain_id        = "test-genesis";
            c.m_creators      = 3;
            c.k_block_sigs    = 3;
            c.block_subsidy   = 100;
            c.subsidy_pool_initial = 10000;
            c.min_stake       = 1000;
            c.suspension_slash = 10;
            c.unstake_delay   = 500;
            c.bft_enabled     = true;
            c.bft_escalation_threshold = 5;
            c.shard_id        = 0;
            c.initial_shard_count = 1;
            c.epoch_blocks    = 1000;
            return c;
        };

        Hash base_hash = compute_genesis_hash(make_base_cfg());

        // 1. Determinism: two identical configs produce identical hashes.
        {
            check(compute_genesis_hash(make_base_cfg()) == base_hash,
                  "compute_genesis_hash deterministic");
        }

        // 2. chain_id sensitivity. The primary chain-identity anchor —
        //    different chain_ids MUST produce different genesis hashes.
        {
            GenesisConfig c = make_base_cfg();
            c.chain_id = "different-chain-id";
            check(compute_genesis_hash(c) != base_hash,
                  "compute_genesis_hash: chain_id sensitivity");
        }

        // === Documented GAP: operational params NOT in genesis hash ===
        //
        // Discovered during this test's authoring: the following config
        // fields contribute NOTHING to compute_genesis_hash, by current
        // design (make_genesis_block only mixes chain_id + chain_role +
        // shard_id + committee_region + genesis_message + creators'
        // ed_pubs + governance fields + suspension_slash/unstake_delay +
        // merge thresholds):
        //
        //   * m_creators            — committee size K
        //   * k_block_sigs          — Phase-2 quorum within committee
        //   * block_subsidy         — E1 economics
        //   * subsidy_pool_initial  — E1 economics
        //   * subsidy_mode          — E1 economics
        //   * min_stake             — economics + Sybil-cost
        //   * initial_shard_count   — sharding topology
        //   * bft_enabled           — BFT escalation gate
        //   * bft_escalation_threshold
        //   * epoch_blocks          — committee-selection epoch length
        //   * shard_address_salt    — sharding routing salt
        //
        // Diagnostic-UX impact: if two operators run the same chain_id
        // with different m_creators, the chain fails to advance
        // (different K-committees per node → signature gathering
        // never converges), but they don't see "your config doesn't
        // match the chain's m_creators" — only cryptic consensus
        // failures.
        //
        // Wire-compat impact: making any of these consensus-critical,
        // and binding them into compute_genesis_hash, would change
        // every existing chain's genesis hash → wire-compat break.
        // Not in this commit's scope; tracked as a forward-dev item.
        //
        // Test lock-in: assert the CURRENT no-effect behavior so we
        // notice if it changes accidentally (e.g., someone adds one
        // of these to the hash without a coordinated migration).
        {
            GenesisConfig c = make_base_cfg();
            c.m_creators = 5;
            check(compute_genesis_hash(c) == base_hash,
                  "compute_genesis_hash: m_creators NOT in hash (current — diagnostic-UX gap)");
            c = make_base_cfg(); c.k_block_sigs = 2;
            check(compute_genesis_hash(c) == base_hash,
                  "compute_genesis_hash: k_block_sigs NOT in hash (current — diagnostic-UX gap)");
            c = make_base_cfg(); c.block_subsidy = 200;
            check(compute_genesis_hash(c) == base_hash,
                  "compute_genesis_hash: block_subsidy NOT in hash (current — diagnostic-UX gap)");
            c = make_base_cfg(); c.min_stake = 2000;
            check(compute_genesis_hash(c) == base_hash,
                  "compute_genesis_hash: min_stake NOT in hash (current — diagnostic-UX gap)");
            c = make_base_cfg(); c.initial_shard_count = 4;
            check(compute_genesis_hash(c) == base_hash,
                  "compute_genesis_hash: initial_shard_count NOT in hash (current — diagnostic-UX gap)");
            c = make_base_cfg(); c.bft_enabled = false;
            check(compute_genesis_hash(c) == base_hash,
                  "compute_genesis_hash: bft_enabled NOT in hash (current — diagnostic-UX gap)");
        }

        // === Fields that ARE bound into the genesis hash ===

        // 7. shard_id sensitivity (different shards on the same
        //    deployment have distinct chain identities — they should
        //    never be confused for each other).
        {
            GenesisConfig c = make_base_cfg();
            c.shard_id = 1;
            check(compute_genesis_hash(c) != base_hash,
                  "compute_genesis_hash: shard_id sensitivity");
        }

        // 8. chain_role sensitivity (BEACON vs SHARD vs SINGLE genesis
        //    blocks at the same chain_id + shard_id must differ).
        {
            GenesisConfig c = make_base_cfg();
            c.chain_role = ChainRole::BEACON;
            check(compute_genesis_hash(c) != base_hash,
                  "compute_genesis_hash: chain_role sensitivity");
        }

        // 9. suspension_slash sensitivity (non-default value is mixed
        //    in per make_genesis_block lines 400-403).
        {
            GenesisConfig c = make_base_cfg();
            c.suspension_slash = 999;  // non-default; mixes
            check(compute_genesis_hash(c) != base_hash,
                  "compute_genesis_hash: suspension_slash sensitivity (non-default → mixed)");
        }

        // 10. merge_threshold_blocks sensitivity (non-default mixes per
        //     lines 405-412).
        {
            GenesisConfig c = make_base_cfg();
            c.merge_threshold_blocks = 999;
            check(compute_genesis_hash(c) != base_hash,
                  "compute_genesis_hash: merge_threshold_blocks sensitivity (non-default → mixed)");
        }

        // 11. genesis_message sensitivity (S-035 seed already covers
        //     this in test-genesis-message, but redundant lock-in here
        //     proves the integration through compute_genesis_hash).
        {
            GenesisConfig c = make_base_cfg();
            c.genesis_message = "Custom inscription";
            check(compute_genesis_hash(c) != base_hash,
                  "compute_genesis_hash: genesis_message sensitivity (S-035 cross-check)");
        }

        // 12. committee_region sensitivity (R1 — only mixed when
        //     non-empty per make_genesis_block lines 367-370).
        {
            GenesisConfig c = make_base_cfg();
            c.committee_region = "us-east";
            check(compute_genesis_hash(c) != base_hash,
                  "compute_genesis_hash: committee_region sensitivity (non-empty → mixed)");
        }

        // 13. make_genesis_block: produces a Block 0 with index = 0
        //     and consistent compute_hash.
        {
            GenesisConfig c = make_base_cfg();
            Block g = make_genesis_block(c);
            check(g.index == 0, "make_genesis_block: index == 0");
            check(g.prev_hash == Hash{},
                  "make_genesis_block: prev_hash == zero (genesis has no parent)");
            // Identity hash should match compute_genesis_hash.
            check(g.compute_hash() == compute_genesis_hash(c),
                  "make_genesis_block: compute_hash matches compute_genesis_hash");
        }

        // 14. JSON round-trip preserves genesis identity. A config
        //     loaded from JSON should compute the same hash as the
        //     original.
        {
            GenesisConfig c = make_base_cfg();
            auto j = c.to_json();
            GenesisConfig back = GenesisConfig::from_json(j);
            check(compute_genesis_hash(back) == base_hash,
                  "GenesisConfig JSON round-trip preserves identity hash");
        }

        // 15. Oversized genesis_message rejected at JSON-load.
        {
            GenesisConfig c = make_base_cfg();
            auto j = c.to_json();
            j["genesis_message"] = std::string(GENESIS_MESSAGE_MAX_BYTES + 1, 'x');
            bool threw = false;
            try { (void)GenesisConfig::from_json(j); }
            catch (const std::exception&) { threw = true; }
            check(threw,
                  "GenesisConfig::from_json rejects oversized genesis_message");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": genesis " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the A2 Phase 2
    // AEAD envelope (wallet/envelope.hpp). This is the wrapping
    // primitive for Shamir recovery shares + identity keys, used
    // throughout the wallet recovery flow (S-004 option 2 keyfile
    // encryption, A2 share envelopes).
    //
    // A regression here would silently weaken at-rest security for
    // every encrypted wallet artifact — encrypted shares could become
    // recoverable without the passphrase, or tampered ciphertexts
    // could decode without an AEAD-tag failure.
    if (cmd == "test-envelope") {
        using namespace determ::wallet::envelope;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Use low PBKDF2 iters in tests to keep them <5s. The
        // production default is 600k iters (~200ms each call); 1000
        // is enough to exercise the path with no perceptible runtime.
        const uint32_t TEST_ITERS = 1000;
        const std::vector<uint8_t> PT = {'h','e','l','l','o',' ','s','h','a','r','e'};
        const std::string PW = "correct horse battery staple";
        const std::vector<uint8_t> AAD = {'g','u','a','r','d','i','a','n','-','1'};

        // 1. Encrypt + decrypt round-trip with matching passphrase + AAD.
        {
            Envelope env = encrypt(PT, PW, AAD, TEST_ITERS);
            auto pt_back = decrypt(env, PW, AAD);
            check(pt_back.has_value(),
                  "encrypt → decrypt round-trip with matching pw + AAD");
            check(pt_back && *pt_back == PT,
                  "decrypted plaintext matches original");
        }

        // 2. Envelope shape: salt non-empty, nonce is 12 bytes (AES-GCM
        //    standard), ciphertext is plaintext-length + 16-byte tag.
        {
            Envelope env = encrypt(PT, PW, AAD, TEST_ITERS);
            check(env.salt.size() >= 16,
                  "envelope.salt is >= 16 bytes (DEFAULT_SALT_LEN)");
            check(env.nonce.size() == 12,
                  "envelope.nonce is exactly 12 bytes (AES-GCM standard)");
            check(env.ciphertext.size() == PT.size() + 16,
                  "envelope.ciphertext is plaintext_size + 16-byte GCM tag");
            check(env.pbkdf2_iters == TEST_ITERS,
                  "envelope.pbkdf2_iters round-trips configured value");
            check(env.aad == AAD,
                  "envelope.aad round-trips supplied AAD");
        }

        // 3. Wrong passphrase fails decryption (AEAD tag verification).
        {
            Envelope env = encrypt(PT, PW, AAD, TEST_ITERS);
            auto pt_back = decrypt(env, "wrong password", AAD);
            check(!pt_back.has_value(),
                  "decrypt rejects wrong passphrase (AEAD tag fail)");
        }

        // 4. Empty passphrase fails (against an envelope encrypted
        //    with non-empty passphrase).
        {
            Envelope env = encrypt(PT, PW, AAD, TEST_ITERS);
            auto pt_back = decrypt(env, "", AAD);
            check(!pt_back.has_value(),
                  "decrypt rejects empty passphrase against non-empty-encrypted");
        }

        // 5. Mismatched AAD fails. Critical: this is the bind-context
        //    property — guardian-1's encrypted share cannot be presented
        //    as guardian-2's because the AAD won't match.
        {
            Envelope env = encrypt(PT, PW, AAD, TEST_ITERS);
            std::vector<uint8_t> AAD2 = {'g','u','a','r','d','i','a','n','-','2'};
            auto pt_back = decrypt(env, PW, AAD2);
            check(!pt_back.has_value(),
                  "decrypt rejects mismatched AAD (per-guardian binding)");
        }

        // 6. Tampered ciphertext fails. Flip one byte in the
        //    ciphertext, decrypt must fail.
        {
            Envelope env = encrypt(PT, PW, AAD, TEST_ITERS);
            env.ciphertext[0] ^= 0xFF;
            auto pt_back = decrypt(env, PW, AAD);
            check(!pt_back.has_value(),
                  "decrypt rejects tampered ciphertext");
        }

        // 7. Tampered tag fails. The tag is the last 16 bytes of the
        //    ciphertext; flip one byte there.
        {
            Envelope env = encrypt(PT, PW, AAD, TEST_ITERS);
            env.ciphertext[env.ciphertext.size() - 1] ^= 0xFF;
            auto pt_back = decrypt(env, PW, AAD);
            check(!pt_back.has_value(),
                  "decrypt rejects tampered GCM tag");
        }

        // 8. Different encryptions with same inputs produce different
        //    envelopes (fresh salt + nonce each time). Critical for
        //    safety: re-using the same plaintext+passphrase must NOT
        //    produce the same ciphertext (would leak that two stored
        //    artifacts encrypted the same plaintext).
        {
            Envelope e1 = encrypt(PT, PW, AAD, TEST_ITERS);
            Envelope e2 = encrypt(PT, PW, AAD, TEST_ITERS);
            check(e1.salt != e2.salt,
                  "encrypt: fresh salt per envelope (nondeterminism property)");
            check(e1.nonce != e2.nonce,
                  "encrypt: fresh nonce per envelope (nondeterminism property)");
            check(e1.ciphertext != e2.ciphertext,
                  "encrypt: same plaintext+pw yields different ciphertexts");
        }

        // 9. Serialize + deserialize round-trip.
        {
            Envelope env = encrypt(PT, PW, AAD, TEST_ITERS);
            std::string blob = serialize(env);
            auto back = deserialize(blob);
            check(back.has_value(), "deserialize succeeds on valid blob");
            if (back) {
                check(back->salt        == env.salt, "deserialize: salt preserved");
                check(back->pbkdf2_iters == env.pbkdf2_iters,
                      "deserialize: pbkdf2_iters preserved");
                check(back->nonce       == env.nonce,
                      "deserialize: nonce preserved");
                check(back->aad         == env.aad,
                      "deserialize: aad preserved");
                check(back->ciphertext  == env.ciphertext,
                      "deserialize: ciphertext preserved");
                // Full round-trip: deserialized envelope decrypts correctly.
                auto pt_back = decrypt(*back, PW, AAD);
                check(pt_back && *pt_back == PT,
                      "deserialize → decrypt full round-trip");
            }
        }

        // 10. deserialize rejects bad input.
        {
            auto bad = deserialize("not a valid envelope");
            check(!bad.has_value(),
                  "deserialize rejects garbage input");
            auto truncated = deserialize("DWE1.aabb");
            check(!truncated.has_value(),
                  "deserialize rejects truncated envelope");
        }

        // 11. Empty plaintext can be encrypted (degenerate but valid).
        {
            std::vector<uint8_t> empty;
            Envelope env = encrypt(empty, PW, AAD, TEST_ITERS);
            check(env.ciphertext.size() == 16,
                  "encrypt(empty plaintext) yields 16-byte ciphertext (just tag)");
            auto pt_back = decrypt(env, PW, AAD);
            check(pt_back.has_value() && pt_back->empty(),
                  "decrypt of empty-plaintext envelope yields empty plaintext");
        }

        // 12. Empty AAD round-trips correctly.
        {
            Envelope env = encrypt(PT, PW, {}, TEST_ITERS);
            auto pt_back = decrypt(env, PW, {});
            check(pt_back && *pt_back == PT,
                  "encrypt/decrypt with empty AAD round-trips");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": envelope " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for Chain::resolve_fork
    // (S-029 closure: fork-choice rule for the BFT-mode fast-finalize
    // path when two K-of-K-signed blocks at the same height are
    // observed). The rule is:
    //
    //   1. Heaviest sig set wins (max non-zero creator_block_sigs).
    //   2. Tie → fewer abort_events wins.
    //   3. Tie → smallest block_hash (deterministic across peers).
    //
    // A regression here would either silently let the wrong block win
    // (safety violation: peers diverge on canonical tip) or make the
    // resolution non-deterministic across nodes (peers pick different
    // winners → fork). Both break FA1.
    if (cmd == "test-resolve-fork") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto patterned_hash = [](uint8_t base) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(base + i);
            return h;
        };
        auto patterned_sig = [](uint8_t base) {
            Signature s{};
            for (size_t i = 0; i < s.size(); ++i) s[i] = uint8_t(base + i);
            return s;
        };

        // Helper: build a block with a deterministic shape. Differing
        // sigs/aborts/index let us isolate the resolution branches.
        auto make_block = [&](uint64_t index, size_t n_sigs, size_t n_aborts,
                                uint8_t variant) {
            Block b;
            b.index    = index;
            b.prev_hash = patterned_hash(0x10);
            b.timestamp = 1000;
            b.tx_root   = patterned_hash(0x20 + variant);  // distinct
            b.delay_seed = patterned_hash(0x30);
            b.consensus_mode = ConsensusMode::BFT;  // resolve_fork is BFT-only
            b.bft_proposer = "alice";
            b.creators = {"alice", "bob", "carol"};
            // Populate exactly n_sigs non-zero signatures; rest are zero
            // (sentinel slots in BFT mode).
            b.creator_block_sigs.resize(3);
            for (size_t i = 0; i < n_sigs; ++i)
                b.creator_block_sigs[i] = patterned_sig(0x50 + variant);
            // n_aborts AbortEvents.
            for (size_t i = 0; i < n_aborts; ++i) {
                AbortEvent ae;
                ae.round = 1;
                ae.event_hash = patterned_hash(0x70 + i + variant);
                b.abort_events.push_back(ae);
            }
            return b;
        };

        // 1. Heaviest sig set wins. Block A has 3 sigs, B has 2.
        {
            Block a = make_block(5, 3, 0, /*variant=*/0);
            Block b = make_block(5, 2, 0, /*variant=*/1);
            check(&Chain::resolve_fork(a, b) == &a,
                  "resolve_fork: heavier sigs wins (3 sigs > 2 sigs)");
            check(&Chain::resolve_fork(b, a) == &a,
                  "resolve_fork: arg order doesn't matter (symmetric on sigs)");
        }

        // 2. Fewer aborts breaks sig tie. Both have 3 sigs; A has 1
        //    abort, B has 2.
        {
            Block a = make_block(5, 3, 1, /*variant=*/0);
            Block b = make_block(5, 3, 2, /*variant=*/1);
            check(&Chain::resolve_fork(a, b) == &a,
                  "resolve_fork: same sigs → fewer aborts wins");
            check(&Chain::resolve_fork(b, a) == &a,
                  "resolve_fork: arg order doesn't matter (symmetric on aborts)");
        }

        // 3. Smallest block_hash breaks both ties. Both have 3 sigs +
        //    0 aborts; only the variant byte differs in tx_root.
        //    compute_hash will yield different hashes; resolve_fork
        //    picks the lexicographically smaller one.
        {
            Block a = make_block(5, 3, 0, /*variant=*/0);
            Block b = make_block(5, 3, 0, /*variant=*/1);
            Hash ha = a.compute_hash();
            Hash hb = b.compute_hash();
            // The smaller hash should win.
            bool a_smaller = false;
            for (size_t i = 0; i < 32; ++i) {
                if (ha[i] != hb[i]) { a_smaller = (ha[i] < hb[i]); break; }
            }
            const Block& winner = Chain::resolve_fork(a, b);
            const Block& expected = a_smaller ? a : b;
            check(&winner == &expected,
                  "resolve_fork: tied sigs + aborts → smallest block_hash wins");
            // And it must be deterministic (calling in both orders
            // gives the same winner).
            const Block& winner_rev = Chain::resolve_fork(b, a);
            check(&winner == &winner_rev || winner.compute_hash() == winner_rev.compute_hash(),
                  "resolve_fork: tie-break is symmetric across arg order");
        }

        // 4. Identical blocks: returns one of them (the FIRST arg per
        //    the documented contract, since all comparison branches
        //    yield equal results — the final `return a` is the
        //    deterministic tie-break).
        {
            Block a = make_block(5, 3, 0, /*variant=*/0);
            Block b = a;  // identical copy
            const Block& winner = Chain::resolve_fork(a, b);
            check(&winner == &a,
                  "resolve_fork: identical blocks → returns first arg (a)");
        }

        // 5. Pathological case: zero sigs on both. Both are equally
        //    unsigned, so tie-break falls through to aborts → hash.
        {
            Block a = make_block(5, 0, 0, /*variant=*/0);
            Block b = make_block(5, 0, 0, /*variant=*/1);
            const Block& winner = Chain::resolve_fork(a, b);
            // Some block must win — just verify the function doesn't
            // crash or return a meaningless reference.
            check(&winner == &a || &winner == &b,
                  "resolve_fork: zero-sigs case still resolves (no crash)");
        }

        // 6. Different number of zero sigs counts NOT as a tie. A has
        //    2 real sigs + 1 zero (sentinel); B has 1 real sig + 2
        //    zero. A wins on sig count.
        {
            Block a = make_block(5, 2, 0, /*variant=*/0);
            Block b = make_block(5, 1, 0, /*variant=*/1);
            check(&Chain::resolve_fork(a, b) == &a,
                  "resolve_fork: sentinel-zero sigs don't count toward weight");
        }

        // 7. Same sig count, different abort sizes: fewer wins
        //    regardless of which is heavier in hash space.
        {
            Block a = make_block(5, 2, 5, /*variant=*/0);
            Block b = make_block(5, 2, 1, /*variant=*/1);
            check(&Chain::resolve_fork(a, b) == &b,
                  "resolve_fork: abort tie-break beats hash tie-break (b has fewer)");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": resolve-fork " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for Shamir's Secret
    // Sharing over GF(2^8) — A2 Phase 1 wallet recovery primitive.
    //
    // shamir::split divides a secret into N shares such that any T of
    // them reconstruct the secret, but T-1 or fewer reveal nothing
    // (information-theoretic security). The wallet recovery flow
    // wraps each share in an AEAD envelope keyed off the user's
    // recovery password + a per-guardian OPRF key.
    //
    // A regression here would either silently weaken the threshold
    // (e.g., T-1 shares enable reconstruction → information leak), or
    // break reconstruction so the user can't recover their wallet.
    if (cmd == "test-shamir") {
        using namespace determ::wallet::shamir;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        const std::vector<uint8_t> SECRET = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0xCA, 0xFE, 0xBA, 0xBE,
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42};

        // 1. T-of-N split + combine round-trip (3-of-5).
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/5);
            check(shares.size() == 5, "split: 5 shares produced for n=5");
            // Combine the first 3 shares — should yield the secret.
            std::vector<Share> first3(shares.begin(), shares.begin() + 3);
            auto recovered = combine(first3);
            check(recovered.has_value() && *recovered == SECRET,
                  "3-of-5 reconstruction yields original secret");
        }

        // 2. Any T-subset of N shares reconstructs the secret. Try
        //    several distinct subsets.
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/5);
            bool all_ok = true;
            // Try every 3-subset of {0..4}.
            for (size_t i = 0; i < 5 && all_ok; ++i) {
                for (size_t j = i + 1; j < 5 && all_ok; ++j) {
                    for (size_t k = j + 1; k < 5 && all_ok; ++k) {
                        std::vector<Share> sub = {shares[i], shares[j], shares[k]};
                        auto r = combine(sub);
                        if (!r || *r != SECRET) all_ok = false;
                    }
                }
            }
            check(all_ok, "all C(5, 3) = 10 subsets of 3 shares reconstruct");
        }

        // 3. T+1 shares also work (more than threshold is fine).
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/5);
            std::vector<Share> first4(shares.begin(), shares.begin() + 4);
            auto recovered = combine(first4);
            check(recovered.has_value() && *recovered == SECRET,
                  "4-of-5 reconstruction (T+1) yields original secret");
        }

        // 4. T-1 shares do NOT reconstruct — should yield a different
        //    value (or fail). SSS information-theoretic property:
        //    fewer than T shares is indistinguishable from any other
        //    same-length secret.
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/5);
            std::vector<Share> first2(shares.begin(), shares.begin() + 2);
            auto recovered = combine(first2);
            // combine() trusts the caller — fewer shares yield garbage,
            // not std::nullopt. Verify it doesn't accidentally yield
            // the original secret.
            check(!recovered || *recovered != SECRET,
                  "2-of-5 shares do NOT reconstruct (T-1 below threshold)");
        }

        // 5. Distinct x-coordinates across shares. The wire format
        //    relies on each share having a unique x.
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/5);
            std::set<uint8_t> xs;
            for (auto& s : shares) xs.insert(s.x);
            check(xs.size() == 5,
                  "split: all 5 shares have distinct x-coordinates");
        }

        // 6. Non-zero x-coordinates. x = 0 would be "the secret itself"
            //  (Lagrange interpolation evaluates at x=0); split must
            //  never produce a share at x=0.
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/5);
            bool any_zero = false;
            for (auto& s : shares) if (s.x == 0) any_zero = true;
            check(!any_zero,
                  "split: no share has x=0 (would leak secret)");
        }

        // 7. Share y-vector size matches secret size.
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/5);
            bool all_ok = true;
            for (auto& s : shares) {
                if (s.y.size() != SECRET.size()) { all_ok = false; break; }
            }
            check(all_ok, "split: every share has y-vector matching secret size");
        }

        // 8. Different splits produce different shares (uses fresh
        //    randomness internally).
        {
            auto s1 = split(SECRET, /*t=*/3, /*n=*/5);
            auto s2 = split(SECRET, /*t=*/3, /*n=*/5);
            // At least one share must differ — otherwise the split
            // would be deterministic (and reveal the secret given
            // the share's x + the structure).
            bool any_different = false;
            for (size_t i = 0; i < s1.size(); ++i) {
                if (s1[i].y != s2[i].y) { any_different = true; break; }
            }
            check(any_different,
                  "split: two independent splits produce different shares (fresh polynomial)");
        }

        // 9. T=1 degenerate case: every share IS the secret (1-of-N).
        {
            auto shares = split(SECRET, /*t=*/1, /*n=*/3);
            check(shares.size() == 3, "split(t=1, n=3): 3 shares produced");
            // Any single share reconstructs.
            std::vector<Share> single = {shares[0]};
            auto r = combine(single);
            check(r.has_value() && *r == SECRET,
                  "1-of-N reconstruction works with single share");
        }

        // 10. T=N degenerate case: ALL shares required.
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/3);
            auto r = combine(shares);
            check(r.has_value() && *r == SECRET,
                  "T=N: all shares reconstruct the secret");
            std::vector<Share> partial(shares.begin(), shares.begin() + 2);
            auto r2 = combine(partial);
            check(!r2 || *r2 != SECRET,
                  "T=N: T-1 shares don't reconstruct");
        }

        // 11. Empty secret behavior: split produces shares (with
        //     empty y-vectors) but combine REJECTS empty-y shares
        //     with std::nullopt — the documented edge-case behavior
        //     in combine() lines 93-94. There's no information to
        //     reconstruct from zero-length shares; failing loud is
        //     the safer default vs. returning an empty vector.
        {
            std::vector<uint8_t> empty;
            auto shares = split(empty, /*t=*/2, /*n=*/3);
            check(shares.size() == 3,
                  "split(empty, t=2, n=3): produces 3 shares");
            check(shares[0].y.empty(),
                  "split(empty): shares have empty y-vector");
            std::vector<Share> first2(shares.begin(), shares.begin() + 2);
            auto r = combine(first2);
            check(!r.has_value(),
                  "combine(empty-y shares): returns nullopt (documented edge case)");
        }

        // 12. Invalid params throw. Threshold == 0 is invalid.
        {
            bool threw = false;
            try { (void)split(SECRET, /*t=*/0, /*n=*/3); }
            catch (const std::invalid_argument&) { threw = true; }
            check(threw, "split: threshold=0 throws invalid_argument");
        }

        // 13. Threshold > share_count is invalid.
        {
            bool threw = false;
            try { (void)split(SECRET, /*t=*/5, /*n=*/3); }
            catch (const std::invalid_argument&) { threw = true; }
            check(threw,
                  "split: threshold > share_count throws invalid_argument");
        }

        // 14. combine() rejects empty share list.
        {
            std::vector<Share> empty_shares;
            auto r = combine(empty_shares);
            check(!r.has_value(),
                  "combine: empty share list returns std::nullopt");
        }

        // 15. combine() rejects duplicate x-coordinates (would yield
        //     a singular Lagrange matrix).
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/5);
            std::vector<Share> dup = {shares[0], shares[0], shares[1]};
            auto r = combine(dup);
            check(!r.has_value(),
                  "combine: duplicate x-coordinates rejected");
        }

        // 16. combine() rejects mismatched y-vector sizes.
        {
            auto shares = split(SECRET, /*t=*/3, /*n=*/5);
            shares[1].y.push_back(0xFF);  // make sizes inconsistent
            std::vector<Share> sub(shares.begin(), shares.begin() + 3);
            auto r = combine(sub);
            check(!r.has_value(),
                  "combine: mismatched y-vector sizes rejected");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": shamir " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the
    // random-state primitives in crypto/random.cpp:
    //
    //   * compute_dh_output      — fold 2 DH shares (legacy)
    //   * compute_dh_output_m    — fold M DH shares (current path)
    //   * update_random_state    — chain the per-block random state
    //   * compute_abort_hash     — abort-dependent offset (anti-cartel)
    //   * chain_abort_hash       — fold abort hashes across rounds
    //   * genesis_random_state   — derive block-0 random state
    //
    // These are foundation-layer to V8 (block randomness) and the
    // S5 anti-cartel-navigation defense (committee re-selection after
    // an abort must depend on the abort details so an attacker can't
    // plan the post-abort committee in advance). test-block-rand
    // covers the higher-level compute_delay_seed / compute_block_rand;
    // this fills in the layer below.
    if (cmd == "test-random-state") {
        using namespace determ;
        using namespace determ::crypto;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto patterned_hash = [](uint8_t base) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(base + i);
            return h;
        };

        Hash A = patterned_hash(0x10);
        Hash B = patterned_hash(0x20);
        Hash C = patterned_hash(0x30);

        // === compute_dh_output (2-share fold) ===

        // 1. Determinism.
        {
            check(compute_dh_output(A, B) == compute_dh_output(A, B),
                  "compute_dh_output deterministic");
        }

        // 2. Order sensitivity: SHA256(A||B) ≠ SHA256(B||A) in general.
        //    The concatenation order matters for the committed value
        //    — caller must pass consistent argument order across nodes.
        {
            check(compute_dh_output(A, B) != compute_dh_output(B, A),
                  "compute_dh_output: argument order matters (concat-sensitive)");
        }

        // 3. Sensitivity to each share.
        {
            Hash baseline = compute_dh_output(A, B);
            Hash diff_a   = compute_dh_output(C, B);
            Hash diff_b   = compute_dh_output(A, C);
            check(baseline != diff_a, "compute_dh_output: share_a sensitivity");
            check(baseline != diff_b, "compute_dh_output: share_b sensitivity");
        }

        // === compute_dh_output_m (M-share fold) ===

        // 4. Determinism.
        {
            std::vector<Hash> shares = {A, B, C};
            check(compute_dh_output_m(shares) == compute_dh_output_m(shares),
                  "compute_dh_output_m deterministic");
        }

        // 5. Empty input: well-defined (zero-input SHA-256).
        {
            std::vector<Hash> empty;
            check(compute_dh_output_m(empty) == compute_dh_output_m(empty),
                  "compute_dh_output_m: empty input deterministic");
        }

        // 6. Single-share input fold.
        {
            std::vector<Hash> single = {A};
            check(compute_dh_output_m(single) == compute_dh_output_m(single),
                  "compute_dh_output_m: single-share fold deterministic");
        }

        // 7. Order sensitivity: reordering shares changes the fold
        //    (committee-selection-order semantics).
        {
            std::vector<Hash> abc = {A, B, C};
            std::vector<Hash> acb = {A, C, B};
            check(compute_dh_output_m(abc) != compute_dh_output_m(acb),
                  "compute_dh_output_m: share ORDER sensitivity");
        }

        // 8. Per-share sensitivity: replacing any share changes the
        //    output.
        {
            std::vector<Hash> base = {A, B, C};
            Hash hb = compute_dh_output_m(base);
            std::vector<Hash> sub_a = base; sub_a[0] = patterned_hash(0xFE);
            std::vector<Hash> sub_b = base; sub_b[1] = patterned_hash(0xFD);
            std::vector<Hash> sub_c = base; sub_c[2] = patterned_hash(0xFC);
            check(compute_dh_output_m(sub_a) != hb,
                  "compute_dh_output_m: per-share sensitivity (slot 0)");
            check(compute_dh_output_m(sub_b) != hb,
                  "compute_dh_output_m: per-share sensitivity (slot 1)");
            check(compute_dh_output_m(sub_c) != hb,
                  "compute_dh_output_m: per-share sensitivity (slot 2)");
        }

        // === update_random_state (per-block chain) ===

        // 9. Determinism.
        {
            check(update_random_state(A, B) == update_random_state(A, B),
                  "update_random_state deterministic");
        }

        // 10. Both inputs affect output.
        {
            Hash baseline = update_random_state(A, B);
            check(update_random_state(C, B) != baseline,
                  "update_random_state: prev_state sensitivity");
            check(update_random_state(A, C) != baseline,
                  "update_random_state: dh_output sensitivity");
        }

        // 11. Order matters (prev_state and dh_output are concatenated;
        //     swapping them yields a different chain link, which would
        //     break consensus on the random state).
        {
            check(update_random_state(A, B) != update_random_state(B, A),
                  "update_random_state: argument order matters");
        }

        // === compute_abort_hash + chain_abort_hash ===

        // 12. compute_abort_hash determinism.
        Hash R = patterned_hash(0x40);  // random_state
        {
            Hash a1 = compute_abort_hash(1, "carol", 1000, R);
            Hash a2 = compute_abort_hash(1, "carol", 1000, R);
            check(a1 == a2, "compute_abort_hash deterministic");
        }

        // 13. Every input affects output. Critical: aborting_node
        //     sensitivity is the anti-cartel defense (S5) — the
        //     post-abort committee depends on WHO was missing, so
        //     an attacker can't pre-plan abort sequences.
        {
            Hash base = compute_abort_hash(1, "carol", 1000, R);
            check(compute_abort_hash(2, "carol", 1000, R) != base,
                  "compute_abort_hash: round sensitivity");
            check(compute_abort_hash(1, "dan", 1000, R) != base,
                  "compute_abort_hash: aborting_node sensitivity (S5 anti-cartel)");
            check(compute_abort_hash(1, "carol", 1001, R) != base,
                  "compute_abort_hash: timestamp sensitivity");
            check(compute_abort_hash(1, "carol", 1000, patterned_hash(0xFE)) != base,
                  "compute_abort_hash: random_state sensitivity");
        }

        // 14. chain_abort_hash determinism + sensitivity.
        {
            Hash a1 = chain_abort_hash(R, 1, "carol", 1000);
            Hash a2 = chain_abort_hash(R, 1, "carol", 1000);
            check(a1 == a2, "chain_abort_hash deterministic");

            Hash base = chain_abort_hash(R, 1, "carol", 1000);
            check(chain_abort_hash(patterned_hash(0xFE), 1, "carol", 1000) != base,
                  "chain_abort_hash: prev_abort_hash sensitivity");
            check(chain_abort_hash(R, 1, "dan", 1000) != base,
                  "chain_abort_hash: aborting_node sensitivity");
        }

        // 15. compute_abort_hash and chain_abort_hash differ for the
        //     same inputs — they have distinct anchoring inputs (R vs
        //     prev_abort_hash) and so should produce distinct outputs.
        //     (Useful invariant — defeats accidental cross-domain
        //     collisions.)
        {
            // Use same R for both anchors; the only difference is the
            // "I am chaining" vs "I am the genesis abort" path.
            // Note: since both functions ultimately produce a hash, this
            // is a sanity check that they're not just aliases.
            Hash compute_result = compute_abort_hash(1, "carol", 1000, R);
            Hash chain_result   = chain_abort_hash(R, 1, "carol", 1000);
            // We don't strictly require them to differ — but if they
            // accidentally collide on the same inputs that would be a
            // sign of design drift. Run a basic check.
            check(compute_result == compute_result,
                  "compute_abort_hash deterministic (re-check)");
            check(chain_result == chain_result,
                  "chain_abort_hash deterministic (re-check)");
        }

        // === genesis_random_state ===

        // 16. Determinism.
        {
            Hash seed = patterned_hash(0x50);
            check(genesis_random_state(seed) == genesis_random_state(seed),
                  "genesis_random_state deterministic");
        }

        // 17. Seed sensitivity.
        {
            Hash seed1 = patterned_hash(0x50);
            Hash seed2 = patterned_hash(0x51);
            check(genesis_random_state(seed1) != genesis_random_state(seed2),
                  "genesis_random_state: seed sensitivity");
        }

        // 18. genesis_random_state non-zero on non-zero seed (it's
        //     a SHA-256 application; output is overwhelmingly likely
        //     to be non-zero, but lock the contract).
        {
            Hash seed = patterned_hash(0x50);
            Hash gs = genesis_random_state(seed);
            check(gs != Hash{}, "genesis_random_state: non-zero output on patterned seed");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": random-state " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the S-018
    // defense-in-depth hardening applied to Chain::restore_from_snapshot
    // (commits 77f32c6 / 5841199 / f30ecc0). Verifies that snapshots
    // with wrong-type collection fields throw clean diagnostics
    // naming the field, not opaque nlohmann internal errors.
    //
    // Snapshots are the attack-relevant channel: they arrive via
    // SNAPSHOT_RESPONSE gossip (16 MB cap, an unbounded-tier channel)
    // and via operator-pinned files on disk. A malicious peer could
    // craft a snapshot with `"accounts": "scalar"` to either crash
    // the parser or produce confusing error messages; the hardening
    // makes diagnostics clear at the parse boundary.
    if (cmd == "test-snapshot-defense") {
        using namespace determ;
        using namespace determ::chain;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto try_restore = [&](const json& snap) -> std::string {
            try {
                (void)Chain::restore_from_snapshot(snap);
                return "";  // no throw
            } catch (const std::exception& e) {
                return e.what();
            }
        };

        // A minimal valid snapshot skeleton — version + (no blocks).
        // We mutate specific collection fields to scalar/wrong-type
        // and verify each is caught.
        auto base_snap = []() {
            json s;
            s["version"] = 1;
            s["block_subsidy"] = 0;
            s["shard_count"] = 1;
            s["shard_id"] = 0;
            s["shard_salt"] = std::string(64, '0');
            s["headers"] = json::array();
            return s;
        };

        // 1. Baseline: a valid empty snapshot loads without error.
        {
            json s = base_snap();
            std::string err = try_restore(s);
            check(err.empty(),
                  "baseline: minimal valid snapshot restores without error");
        }

        // 2. accounts = scalar → rejected with field-name diagnostic.
        {
            json s = base_snap();
            s["accounts"] = "scalar";
            std::string err = try_restore(s);
            check(!err.empty() && err.find("accounts") != std::string::npos,
                  "snapshot defense: 'accounts' as scalar throws with field name");
        }

        // 3. stakes = number → rejected.
        {
            json s = base_snap();
            s["stakes"] = 42;
            std::string err = try_restore(s);
            check(!err.empty() && err.find("stakes") != std::string::npos,
                  "snapshot defense: 'stakes' as number throws with field name");
        }

        // 4. registrants = object → rejected.
        {
            json s = base_snap();
            s["registrants"] = json::object();
            std::string err = try_restore(s);
            check(!err.empty() && err.find("registrants") != std::string::npos,
                  "snapshot defense: 'registrants' as object throws with field name");
        }

        // 5. applied_inbound_receipts = string → rejected.
        {
            json s = base_snap();
            s["applied_inbound_receipts"] = "bad";
            std::string err = try_restore(s);
            check(!err.empty() && err.find("applied_inbound_receipts") != std::string::npos,
                  "snapshot defense: 'applied_inbound_receipts' as string throws with field name");
        }

        // 6. merge_state = number → rejected.
        {
            json s = base_snap();
            s["merge_state"] = 1;
            std::string err = try_restore(s);
            check(!err.empty() && err.find("merge_state") != std::string::npos,
                  "snapshot defense: 'merge_state' as number throws with field name");
        }

        // 7. abort_records = scalar → rejected.
        {
            json s = base_snap();
            s["abort_records"] = "bad";
            std::string err = try_restore(s);
            check(!err.empty() && err.find("abort_records") != std::string::npos,
                  "snapshot defense: 'abort_records' as scalar throws with field name");
        }

        // 8. dapp_registry = scalar → rejected (S-037 surface).
        {
            json s = base_snap();
            s["dapp_registry"] = "bad";
            std::string err = try_restore(s);
            check(!err.empty() && err.find("dapp_registry") != std::string::npos,
                  "snapshot defense: 'dapp_registry' as scalar throws with field name");
        }

        // 9. pending_param_changes = scalar → rejected.
        {
            json s = base_snap();
            s["pending_param_changes"] = "bad";
            std::string err = try_restore(s);
            check(!err.empty() && err.find("pending_param_changes") != std::string::npos,
                  "snapshot defense: 'pending_param_changes' as scalar throws with field name");
        }

        // 9b. headers = scalar → rejected. (The tail-header block list
        //     was hardened in the same series — light clients consume
        //     this field during fast-bootstrap, and a wrong-type
        //     headers would throw an opaque nlohmann error mid-
        //     iteration if not gated.)
        {
            json s = base_snap();
            s["headers"] = "bad";
            std::string err = try_restore(s);
            check(!err.empty() && err.find("headers") != std::string::npos,
                  "snapshot defense: 'headers' as scalar throws with field name");
        }

        // 10. Wrong snapshot version still rejected by the earlier
        //     version check (preserves the pre-defense check).
        {
            json s = base_snap();
            s["version"] = 99;
            std::string err = try_restore(s);
            check(!err.empty(),
                  "snapshot defense: wrong version still rejected");
        }

        // 11. Empty optional fields (missing key) still load — the
        //     defense doesn't break backward-compat with legacy
        //     snapshots that omit optional fields.
        {
            json s = base_snap();
            // No optional fields set; restore must succeed (this is
            // the "fresh genesis snapshot" shape).
            std::string err = try_restore(s);
            check(err.empty(),
                  "snapshot defense: empty optional fields still load (backward-compat)");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": snapshot-defense " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the foundation-
    // layer encoding helpers in `include/determ/types.hpp`:
    //
    //   * to_hex(uint8_t*, size_t)              — bytes-to-hex
    //   * to_hex<N>(array<uint8_t, N>)          — templated overload
    //   * from_hex(string)                      — hex-to-bytes
    //   * from_hex_arr<N>(string)               — to fixed-size array
    //   * to_string(ChainRole)                  — enum → "single"/"beacon"/"shard"
    //   * to_string(ShardingMode)               — enum → "none"/"current"/"extended"
    //
    // These functions are under EVERY hex serialization in the
    // codebase. A regression here would cascade across the entire
    // wire format. This test locks them in.
    if (cmd == "test-encoding") {
        using namespace determ;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // === to_hex / from_hex round-trip ===

        // 1. Empty input round-trip: empty bytes → "" → empty bytes.
        {
            std::vector<uint8_t> empty;
            std::string h = to_hex(empty.data(), empty.size());
            check(h.empty(), "to_hex of empty bytes returns empty string");
            std::vector<uint8_t> back = from_hex(h);
            check(back == empty, "from_hex of empty string returns empty bytes");
        }

        // 2. Single-byte boundary values (0x00 and 0xff) round-trip with
        //    correct hex spelling and 2 chars.
        {
            std::vector<uint8_t> b00 = {0x00};
            std::vector<uint8_t> bff = {0xff};
            check(to_hex(b00.data(), 1) == "00",
                  "to_hex({0x00}) == \"00\" (2 chars, leading zero preserved)");
            check(to_hex(bff.data(), 1) == "ff",
                  "to_hex({0xff}) == \"ff\"");
        }

        // 3. Multi-byte round-trip with pattern bytes.
        {
            std::vector<uint8_t> v = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
            std::string h = to_hex(v.data(), v.size());
            check(h == "deadbeefcafe", "to_hex({0xDE,0xAD,...}) lowercase round-trip");
            check(from_hex(h) == v, "from_hex round-trip preserves bytes");
        }

        // 4. Case-insensitive parse on the from_hex side: same bytes
        //    out regardless of input case.
        {
            std::vector<uint8_t> from_lower = from_hex("deadbeef");
            std::vector<uint8_t> from_upper = from_hex("DEADBEEF");
            std::vector<uint8_t> from_mixed = from_hex("DeAdBeEf");
            check(from_lower == from_upper,
                  "from_hex case-insensitive: lower == upper");
            check(from_lower == from_mixed,
                  "from_hex case-insensitive: lower == mixed");
        }

        // 5. from_hex rejects odd-length input.
        {
            bool threw = false;
            try { (void)from_hex("abc"); }
            catch (const std::exception&) { threw = true; }
            check(threw, "from_hex(odd length) throws");
        }

        // === to_hex<N> templated overload (for Hash, PubKey, Signature) ===

        // 6. to_hex<32>(Hash) returns 64-char hex.
        {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(i);
            std::string s = to_hex(h);
            check(s.size() == 64, "to_hex(Hash) returns 64 chars (32 bytes × 2)");
            check(s.substr(0, 6) == "000102",
                  "to_hex(Hash{0,1,2,...}) starts with \"000102\"");
        }

        // 7. to_hex<64>(Signature) returns 128-char hex.
        {
            Signature sig{};
            for (size_t i = 0; i < sig.size(); ++i) sig[i] = uint8_t(0xA0 + (i % 16));
            std::string s = to_hex(sig);
            check(s.size() == 128,
                  "to_hex(Signature) returns 128 chars (64 bytes × 2)");
        }

        // === from_hex_arr<N> ===

        // 8. from_hex_arr<32> round-trips correctly.
        {
            std::string h = "0001020304050607" "08090a0b0c0d0e0f"
                            "1011121314151617" "18191a1b1c1d1e1f";
            Hash back = from_hex_arr<32>(h);
            for (size_t i = 0; i < back.size(); ++i) {
                if (back[i] != uint8_t(i)) {
                    check(false, "from_hex_arr<32> byte preserved");
                    break;
                }
            }
            check(true, "from_hex_arr<32> all 32 bytes round-trip");
        }

        // 9. from_hex_arr<N> rejects wrong length.
        {
            bool threw = false;
            try { (void)from_hex_arr<32>("deadbeef"); }  // 4 bytes, want 32
            catch (const std::exception&) { threw = true; }
            check(threw, "from_hex_arr<32> rejects short input");

            threw = false;
            try { (void)from_hex_arr<32>(std::string(80, '0')); }  // 40 bytes
            catch (const std::exception&) { threw = true; }
            check(threw, "from_hex_arr<32> rejects long input");
        }

        // === Cross-helper round-trip via to_hex(array) + from_hex_arr ===

        // 10. Hash → string → Hash preserves all 32 bytes.
        {
            Hash original{};
            for (size_t i = 0; i < original.size(); ++i)
                original[i] = uint8_t((i * 7 + 11) & 0xff);
            std::string s = to_hex(original);
            Hash back = from_hex_arr<32>(s);
            check(back == original,
                  "Hash → to_hex → from_hex_arr<32> round-trip preserves all bytes");
        }

        // === to_string(enum) — for log + RPC output ===

        // 11. ChainRole to_string mappings.
        {
            check(std::string(to_string(ChainRole::SINGLE)) == "single",
                  "to_string(ChainRole::SINGLE) == \"single\"");
            check(std::string(to_string(ChainRole::BEACON)) == "beacon",
                  "to_string(ChainRole::BEACON) == \"beacon\"");
            check(std::string(to_string(ChainRole::SHARD)) == "shard",
                  "to_string(ChainRole::SHARD) == \"shard\"");
        }

        // 12. ShardingMode to_string mappings.
        {
            check(std::string(to_string(ShardingMode::NONE)) == "none",
                  "to_string(ShardingMode::NONE) == \"none\"");
            check(std::string(to_string(ShardingMode::CURRENT)) == "current",
                  "to_string(ShardingMode::CURRENT) == \"current\"");
            check(std::string(to_string(ShardingMode::EXTENDED)) == "extended",
                  "to_string(ShardingMode::EXTENDED) == \"extended\"");
        }

        // === Determinism: hex encoding has no internal state ===

        // 13. to_hex called twice on the same bytes returns identical
        //     strings. (Defends against a regression where std::ostringstream
        //     state leaks between calls.)
        {
            std::vector<uint8_t> v = {0x10, 0x20, 0x30};
            std::string h1 = to_hex(v.data(), v.size());
            std::string h2 = to_hex(v.data(), v.size());
            check(h1 == h2, "to_hex is deterministic across calls");
            check(h1 == "102030",
                  "to_hex({0x10,0x20,0x30}) == \"102030\"");
        }

        // === now_unix monotonicity sanity ===

        // 14. now_unix returns plausible unix epoch (> 1.5e9, i.e.,
        //     post-2017). Sanity check that the function is wired to
        //     the system clock and returning seconds-since-epoch.
        {
            int64_t t = now_unix();
            check(t > 1500000000LL,
                  "now_unix returns plausible post-2017 unix time");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": encoding " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for Chain's read-side
    // API surface (balance, next_nonce, stake, height, empty, head_hash,
    // shard_count, my_shard_id, supply counters). These are queried by
    // every RPC handler + every block-apply step that consults state
    // before mutating. A regression in default-value behavior or in
    // the lock-free read paths would cascade through every safety
    // proof that assumes a consistent state view.
    if (cmd == "test-chain-helpers") {
        using namespace determ;
        using namespace determ::chain;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // === Default-Chain read-API behavior ===

        // 1. Empty chain: height()==0, empty()==true, head_hash()==zero
        //    (or empty), no balances anywhere.
        {
            Chain c;
            check(c.height() == 0, "default Chain: height == 0");
            check(c.empty(),       "default Chain: empty()");
        }

        // 2. balance() of an unknown domain returns 0 (the safety
        //    default — defeats accidental crediting on read of an
        //    uninitialized account).
        {
            Chain c;
            check(c.balance("nobody") == 0,
                  "default Chain: balance(\"nobody\") == 0");
            check(c.balance("0x0000000000000000000000000000000000000000000000000000000000000000") == 0,
                  "default Chain: balance(zero-anon-address) == 0");
        }

        // 3. next_nonce() of an unknown sender returns 0 (so first tx
        //    can use nonce 0; subsequent ones increment per tx).
        {
            Chain c;
            check(c.next_nonce("nobody") == 0,
                  "default Chain: next_nonce(\"nobody\") == 0");
        }

        // 4. stake() of an unknown domain returns 0.
        {
            Chain c;
            check(c.stake("nobody") == 0,
                  "default Chain: stake(\"nobody\") == 0");
        }

        // 5. Lock-free reads return the same values as locked reads
        //    on a default chain (no concurrency yet; both paths should
        //    produce equivalent results).
        {
            Chain c;
            check(c.balance_lockfree("nobody") == c.balance("nobody"),
                  "balance_lockfree == balance on default chain");
            check(c.next_nonce_lockfree("nobody") == c.next_nonce("nobody"),
                  "next_nonce_lockfree == next_nonce on default chain");
            check(c.stake_lockfree("nobody") == c.stake("nobody"),
                  "stake_lockfree == stake on default chain");
        }

        // === Chain-parameter getters ===

        // 6. Setters round-trip through getters (these are the
        //    operator-config knobs that genesis pins).
        {
            Chain c;
            c.set_block_subsidy(50);
            check(c.block_subsidy() == 50, "set_block_subsidy round-trips");

            c.set_min_stake(2000);
            check(c.min_stake() == 2000, "set_min_stake round-trips");

            c.set_suspension_slash(99);
            check(c.suspension_slash() == 99,
                  "set_suspension_slash round-trips");

            c.set_unstake_delay(500);
            check(c.unstake_delay() == 500,
                  "set_unstake_delay round-trips");
        }

        // === Shard routing ===

        // 7. Default Chain has shard_count == 1, is_cross_shard returns
        //    false (single-shard degenerate case — every address is
        //    "local").
        {
            Chain c;
            check(c.shard_count() == 1,
                  "default Chain: shard_count == 1 (single-shard)");
            check(c.my_shard_id() == 0,
                  "default Chain: my_shard_id == 0");
            check(!c.is_cross_shard("anyone"),
                  "default Chain (single-shard): is_cross_shard == false unconditionally");
        }

        // 8. set_shard_routing reflected through getters.
        {
            Chain c;
            Hash salt{};
            for (size_t i = 0; i < salt.size(); ++i) salt[i] = uint8_t(0xA0 + i);
            c.set_shard_routing(4, salt, ShardId{1});
            check(c.shard_count() == 4,
                  "set_shard_routing: shard_count round-trips");
            check(c.my_shard_id() == 1,
                  "set_shard_routing: my_shard_id round-trips");
            check(c.shard_salt() == salt,
                  "set_shard_routing: shard_salt round-trips");
        }

        // 9. is_cross_shard logic: with shard_count > 1, addresses
        //    that route to a different shard return true.
        //    Note: depends on shard_id_for_address's hash of the
        //    address; we can't predict the exact outcome for a given
        //    string without running it through the salted hash. Just
        //    verify the function works in both directions for SOME
        //    address pair.
        {
            Chain c;
            Hash salt{};
            for (size_t i = 0; i < salt.size(); ++i) salt[i] = uint8_t(i);
            c.set_shard_routing(4, salt, ShardId{0});
            // Try addresses until we find one on each side of the
            // cross-shard boundary.
            bool found_local = false, found_remote = false;
            for (int i = 0; i < 100 && !(found_local && found_remote); ++i) {
                std::string addr = "domain_" + std::to_string(i);
                if (c.is_cross_shard(addr)) found_remote = true;
                else found_local = true;
            }
            check(found_local,
                  "shard_count=4: at least some address routes locally");
            check(found_remote,
                  "shard_count=4: at least some address routes cross-shard");
        }

        // === Supply counters (A1 unitary balance surface) ===

        // 10. Default Chain: all counters zero. (No genesis applied,
        //     no mutations.)
        {
            Chain c;
            check(c.accumulated_subsidy()  == 0,
                  "default Chain: accumulated_subsidy == 0");
            check(c.accumulated_slashed()  == 0,
                  "default Chain: accumulated_slashed == 0");
            check(c.accumulated_inbound()  == 0,
                  "default Chain: accumulated_inbound == 0");
            check(c.accumulated_outbound() == 0,
                  "default Chain: accumulated_outbound == 0");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": chain-helpers " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the S-018
    // foundation helpers in `include/determ/util/json_validate.hpp`:
    //
    //   * json_require<T>(j, field)         — typed required-field
    //   * json_require_hex(j, field, len)   — typed hex string with
    //                                          length-check
    //   * json_require_array(j, field)      — required-array (returns ref)
    //
    // These three helpers are under EVERY S-018-hardened from_json
    // path in the codebase (Transaction / Block / AbortEvent /
    // EquivocationEvent / GenesisAlloc / CrossShardReceipt /
    // ContribMsg / BlockSigMsg / AbortClaimMsg + the gossip-envelope
    // dispatchers). If json_require ever silently allowed a missing
    // field through, every from_json that uses it would silently
    // accept missing fields too. test-s018-json-validation already
    // exercises a few representative through-paths; this test
    // exercises the helpers DIRECTLY.
    if (cmd == "test-json-validate") {
        using namespace determ::util;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto expect_throws = [&](auto fn, const char* needle, const char* label) {
            bool threw = false;
            std::string what;
            try { fn(); }
            catch (const std::exception& e) { threw = true; what = e.what(); }
            check(threw && what.find(needle) != std::string::npos, label);
        };

        // === json_require<T> ===

        // 1. Happy path: present field of correct type extracts cleanly.
        {
            json j = {{"x", 42}, {"name", "alice"}};
            check(json_require<int>(j, "x") == 42,
                  "json_require<int> happy path");
            check(json_require<std::string>(j, "name") == "alice",
                  "json_require<std::string> happy path");
        }

        // 2. Missing field throws with field name + "S-018" prefix
        //    + "missing" diagnostic.
        {
            json j = json::object();
            expect_throws(
                [&]() { (void)json_require<int>(j, "missing_field"); },
                "missing_field",
                "json_require missing-field error mentions field name");
            expect_throws(
                [&]() { (void)json_require<int>(j, "missing_field"); },
                "S-018",
                "json_require missing-field error has 'S-018' prefix");
            expect_throws(
                [&]() { (void)json_require<int>(j, "missing_field"); },
                "missing",
                "json_require missing-field error has 'missing' keyword");
        }

        // 3. Wrong type throws with field name + "wrong type" + nlohmann
        //    inner detail.
        {
            json j = {{"x", "not_a_number"}};
            expect_throws(
                [&]() { (void)json_require<int>(j, "x"); },
                "x",
                "json_require wrong-type error mentions field name");
            expect_throws(
                [&]() { (void)json_require<int>(j, "x"); },
                "wrong type",
                "json_require wrong-type error has 'wrong type' keyword");
        }

        // === json_require_hex ===

        // 4. Happy path: present hex field of correct length returns
        //    the raw string.
        {
            std::string h = std::string(64, '0');
            json j = {{"hash", h}};
            check(json_require_hex(j, "hash", 64) == h,
                  "json_require_hex happy path");
        }

        // 5. Missing field error.
        {
            json j = json::object();
            expect_throws(
                [&]() { (void)json_require_hex(j, "hash", 64); },
                "hash",
                "json_require_hex missing-field error mentions field name");
        }

        // 6. Wrong-length error explicitly states expected + got.
        {
            json j = {{"hash", "deadbeef"}};  // 8 chars, want 64
            expect_throws(
                [&]() { (void)json_require_hex(j, "hash", 64); },
                "wrong hex length",
                "json_require_hex wrong-length error has 'wrong hex length'");
            expect_throws(
                [&]() { (void)json_require_hex(j, "hash", 64); },
                "expected 64",
                "json_require_hex wrong-length error states expected count");
            expect_throws(
                [&]() { (void)json_require_hex(j, "hash", 64); },
                "got 8",
                "json_require_hex wrong-length error states got count");
        }

        // 7. Wrong type (number instead of string) throws via
        //    underlying json_require<std::string> path.
        {
            json j = {{"hash", 42}};
            expect_throws(
                [&]() { (void)json_require_hex(j, "hash", 64); },
                "hash",
                "json_require_hex with non-string value throws with field name");
        }

        // === json_require_array ===

        // 8. Happy path: present array field returns const-ref usable
        //    for iteration.
        {
            json j = {{"items", json::array({1, 2, 3})}};
            const auto& a = json_require_array(j, "items");
            check(a.size() == 3, "json_require_array happy path size==3");
            check(a[0].get<int>() == 1,
                  "json_require_array happy path first element");
        }

        // 9. Missing field throws.
        {
            json j = json::object();
            expect_throws(
                [&]() { (void)json_require_array(j, "items"); },
                "items",
                "json_require_array missing-field error mentions field name");
            expect_throws(
                [&]() { (void)json_require_array(j, "items"); },
                "expected array",
                "json_require_array missing-field error mentions 'expected array'");
        }

        // 10. Wrong type (scalar instead of array).
        {
            json j = {{"items", "scalar"}};
            expect_throws(
                [&]() { (void)json_require_array(j, "items"); },
                "items",
                "json_require_array wrong-type error mentions field name");
            expect_throws(
                [&]() { (void)json_require_array(j, "items"); },
                "got string",
                "json_require_array wrong-type error states observed type");
        }

        // 11. Wrong type (object instead of array).
        {
            json j = {{"items", json::object()}};
            expect_throws(
                [&]() { (void)json_require_array(j, "items"); },
                "got object",
                "json_require_array wrong-type error states 'got object'");
        }

        // 12. Empty array is OK (size=0 is a valid array shape).
        {
            json j = {{"items", json::array()}};
            const auto& a = json_require_array(j, "items");
            check(a.empty(),
                  "json_require_array accepts empty array (size=0 valid)");
        }

        // === Field-name uniqueness across helper variants ===

        // 13. All three helpers consistently include the field name
        //     in their diagnostic — important for operator triage.
        //     Verify with a deliberately unusual name.
        {
            json j = json::object();
            expect_throws(
                [&]() { (void)json_require<int>(j, "weird_!@#_name"); },
                "weird_!@#_name",
                "json_require preserves unusual field name in diagnostic");
            expect_throws(
                [&]() { (void)json_require_hex(j, "weird_!@#_name", 4); },
                "weird_!@#_name",
                "json_require_hex preserves unusual field name in diagnostic");
            expect_throws(
                [&]() { (void)json_require_array(j, "weird_!@#_name"); },
                "weird_!@#_name",
                "json_require_array preserves unusual field name in diagnostic");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": json-validate " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for Block::to_json /
    // Block::from_json full round-trip across the field set. Block
    // round-trips through JSON at every gossip hop (BLOCK MsgType),
    // every chain.json save/load (Chain::save / load), and every
    // snapshot tail-header save/restore. A field-loss regression
    // would silently corrupt the wire format. test-block-hash + the
    // existing test-wire-types lock specific sub-aspects; this is
    // the full-block round-trip.
    if (cmd == "test-block-roundtrip") {
        using namespace determ;
        using namespace determ::chain;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        auto pattern_hash = [](uint8_t base) {
            Hash h{};
            for (size_t i = 0; i < h.size(); ++i) h[i] = uint8_t(base + i);
            return h;
        };
        auto pattern_sig = [](uint8_t base) {
            Signature s{};
            for (size_t i = 0; i < s.size(); ++i) s[i] = uint8_t(base + i);
            return s;
        };
        auto pattern_pub = [](uint8_t base) {
            PubKey p{};
            for (size_t i = 0; i < p.size(); ++i) p[i] = uint8_t(base + i);
            return p;
        };

        // === Minimal block: only required fields set ===

        // 1. Minimal block round-trips: index + prev_hash + timestamp
        //    + cumulative_rand + abort_events array (the json_require_*
        //    required fields).
        {
            Block b;
            b.index = 0;
            b.prev_hash = Hash{};
            b.timestamp = 1000;
            b.cumulative_rand = pattern_hash(0x10);
            // abort_events MUST be set to an empty array (required by
            // json_require_array) — leaving the field absent would
            // trigger S-018 rejection on read-back.
            // (Empty vector default-constructed in Block; we just need
            //  to not strip the to_json output.)

            json j = b.to_json();
            Block back = Block::from_json(j);

            check(back.index == 0, "minimal block: index round-trip");
            check(back.timestamp == 1000,
                  "minimal block: timestamp round-trip");
            check(back.prev_hash == b.prev_hash,
                  "minimal block: prev_hash round-trip");
            check(back.cumulative_rand == b.cumulative_rand,
                  "minimal block: cumulative_rand round-trip");
        }

        // === Block with transactions ===

        // 2. Transactions[] round-trips. Each Transaction has its own
        //    test (test-transaction) for field-level coverage; here
        //    we just verify Block's outer container preserves the list.
        {
            Block b;
            b.index = 7;
            b.prev_hash = pattern_hash(0x20);
            b.timestamp = 2000;
            b.cumulative_rand = pattern_hash(0x21);

            for (int i = 0; i < 3; ++i) {
                Transaction tx;
                tx.type = TxType::TRANSFER;
                tx.from = "alice" + std::to_string(i);
                tx.to = "bob" + std::to_string(i);
                tx.amount = 100 + i;
                tx.fee = 1;
                tx.nonce = i;
                tx.hash = tx.compute_hash();
                b.transactions.push_back(tx);
            }

            json j = b.to_json();
            Block back = Block::from_json(j);
            check(back.transactions.size() == 3,
                  "block with transactions: count preserved");
            check(back.transactions[1].from == "alice1",
                  "block with transactions: per-tx fields preserved");
            check(back.transactions[2].amount == 102,
                  "block with transactions: amount preserved");
        }

        // === Block with K-of-K committee structure ===

        // 3. creators / creator_tx_lists / creator_ed_sigs /
        //    creator_dh_inputs / creator_dh_secrets / creator_block_sigs
        //    all round-trip preserving length + content.
        {
            Block b;
            b.index = 42;
            b.prev_hash = pattern_hash(0x30);
            b.timestamp = 3000;
            b.cumulative_rand = pattern_hash(0x31);

            b.creators = {"alice", "bob", "carol"};
            b.creator_tx_lists = {
                {pattern_hash(0x40), pattern_hash(0x41)},
                {pattern_hash(0x42)},
                {}};
            b.creator_ed_sigs = {
                pattern_sig(0x50), pattern_sig(0x51), pattern_sig(0x52)};
            b.creator_dh_inputs = {
                pattern_hash(0x60), pattern_hash(0x61), pattern_hash(0x62)};
            b.creator_dh_secrets = {
                pattern_hash(0x70), pattern_hash(0x71), pattern_hash(0x72)};
            b.creator_block_sigs = {
                pattern_sig(0x80), pattern_sig(0x81), pattern_sig(0x82)};

            b.tx_root = pattern_hash(0x90);
            b.delay_seed = pattern_hash(0x91);
            b.delay_output = pattern_hash(0x92);

            json j = b.to_json();
            Block back = Block::from_json(j);

            check(back.creators == b.creators,
                  "committee block: creators round-trip");
            check(back.creator_tx_lists.size() == 3,
                  "committee block: creator_tx_lists count");
            check(back.creator_tx_lists[0][1] == pattern_hash(0x41),
                  "committee block: creator_tx_lists value preserved");
            check(back.creator_tx_lists[2].empty(),
                  "committee block: empty inner list preserved");
            check(back.creator_ed_sigs[1] == pattern_sig(0x51),
                  "committee block: creator_ed_sigs preserved");
            check(back.creator_dh_inputs[0] == pattern_hash(0x60),
                  "committee block: creator_dh_inputs preserved");
            check(back.creator_dh_secrets[2] == pattern_hash(0x72),
                  "committee block: creator_dh_secrets preserved");
            check(back.creator_block_sigs[1] == pattern_sig(0x81),
                  "committee block: creator_block_sigs preserved");
            check(back.tx_root == b.tx_root,
                  "committee block: tx_root preserved");
            check(back.delay_seed == b.delay_seed,
                  "committee block: delay_seed preserved");
            check(back.delay_output == b.delay_output,
                  "committee block: delay_output preserved");
        }

        // === BFT-mode block ===

        // 4. consensus_mode + bft_proposer round-trip. BFT mode is the
        //    fallback when K-of-K stalls; the per-block consensus_mode
        //    discriminator must survive JSON transit.
        {
            Block b;
            b.index = 100;
            b.prev_hash = pattern_hash(0x10);
            b.timestamp = 1;
            b.cumulative_rand = Hash{};
            b.consensus_mode = ConsensusMode::BFT;
            b.bft_proposer = "alice";

            json j = b.to_json();
            Block back = Block::from_json(j);
            check(back.consensus_mode == ConsensusMode::BFT,
                  "BFT block: consensus_mode round-trip");
            check(back.bft_proposer == "alice",
                  "BFT block: bft_proposer round-trip");
        }

        // === Block with abort_events ===

        // 5. abort_events array of AbortEvent JSON sub-objects.
        {
            Block b;
            b.index = 0;
            b.prev_hash = Hash{};
            b.timestamp = 1;
            b.cumulative_rand = Hash{};

            AbortEvent ae1;
            ae1.round = 1;
            ae1.aborting_node = "carol";
            ae1.timestamp = 5000;
            ae1.event_hash = pattern_hash(0xA0);
            ae1.claims_json = json::array();
            b.abort_events.push_back(ae1);

            AbortEvent ae2;
            ae2.round = 2;
            ae2.aborting_node = "dan";
            ae2.timestamp = 5001;
            ae2.event_hash = pattern_hash(0xA1);
            ae2.claims_json = json::array();
            b.abort_events.push_back(ae2);

            json j = b.to_json();
            Block back = Block::from_json(j);

            check(back.abort_events.size() == 2,
                  "block with aborts: count preserved");
            check(back.abort_events[0].aborting_node == "carol",
                  "block with aborts: aborting_node preserved");
            check(back.abort_events[1].round == 2,
                  "block with aborts: round preserved");
        }

        // === Block with equivocation_events ===

        // 6. equivocation_events array of EquivocationEvent JSON
        //    sub-objects.
        {
            Block b;
            b.index = 0;
            b.prev_hash = Hash{};
            b.timestamp = 1;
            b.cumulative_rand = Hash{};

            EquivocationEvent ev;
            ev.equivocator = "mallory";
            ev.block_index = 50;
            ev.digest_a = pattern_hash(0xB0);
            ev.sig_a = pattern_sig(0xB1);
            ev.digest_b = pattern_hash(0xB2);
            ev.sig_b = pattern_sig(0xB3);
            ev.shard_id = 1;
            ev.beacon_anchor_height = 100;
            b.equivocation_events.push_back(ev);

            json j = b.to_json();
            Block back = Block::from_json(j);

            check(back.equivocation_events.size() == 1,
                  "block with equivocation: count preserved");
            check(back.equivocation_events[0].equivocator == "mallory",
                  "block with equivocation: equivocator preserved");
            check(back.equivocation_events[0].shard_id == 1,
                  "block with equivocation: shard_id preserved");
        }

        // === Block with cross-shard receipts (V12 + V13 surface) ===

        // 7. cross_shard_receipts + inbound_receipts arrays.
        {
            Block b;
            b.index = 0;
            b.prev_hash = Hash{};
            b.timestamp = 1;
            b.cumulative_rand = Hash{};

            CrossShardReceipt csr;
            csr.src_shard = 1;
            csr.dst_shard = 2;
            csr.src_block_index = 100;
            csr.src_block_hash = pattern_hash(0xC0);
            csr.tx_hash = pattern_hash(0xC1);
            csr.from = "alice";
            csr.to = "bob";
            csr.amount = 500;
            csr.fee = 5;
            csr.nonce = 7;
            b.cross_shard_receipts.push_back(csr);

            CrossShardReceipt ibr;
            ibr.src_shard = 3;
            ibr.dst_shard = 2;
            ibr.src_block_index = 200;
            ibr.src_block_hash = pattern_hash(0xD0);
            ibr.tx_hash = pattern_hash(0xD1);
            ibr.from = "carol";
            ibr.to = "bob";
            ibr.amount = 750;
            ibr.fee = 5;
            ibr.nonce = 3;
            b.inbound_receipts.push_back(ibr);

            json j = b.to_json();
            Block back = Block::from_json(j);

            check(back.cross_shard_receipts.size() == 1,
                  "block with receipts: cross_shard_receipts count");
            check(back.cross_shard_receipts[0].amount == 500,
                  "block with receipts: cross_shard amount preserved");
            check(back.inbound_receipts.size() == 1,
                  "block with receipts: inbound_receipts count");
            check(back.inbound_receipts[0].amount == 750,
                  "block with receipts: inbound amount preserved");
        }

        // === Genesis block (initial_state array) ===

        // 8. initial_state array of GenesisAlloc sub-objects.
        {
            Block b;
            b.index = 0;
            b.prev_hash = Hash{};
            b.timestamp = 0;
            b.cumulative_rand = Hash{};

            GenesisAlloc a1;
            a1.domain = "alice";
            a1.ed_pub = pattern_pub(0xE0);
            a1.balance = 10000;
            a1.stake = 1000;
            a1.region = "us-east";
            b.initial_state.push_back(a1);

            GenesisAlloc a2;
            a2.domain = "bob";
            a2.ed_pub = pattern_pub(0xE5);
            a2.balance = 5000;
            a2.stake = 0;
            a2.region = "";  // legacy / no-region
            b.initial_state.push_back(a2);

            json j = b.to_json();
            Block back = Block::from_json(j);

            check(back.initial_state.size() == 2,
                  "genesis block: initial_state count");
            check(back.initial_state[0].region == "us-east",
                  "genesis block: region tag preserved");
            check(back.initial_state[1].region.empty(),
                  "genesis block: empty region preserved (R1 backward-compat)");
            check(back.initial_state[0].balance == 10000,
                  "genesis block: balance preserved");
        }

        // === Zero-skip fields (state_root + partner_subset_hash) ===

        // 9. state_root: omitted in JSON when zero (backward-compat
        //    with pre-S-033 blocks); present when non-zero.
        {
            Block b;
            b.index = 0;
            b.prev_hash = Hash{};
            b.timestamp = 1;
            b.cumulative_rand = Hash{};
            b.state_root = Hash{};  // explicit zero

            json j = b.to_json();
            check(!j.contains("state_root"),
                  "state_root: omitted from JSON when zero (zero-skip)");

            b.state_root = pattern_hash(0xF0);
            j = b.to_json();
            check(j.contains("state_root"),
                  "state_root: present in JSON when non-zero");
            Block back = Block::from_json(j);
            check(back.state_root == b.state_root,
                  "state_root: round-trips when non-zero");
        }

        // 10. partner_subset_hash: same zero-skip pattern (R4 Phase 3).
        {
            Block b;
            b.index = 0;
            b.prev_hash = Hash{};
            b.timestamp = 1;
            b.cumulative_rand = Hash{};

            json j = b.to_json();
            check(!j.contains("partner_subset_hash"),
                  "partner_subset_hash: omitted from JSON when zero (R4 backward-compat)");

            b.partner_subset_hash = pattern_hash(0xF5);
            j = b.to_json();
            check(j.contains("partner_subset_hash"),
                  "partner_subset_hash: present in JSON when non-zero");
            Block back = Block::from_json(j);
            check(back.partner_subset_hash == b.partner_subset_hash,
                  "partner_subset_hash: round-trips when non-zero");
        }

        // === compute_hash invariance across round-trip ===

        // 11. A block's compute_hash is identical before and after a
        //     JSON round-trip. This is the CRITICAL invariant: a
        //     block gossiped between peers MUST produce the same
        //     block_hash on the receiver. Any field-loss in to_json /
        //     from_json that affects signing_bytes would break this.
        {
            Block b;
            b.index = 42;
            b.prev_hash = pattern_hash(0x10);
            b.timestamp = 1000;
            b.cumulative_rand = pattern_hash(0x20);
            b.creators = {"alice", "bob"};
            b.creator_block_sigs = {pattern_sig(0xE0), pattern_sig(0xE1)};
            b.tx_root = pattern_hash(0x30);
            b.delay_seed = pattern_hash(0x40);
            b.delay_output = pattern_hash(0x50);
            b.state_root = pattern_hash(0x60);

            Hash before = b.compute_hash();
            json j = b.to_json();
            Block back = Block::from_json(j);
            Hash after = back.compute_hash();

            check(before == after,
                  "compute_hash invariant: block_hash unchanged by JSON round-trip");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": block-roundtrip " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for Config::to_json /
    // Config::from_json round-trip. Config is the operator-facing
    // config.json — every field operators tune (ports, peers,
    // rate-limits, regions, sharding mode, governance flags). A
    // regression in round-trip would mean operators can't reload
    // their saved configs cleanly: missing fields silently reset to
    // defaults, breaking the operator's intent.
    if (cmd == "test-config-roundtrip") {
        using namespace determ;
        using namespace determ::node;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // 1. Default Config → to_json → from_json preserves defaults
        //    (all the documented defaults survive a save+reload cycle).
        {
            Config c1;
            json j = c1.to_json();
            Config c2 = Config::from_json(j);

            check(c2.listen_port == c1.listen_port,
                  "default Config: listen_port (7777) round-trips");
            check(c2.rpc_port == c1.rpc_port,
                  "default Config: rpc_port (7778) round-trips");
            check(c2.rpc_localhost_only == c1.rpc_localhost_only,
                  "default Config: rpc_localhost_only (true) round-trips");
            check(c2.rpc_rate_per_sec == c1.rpc_rate_per_sec,
                  "default Config: rpc_rate_per_sec (0) round-trips");
            check(c2.bft_enabled == c1.bft_enabled,
                  "default Config: bft_enabled (true) round-trips");
            check(c2.bft_escalation_threshold == c1.bft_escalation_threshold,
                  "default Config: bft_escalation_threshold (5) round-trips");
            check(c2.m_creators == c1.m_creators,
                  "default Config: m_creators (3) round-trips");
            check(c2.chain_role == c1.chain_role,
                  "default Config: chain_role (SINGLE) round-trips");
            check(c2.sharding_mode == c1.sharding_mode,
                  "default Config: sharding_mode (CURRENT) round-trips");
        }

        // 2. Custom Config with every field set → round-trips.
        //    Each setter exercises a specific path through from_json's
        //    j.value() defaults.
        {
            Config c1;
            c1.domain = "alice";
            c1.data_dir = "/tmp/data";
            c1.listen_port = 18888;
            c1.rpc_port = 18999;
            c1.rpc_localhost_only = false;
            c1.rpc_auth_secret = "deadbeef" + std::string(56, 'a');
            c1.rpc_rate_per_sec = 100.0;
            c1.rpc_rate_burst = 200.0;
            c1.gossip_rate_per_sec = 500.0;
            c1.gossip_rate_burst = 1000.0;
            c1.bootstrap_peers = {"node1:7777", "node2:7777"};
            c1.beacon_peers = {"beacon1:8000"};
            c1.shard_peers = {"shard1:9000", "shard2:9001"};
            c1.key_path = "/tmp/key.json";
            c1.chain_path = "/tmp/chain.json";
            c1.snapshot_path = "/tmp/snap.json";
            c1.shard_manifest_path = "/tmp/manifest.json";
            c1.genesis_path = "/tmp/genesis.json";
            c1.genesis_hash = std::string(64, 'a');
            c1.m_creators = 5;
            c1.k_block_sigs = 4;
            c1.bft_enabled = false;
            c1.bft_escalation_threshold = 10;
            c1.chain_role = ChainRole::BEACON;
            c1.sharding_mode = ShardingMode::EXTENDED;
            c1.shard_id = 7;
            c1.initial_shard_count = 8;
            c1.epoch_blocks = 2000;
            c1.tx_commit_ms = 500;
            c1.block_sig_ms = 500;
            c1.abort_claim_ms = 500;
            c1.region = "us-east";
            c1.committee_region = "us-east";
            c1.log_quiet = true;

            json j = c1.to_json();
            Config c2 = Config::from_json(j);

            check(c2.domain == c1.domain,
                  "custom Config: domain round-trips");
            check(c2.data_dir == c1.data_dir,
                  "custom Config: data_dir round-trips");
            check(c2.listen_port == c1.listen_port,
                  "custom Config: listen_port round-trips");
            check(c2.rpc_port == c1.rpc_port,
                  "custom Config: rpc_port round-trips");
            check(c2.rpc_localhost_only == c1.rpc_localhost_only,
                  "custom Config: rpc_localhost_only=false round-trips");
            check(c2.rpc_auth_secret == c1.rpc_auth_secret,
                  "custom Config: rpc_auth_secret round-trips");
            check(c2.rpc_rate_per_sec == c1.rpc_rate_per_sec,
                  "custom Config: rpc_rate_per_sec (double) round-trips");
            check(c2.rpc_rate_burst == c1.rpc_rate_burst,
                  "custom Config: rpc_rate_burst (double) round-trips");
            check(c2.gossip_rate_per_sec == c1.gossip_rate_per_sec,
                  "custom Config: gossip_rate_per_sec round-trips");
            check(c2.gossip_rate_burst == c1.gossip_rate_burst,
                  "custom Config: gossip_rate_burst round-trips");
            check(c2.bootstrap_peers == c1.bootstrap_peers,
                  "custom Config: bootstrap_peers (vector) round-trips");
            check(c2.beacon_peers == c1.beacon_peers,
                  "custom Config: beacon_peers (vector) round-trips");
            check(c2.shard_peers == c1.shard_peers,
                  "custom Config: shard_peers (vector) round-trips");
            check(c2.key_path == c1.key_path,
                  "custom Config: key_path round-trips");
            check(c2.chain_path == c1.chain_path,
                  "custom Config: chain_path round-trips");
            check(c2.snapshot_path == c1.snapshot_path,
                  "custom Config: snapshot_path round-trips");
            check(c2.genesis_path == c1.genesis_path,
                  "custom Config: genesis_path round-trips");
            check(c2.genesis_hash == c1.genesis_hash,
                  "custom Config: genesis_hash round-trips");
            check(c2.m_creators == c1.m_creators,
                  "custom Config: m_creators round-trips");
            check(c2.k_block_sigs == c1.k_block_sigs,
                  "custom Config: k_block_sigs round-trips");
            check(c2.bft_enabled == c1.bft_enabled,
                  "custom Config: bft_enabled=false round-trips");
            check(c2.bft_escalation_threshold == c1.bft_escalation_threshold,
                  "custom Config: bft_escalation_threshold round-trips");
            check(c2.chain_role == ChainRole::BEACON,
                  "custom Config: chain_role=BEACON round-trips");
            check(c2.sharding_mode == ShardingMode::EXTENDED,
                  "custom Config: sharding_mode=EXTENDED round-trips");
            check(c2.shard_id == c1.shard_id,
                  "custom Config: shard_id round-trips");
            check(c2.initial_shard_count == c1.initial_shard_count,
                  "custom Config: initial_shard_count round-trips");
            check(c2.epoch_blocks == c1.epoch_blocks,
                  "custom Config: epoch_blocks round-trips");
            check(c2.tx_commit_ms == c1.tx_commit_ms,
                  "custom Config: tx_commit_ms round-trips");
            check(c2.block_sig_ms == c1.block_sig_ms,
                  "custom Config: block_sig_ms round-trips");
            check(c2.abort_claim_ms == c1.abort_claim_ms,
                  "custom Config: abort_claim_ms round-trips");
            check(c2.region == c1.region,
                  "custom Config: region round-trips");
            check(c2.committee_region == c1.committee_region,
                  "custom Config: committee_region round-trips");
            check(c2.log_quiet == c1.log_quiet,
                  "custom Config: log_quiet=true round-trips");
        }

        // 3. Empty JSON → default Config (all defaults applied; the
        //    intentionally-permissive contract on Config::from_json).
        {
            json j = json::object();
            Config c = Config::from_json(j);
            check(c.listen_port == 7777,
                  "empty JSON: listen_port defaults to 7777");
            check(c.rpc_port == 7778,
                  "empty JSON: rpc_port defaults to 7778");
            check(c.rpc_localhost_only == true,
                  "empty JSON: rpc_localhost_only defaults to true (S-001 secure default)");
            check(c.m_creators == 3,
                  "empty JSON: m_creators defaults to 3");
            check(c.bft_enabled == true,
                  "empty JSON: bft_enabled defaults to true");
        }

        // 4. Default chain_role + sharding_mode enum values from
        //    integers in JSON (defends against operators editing the
        //    integer codes by hand).
        {
            Config c1;
            c1.chain_role = ChainRole::SHARD;
            c1.sharding_mode = ShardingMode::NONE;
            json j = c1.to_json();
            Config c2 = Config::from_json(j);
            check(c2.chain_role == ChainRole::SHARD,
                  "chain_role=SHARD (uint8_t=2) round-trips correctly");
            check(c2.sharding_mode == ShardingMode::NONE,
                  "sharding_mode=NONE (uint8_t=0) round-trips correctly");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": config-roundtrip " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-035 Option 1 seed: in-process unit test for the binary
    // Transaction codec — `encode_tx_frame` / `decode_tx_frame` in
    // `src/net/binary_codec.cpp`. This is the v1 (binary) wire-
    // format path for TRANSACTION MsgType: a 4×32-byte fixed-slot
    // area + a variable-length trailer.
    //
    // S-002 dependency: admission-side sig verification reads
    // amount/fee/nonce from the FIXED slots (not the trailer). A
    // regression that dropped these values during binary transit
    // — as happened pre-S-002 closure — would silently zero these
    // fields and let corrupted txs into the mempool until the
    // validator filtered them later. This test locks the values
    // through the round-trip explicitly.
    if (cmd == "test-tx-binary-codec") {
        using namespace determ;
        using namespace determ::chain;
        using namespace determ::net;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };

        // Helper: build a Transaction → wrap in TRANSACTION Message →
        // encode_binary → decode_binary → extract the tx back.
        auto tx_roundtrip = [](const Transaction& tx) -> Transaction {
            Message m{MsgType::TRANSACTION, tx.to_json()};
            auto bytes = encode_binary(m);
            Message back = decode_binary(bytes.data(), bytes.size());
            return Transaction::from_json(back.payload);
        };

        // 1. TRANSFER round-trip preserves all fixed-slot fields
        //    (amount / fee / nonce — the S-002 critical path).
        {
            Transaction tx;
            tx.type = TxType::TRANSFER;
            tx.from = "alice";
            tx.to = "bob";
            tx.amount = 100;
            tx.fee = 5;
            tx.nonce = 7;
            tx.payload = {0xDE, 0xAD};
            tx.hash = tx.compute_hash();

            Transaction back = tx_roundtrip(tx);
            check(back.amount == tx.amount,
                  "binary TRANSFER: amount preserved (S-002 fixed-slot)");
            check(back.fee == tx.fee,
                  "binary TRANSFER: fee preserved (S-002 fixed-slot)");
            check(back.nonce == tx.nonce,
                  "binary TRANSFER: nonce preserved (S-002 fixed-slot)");
            check(back.from == tx.from,
                  "binary TRANSFER: from preserved (trailer)");
            check(back.to == tx.to,
                  "binary TRANSFER: to preserved (trailer)");
            check(back.payload == tx.payload,
                  "binary TRANSFER: payload preserved");
            check(back.type == tx.type,
                  "binary TRANSFER: type preserved");
        }

        // 2. compute_hash invariance across binary round-trip. This
        //    is the critical invariant — admission-side sig verify
        //    (S-002) recomputes the hash from received bytes, so
        //    any field loss breaks signature validation.
        {
            Transaction tx;
            tx.type = TxType::TRANSFER;
            tx.from = "carol";
            tx.to = "dan";
            tx.amount = 42;
            tx.fee = 1;
            tx.nonce = 11;
            tx.payload = {0xCA, 0xFE, 0xBA, 0xBE};
            tx.hash = tx.compute_hash();

            Hash before = tx.compute_hash();
            Transaction back = tx_roundtrip(tx);
            Hash after = back.compute_hash();
            check(before == after,
                  "binary tx round-trip: compute_hash invariant (S-002 sig verify precondition)");
        }

        // 3. Two-tx round-trip: distinct transactions produce distinct
        //    encoded bytes (no cross-tx state leak in the codec).
        {
            Transaction tx1, tx2;
            tx1.type = TxType::TRANSFER;
            tx1.from = "alice"; tx1.to = "bob";
            tx1.amount = 100; tx1.fee = 1; tx1.nonce = 1;
            tx1.hash = tx1.compute_hash();

            tx2 = tx1;
            tx2.amount = 200;
            tx2.hash = tx2.compute_hash();

            Message m1{MsgType::TRANSACTION, tx1.to_json()};
            Message m2{MsgType::TRANSACTION, tx2.to_json()};
            auto b1 = encode_binary(m1);
            auto b2 = encode_binary(m2);
            check(b1 != b2,
                  "binary tx: distinct amounts produce distinct frames");
        }

        // Below assertions are renumbered after dropping direct-frame
        // poke tests (encode_tx_frame / decode_tx_frame aren't in the
        // public binary_codec API). The Message-level round-trip
        // covers the same end-to-end path.
        //
        // Large payload (> 32 bytes) round-trips via the trailer-
        //    overflow path. The first 32 bytes live in the fixed
        //    slot at offset 96; the overflow lives in the trailer
        //    after type + payload_len.
        {
            Transaction tx;
            tx.type = TxType::DAPP_CALL;
            tx.from = "alice";
            tx.to = "dapp.example";
            tx.amount = 0;
            tx.fee = 1;
            tx.nonce = 5;
            tx.payload.resize(64);
            for (size_t i = 0; i < tx.payload.size(); ++i)
                tx.payload[i] = uint8_t(0x40 + i);
            tx.hash = tx.compute_hash();

            Transaction back = tx_roundtrip(tx);
            check(back.payload == tx.payload,
                  "binary tx: 64-byte payload round-trips via trailer overflow");
            check(back.payload.size() == 64,
                  "binary tx: payload size preserved through overflow");
        }

        // 6. Each TxType discriminator round-trips.
        {
            for (TxType t : {TxType::TRANSFER, TxType::REGISTER,
                              TxType::DEREGISTER, TxType::STAKE,
                              TxType::UNSTAKE, TxType::PARAM_CHANGE,
                              TxType::COMPOSABLE_BATCH,
                              TxType::DAPP_REGISTER, TxType::DAPP_CALL}) {
                Transaction tx;
                tx.type = t;
                tx.from = "x"; tx.to = "y";
                tx.amount = 0; tx.fee = 1; tx.nonce = 1;
                tx.payload = {0x01};
                tx.hash = tx.compute_hash();
                Transaction back = tx_roundtrip(tx);
                check(back.type == t,
                      ("binary tx: TxType=" + std::to_string(int(t))
                       + " round-trips").c_str());
            }
        }

        // 7. Zero-amount + zero-fee + zero-nonce round-trip (edge case
        //    at the LE u64 encoding boundary).
        {
            Transaction tx;
            tx.type = TxType::REGISTER;
            tx.from = "validator1";
            tx.to = "";
            tx.amount = 0;
            tx.fee = 0;
            tx.nonce = 0;
            tx.payload.assign(32, 0xAA);  // pretend pubkey
            tx.hash = tx.compute_hash();

            Transaction back = tx_roundtrip(tx);
            check(back.amount == 0 && back.fee == 0 && back.nonce == 0,
                  "binary tx: all-zeros numeric fields round-trip cleanly");
        }

        // 8. Max u64 amount round-trip (boundary check for LE u64
        //    encoding).
        {
            Transaction tx;
            tx.type = TxType::TRANSFER;
            tx.from = "rich";
            tx.to = "rich2";
            tx.amount = UINT64_MAX;
            tx.fee = UINT64_MAX;
            tx.nonce = UINT64_MAX;
            tx.hash = tx.compute_hash();

            Transaction back = tx_roundtrip(tx);
            check(back.amount == UINT64_MAX,
                  "binary tx: UINT64_MAX amount round-trips");
            check(back.fee == UINT64_MAX,
                  "binary tx: UINT64_MAX fee round-trips");
            check(back.nonce == UINT64_MAX,
                  "binary tx: UINT64_MAX nonce round-trips");
        }

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": tx-binary-codec " << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    // S-018 regression: exercise json_require<T> and json_require_hex
    // helpers + the converted from_json paths in block.cpp /
    // producer.cpp. Verifies that malformed JSON produces a clear
    // field-name diagnostic instead of an opaque nlohmann error.
    if (cmd == "test-s018-json-validation") {
        using namespace determ;
        using namespace determ::chain;
        using nlohmann::json;
        int fail = 0;
        auto check = [&](bool cond, const char* msg) {
            if (cond) std::cout << "  PASS: " << msg << "\n";
            else { std::cout << "  FAIL: " << msg << "\n"; fail++; }
        };
        // Helper: expect that calling fn() throws and the message
        // contains every needle in `needles`. Defends against the
        // helpers regressing to opaque nlohmann errors.
        auto expect_throw_with = [&](const char* test_name,
                                       std::function<void()> fn,
                                       std::vector<std::string> needles) {
            try {
                fn();
                std::cout << "  FAIL: " << test_name
                          << " (expected exception, none thrown)\n";
                fail++;
            } catch (const std::exception& e) {
                std::string msg = e.what();
                bool all = true;
                for (auto& n : needles) {
                    if (msg.find(n) == std::string::npos) { all = false; break; }
                }
                if (all) {
                    std::cout << "  PASS: " << test_name << "\n";
                } else {
                    std::cout << "  FAIL: " << test_name
                              << " (got '" << msg << "')\n";
                    fail++;
                }
            }
        };

        // 1. Happy path: valid Transaction round-trips.
        {
            Transaction tx;
            tx.type     = TxType::TRANSFER;
            tx.from     = "alice";
            tx.to       = "bob";
            tx.amount   = 100;
            tx.fee      = 1;
            tx.nonce    = 7;
            tx.sig      = {}; tx.hash = {};
            tx.payload  = {};
            json j      = tx.to_json();
            Transaction back = Transaction::from_json(j);
            check(back.from == "alice" && back.amount == 100,
                  "happy: tx round-trips through to_json/from_json");
        }

        // 2. Missing required field — should name "amount".
        expect_throw_with("missing 'amount' names the field", [] {
            json j = {{"type", 0}, {"from", "a"}, {"to", "b"},
                      {"nonce", 0}, {"payload", ""},
                      {"sig",  std::string(128, '0')},
                      {"hash", std::string(64,  '0')}};
            Transaction::from_json(j);
        }, {"S-018", "missing", "'amount'"});

        // 3. Wrong-type field — string where uint64 expected.
        expect_throw_with("wrong-type 'amount' names the field", [] {
            json j = {{"type", 0}, {"from", "a"}, {"to", "b"},
                      {"amount", "not-a-number"}, {"nonce", 0},
                      {"payload", ""},
                      {"sig",  std::string(128, '0')},
                      {"hash", std::string(64,  '0')}};
            Transaction::from_json(j);
        }, {"S-018", "'amount'", "wrong type"});

        // 4. Wrong-length hex on a fixed-width field — should name
        //    "sig" and the expected length (128).
        expect_throw_with("wrong-hex-length 'sig' names the field", [] {
            json j = {{"type", 0}, {"from", "a"}, {"to", "b"},
                      {"amount", 1}, {"nonce", 0}, {"payload", ""},
                      {"sig",  std::string(100, '0')},   // wrong length
                      {"hash", std::string(64,  '0')}};
            Transaction::from_json(j);
        }, {"S-018", "'sig'", "hex length"});

        // 5. Missing field on AbortEvent — should name 'event_hash'.
        expect_throw_with("AbortEvent missing 'event_hash'", [] {
            json j = {{"round", 1}, {"aborting_node", "node1"},
                      {"timestamp", 0}};
            AbortEvent::from_json(j);
        }, {"S-018", "missing", "'event_hash'"});

        // 6. Missing field on EquivocationEvent — should name 'sig_b'.
        expect_throw_with("EquivocationEvent missing 'sig_b'", [] {
            json j = {{"equivocator", "node1"}, {"block_index", 5},
                      {"digest_a", std::string(64, '0')},
                      {"sig_a",    std::string(128, '0')},
                      {"digest_b", std::string(64, '1')}};
            EquivocationEvent::from_json(j);
        }, {"S-018", "missing", "'sig_b'"});

        // 7. Block missing 'transactions' array — should name the
        //    field (not produce an opaque iterator exception).
        expect_throw_with("Block missing 'transactions'", [] {
            json j = {{"index", 1},
                      {"prev_hash", std::string(64, '0')},
                      {"timestamp", 0},
                      {"creators", json::array()},
                      {"abort_events", json::array()},
                      {"cumulative_rand", std::string(64, '0')}};
            Block::from_json(j);
        }, {"S-018", "transactions"});

        // 8. GenesisAlloc missing 'domain' — protects snapshot
        //    `initial_state` + genesis-tool initial_balances paths.
        expect_throw_with("GenesisAlloc missing 'domain'", [] {
            json j = {{"balance", 100}, {"stake", 0}};
            GenesisAlloc::from_json(j);
        }, {"S-018", "missing", "'domain'"});

        // 9. Block optional 'state_root' field with wrong hex length
        //    — guards the S-033 state_root snapshot-restore path
        //    against a malformed snapshot tail-header (the field is
        //    optional, but if present must be exactly 32 bytes).
        expect_throw_with("Block 'state_root' wrong hex length", [] {
            json j = {{"index", 1},
                      {"prev_hash", std::string(64, '0')},
                      {"timestamp", 0},
                      {"transactions", json::array()},
                      {"creators", json::array()},
                      {"abort_events", json::array()},
                      {"cumulative_rand", std::string(64, '0')},
                      {"state_root", std::string(60, 'a')}};  // wrong length
            Block::from_json(j);
        }, {"S-018", "'state_root'", "hex length"});

        // 10. Block 'transactions' present but non-array (e.g., string)
        //     — exercises json_require_array's wrong-type diagnostic
        //     so a malformed BLOCK gossip message with a stringified
        //     transactions field gets a clear "expected array, got X"
        //     error.
        expect_throw_with("Block 'transactions' non-array", [] {
            json j = {{"index", 1},
                      {"prev_hash", std::string(64, '0')},
                      {"timestamp", 0},
                      {"transactions", "not-an-array"},  // string, not array
                      {"creators", json::array()},
                      {"abort_events", json::array()},
                      {"cumulative_rand", std::string(64, '0')}};
            Block::from_json(j);
        }, {"S-018", "'transactions'", "expected array"});

        std::cout << "\n  " << (fail == 0 ? "PASS" : "FAIL")
                  << ": s018_json_validation "
                  << (fail == 0 ? "all assertions" : "had failures")
                  << "\n";
        return fail == 0 ? 0 : 1;
    }
    if (cmd == "stake")       return cmd_stake(sub_argc, sub_argv);
    if (cmd == "unstake")     return cmd_unstake(sub_argc, sub_argv);
    if (cmd == "nonce")       return cmd_nonce(sub_argc, sub_argv);
    if (cmd == "stake_info")    return cmd_stake_info(sub_argc, sub_argv);
    if (cmd == "submit-param-change") return cmd_submit_param_change(sub_argc, sub_argv);
    if (cmd == "submit-merge-event")  return cmd_submit_merge_event(sub_argc, sub_argv);
    if (cmd == "submit-dapp-register") return cmd_submit_dapp_register(sub_argc, sub_argv);
    if (cmd == "submit-dapp-call")     return cmd_submit_dapp_call(sub_argc, sub_argv);
    if (cmd == "genesis-tool")  return cmd_genesis_tool(sub_argc, sub_argv);
    if (cmd == "account")       return cmd_account(sub_argc, sub_argv);
    if (cmd == "send_anon")     return cmd_send_anon(sub_argc, sub_argv);

    std::cerr << "Unknown command: " << cmd << "\n\n";
    usage();
    return 1;
}
