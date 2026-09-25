/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Determ Experimental Services Daemon (hosted C99).
 * Uses POSIX and libc. The freestanding target remains a separate qualification.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include <determ/consensus/duel_state.h>
#include <determ/consensus/dda.h>
#include <determ/crypto/vdf.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/net/k2_net.h>
#include <determ/net/peer_mesh.h>
#include <determ/storage/block_store.h>
#include <determ/wire/parser.h>
#include <determ/wire/json_token.h>
#include <determ/rpc/json_rpc.h>
#include <determ/rpc/http_rpc_server.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* BSS-allocated node contexts to prevent stack exhaustion */
static peer_mesh_t       g_mesh;
static block_store_t     g_store;
static k2_aggregator_t   g_agg;
static k2_contributor_t  g_cont;
static http_rpc_server_t g_rpc;
static dda_tracker_t     g_dda;
static pending_transfer_pool_t    g_pending;
static pending_shard_t   g_pending_shards[PENDING_TRANSFER_MAX_SHARDS];

static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void print_usage(const char *prog) {
    printf("Determ C99 Experimental Services\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Duel Protocol:\n");
    printf("  --aggregator              Run one bounded experimental Aggregator attempt\n");
    printf("  --contributor             Run one bounded experimental Contributor attempt\n");
    printf("  --port <port>             Duel listen/target port (default: 9000)\n");
    printf("  --connect <ip>            Duel Aggregator IP to connect (default: 127.0.0.1)\n\n");
    printf("P2P Gossip Mesh & Storage:\n");
    printf("  --p2p-port <port>         Listen port for P2P gossip mesh\n");
    printf("  --peer <ip:port>          Outbound peer to connect\n");
    printf("  --data-dir <path>         Directory for the experimental C99 block store\n");
    printf("                           (<path>/manifest.bin, <path>/<height>.blk; not the C++ store)\n");
    printf("  --domain <name>           Node domain advertisement (default: node.local)\n\n");
    printf("HTTP JSON-RPC Server:\n");
    printf("  --rpc-port <port>         Listen port for HTTP JSON-RPC endpoint (e.g. 8545)\n");
    printf("  --routing-shards <S>      Local routing shard count, 1..4294967295 (default: 1)\n");
    printf("  --routing-salt <hex64>    Local routing 32-byte salt (default: all zero)\n");
    printf("  --pending-genesis <hex64> Enable bounded signed-transfer inbox for this chain identity\n");
    printf("                           Fixed local settings; no genesis authentication or state validation\n\n");
    printf("Diagnostics & Calibration:\n");
    printf("  --benchmark               Measure this machine's AES evaluation rate\n");
    printf("  --version                 Print version and architectural info\n");
    printf("  --help                    Show this help message\n");
}

static int run_benchmark(void) {
    printf("[VDF Benchmark] Measuring local AES evaluation rate...\n");
    vdf_context_t ctx;
    const uint8_t seed[] = "determ-vdf-hardware-calibration-seed";
    uint8_t out[VDF_OUTPUT_LEN];

    if (vdf_init(&ctx, seed, sizeof(seed) - 1, 5000) != 0) {
        fprintf(stderr, "Failed to initialize VDF context\n");
        return 1;
    }

    if (vdf_evaluate(&ctx, out) != 0) {
        fprintf(stderr, "VDF evaluation failed\n");
        return 1;
    }

    double ns_per_iter = (double)ctx.elapsed_ns / 5000.0;
    printf("[VDF Benchmark] Completed 5000 iterations in %.3f ms (%.2f ns/iter)\n",
           (double)ctx.elapsed_ns / 1000000.0, ns_per_iter);

    uint64_t w_reveal_ns = DUEL_REVEAL_WINDOW_NS;
    uint64_t delta_ns = 200000000ULL; /* 200ms network propagation grace Delta */
    uint64_t lower_bound_ns = w_reveal_ns + delta_ns;
    uint64_t required_iters = (uint64_t)((double)lower_bound_ns / ns_per_iter) + 5000;

    printf("[VDF Benchmark] Lower bound (W_reveal + Delta): %llu ms\n",
           (unsigned long long)(lower_bound_ns / 1000000ULL));
    printf("[VDF Benchmark] Estimated iterations for this local duration (not a security bound): %llu\n",
           (unsigned long long)required_iters);
    return 0;
}

static void on_p2p_message(peer_mesh_t *mesh, int peer_idx, const wire_envelope_t *env, void *ud) {
    (void)mesh;
    (void)ud;
    printf("[P2P Mesh] Received message 0x%02X (%zu bytes) from peer #%d\n",
           env->msg_type, env->payload_len, peer_idx);
}

static void on_p2p_connect(peer_mesh_t *mesh, int peer_idx, void *ud) {
    (void)mesh;
    (void)ud;
    printf("[P2P Mesh] Peer #%d connected successfully.\n", peer_idx);
}

static int routing_count_arg(const char *text, uint32_t *out) {
    uint32_t value = 0;
    if (!text || !*text) return -1;
    for (size_t i = 0; text[i]; ++i) {
        uint32_t digit;
        if (text[i] < '0' || text[i] > '9') return -1;
        digit = (uint32_t)(text[i] - '0');
        if (value > (UINT32_MAX - digit) / 10) return -1;
        value = value * 10 + digit;
    }
    if (value == 0) return -1;
    *out = value;
    return 0;
}

static int routing_salt_arg(const char *text, uint8_t out[32]) {
    if (!text || strlen(text) != 64) return -1;
    for (size_t i = 0; i < 32; ++i) {
        unsigned value = 0;
        for (size_t j = 0; j < 2; ++j) {
            char c = text[2 * i + j];
            unsigned digit;
            if (c >= '0' && c <= '9') digit = (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') digit = (unsigned)(c - 'a') + 10;
            else if (c >= 'A' && c <= 'F') digit = (unsigned)(c - 'A') + 10;
            else return -1;
            value = value * 16 + digit;
        }
        out[i] = (uint8_t)value;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    bool is_aggregator = false;
    bool is_contributor = false;
    bool do_benchmark = false;
    uint16_t duel_port = 9000;
    const char *connect_ip = "127.0.0.1";

    uint16_t p2p_port = 0;
    uint16_t rpc_port = 0;
    const char *peer_target = NULL;
    const char *data_dir = NULL;
    const char *domain = "node.local";
    /* These match GenesisConfig field defaults, not an authenticated chain's
     * configuration. They configure the routing query and optional inbox. */
    uint32_t routing_count = 1;
    uint8_t routing_salt[32] = {0};
    bool have_routing_count = false, have_routing_salt = false;
    shard_routing_config_t routing;
    uint8_t pending_genesis[32] = {0};
    bool have_pending_genesis = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--aggregator") == 0) {
            is_aggregator = true;
        } else if (strcmp(argv[i], "--contributor") == 0) {
            is_contributor = true;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            duel_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--connect") == 0 && i + 1 < argc) {
            connect_ip = argv[++i];
        } else if (strcmp(argv[i], "--p2p-port") == 0 && i + 1 < argc) {
            p2p_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rpc-port") == 0 && i + 1 < argc) {
            rpc_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--routing-shards") == 0) {
            if (have_routing_count || i + 1 >= argc || routing_count_arg(argv[++i], &routing_count) != 0) {
                fprintf(stderr, "--routing-shards requires one decimal count in 1..4294967295\n");
                return 1;
            }
            have_routing_count = true;
        } else if (strcmp(argv[i], "--routing-salt") == 0) {
            if (have_routing_salt || i + 1 >= argc || routing_salt_arg(argv[++i], routing_salt) != 0) {
                fprintf(stderr, "--routing-salt requires one 64-character hexadecimal salt\n");
                return 1;
            }
            have_routing_salt = true;
        } else if (strcmp(argv[i], "--pending-genesis") == 0) {
            if (have_pending_genesis || i + 1 >= argc || routing_salt_arg(argv[++i], pending_genesis) != 0) {
                fprintf(stderr, "--pending-genesis requires one 64-character hexadecimal chain identity\n");
                return 1;
            }
            have_pending_genesis = true;
        } else if (strcmp(argv[i], "--peer") == 0 && i + 1 < argc) {
            peer_target = argv[++i];
        } else if (strcmp(argv[i], "--data-dir") == 0 && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) {
            domain = argv[++i];
        } else if (strcmp(argv[i], "--benchmark") == 0) {
            do_benchmark = true;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("Determ Node v2.18 (Hosted C99 experiment; POSIX/libc runtime)\n");
            printf("Experimental two-party computation; PoSW consensus integration is incomplete\n");
            printf("Networking: Native POSIX non-blocking kqueue/epoll (Zero Asio)\n");
            printf("Storage: experimental C99 block store <dir>/manifest.bin + <dir>/<height>.blk "
                   "(DMF1/DBK1 records; not the C++ node's <path>.blocks/ store)\n");
            printf("RPC: Hosted C99 HTTP/1.1 In-Place JSON-RPC Transport\n");
            return 0;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (shard_routing_init(&routing, routing_count, routing_salt) != 0) {
        fprintf(stderr, "Invalid local routing configuration\n");
        return 1;
    }

    if (have_pending_genesis && (rpc_port == 0 ||
        pending_transfer_init(&g_pending, g_pending_shards, PENDING_TRANSFER_MAX_SHARDS,
                          &routing, pending_genesis) != 0)) {
        fprintf(stderr, "--pending-genesis requires an RPC port and valid local configuration\n");
        return 1;
    }

    if (do_benchmark) {
        return run_benchmark();
    }

    if (is_aggregator && is_contributor) {
        fprintf(stderr, "Choose one experimental duel role\n");
        return 1;
    }
    if ((is_aggregator || is_contributor) && data_dir != NULL) {
        fprintf(stderr, "Duel output is not a validated block; --data-dir cannot be used with duel modes\n");
        return 1;
    }
    int exit_status = 0;
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Initialize DDA tracker baseline */
    dda_init(&g_dda, 100000ULL);

    /* 1. Initialize persistent storage engine if requested */
    bool store_active = false;
    if (data_dir != NULL) {
        printf("[Storage] Initializing block store at '%s'...\n", data_dir);
        if (block_store_open(&g_store, data_dir) != BLOCK_STORE_OK) {
            fprintf(stderr, "Error: Failed to initialize block store at '%s'\n", data_dir);
            return 1;
        }
        uint64_t cur_height = 0;
        uint8_t head_hash[32];
        block_store_get_head(&g_store, &cur_height, head_hash);
        printf("[Storage] Manifest active: height=%llu\n", (unsigned long long)cur_height);
        store_active = true;
    }

    /* 2. Initialize P2P gossip mesh if configured */
    bool mesh_active = false;
    if (p2p_port > 0 || peer_target != NULL) {
        peer_mesh_config_t mcfg = {
            .domain = "",
            .listen_port = p2p_port,
            .role = CHAIN_ROLE_SINGLE,
            .shard_id = 0,
            .rate_limit_per_sec = 100.0,
            .rate_limit_burst = 200.0,
            .on_message = on_p2p_message,
            .on_connect = on_p2p_connect,
            .on_disconnect = NULL,
            .user_data = NULL
        };
        snprintf(mcfg.domain, sizeof(mcfg.domain), "%s", domain);

        if (peer_mesh_init(&g_mesh, &mcfg) != 0) {
            fprintf(stderr, "Error: Failed to initialize peer mesh\n");
            if (store_active) block_store_close(&g_store);
            return 1;
        }

        if (p2p_port > 0) {
            if (peer_mesh_listen(&g_mesh, p2p_port) != 0) {
                fprintf(stderr, "Error: Failed to listen on P2P port %u\n", p2p_port);
                peer_mesh_close(&g_mesh);
                if (store_active) block_store_close(&g_store);
                return 1;
            }
            printf("[P2P Mesh] Listening on port %u (domain='%s')...\n", p2p_port, domain);
        }

        if (peer_target != NULL) {
            char ip[64];
            snprintf(ip, sizeof(ip), "%s", peer_target);
            char *colon = strrchr(ip, ':');
            if (colon) {
                *colon = '\0';
                uint16_t rport = (uint16_t)atoi(colon + 1);
                printf("[P2P Mesh] Connecting to remote peer %s:%u...\n", ip, rport);
                peer_mesh_connect(&g_mesh, ip, rport);
            }
        }
        mesh_active = true;
    }

    /* 3. Initialize HTTP JSON-RPC Server if requested */
    bool rpc_active = false;
    if (rpc_port > 0) {
        http_rpc_config_t rcfg;
        memset(&rcfg, 0, sizeof(rcfg));
        rcfg.port = rpc_port;
        rcfg.rpc_ctx.store = store_active ? &g_store : NULL;
        rcfg.rpc_ctx.mesh = mesh_active ? &g_mesh : NULL;
        rcfg.rpc_ctx.dda = &g_dda;
        rcfg.rpc_ctx.node_version = "v2.18-c99";
        rcfg.rpc_ctx.routing = &routing; /* main's lifetime exceeds all server use */
        rcfg.rpc_ctx.pending = have_pending_genesis ? &g_pending : NULL;

        if (http_rpc_server_init(&g_rpc, &rcfg) != 0 || http_rpc_server_start(&g_rpc) != 0) {
            fprintf(stderr, "Error: Failed to start HTTP JSON-RPC server on port %u\n", rpc_port);
            if (mesh_active) peer_mesh_close(&g_mesh);
            if (store_active) block_store_close(&g_store);
            return 1;
        }
        printf("[HTTP RPC] Server listening on http://127.0.0.1:%u (JSON-RPC 2.0)\n", rpc_port);
        rpc_active = true;
    }

    /* 4. Execution Mode */
    if (is_aggregator) {
        printf("[Aggregator] Starting K=2 duel server on port %u...\n", duel_port);
        if (k2_aggregator_init(&g_agg, duel_port) != 0) {
            fprintf(stderr, "Failed to start Aggregator on port %u\n", duel_port);
            if (rpc_active) http_rpc_server_close(&g_rpc);
            if (mesh_active) peer_mesh_close(&g_mesh);
            if (store_active) block_store_close(&g_store);
            return 1;
        }

        if (rpc_active) {
            rpc_context_t ctx = g_rpc.rpc_ctx;
            ctx.sm = &g_agg.duel_sm;
            http_rpc_server_set_context(&g_rpc, &ctx);
        }

        const uint8_t agg_payload[] = "experimental-aggregator-payload";
        if (k2_aggregator_start_duel(&g_agg, agg_payload, sizeof(agg_payload) - 1) != 0) {
            fprintf(stderr, "Failed to start local attempt\n");
            g_running = 0;
            exit_status = 1;
        }
        printf("[Aggregator] Local attempt started; commitment deadline is one second\n");
        while (g_running && !g_agg.duel_completed) {
            int rc = k2_aggregator_poll(&g_agg, 20);
            if (rc < 0) {
                fprintf(stderr, "[Aggregator] Attempt failed (%d); no block produced\n", rc);
                exit_status = 1;
                break;
            }
            if (mesh_active) peer_mesh_poll(&g_mesh, 10);
            if (rpc_active) http_rpc_server_poll(&g_rpc, 10);
        }

        if (g_agg.duel_completed)
            printf("[Aggregator] Local computation completed; output is not consensus settlement\n");
        else exit_status = 1;
        k2_aggregator_close(&g_agg);
    } else if (is_contributor) {
        printf("[Contributor] Connecting to Aggregator at %s:%u...\n", connect_ip, duel_port);
        if (k2_contributor_init(&g_cont) != 0) {
            fprintf(stderr, "Failed to initialize Contributor\n");
            if (rpc_active) http_rpc_server_close(&g_rpc);
            if (mesh_active) peer_mesh_close(&g_mesh);
            if (store_active) block_store_close(&g_store);
            return 1;
        }

        if (k2_contributor_connect(&g_cont, connect_ip, duel_port) != 0) {
            fprintf(stderr, "Failed to connect to %s:%u\n", connect_ip, duel_port);
            k2_contributor_close(&g_cont);
            if (rpc_active) http_rpc_server_close(&g_rpc);
            if (mesh_active) peer_mesh_close(&g_mesh);
            if (store_active) block_store_close(&g_store);
            return 1;
        }

        const uint8_t cont_reveal[] = "experimental-contributor-payload";
        memcpy(g_cont.reveal_payload, cont_reveal, sizeof(cont_reveal) - 1);
        g_cont.reveal_payload_len = sizeof(cont_reveal) - 1;
        uint8_t commitment[32];
        determ_sha256(cont_reveal, sizeof(cont_reveal) - 1, commitment);
        if (k2_contributor_send_commitment(&g_cont, commitment) != 0) {
            fprintf(stderr, "Failed to send commitment\n");
            k2_contributor_close(&g_cont);
            if (rpc_active) http_rpc_server_close(&g_rpc);
            if (mesh_active) peer_mesh_close(&g_mesh);
            if (store_active) block_store_close(&g_store);
            return 1;
        }

        printf("[Contributor] Commitment sent, awaiting duel resolution...\n");
        while (g_running && !g_cont.result_received) {
            if (k2_contributor_poll(&g_cont, 20) < 0) {
                fprintf(stderr, "[Contributor] Attempt failed or response deadline expired\n");
                exit_status = 1;
                break;
            }
            if (mesh_active) peer_mesh_poll(&g_mesh, 10);
            if (rpc_active) http_rpc_server_poll(&g_rpc, 10);
        }

        if (g_cont.result_received) {
            printf("[Contributor] Received unauthenticated computation output, not a validated block\n");
        } else exit_status = 1;
        k2_contributor_close(&g_cont);
    } else if (mesh_active || rpc_active) {
        printf("[Node] Running active services (press Ctrl+C to exit)...\n");
        while (g_running) {
            if (mesh_active) peer_mesh_poll(&g_mesh, 20);
            if (rpc_active) http_rpc_server_poll(&g_rpc, 20);
        }
    } else {
        printf("Determ Node: No mode specified. Running verification benchmark by default.\n");
        run_benchmark();
    }

    if (rpc_active) http_rpc_server_close(&g_rpc);
    if (mesh_active) peer_mesh_close(&g_mesh);
    if (store_active) block_store_close(&g_store);

    printf("[Node] Shutdown complete.\n");
    return exit_status;
}
