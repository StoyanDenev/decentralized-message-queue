/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Hosted C99 Peer Mesh & Gossip Protocol Engine.
 *
 * Connects to explicitly configured peers and accepts inbound peers, with:
 *   1. Non-blocking POSIX TCP connections driven by net_event_loop_t.
 *   2. Strict Big-Endian [u32 len] outer framing + [0xB1 v1] canonical wire envelope.
 *   3. An unauthenticated HELLO exchange (domain, port, role, shard id) on
 *      connect; wire_version is recorded, not negotiated. Role-based
 *      cross-chain gating of delivered and broadcast messages.
 *   4. Broadcast dedup: a zero-allocation FIFO ring of the SHA-256
 *      (type || payload) keys of the last PEER_MESH_DEDUP_CAPACITY locally
 *      broadcast messages suppresses an identical re-broadcast. Inbound
 *      messages are delivered to on_message only; the mesh does not relay them.
 *   5. Per-peer token-bucket rate limiting of inbound non-HELLO messages
 *      without dynamic allocation.
 */

#ifndef DETERMINISTIC_NET_PEER_MESH_H
#define DETERMINISTIC_NET_PEER_MESH_H

#include <determ/net/event_loop.h>
#include <determ/wire/binary_codec.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PEER_MESH_MAX_PEERS         32U
#define PEER_MESH_RX_BUF_SIZE       (128U * 1024U) /* 128 KB */
#define PEER_MESH_TX_BUF_SIZE       (128U * 1024U) /* 128 KB */
#define PEER_MESH_MAX_DOMAIN_LEN    64U
#define PEER_MESH_DEDUP_CAPACITY    512U

/* Stage-B Sharding Chain Role */
typedef enum {
    CHAIN_ROLE_SINGLE = 0,
    CHAIN_ROLE_BEACON = 1,
    CHAIN_ROLE_SHARD  = 2
} chain_role_t;

typedef enum {
    PEER_STATE_FREE = 0,
    PEER_STATE_CONNECTING,
    PEER_STATE_HANDSHAKING,
    PEER_STATE_ACTIVE,
    PEER_STATE_CLOSING
} peer_state_t;

typedef struct {
    int          fd;
    uintptr_t    registration; /* captured event identity; meaningful only while state != PEER_STATE_FREE */
    peer_state_t state;
    bool         inbound;
    bool         hello_received;

    char         domain[PEER_MESH_MAX_DOMAIN_LEN];
    uint16_t     port;
    uint8_t      role;
    uint32_t     shard_id;
    uint8_t      wire_version;

    char         remote_addr[48];

    /* Inbound Framing */
    uint8_t      rx_buf[PEER_MESH_RX_BUF_SIZE];
    size_t       rx_cursor;
    size_t       rx_expected_len; /* 0 = reading 4-byte BE length, >0 = reading payload */

    /* Outbound Framing */
    uint8_t      tx_buf[PEER_MESH_TX_BUF_SIZE];
    size_t       tx_cursor;
    size_t       tx_len;

    /* Rate limiting token bucket */
    double       tokens;
    uint64_t     last_token_update_ms;
} peer_entry_t;

struct peer_mesh;
typedef struct peer_mesh peer_mesh_t;

typedef void (*peer_message_cb_t)(peer_mesh_t *mesh, int peer_idx, const wire_envelope_t *env, void *user_data);
typedef void (*peer_connect_cb_t)(peer_mesh_t *mesh, int peer_idx, void *user_data);
typedef void (*peer_disconnect_cb_t)(peer_mesh_t *mesh, int peer_idx, void *user_data);

typedef struct {
    char                domain[PEER_MESH_MAX_DOMAIN_LEN];
    uint16_t            listen_port;
    chain_role_t        role;
    uint32_t            shard_id;
    double              rate_limit_per_sec;
    double              rate_limit_burst;
    peer_message_cb_t   on_message;
    peer_connect_cb_t   on_connect;
    peer_disconnect_cb_t on_disconnect;
    void               *user_data;
} peer_mesh_config_t;

/* FIFO ring of 32-byte broadcast keys; the oldest key is overwritten. */
typedef struct {
    uint8_t entries[PEER_MESH_DEDUP_CAPACITY][32];
    size_t  head;
    size_t  count;
} peer_mesh_dedup_t;

struct peer_mesh {
    peer_mesh_config_t config;
    net_event_loop_t   loop;
    int                listen_fd;
    peer_entry_t       peers[PEER_MESH_MAX_PEERS];
    peer_mesh_dedup_t  dedup;
    bool               running;
    uintptr_t          next_generation; /* never wraps: at UINTPTR_MAX >> 8 new peers are refused */
};

/*
 * Initialize the peer mesh engine in fresh or previously closed storage; cfg must
 * not overlap mesh. Returns 0 on success.
 *
 * Ownership: one thread owns every peer mesh and reactor in the process; the
 * nested-dispatch guard is a single module-wide flag, so a second thread is
 * unsupported. Callers must not modify lifecycle/cursor fields directly.
 * Initialization or polling of any mesh from inside a callback is refused and
 * leaves the supplied storage unchanged (on fresh zero-filled storage such a
 * refusal establishes no descriptor sentinels: do not close it then). Outside
 * callbacks, a failed init on non-NULL storage is safe to close.
 * Callbacks may disconnect/reconnect peers; envelope/payload pointers are
 * borrowed for the callback only and must not be retained across any operation
 * changing peers.
 * Every outbound connect and every accepted inbound connection consumes one
 * registration generation before any HELLO. The counter is refused rather than
 * wrapped at UINTPTR_MAX >> 8: on a 32-bit host an unauthenticated peer can
 * exhaust the 2^24 - 1 generations by reconnecting, after which the mesh refuses
 * connections until it is closed and re-initialized (ADR-006 §4). 64-bit hosts
 * have 2^56 - 1.
 */
int peer_mesh_init(peer_mesh_t *mesh, const peer_mesh_config_t *cfg);

/*
 * Bind and listen on a local TCP port for inbound peer handshakes.
 */
int peer_mesh_listen(peer_mesh_t *mesh, uint16_t port);

/*
 * Initiate an asynchronous outbound connection to a remote peer.
 * Returns the allocated peer index (0..MAX-1), or negative on error.
 */
int peer_mesh_connect(peer_mesh_t *mesh, const char *host, uint16_t port);

/*
 * Disconnect a specific peer and free its slot.
 */
void peer_mesh_disconnect(peer_mesh_t *mesh, int peer_idx);

/*
 * Queue a message for every active peer whose role permits it, unless
 * SHA-256(msg_type || payload) is already in the dedup ring (then nothing is
 * sent and 0 is returned); otherwise the key is recorded. Returns the number
 * of peers the frame was queued for.
 */
int peer_mesh_broadcast(peer_mesh_t *mesh, uint8_t msg_type, const uint8_t *payload, size_t payload_len);

/*
 * Queue a message for a specific peer index as one outer frame
 * [BE32 envelope length][envelope]. Returns 0 when the whole frame was queued;
 * a negative return (e.g. outbound buffer full) means nothing was queued.
 */
int peer_mesh_send_to(peer_mesh_t *mesh, int peer_idx, uint8_t msg_type, const uint8_t *payload, size_t payload_len);

/*
 * Poll the mesh event loop and dispatch non-blocking network I/O events.
 * timeout_ms = -1 blocks, 0 returns immediately.
 */
int peer_mesh_poll(peer_mesh_t *mesh, int timeout_ms);

/*
 * Tear down all connections, close listener, and release event loop.
 */
void peer_mesh_close(peer_mesh_t *mesh);

/*
 * Role-based cross-chain gossip gating filter.
 * Returns true if msg_type is allowed from a peer with (peer_role, peer_shard_id)
 * given (our_role, our_shard_id).
 */
bool peer_mesh_is_allowed(uint8_t msg_type, uint8_t peer_role, uint32_t peer_shard_id,
                          uint8_t our_role, uint32_t our_shard_id);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_NET_PEER_MESH_H */
