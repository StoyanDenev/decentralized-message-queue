/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Experimental unauthenticated two-party computation (POSIX transport).
 *
 * Implements raw non-blocking POSIX socket communication between
 * the Aggregator and Contributor; no authenticated election or block validation.
 *
 * Strictly zero dynamic memory allocations (no malloc/free).
 */

#ifndef DETERMINISTIC_NET_K2_NET_H
#define DETERMINISTIC_NET_K2_NET_H

#include <determ/net/event_loop.h>
#include <determ/consensus/duel_state.h>
#include <determ/crypto/vdf.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define K2_EXPERIMENT_ITERATIONS 2000ULL
/* Local response deadline, not a consensus parameter or physical-time proof. */
#define K2_RESPONSE_TIMEOUT_NS 10000000000ULL
#define K2_NET_MAGIC            0x4B324E54U /* "K2NT" */
#define K2_NET_HEADER_LEN       12U
#define K2_NET_MAX_FRAME_LEN    (K2_NET_HEADER_LEN + DUEL_MAX_PAYLOAD_SIZE)

/* Protocol Message Types (Big-Endian Wire Code) */
typedef enum {
    K2_MSG_HELLO          = 0x0001,
    K2_MSG_COMMITMENT     = 0x0002,
    K2_MSG_REVEAL_WINDOW  = 0x0003,
    K2_MSG_REVEAL_PAYLOAD = 0x0004,
    K2_MSG_BLOCK_RESULT   = 0x0005,
    K2_MSG_ERROR          = 0x00FF
} k2_msg_type_t;

/*
 * Wire Frame Header:
 * [0..3]:  Magic (0x4B324E54)
 * [4..5]:  Message Type (uint16_t BE)
 * [6..7]:  Reserved (0x0000)
 * [8..11]: Payload Length (uint32_t BE)
 */
typedef struct {
    uint32_t magic;
    uint16_t msg_type;
    uint16_t reserved;
    uint32_t payload_len;
} k2_net_header_t;

/*
 * Connection state machine for non-blocking I/O stream parsing.
 */
typedef struct {
    int fd;
    bool connected;
    uint8_t rx_buf[K2_NET_MAX_FRAME_LEN];
    size_t rx_cursor;
    size_t expected_total_len;
    k2_net_header_t current_hdr;
} k2_connection_t;

/*
 * Aggregator Server Context.
 */
typedef struct {
    int listen_fd;
    uint16_t port;
    net_event_loop_t loop;
    k2_connection_t peer;
    duel_state_machine_t duel_sm;
    vdf_context_t vdf_ctx;
    uint8_t agg_reveal[DUEL_MAX_PAYLOAD_SIZE];
    uint32_t agg_reveal_len;
    uint8_t latest_vdf_output[VDF_OUTPUT_LEN];
    bool duel_completed;
} k2_aggregator_t;

/*
 * Contributor Client Context.
 */
typedef struct {
    k2_connection_t conn;
    net_event_loop_t loop;
    uint8_t commitment[32];
    uint8_t reveal_payload[DUEL_MAX_PAYLOAD_SIZE];
    uint32_t reveal_payload_len;
    uint8_t block_result[VDF_OUTPUT_LEN];
    bool result_received; /* Unauthenticated peer output, not a validated block. */
    uint64_t attempt_start_ns;
    bool attempt_started;
    bool reveal_window_seen;
} k2_contributor_t;

/*
 * Frame Serialization & Deserialization
 */
int k2_net_encode_frame(k2_msg_type_t type, const uint8_t *payload, uint32_t payload_len,
                        uint8_t *out_buf, size_t out_max, size_t *out_len);

int k2_net_parse_header(const uint8_t *buf, size_t len, k2_net_header_t *out_hdr);

/*
 * Aggregator Functions: poll returns <0 on terminal failure, 1 on computation completion.
 * Explicit start_duel after failure/completion closes the old connection and resets state.
 * Caller must arrange a new connection; no automatic election or retry is implied.
 */
int k2_aggregator_init(k2_aggregator_t *agg, uint16_t port);
int k2_aggregator_start_duel(k2_aggregator_t *agg, const uint8_t *agg_reveal, uint32_t agg_len);
int k2_aggregator_poll(k2_aggregator_t *agg, int timeout_ms);
void k2_aggregator_close(k2_aggregator_t *agg);

/*
 * Contributor Functions
 */
int k2_contributor_init(k2_contributor_t *cont);
int k2_contributor_connect(k2_contributor_t *cont, const char *ip_addr, uint16_t port);
int k2_contributor_send_commitment(k2_contributor_t *cont, const uint8_t commitment[32]);
int k2_contributor_send_reveal(k2_contributor_t *cont, const uint8_t *reveal, uint32_t reveal_len);
int k2_contributor_poll(k2_contributor_t *cont, int timeout_ms);
void k2_contributor_close(k2_contributor_t *cont);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_NET_K2_NET_H */
