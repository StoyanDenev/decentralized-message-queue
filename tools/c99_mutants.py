#!/usr/bin/env python3
"""Isolated C99 mutation gate; invoked only by tools/ci_local.sh --c99-mutants.

Every case compiles and runs via ci_local in a temporary source snapshot. A
configuration, compilation, launch, or timeout failure is an infrastructure
failure, never evidence that a test rejects a mutant.
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


# name, target, repository-relative source, literal old text, literal new text.
# Each replacement must match exactly once in the unmutated source snapshot.
ROOT_RANK = """if(best<0 || n->records[i].candidate.tx_count>n->records[best].candidate.tx_count ||
           (n->records[i].candidate.tx_count==n->records[best].candidate.tx_count &&
            memcmp(n->records[i].header,n->records[best].header,K2_MODEL_HEADER_BYTES)<0)) best=(int)i;"""
TX_OVERRIDES_ROOT_RANK = """int tx_priority=0;
        if(best>=0 && n->records[i].candidate.tx_count && n->records[best].candidate.tx_count) {
            const triple_entry_tx_t *x=&n->records[i].candidate.txs[0], *y=&n->records[best].candidate.txs[0];
            if(x->nonce==y->nonce && !memcmp(x->from,y->from,32)) {
                uint8_t first[32],second[32]; k2_model_tx_id(x,first); k2_model_tx_id(y,second);
                tx_priority=memcmp(first,second,32);
            }
        }
        if(tx_priority<0 || (tx_priority==0 && (best<0 || n->records[i].candidate.tx_count>n->records[best].candidate.tx_count ||
           (n->records[i].candidate.tx_count==n->records[best].candidate.tx_count &&
            memcmp(n->records[i].header,n->records[best].header,K2_MODEL_HEADER_BYTES)<0)))) best=(int)i;"""
REJECT_CONFLICTING_ROOTS = """for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid && !memcmp(n->records[i].candidate.parent,n->config->anchor_id,32))
        for(size_t j=0;j<i;j++) if(n->records[j].valid && !memcmp(n->records[j].candidate.parent,n->config->anchor_id,32))
            for(size_t x=0;x<n->records[i].candidate.tx_count;x++) for(size_t y=0;y<n->records[j].candidate.tx_count;y++) {
                const triple_entry_tx_t *first=&n->records[i].candidate.txs[x], *second=&n->records[j].candidate.txs[y];
                if(first->nonce==second->nonce && !memcmp(first->from,second->from,32)) {
                    uint8_t first_id[32],second_id[32]; k2_model_tx_id(first,first_id); k2_model_tx_id(second,second_id);
                    if(memcmp(first_id,second_id,32)) return K2_MODEL_INVALID;
                }
            }
    /* This model does not select between competing complete histories. */"""
MUTANTS = [
    # Audit regressions first: report instrumentation failures before the legacy sweep.
    ('codec-size-preflight-wrap',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     'return prefix <= cap && length <= cap - prefix;',
     'return prefix + length <= cap;'),
    ('codec-pq-u32-addition',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     '        if (!bytes_fit(buf_cap, required, 4)) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;\n'
     '        required += 4;\n'
     '        if (tx->pq_auth_len > buf_cap - required) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;\n'
     '        required += (size_t)tx->pq_auth_len;',
     '        required += 4 + tx->pq_auth_len;\n'
     '        if (buf_cap < required) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;'),
    ('codec-dhf1-u32-addition',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     '    if (buf_cap < 40 || block_frame_len > buf_cap - 40) return '
     'WIRE_CODEC_ERR_BUFFER_TOO_SMALL;\n'
     '    size_t required = 40 + (size_t)block_frame_len;',
     '    size_t required = 40 + block_frame_len;\n'
     '    if (buf_cap < required) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;'),
    ('codec-envelope-null-source',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     'if (payload_len > 0 && !payload) return WIRE_CODEC_ERR_INVALID_ARG;',
     '/* mutant: missing payload pointer accepted */'),
    ('codec-contrib-null-source',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     '(msg->view_shardtip_count > 0 && !msg->view_shardtip_list)',
     '0 /* mutant: missing shardtip list accepted */'),
    ('codec-status-null-source',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     'if (msg->genesis_len > 0 && !msg->genesis_hex) return WIRE_CODEC_ERR_INVALID_ARG;',
     '/* mutant: missing genesis bytes accepted */'),
    # Review 2026-09-25: exact-capacity and extent edges of the codec preflight.
    ('codec-tx-base-capacity',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     '    size_t required = 128 + 1 + 2 + overflow + 1 + tx->from_len + 1 + tx->to_len + 64 + 32 + 32 + 4;\n'
     '    if (buf_cap < required) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;\n',
     '    size_t required = 128 + 1 + 2 + overflow + 1 + tx->from_len + 1 + tx->to_len + 64 + 32 + 32 + 4;\n'),
    ('codec-tx-pq-prefix',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     '        if (!bytes_fit(buf_cap, required, 4)) return WIRE_CODEC_ERR_BUFFER_TOO_SMALL;\n',
     ''),
    ('codec-dhf1-short-capacity',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     'if (buf_cap < 40 || block_frame_len > buf_cap - 40)',
     'if (block_frame_len > buf_cap - 40)'),
    ('codec-chain-frame-extent',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     '    uint32_t flen = le_get_u32(blocks_data + off); off += 4;\n'
     '    if (flen > total_len || off > total_len - flen) return WIRE_CODEC_ERR_TRUNCATED;\n',
     '    uint32_t flen = le_get_u32(blocks_data + off); off += 4;\n'),
    ('codec-dhf1-frame-extent',
     'test-c99-codec-bounds',
     'src/wire/binary_codec.c',
     '    uint32_t flen = le_get_u32(headers_data + off); off += 4;\n'
     '    if (flen > total_len || off > total_len - flen) return WIRE_CODEC_ERR_TRUNCATED;\n',
     '    uint32_t flen = le_get_u32(headers_data + off); off += 4;\n'),
    ('rpc-get-block-height-used',
     'test-http-rpc',
     'src/rpc/json_rpc.c',
     'determ_json_token_to_uint64(request_json, h_tok, &target_height) != 0',
     'determ_json_token_to_uint64(request_json, h_tok, &(uint64_t){0}) != 0'),
    ('rpc-get-block-height-type',
     'test-http-rpc',
     'src/rpc/json_rpc.c',
     'if (!h_tok || h_tok->type != JSON_TOK_PRIMITIVE ||',
     'if (!h_tok ||'),
    ('json-u64-overflow',
     'test-http-rpc',
     'src/wire/json_token.c',
     'if (val > (UINT64_MAX - digit) / 10) return -1;',
     '/* mutant: decimal overflow wraps */'),
    ('json-count-int-range',
     'test-http-rpc',
     'src/wire/json_token.c',
     ' || max_tokens > INT_MAX',
     ''),
    ('rpc-actual-output-length',
     'test-http-rpc',
     'src/rpc/json_rpc.c',
     '    va_end(args);\n    return written < 0 || (size_t)written >= cap ? -1 : written;',
     '    va_end(args);\n    return written; /* mutant: reports would-have-written length */'),
    ('http-null-config-ownership',
     'test-http-rpc',
     'src/rpc/http_rpc_server.c',
     '    if (!server) return -1;\n    memset(server, 0, sizeof(*server));',
     '    if (!server || !config) return -1;\n    memset(server, 0, sizeof(*server));'),
    ('http-accepted-setup-failure',
     'test-c99-http-safety',
     'src/rpc/http_rpc_server.c',
     'if (prepare_client_socket(c_fd) != 0) {',
     'if (prepare_client_socket(c_fd) == -2) {'),
    ('json-string-terminator-room',
     'test-http-rpc',
     'src/wire/json_token.c',
     'if (tok_len >= max_out) return -1;',
     'if (tok_len > max_out) return -1;'),
    ('http-safe-send-path',
     'test-c99-http-safety',
     'src/rpc/http_rpc_server.c',
     'static ssize_t send_client_bytes(int fd, const void *data, size_t len) {\n'
     '#ifdef MSG_NOSIGNAL\n'
     '    return send(fd, data, len, MSG_NOSIGNAL);\n'
     '#else\n'
     '    return send(fd, data, len, 0); /* SO_NOSIGPIPE checked before publication. */\n'
     '#endif\n'
     '}',
     'static ssize_t send_client_bytes(int fd, const void *data, size_t len) {\n'
     '    return write(fd, data, len);\n'
     '}'),
    ('json-key-value-same-parent',
     'test-http-rpc',
     'src/wire/json_token.c',
     'if (i + 1 < num_tokens && tokens[i + 1].parent == obj_idx)',
     'if (i + 1 < num_tokens)'),
    # Heap-free SHA-256 MAC/KDFs (C99-MINIX-PORT 14.2 B): no failure path is
    # left to propagate, so these target the streaming logic and the bounds.
    ('crypto-hmac-long-key',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/hmac.c',
     'if (keylen > sizeof k0) determ_sha256(key, keylen, k0);',
     'if (keylen > sizeof k0) keylen = sizeof k0;'),
    ('crypto-hmac-key-block-edge',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/hmac.c',
     'if (keylen > sizeof k0) determ_sha256(key, keylen, k0);',
     'if (keylen >= sizeof k0) determ_sha256(key, keylen, k0);'),
    ('crypto-hmac-heap-free',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/hmac.c',
     '    uint8_t pad[64];\n    size_t i;\n\n    memset(k0, 0, sizeof k0);',
     '    uint8_t pad[64];\n    size_t i;\n    free(malloc(1));\n\n    memset(k0, 0, sizeof k0);'),
    ('crypto-hkdf-bound',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/hkdf.c',
     'if (outlen > 255 * HASHLEN) return -1;',
     'if (outlen > 256 * HASHLEN) return -1;'),
    ('crypto-hkdf-chain',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/hkdf.c',
     'determ_hmac_sha256_update(&ctx, t, tlen);',
     '(void)tlen;'),
    ('crypto-hkdf-counter',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/hkdf.c',
     'uint8_t ctr = (uint8_t)counter;',
     'uint8_t ctr = (uint8_t)(counter - 1u);'),
    ('crypto-hkdf-counter-width',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/hkdf.c',
     'uint8_t ctr = (uint8_t)counter;',
     'uint8_t ctr = (uint8_t)(counter & 0x7fu);'),
    ('crypto-pbkdf2-zero-iters',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/pbkdf2.c',
     '    if (iters == 0) return -1;\n',
     ''),
    ('crypto-pbkdf2-keyed-copy',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/pbkdf2.c',
     '            ctx = keyed;\n            determ_hmac_sha256_update(&ctx, U, hLen);',
     '            determ_hmac_sha256_update(&ctx, U, hLen);'),
    ('crypto-pbkdf2-counter',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/pbkdf2.c',
     'uint32_t block_index = i + 1u;',
     'uint32_t block_index = i;'),
    ('crypto-pbkdf2-ceil',
     'test-c99-crypto-bounds',
     'src/crypto/sha2/pbkdf2.c',
     'blocks = outlen / hLen + (outlen % hLen != 0u);',
     'blocks = outlen / hLen;'),
    ('crypto-p256-xmd-size',
     'test-c99-crypto-bounds',
     'src/crypto/p256/p256.c',
     'if (msglen > SIZE_MAX - 68u - dstlen) return -1;',
     '/* MUTANT: no size preflight */'),
    ('crypto-p256-derive-size',
     'test-c99-crypto-bounds',
     'src/crypto/p256/p256.c',
     'if (seedlen > SIZE_MAX - 3u || infolen > SIZE_MAX - 3u - seedlen) return -1;',
     '/* MUTANT: no size preflight */'),
    ('crypto-p256-finalize-size',
     'test-c99-crypto-bounds',
     'src/crypto/p256/p256.c',
     'if (inputlen > SIZE_MAX - 45u) return -1;',
     '/* MUTANT: no size preflight */'),
    ('crypto-balance-count',
     'test-c99-crypto-bounds',
     'src/crypto/pedersen/balance.c',
     'if (n_out == SIZE_MAX || n_in > SIZE_MAX - n_out - 1u) return -1;',
     '/* MUTANT: no count preflight */'),
    ('crypto-balance-bytes',
     'test-c99-crypto-bounds',
     'src/crypto/pedersen/balance.c',
     'if (cnt > SIZE_MAX / SC || cnt > SIZE_MAX / PT) return -1;',
     '/* MUTANT: no byte preflight */'),
    ('crypto-opaque-expand',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     'if (determ_hmac_sha256(prk, NH, buf, off, t) != 0) goto done;',
     'if (determ_hmac_sha256(prk, NH, buf, off, t) == -2) goto done;'),
    ('crypto-opaque-extract',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     'if (determ_hmac_sha256(zero_salt, NH, ikm, 99, prk) != 0) goto done;',
     '(void)determ_hmac_sha256(zero_salt, NH, ikm, 99, prk);'),
    ('crypto-opaque-server-mac',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     'if (determ_hmac_sha256(km2, NH, pre_hash, NH, smac_tmp) != 0) goto done;',
     '(void)determ_hmac_sha256(km2, NH, pre_hash, NH, smac_tmp);'),
    ('crypto-opaque-server-expected',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     'if (determ_hmac_sha256(km3, NH, pre_smac_hash, NH, cmac_tmp) != 0) goto done;',
     '(void)determ_hmac_sha256(km3, NH, pre_smac_hash, NH, cmac_tmp);'),
    ('crypto-opaque-client-expected',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     'if (determ_hmac_sha256(km2, NH, pre_hash, NH, expect_smac) != 0) goto done;',
     '(void)determ_hmac_sha256(km2, NH, pre_hash, NH, expect_smac);'),
    ('crypto-opaque-client-mac',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     'if (determ_hmac_sha256(km3, NH, pre_smac_hash, NH, mac_tmp) != 0) goto done;',
     '(void)determ_hmac_sha256(km3, NH, pre_smac_hash, NH, mac_tmp);'),
    ('crypto-opaque-early-auth',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     'mac_matches = (determ_ct_memcmp(server_mac, expect_smac, NH) == 0) ? 1 : 0;',
     'mac_matches = (determ_ct_memcmp(server_mac, expect_smac, NH) == 0) ? 1 : 0; *server_mac_ok '
     '= mac_matches;'),
    # Review 2026-09-25: first rejected sizes, the RFC 9380 length bound and
    # the C2-h contract (NULL-argument rejection leaves server_mac_ok untouched).
    ('crypto-p256-xmd-size-edge',
     'test-c99-crypto-bounds',
     'src/crypto/p256/p256.c',
     'if (msglen > SIZE_MAX - 68u - dstlen) return -1;',
     'if (msglen > SIZE_MAX - 67u - dstlen) return -1;'),
    ('crypto-p256-finalize-size-edge',
     'test-c99-crypto-bounds',
     'src/crypto/p256/p256.c',
     'if (inputlen > SIZE_MAX - 45u) return -1;',
     'if (inputlen > SIZE_MAX - 44u) return -1;'),
    ('crypto-p256-xmd-length-bound',
     'test-c99-crypto-bounds',
     'src/crypto/p256/p256.c',
     'if (outlen == 0 || outlen > 8160 || dstlen > 255) return -1;',
     'if (outlen == 0 || outlen > 8192 || dstlen > 255) return -1;'),
    ('crypto-opaque-null-untouched',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     '    /* C2-h: a NULL-argument rejection leaves every output untouched,\n',
     '    if (server_mac_ok) *server_mac_ok = 0; /* mutant: reset before validation */\n'
     '    /* C2-h: a NULL-argument rejection leaves every output untouched,\n'),
    ('crypto-opaque-failure-reset',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     '    *server_mac_ok = 0;   /* every later failure leaves 0, never a stale 1 */\n',
     '    /* mutant: a failure after validation leaves the caller\'s value */\n'),
    # Review 2026-09-25: network guards that previously had no killing test.
    ('reactor-send-api-bound',
     'test-c99-network-safety',
     'src/net/reactor.c',
     'if (!reactor || fd < 0 || !data || len == 0 || len > REACTOR_BUFFER_CAPACITY) return -1;',
     'if (!reactor || fd < 0 || !data || len == 0) return -1;'),
    ('reactor-flush-sigpipe',
     'test-c99-network-safety',
     'src/net/reactor.c',
     '        ssize_t n = reactor_socket_send(slot->fd, slot->tx_buf, slot->tx_len);\n',
     '        ssize_t n = send(slot->fd, (const char *)slot->tx_buf, slot->tx_len, 0);\n'),
    ('reactor-run-dispatch-guard',
     'test-c99-network-safety',
     'src/net/reactor.c',
     'if (!reactor || reactor_dispatching || reactor->loop.poll_fd < 0) return;',
     'if (!reactor || reactor->loop.poll_fd < 0) return;'),
    ('mesh-connect-failure-silent',
     'test-c99-network-safety',
     'src/net/peer_mesh.c',
     'static void release_unpublished_peer(peer_mesh_t *mesh, int slot) {\n',
     'static void release_unpublished_peer(peer_mesh_t *mesh, int slot) {\n'
     '    if (mesh) { peer_mesh_disconnect(mesh, slot); return; } /* mutant: announce */\n'),
    ('mesh-connect-failure-close',
     'test-c99-network-safety',
     'src/net/peer_mesh.c',
     '        net_event_loop_del(&mesh->loop, peer->fd);\n'
     '        close(peer->fd);\n'
     '        peer->fd = -1;\n'
     '    }\n'
     '    peer->state = PEER_STATE_FREE;\n'
     '    peer->registration = 0;\n'
     '}\n'
     '\n'
     'int peer_mesh_connect(',
     '        net_event_loop_del(&mesh->loop, peer->fd);\n'
     '        peer->fd = -1; /* mutant: descriptor leaked */\n'
     '    }\n'
     '    peer->state = PEER_STATE_FREE;\n'
     '    peer->registration = 0;\n'
     '}\n'
     '\n'
     'int peer_mesh_connect('),
    ('mesh-connect-bad-address-close',
     'test-c99-network-safety',
     'src/net/peer_mesh.c',
     '    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {\n'
     '        close(fd);\n'
     '        return -4;',
     '    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {\n'
     '        return -4; /* mutant: descriptor leaked */'),
    ('crypto-opaque-null-key-untouched',
     'test-c99-crypto-bounds',
     'src/crypto/dsso/opaque3dh.c',
     '    /* C2-h: a NULL-argument rejection leaves every output untouched,\n',
     '    if (t && server_mac_ok) *server_mac_ok = 0; /* mutant: reset before key checks */\n'
     '    /* C2-h: a NULL-argument rejection leaves every output untouched,\n'),
    ('k2-contributor-connect-preconditions',
     'test-c99-network-safety',
     'src/net/k2_net.c',
     'if (!cont || !ip_addr || cont->conn.fd >= 0 || cont->conn.connected || cont->loop.poll_fd < 0) return -1;',
     'if (!cont || !ip_addr) return -1;'),
    ('reactor-stale-cookie',
     'test-c99-network-safety',
     'src/net/reactor.c',
     'slot->state != REACTOR_SLOT_UNUSED && slot->registration == cookie ? slot : NULL',
     'slot->state != REACTOR_SLOT_UNUSED ? slot : NULL'),
    ('mesh-stale-cookie',
     'test-c99-network-safety',
     'src/net/peer_mesh.c',
     'peer->state != PEER_STATE_FREE && peer->registration == registration ? index : -1',
     'peer->state != PEER_STATE_FREE ? index : -1'),
    ('mesh-callback-incarnation',
     'test-c99-network-safety',
     'src/net/peer_mesh.c',
     'if (!mesh->running || registration_index(mesh, registration) != peer_idx) return;',
     '(void)registration; /* mutant: continue processing the retired frame */'),
    ('reactor-read-incarnation',
     'test-c99-network-safety',
     'src/net/reactor.c',
     'while (find_registration(reactor, registration) == slot) {\n        ssize_t n = recv',
     'while (slot->state == REACTOR_SLOT_CONNECTED && registration != 0) {\n'
     '        ssize_t n = recv'),
    ('reactor-read-write-incarnation',
     'test-c99-network-safety',
     'src/net/reactor.c',
     'if (find_registration(reactor, registration) == slot &&\n            slot->state',
     'if (slot->state'),
    ('reactor-retirement-before-callback',
     'test-c99-network-safety',
     'src/net/reactor.c',
     '    memset(slot, 0, sizeof(*slot));\n    slot->fd = -1;',
     '    /* mutant: retain slot state through callback */\n    slot->fd = -1;'),
    ('mesh-generation-exhaustion',
     'test-c99-network-safety',
     'src/net/peer_mesh.c',
     'if (!mesh || !host || !mesh->running || mesh->next_generation == (UINTPTR_MAX >> '
     'PEER_COOKIE_BITS)) return -1;',
     'if (!mesh || !host || !mesh->running) return -1;'),
    ('reactor-queue-room',
     'test-c99-network-safety',
     'src/net/reactor.c',
     'len > REACTOR_BUFFER_CAPACITY - slot->tx_len',
     'len > REACTOR_BUFFER_CAPACITY - slot->tx_len + 1U'),
    ('reactor-duplicate-registration',
     'test-c99-network-safety',
     'src/net/reactor.c',
     'if (find_slot_by_fd(reactor, client_fd) || reactor_prepare_socket(client_fd) != 0)',
     'if (reactor_prepare_socket(client_fd) != 0)'),
    ('mesh-null-init-sentinels',
     'test-c99-network-safety',
     'src/net/peer_mesh.c',
     'if (!mesh || mesh_dispatching) return -1;',
     'if (!mesh || !cfg || mesh_dispatching) return -1;'),
    ('k2-aggregator-close-sentinels',
     'test-c99-network-safety',
     'src/net/k2_net.c',
     'determ_secure_zero(agg, sizeof(*agg));\n'
     '    agg->listen_fd = -1;\n'
     '    agg->peer.fd = -1;\n'
     '    agg->loop.poll_fd = -1;',
     'determ_secure_zero(agg, sizeof(*agg));'),
    ('k2-contributor-close-sentinels',
     'test-c99-network-safety',
     'src/net/k2_net.c',
     'determ_secure_zero(cont, sizeof(*cont));\n'
     '    cont->conn.fd = -1;\n'
     '    cont->loop.poll_fd = -1;',
     'determ_secure_zero(cont, sizeof(*cont));'),
    ('reactor-sigpipe',
     'test-c99-network-safety',
     'src/net/reactor.c',
     'static ssize_t reactor_socket_send(int fd, const void *data, size_t len) {\n'
     '    int flags = 0;\n'
     '#ifdef MSG_NOSIGNAL\n'
     '    flags = MSG_NOSIGNAL;\n'
     '#endif\n'
     '    return send(fd, (const char *)data, len, flags);\n'
     '}',
     'static ssize_t reactor_socket_send(int fd, const void *data, size_t len) {\n'
     '#ifdef SO_NOSIGPIPE\n'
     '    int no = 0;\n'
     '    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no, sizeof(no));\n'
     '#endif\n'
     '    return send(fd, data, len, 0);\n'
     '}'),
    ('mesh-sigpipe',
     'test-c99-network-safety',
     'src/net/peer_mesh.c',
     'static ssize_t peer_socket_send(int fd, const void *data, size_t len) {\n'
     '    int flags = 0;\n'
     '#ifdef MSG_NOSIGNAL\n'
     '    flags = MSG_NOSIGNAL;\n'
     '#endif\n'
     '    return send(fd, data, len, flags);\n'
     '}',
     'static ssize_t peer_socket_send(int fd, const void *data, size_t len) {\n'
     '#ifdef SO_NOSIGPIPE\n'
     '    int no = 0;\n'
     '    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no, sizeof(no));\n'
     '#endif\n'
     '    return send(fd, data, len, 0);\n'
     '}'),
    ('http-body-capacity', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (value > limit / 10 || (value == limit / 10 && digit > limit % 10)) return 413;', '(void)limit; /* mutant: unchecked length accumulation */'),
    ('http-header-case', 'test-http-rpc', 'src/rpc/http_rpc_server.c', "if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + ('a' - 'A'));", '/* mutant: case-sensitive header comparison */'),
    ('http-header-name', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (len != strlen(expected)) return 0;', 'if (len < strlen(expected)) return 0;\n    name += len - strlen(expected);\n    len = strlen(expected);'),
    ('http-duplicate-length', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (seen) return 400;', '/* mutant: accept duplicate length */'),
    ('http-transfer-encoding', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (http_field_is(data + pos, colon - pos, "transfer-encoding")) return 400;', '/* mutant: accept transfer encoding with content length */'),
    ('http-decimal-length', 'test-http-rpc', 'src/rpc/http_rpc_server.c', "if (data[i] < '0' || data[i] > '9') return 400;", '/* mutant: accept nondecimal digits */'),
    ('http-reserved-byte', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'const size_t limit = (HTTP_RPC_BUF_SIZE - 1) - header_len;', 'const size_t limit = HTTP_RPC_BUF_SIZE - header_len;'),
    ('http-init-client-fds', 'test-http-rpc', 'src/rpc/http_rpc_server.c', '        server->clients[i].fd = -1;\n        server->clients[i].state = HTTP_CLIENT_INACTIVE;\n    }\n    if (!config)', '        server->clients[i].state = HTTP_CLIENT_INACTIVE;\n    }\n    if (!config)'),
    ('http-incomplete-body', 'test-http-rpc', 'src/rpc/http_rpc_server.c', 'if (c->rx_len < header_len + content_len) {', 'if (0) {'),
    ('pending-signature', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (determ_ed25519_verify(sender, signing, sizeof(signing), tx.sig) != 0)', 'if (0)'),
    ('pending-small-order', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (determ_ed25519_point_has_small_order(sender) != 0)', 'if (0)'),
    ('pending-genesis', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (memcmp(tx.genesis_hash, pool->genesis_hash, 32) != 0)', 'if (0)'),
    ('pending-source-route', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'tx.shard_id >= pool->routing.shard_count || tx.shard_id != source_shard', 'tx.shard_id >= pool->routing.shard_count'),
    ('pending-destination-route', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'destination_shard != source_shard', '0'),
    ('pending-data-hash', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (memcmp(hash, tx.hash, sizeof(hash)) != 0) return PENDING_TRANSFER_ERR_HASH;', '/* mutant: trust advertised hash */'),
    # The decoder's payload-padding rule is judged at test-binary-codec
    # (codec-tx-padding below). The pending inbox also re-encodes and compares
    # (defense in depth), so a mutant of either check alone is masked at the
    # inbox; neither is judged there.
    ('pending-core-prefix', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'if (memcmp(tx.sender_pubkey, tx.from, 32) != 0 || memcmp(tx.recipient_pubkey, tx.to, 32) != 0)', 'if (0)'),
    ('pending-conflict-preference', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'int order = memcmp(candidate.hash, incumbent->hash, sizeof(candidate.hash));', 'int order = -memcmp(candidate.hash, incumbent->hash, sizeof(candidate.hash));'),
    ('pending-bucket-isolation', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'else if (at->shard_id == shard_id) { bucket = at; break; }', 'else { bucket = at; break; }'),
    ('pending-owned-frame', 'test-pending-transfer', 'src/ledger/pending_transfer.c', 'memcpy(entry->frame, frame, len);', 'memcpy(entry->frame, frame, len - 64);'),
    ('pending-rpc-output-preflight', 'test-rpc-pending-transfer', 'src/rpc/json_rpc.c', 'if (cap < RPC_PENDING_SUBMIT_RESPONSE_LEN) return -1;', '/* mutant: mutate before discovering short response buffer */'),
    ('pending-rpc-request-bound', 'test-rpc-pending-transfer', 'src/rpc/json_rpc.c', 'len > RPC_PENDING_MAX_REQUEST_LEN', 'len > RPC_PENDING_MAX_REQUEST_LEN + 1'),
    ('pending-node-context', 'determ-node', 'src/determ_node.c', 'rcfg.rpc_ctx.pending = have_pending_genesis ? &g_pending : NULL;', 'rcfg.rpc_ctx.pending = NULL;'),
    ("ed25519-sign-small-heap", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "buf = msglen <= sizeof sign_buf - 64u ? sign_buf : (u8 *)malloc(64 + msglen);",
     "buf = (u8 *)malloc(64 + msglen);"),
    ("ed25519-verify-small-heap", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "buf = msglen <= sizeof verify_buf - 64u ? verify_buf : (u8 *)malloc(64 + msglen);",
     "buf = (u8 *)malloc(64 + msglen);"),
    ("ed25519-sign-boundary", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "msglen <= sizeof sign_buf - 64u", "msglen < sizeof sign_buf - 64u"),
    ("ed25519-verify-boundary", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "msglen <= sizeof verify_buf - 64u", "msglen < sizeof verify_buf - 64u"),
    ("ed25519-sign-stack-free", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "if (buf != sign_buf) free(buf);", "free(buf);"),
    ("ed25519-verify-stack-free", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "if (buf != verify_buf) free(buf);", "free(buf);"),
    ("ed25519-sign-length-overflow", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "if (msglen > SIZE_MAX - 64u) return -1;\n\n    determ_sha512(seed, 32, h);",
     "/* mutant: unchecked signing length */\n\n    determ_sha512(seed, 32, h);"),
    ("ed25519-verify-length-overflow", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "if (msglen > SIZE_MAX - 64u) return -1;\n    if (!point_y_is_canonical(pk))",
     "/* mutant: unchecked verification length */\n    if (!point_y_is_canonical(pk))"),
    ("ed25519-sign-buffer-wipe", "test-ed25519-bounded", "src/crypto/ed25519/ed25519.c",
     "determ_secure_zero(buf, 64 + msglen);", "/* mutant: leave signing buffer uncleansed */"),
    ("recovery-reject-conflicting-roots", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "/* This model does not select between competing complete histories. */", REJECT_CONFLICTING_ROOTS),
    ("recovery-tx-hash-overrides-block", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     ROOT_RANK, TX_OVERRIDES_ROOT_RANK),
    ("recovery-sibling-selected-state", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "*state=n->config->anchor_state;", "*state=n->state;"),
    ("recovery-requeue-anchor-state", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "bool conflict=false; *scratch=n->state;", "bool conflict=false; *scratch=n->config->anchor_state;"),
    ("recovery-message-count", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "n->records[i].candidate.tx_count>n->records[best].candidate.tx_count",
     "n->records[i].candidate.tx_count<n->records[best].candidate.tx_count"),
    ("recovery-header-not-hash", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "memcmp(n->records[i].header,n->records[best].header,K2_MODEL_HEADER_BYTES)<0",
     "memcmp(n->records[i].id,n->records[best].id,32)<0"),
    ("recovery-original-parent", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid && !memcmp(n->records[i].candidate.parent,n->records[best].id,32)) child=(int)i;",
     "for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid && n->records[i].candidate.height==n->records[best].candidate.height+1) child=(int)i;"),
    ("recovery-shared-receipt", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(!shared) return false;", "(void)shared;"),
    ("recovery-pair-authority", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(!authorized) return false;", "(void)authorized;"),
    ("recovery-requeue-validity", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(ledger_apply_tx(scratch,txs[i],0)!=LEDGER_OK)", "if(false)"),
    ("recovery-message-hash-order", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "while(pos && memcmp(ids[pos-1],id,32)>0)", "while(pos && memcmp(ids[pos-1],id,32)<0)"),
    ("recovery-restore-revision", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "w->restoring.generation=next_generation;", "(void)next_generation;"),
    ("recovery-journal-body-binding", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(memcmp(header,p,sizeof(header))) return K2_MODEL_INVALID;", "(void)header;"),
    ("recovery-impossible-root", "test-dsf-k2-recovery", "sim/k2_recovery_model.c",
     "if(c->height==n->config->anchor_height+1) return K2_MODEL_INVALID;", "/* mutant: wait for impossible parent */"),
    ("routing-zero-count", "test-shard-routing", "src/ledger/shard_routing.c",
     "if (!out || !salt || shard_count == 0)", "if (!out || !salt)"),
    ("routing-domain", "test-shard-routing", "src/ledger/shard_routing.c",
     'static const char tag[] = "shard-route";', 'static const char tag[] = "shard-routex";'),
    ("routing-salt", "test-shard-routing", "src/ledger/shard_routing.c",
     "determ_sha256_update(&hash, config->salt, sizeof(config->salt));", "/* mutant: omit salt */"),
    ("routing-key-length", "test-shard-routing", "src/ledger/shard_routing.c",
     "pubkey_len != 32", "pubkey_len == 99"),
    ("routing-hash-width", "test-shard-routing", "src/ledger/shard_routing.c",
     "i < 8;", "i < 4;"),
    ("routing-rpc-duplicate-field", "test-rpc-shard-routing", "src/rpc/json_rpc.c",
     "if (seen & bit) return -32600;", "if (0) return -32600;"),
    ("routing-rpc-method-key", "test-rpc-shard-routing", "src/rpc/json_rpc.c",
     "const determ_json_tok_t *method_tok = rpc_method_token(request_json, tokens, (size_t)num_tokens);",
     'const determ_json_tok_t *method_tok = determ_json_find_key(request_json, tokens, (size_t)num_tokens, &tokens[0], "method"); (void)rpc_method_token;'),
    ("routing-rpc-request-bound", "test-rpc-shard-routing", "src/rpc/json_rpc.c",
     "len > RPC_ROUTING_MAX_REQUEST_LEN", "len > RPC_ROUTING_MAX_REQUEST_LEN + 1"),
    ("routing-rpc-error-id", "test-rpc-shard-routing", "src/rpc/json_rpc.c",
     '\n            error == -32602 ? id : "null"', '\n            "null"'),
    ("routing-node-context", "determ-node", "src/determ_node.c",
     "rcfg.rpc_ctx.routing = &routing;", "rcfg.rpc_ctx.routing = NULL;"),
    ("ledger-fee-wrap", "test-triple-entry-ledger", "src/ledger/state.c",
     "if (UINT64_MAX - state->total_fees < tx_fee)", "if (0)"),
    ("ledger-fee-exact-fit", "test-triple-entry-ledger", "src/ledger/state.c",
     "if (UINT64_MAX - state->total_fees < tx_fee)",
     "if (UINT64_MAX - state->total_fees <= tx_fee)"),
    ("ledger-nonce-wrap", "test-triple-entry-ledger", "src/ledger/state.c",
     "sender_nonce == UINT64_MAX || tx_nonce != sender_nonce + 1",
     "tx_nonce != sender_nonce + 1"),
    ("ledger-self-alias", "test-triple-entry-ledger", "src/ledger/state.c",
     "if (sender == receiver)", "if (0)"),
    ("ledger-self-fee", "test-triple-entry-ledger", "src/ledger/state.c",
     "sender_balance -= tx_fee;", "sender_balance -= tx_amount + tx_fee;"),
    ("ledger-self-nonce", "test-triple-entry-ledger", "src/ledger/state.c",
     "memcpy(&sender->nonce, &tx_nonce, sizeof(uint64_t));",
     "/* mutant: leave the self-transfer nonce unchanged */"),
    ("qpc-remainder-overflow", "test-qpc-clock-overflow", "include/determ/time/clock.h",
     "return ns + quotient;", "return ns + (fraction_ticks * scale) / freq;"),
    ("qpc-whole-saturation", "test-qpc-clock-overflow", "include/determ/time/clock.h",
     "if (whole > UINT64_MAX / scale)", "if (false)"),
    ("qpc-fraction-saturation", "test-qpc-clock-overflow", "include/determ/time/clock.h",
     "if (quotient > UINT64_MAX - ns)", "if (false)"),
    ("dda-interval-count", "test-dda", "src/consensus/dda.c",
     "uint64_t average = delta / (tracker->count - 1);",
     "uint64_t average = delta / tracker->count;"),
    ("dda-average-wrap", "test-dda", "src/consensus/dda.c",
     "return average > UINT32_MAX ? UINT32_MAX : (uint32_t)average;",
     "return (uint32_t)average;"),
    ("dda-timestamp-order", "test-dda", "src/consensus/dda.c",
     "if (timestamp_ms <= tracker->block_timestamps[newest_idx])",
     "(void)newest_idx;\n        if (false)"),
    ("dda-predecessor-work", "test-dda", "src/consensus/dda.c",
     "if (!tracker || !dda_verify_block_iterations(tracker, iterations))", "if (!tracker)"),
    ("dda-work-progress", "test-dda", "src/consensus/dda.c",
     "tracker->current_iterations = iterations;", "/* mutant: stale work state */"),
    ("duel-both-commits", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     "if (!sm->aggregator_commit.present || !sm->contributor_commit.present)", "if (false)"),
    ("duel-reveal-binding", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     "if (!commit->present || !is_valid || memcmp(digest, commit->hash, 32) != 0)",
     "if (!commit->present || !is_valid)"),
    ("duel-commit-deadline", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     "if (attempt_elapsed(sm) >= DUEL_COMMIT_TIMEOUT_NS)\n        return abort_attempt(sm, ERR_EPOCH_SKIPPED_SILENCE);",
     "if (attempt_elapsed(sm) > DUEL_COMMIT_TIMEOUT_NS)\n        return abort_attempt(sm, ERR_EPOCH_SKIPPED_SILENCE);"),
    ("duel-incomplete-timeout", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     "if (attempt_elapsed(sm) < DUEL_REVEAL_WINDOW_NS) return DUEL_SUCCESS;\n        return abort_attempt(sm, ERR_EPOCH_SKIPPED_INCOMPLETE);",
     "if (attempt_elapsed(sm) < DUEL_REVEAL_WINDOW_NS) return DUEL_SUCCESS;\n        return DUEL_SUCCESS;"),
    ("duel-explicit-retry", "test-k2-duel-fallback", "src/consensus/duel_state.c",
     " && sm->state != DUEL_STATE_ABORTED)", ")"),
    ("node-refusal-status", "determ-node", "src/determ_node.c",
     'fprintf(stderr, "Duel output is not a validated block; --data-dir cannot be used with duel modes\\n");\n        return 1;',
     'fprintf(stderr, "Duel output is not a validated block; --data-dir cannot be used with duel modes\\n");\n        return 0;'),
    ("net-timeout-propagation", "test-k2-net-rpc", "src/net/k2_net.c",
     "return status == DUEL_SUCCESS ? 0 : fail_attempt(agg, status);", "return 0;"),
    ("net-premature-deadline-wakeup", "test-k2-net-rpc", "src/net/k2_net.c",
     "return requested < 0 || requested > remaining ? remaining : requested;",
     "return requested < 0 || requested > remaining ? 0 : requested;"),
    ("net-reveal-binding", "test-k2-net-rpc", "src/consensus/duel_state.c",
     "if (!commit->present || !is_valid || memcmp(digest, commit->hash, 32) != 0)",
     "if (!commit->present || !is_valid)"),
    ("net-eof-before-buffered-result", "test-k2-net-rpc", "src/net/k2_net.c",
     "/* READ|EOF can carry the final complete frame followed by FIN. */",
     "if (flags & NET_EV_EOF) return fail_contributor(cont);\n        /* mutant: discard unread final frame on EOF */"),
    # The status is unchanged (a later bound still rejects); the read past the
    # input reaches the test's inaccessible page and the process faults.
    ("parser-from-bound", "fuzzer-parser", "src/wire/parser.c",
     "if (from_len > WIRE_MAX_ADDR_LEN || offset + from_len > data_len) {",
     "if (from_len > WIRE_MAX_ADDR_LEN) {"),
    ("parser-reject-all", "fuzzer-parser", "src/wire/parser.c",
     "    if (offset != data_len) {", "    if (offset <= data_len) {"),
    ("parser-header-trailing", "fuzzer-parser", "src/wire/parser.c",
     "data_len != WIRE_BLOCK_HEADER_LEN", "data_len < WIRE_BLOCK_HEADER_LEN"),
    ("dda-header-trailing", "test-dda", "src/consensus/dda.c",
     "if (len != CONSENSUS_BLOCK_HEADER_SIZE) return -2;", "if (len < CONSENSUS_BLOCK_HEADER_SIZE) return -2;"),
    ("parser-charset-bypass", "fuzzer-parser", "src/wire/parser.c",
     "wire_status_t wire_validate_charset_strict(const uint8_t *field, size_t len, size_t max_len) {\n",
     "wire_status_t wire_validate_charset_strict(const uint8_t *field, size_t len, size_t max_len) {\n    return WIRE_OK;\n"),
    ("ledger-overspend", "fuzz-ledger", "src/ledger/state.c",
     "    if (sender_balance < total_debit) {", "    if (sender_balance < total_debit && 0) {"),
    ("ledger-amount-overflow", "fuzz-ledger", "src/ledger/state.c",
     "    if (UINT64_MAX - tx_amount < tx_fee) {", "    if (0) {"),
    ("ledger-receiver-overflow", "fuzz-ledger", "src/ledger/state.c",
     "    if (UINT64_MAX - receiver_balance < tx_amount) {", "    if (0) {"),
    ("vdf-zero-iterations", "test-k2-duel", "src/crypto/vdf.c",
     "for (uint64_t i = 0; i < iters; ++i) {", "for (uint64_t i = iters; i < iters; ++i) {"),
    ("codec-envelope-reserved", "test-binary-codec", "src/wire/binary_codec.c",
     "if (data[3] != 0x00) {", "if (data[3] != 0x00 && 0) {"),
    ("codec-tx-reserved", "test-binary-codec", "src/wire/binary_codec.c",
     "if (reserved != 0) {", "if (reserved != 0 && 0) {"),
    ("codec-hello-trailing", "test-binary-codec", "src/wire/binary_codec.c",
     "msg->wire_version = data[off++];\n    if (off != len) {",
     "msg->wire_version = data[off++];\n    if (off != len && 0) {"),
    ("codec-tx-padding", "test-binary-codec", "src/wire/binary_codec.c",
     "if (data[i] != 0) {", "if (data[i] != 0 && 0) {"),
    ("codec-tx-overflow-segment", "test-binary-codec", "src/wire/binary_codec.c",
     "tx->payload_overflow = data + off;", "tx->payload_overflow = data + 96;"),
    ("duel-reveal-deadline", "test-dsf-k2-duel", "src/consensus/duel_state.c",
     "if (attempt_elapsed(sm) >= DUEL_REVEAL_WINDOW_NS) return DUEL_DROPPED_BUZZER_EXCEEDED;",
     "if (0) return DUEL_DROPPED_BUZZER_EXCEEDED;"),
    ("mesh-rate-limit", "test-peer-mesh", "src/net/peer_mesh.c",
     "    if (per_sec <= 0.0 || burst <= 0.0) return true;",
     "    if (per_sec <= 0.0 || burst <= 0.0 || 1) return true;"),
    ("mesh-partial-frame", "test-peer-mesh", "src/net/peer_mesh.c",
     "    if (env_len > PEER_MESH_TX_BUF_SIZE - 4 || peer->tx_len > PEER_MESH_TX_BUF_SIZE - 4 - env_len)\n"
     "        return -2; /* Outbound buffer full */",
     "    if (env_len > PEER_MESH_TX_BUF_SIZE - 4 || peer->tx_len > PEER_MESH_TX_BUF_SIZE - 4 - env_len) {\n"
     "        if (peer->tx_len <= PEER_MESH_TX_BUF_SIZE - 4) {\n"
     "            be_put_u32(peer->tx_buf + peer->tx_len, (uint32_t)env_len);\n"
     "            peer->tx_len += 4; /* mutant: header queued without its envelope */\n"
     "        }\n"
     "        return -2;\n"
     "    }"),
    ("mesh-dedup-type", "test-peer-mesh", "src/net/peer_mesh.c",
     "determ_sha256_update(&sha, &msg_type, 1);", "/* mutant: key covers the payload only */"),
    ("mesh-accept-once", "test-peer-mesh", "src/net/peer_mesh.c",
     "if (net_event_loop_add(&mesh->loop, cfd, NET_EV_READ, (void *)peer->registration) != 0 ||\n            peer_mesh_send_hello(mesh, slot) != 0) peer_mesh_disconnect(mesh, slot);",
     "if (net_event_loop_add(&mesh->loop, cfd, NET_EV_READ, (void *)peer->registration) != 0 ||\n            peer_mesh_send_hello(mesh, slot) != 0) peer_mesh_disconnect(mesh, slot);\n        return;"),
    ("loop-epoll-edge-triggered", "test-peer-mesh", "src/net/event_loop.c",
     "ev.events |= EPOLLERR | EPOLLHUP; /* level-triggered, as mod() and kqueue */",
     "ev.events |= EPOLLERR | EPOLLHUP | EPOLLET;"),
    ("loop-kqueue-write-kept", "test-peer-mesh", "src/net/event_loop.c",
     "EV_ADD | ((events & NET_EV_WRITE) ? EV_ENABLE : EV_DISABLE)", "EV_ADD | EV_ENABLE"),
    ("store-dbk1-magic", "test-block-store", "src/storage/block_store.c",
     'if (mn != 4 || memcmp(magic, "DBK1", 4) != 0) {', "if (mn != 4) {"),
    ("store-unvouched-hash", "test-block-store", "src/storage/block_store.c",
     "height >= store->indexed_count ||\n        !store->index[height].hash_known) {",
     "height >= store->indexed_count) {"),
    ("ledger-nonce-gap", "test-ledger-state", "src/ledger/state.c",
     "sender_nonce == UINT64_MAX || tx_nonce != sender_nonce + 1",
     "sender_nonce == UINT64_MAX || tx_nonce <= sender_nonce"),
    ("ledger-fee-floor", "test-ledger-state", "src/ledger/state.c",
     "    if (tx_fee < min_fee) {", "    if (tx_fee < min_fee && 0) {"),
    ("ledger-root-count", "test-ledger-state", "src/ledger/state.c",
     "safe_write_uint64_be(preimage, (uint64_t)count);", "safe_write_uint64_be(preimage, 0);"),
    ("ledger-root-native-endian", "test-ledger-state", "src/ledger/state.c",
     "safe_write_uint64_be(leaf + LEDGER_PUBKEY_LEN, balance);",
     "memcpy(leaf + LEDGER_PUBKEY_LEN, &balance, sizeof(balance));"),
    ("ledger-tx-root-sig", "test-ledger-state", "src/ledger/state.c",
     "determ_sha256_update(&sha, txs[i].sig, LEDGER_SIG_LEN);", "/* mutant: signature not committed */"),
    # Streaming stake quorum (ADR-004 §9.7, FB76 Lemma Q): each case breaks one
    # clause of (C1)-(C3), the exact 128-bit comparison, or a guard the proof or
    # the header's contract relies on.
    ("sq-carry-dropped", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "uint64_t sum3_high = (sum >> 63) + (sum3_low < sum2_low ? 1U : 0U); /* SQ_CARRY */",
     "uint64_t sum3_high = (sum >> 63); /* mutant: carry out of the low word lost */"),
    ("sq-quorum-strict", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "(sum3_high == total2_high && sum3_low >= total2_low); /* SQ_QUORUM_COMPARE */",
     "(sum3_high == total2_high && sum3_low > total2_low); /* mutant: exactly two thirds refused */"),
    ("sq-high-word-ignored", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "return sum3_high > total2_high ||",
     "return 0 ||"),
    ("sq-total-high-lost", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "uint64_t total2_high = total >> 63;",
     "uint64_t total2_high = 0U; (void)(total >> 63);"),
    ("sq-quorum-off-by-one", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (sq_is_quorum(acc->sum, acc->total)) { /* SQ_QUORUM_CHECK */",
     "if (sq_is_quorum(acc->sum + 1U, acc->total)) { /* mutant: one stake unit short */"),
    ("sq-duplicate-signer", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (index < acc->next) return sq_reject(acc, SQ_ERR_ORDER); /* SQ_ORDER_CHECK */",
     "if (index + 1U < acc->next) return sq_reject(acc, SQ_ERR_ORDER); /* mutant: repeat allowed */"),
    ("sq-range-member-n", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (index >= acc->count) return sq_reject(acc, SQ_ERR_RANGE); /* SQ_RANGE_CHECK */",
     "if (index > acc->count) return sq_reject(acc, SQ_ERR_RANGE); /* mutant: index N accepted */"),
    ("sq-signature-ignored", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "acc->msg, acc->msg_len, signature) != 1)",
     "acc->msg, acc->msg_len, signature) == 2)"),
    ("sq-signature-nonzero", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "acc->msg, acc->msg_len, signature) != 1)",
     "acc->msg, acc->msg_len, signature) == 0)"),
    ("sq-key-unbound", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "acc->keys + (size_t)index * SQ_KEY_BYTES,",
     "acc->keys, /* mutant: member 0's key for every entry */"),
    ("sq-statement-truncated", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "acc->msg, acc->msg_len, signature)",
     "acc->msg, acc->msg_len / 2U, signature)"),
    ("sq-sum-not-updated", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "acc->sum += stake; /* SQ_SUM_UPDATE */",
     "acc->sum += 0U; /* mutant */"),
    ("sq-next-not-updated", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "acc->next = index + 1U; /* SQ_NEXT_UPDATE",
     "acc->next = index; /* mutant"),
    ("sq-next-16-bit", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "acc->next = index + 1U; /* SQ_NEXT_UPDATE",
     "acc->next = (uint16_t)(index + 1U); /* mutant"),
    ("sq-finish-repeat-closed", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "    if (acc->state != SQ_STATE_OPEN) return acc->verdict;\n",
     "    if (acc->state == SQ_STATE_ACCEPTED) return SQ_ERR_CLOSED; /* mutant */\n"
     "    if (acc->state != SQ_STATE_OPEN) return acc->verdict;\n"),
    ("sq-null-signature-unchecked", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "    if (signature == NULL) return sq_reject(acc, SQ_ERR_ARGUMENT);\n",
     "    /* mutant: a NULL signature reaches the verifier */\n"),
    ("sq-verify-context-dropped", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "acc->verify(acc->verify_context,",
     "acc->verify(NULL, /* mutant */"),
    ("sq-signers-16-bit", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "    acc->signers += 1U;\n",
     "    acc->signers = (uint16_t)(acc->signers + 1U); /* mutant */\n"),
    ("sq-terminal-ignored", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (acc->state != SQ_STATE_OPEN) return SQ_ERR_CLOSED; /* SQ_TERMINAL */",
     "/* mutant: absorbing continues after a rejection */"),
    ("sq-late-entry-kept", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (acc->state == SQ_STATE_ACCEPTED) return sq_reject(acc, SQ_ERR_CLOSED); /* SQ_LATE_ENTRY */",
     "if (acc->state == SQ_STATE_ACCEPTED) return SQ_ERR_CLOSED; /* mutant: acceptance stands */"),
    ("sq-late-duplicate-kept", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (acc->state == SQ_STATE_ACCEPTED) return sq_reject(acc, SQ_ERR_CLOSED); /* SQ_LATE_ENTRY */",
     "if (acc->state == SQ_STATE_ACCEPTED && index >= acc->next) return sq_reject(acc, SQ_ERR_CLOSED);"),
    ("sq-late-range-kept", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (acc->state == SQ_STATE_ACCEPTED) return sq_reject(acc, SQ_ERR_CLOSED); /* SQ_LATE_ENTRY */",
     "if (acc->state == SQ_STATE_ACCEPTED && index < acc->count) return sq_reject(acc, SQ_ERR_CLOSED);"),
    ("sq-late-null-kept", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (acc->state == SQ_STATE_ACCEPTED) return sq_reject(acc, SQ_ERR_CLOSED); /* SQ_LATE_ENTRY */",
     "if (acc->state == SQ_STATE_ACCEPTED && signature != NULL) return sq_reject(acc, SQ_ERR_CLOSED);"),
    ("sq-sum-guard-removed", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (stake > acc->total - acc->sum) return sq_reject(acc, SQ_ERR_SNAPSHOT); /* SQ_SUM_GUARD */",
     "/* mutant: changed stakes not detected */"),
    ("sq-zero-stake-accepted", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (stakes[i] == 0U) return SQ_ERR_SNAPSHOT; /* SQ_ZERO_STAKE */",
     "/* mutant: zero stake accepted */"),
    ("sq-zero-stake-first-accepted", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (stakes[i] == 0U) return SQ_ERR_SNAPSHOT; /* SQ_ZERO_STAKE */",
     "if (i > 0U && stakes[i] == 0U) return SQ_ERR_SNAPSHOT; /* mutant: first stake unchecked */"),
    ("sq-total-overflow", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (stakes[i] > UINT64_MAX - total) return SQ_ERR_SNAPSHOT; /* SQ_TOTAL_OVERFLOW */",
     "/* mutant: total may wrap */"),
    ("sq-total-max-refused", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (stakes[i] > UINT64_MAX - total) return SQ_ERR_SNAPSHOT; /* SQ_TOTAL_OVERFLOW */",
     "if (stakes[i] >= UINT64_MAX - total) return SQ_ERR_SNAPSHOT; /* mutant: W = 2^64 - 1 refused */"),
    ("sq-total-recorded-low", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "    snapshot->total = total;\n",
     "    snapshot->total = total - (count > 32U ? 1U : 0U); /* mutant */\n"),
    ("sq-total-recorded-high", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "    snapshot->total = total;\n",
     "    snapshot->total = total + (count > 8U ? 1U : 0U); /* mutant */\n"),
    ("sq-total-copied-low", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "acc->total = snapshot->total;",
     "acc->total = snapshot->total - (snapshot->count > 32U ? 1U : 0U); /* mutant */"),
    ("sq-begin-keys", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (snapshot->keys == NULL) return SQ_ERR_SNAPSHOT; /* SQ_BEGIN_KEYS */",
     "/* mutant: NULL keys accepted */"),
    ("sq-begin-stakes", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (snapshot->stakes == NULL) return SQ_ERR_SNAPSHOT; /* SQ_BEGIN_STAKES */",
     "/* mutant: NULL stakes accepted */"),
    ("sq-begin-count", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (snapshot->count == 0U) return SQ_ERR_SNAPSHOT; /* SQ_BEGIN_COUNT */",
     "/* mutant: empty member list accepted */"),
    ("sq-begin-total", "test-stake-quorum", "src/consensus/stake_quorum.c",
     "if (snapshot->total == 0U) return SQ_ERR_SNAPSHOT; /* SQ_BEGIN_TOTAL */",
     "/* mutant: zero total accepted */"),

]

# Targets whose harness reports every failed assertion with a marker line and
# exit status 1. For these a mutant counts as rejected only when the marker and
# exit 1 both appear, so a crash, sanitizer abort or signal is never a kill
# (the recorded gap for the other harnesses: DECISION-LOG 2026-09-24).
ASSERTION_MARKERS = {
    "test-stake-quorum": "SQ-TEST ASSERTION FAILED",
    "test-c99-crypto-bounds": "C99-CRYPTO-BOUNDS ASSERTION FAILED",
    "test-c99-codec-bounds": "ASSERTION FAILED:",
    "test-c99-http-safety": "ASSERTION FAILED:",
    "test-http-rpc": "ASSERTION FAILED:",
    "test-c99-network-safety": "NETWORK_SAFETY_ASSERT:",
}


# Cases observable on one event-loop backend only; on the other backends the
# mutation is either not compiled or has no observable effect, so the case is
# skipped there rather than counted.
#  - reactor-read-write-incarnation: kqueue reports READ and WRITE as separate
#    events, so the combined-event path it breaks does not arise.
#  - reactor-flush-sigpipe: on kqueue, EVFILT_WRITE after a local SHUT_WR carries
#    EV_EOF, so reactor_step closes the slot before the flush path runs (and
#    macOS also sets SO_NOSIGPIPE at registration).
EPOLL_ONLY = ("loop-epoll-edge-triggered", "reactor-read-write-incarnation",
              "reactor-flush-sigpipe")
# epoll ADD already rejects a duplicate FD (EEXIST); kqueue EV_ADD replaces it.
# Removing the explicit registration guard is observable only on kqueue here.
KQUEUE_ONLY = ("loop-kqueue-write-kept", "reactor-duplicate-registration")

# The targets tools/ci_c99.sh lists in C99_UNIX (POSIX transport only).
POSIX_TARGETS = ("test-c99-network-safety", "test-c99-http-safety", "test-dsf-k2-duel", "test-k2-net-rpc", "test-peer-mesh", "test-block-store",
                 "test-http-rpc", "test-ledger-state", "fuzz-ledger", "test-triple-entry-ledger",
                 "test-rpc-shard-routing", "test-rpc-pending-transfer", "determ-node")


def run_gate(source, build, targets, jobs):
    command = ["bash", str(source / "tools/ci_local.sh"), "--c99",
               "--build-dir", str(build), "--jobs", str(jobs)]
    for target in targets:
        command.extend(["--c99-test", target])
    process = subprocess.Popen(command, cwd=source, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=(os.name == "posix"))
    try:
        output, _ = process.communicate(timeout=300)
    except subprocess.TimeoutExpired as error:
        # On POSIX, kill the wrapper and its compiler/test descendants together.
        # An infrastructure timeout must not leave a listener or mutant running.
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.communicate()
        raise RuntimeError("gate timed out; not a killed mutant") from error
    return process.returncode, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if not MUTANTS:
        raise RuntimeError("no mutation cases configured")
    cases = list(MUTANTS)
    if sys.platform in ("win32", "cygwin", "msys"):
        cases = [case for case in MUTANTS if case[1] not in POSIX_TARGETS]
        for case in MUTANTS:
            if case not in cases:
                print("PLATFORM-SKIP(mutant): " + case[0] + " (POSIX prototype)", flush=True)
    kqueue = sys.platform == "darwin" or "bsd" in sys.platform
    for case in list(cases):
        if (case[0] in EPOLL_ONLY and not sys.platform.startswith("linux")) or \
                (case[0] in KQUEUE_ONLY and not kqueue):
            cases.remove(case)
            print("PLATFORM-SKIP(mutant): " + case[0] + " (other event-loop backend)", flush=True)
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="determ-c99-mutants-") as temporary:
        work = Path(temporary)
        baseline = work / "baseline"
        baseline.mkdir()
        # Copy current source, including uncommitted fixes. No checkout writes,
        # stale binaries, dependencies, or .git metadata enter this snapshot.
        for name in ("include", "src", "tests", "tools", "third_party",
                     "wallet", "light", "sim", "dapps"):
            shutil.copytree(root / name, baseline / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(root / "CMakeLists.txt", baseline / "CMakeLists.txt")
        targets = list(dict.fromkeys(case[1] for case in cases))
        print("=== ci_local --c99-mutants: fresh baseline ===", flush=True)
        code, output = run_gate(baseline, work / "baseline-build", targets, args.jobs)
        if code != 0 or "BUILD_OK(c99):" not in output:
            print(output, flush=True)
            raise RuntimeError("baseline must build and pass before mutation")
        for target in targets:
            if "PASS(test): " + target + "\n" not in output:
                raise RuntimeError("baseline did not execute " + target)
        print("PASS: baseline compiled and all selected gates executed", flush=True)
        for number, (name, target, relative, old, new) in enumerate(cases, 1):
            source = work / ("mutant-%02d" % number)
            shutil.copytree(baseline, source)
            path = source / relative
            original = path.read_text()
            if original.count(old) != 1:
                raise RuntimeError("mutation anchor must match once: " + name)
            path.write_text(original.replace(old, new, 1))
            code, output = run_gate(source, work / ("build-%02d" % number),
                                    [target], args.jobs)
            if "BUILD_OK(c99): " + target + "\n" not in output:
                print(output, flush=True)
                raise RuntimeError("mutant failed to build: " + name)
            if code == 0 or "FAIL(test): " + target + " (exit " not in output:
                print(output, flush=True)
                raise RuntimeError("mutant survived or failed outside its gate: " + name)
            marker = ASSERTION_MARKERS.get(target)
            if marker is not None and (marker not in output or
                                       "FAIL(test): " + target + " (exit 1)" not in output):
                print(output, flush=True)
                raise RuntimeError("mutant was not rejected by an assertion: " + name)
            print("RED(mutant): %s [%s; fresh build succeeded]" % (name, target), flush=True)
            shutil.rmtree(source)
            shutil.rmtree(work / ("build-%02d" % number))
        print("PASS: %d/%d mutants rejected after successful builds" %
              (len(cases), len(cases)), flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print("FAIL(c99-mutants): " + str(error), file=sys.stderr)
        sys.exit(1)
