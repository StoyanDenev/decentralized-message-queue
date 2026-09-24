/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Checks for the C99 wire parser (src/wire/parser.c) plus a libFuzzer entry.
 *
 * LLVMFuzzerTestOneInput asserts properties that hold for every input: a
 * transaction shorter than the 35-byte minimum frame is rejected, an accepted
 * one consumed exactly its bytes with every length and charset bound met, the
 * charset validator agrees with a reference predicate, the block header
 * decoder accepts exactly WIRE_BLOCK_HEADER_LEN bytes, and the VDF input
 * bundle has the documented layout. The standalone main additionally pins a
 * known frame's fields and rejects every truncation, a trailing byte, embedded
 * NULs, out-of-charset bytes and length fields that overrun the input.
 *
 * In the standalone run every input is copied so that its last byte is the
 * last readable byte before an inaccessible page: a parser read past data_len
 * terminates the process instead of reading adjacent memory.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "determ/wire/parser.h"

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
        abort(); \
    } \
} while (0)

/* type(1) + three u16 lengths + amount/fee/nonce(24) + u32 payload length */
#define MIN_TX_FRAME 35U

/* Static zero-allocation context */
static wire_tx_t s_fuzz_tx;
static wire_block_header_t s_fuzz_hdr;
static uint8_t s_fuzz_bundle[WIRE_MAX_VDF_BUNDLE_LEN];

static bool be32_is(const uint8_t *p, size_t value) {
    return p[0] == (uint8_t)(value >> 24) && p[1] == (uint8_t)(value >> 16) &&
           p[2] == (uint8_t)(value >> 8) && p[3] == (uint8_t)value;
}

static bool in_charset(const uint8_t *p, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'))
            return false;
    }
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size == 0) {
        return 0;
    }

    /* 1. Transaction deserializer. */
    wire_status_t rc = wire_parse_transaction(Data, Size, &s_fuzz_tx);
    if (Size < MIN_TX_FRAME) CHECK(rc != WIRE_OK);
    if (rc == WIRE_OK) {
        const wire_tx_t *tx = &s_fuzz_tx;
        CHECK(tx->from_len <= WIRE_MAX_ADDR_LEN && tx->to_len <= WIRE_MAX_ADDR_LEN);
        CHECK(tx->domain_len <= WIRE_MAX_DOMAIN_LEN && tx->payload_len <= WIRE_MAX_PAYLOAD_LEN);
        CHECK((size_t)MIN_TX_FRAME + tx->from_len + tx->to_len + tx->domain_len +
              tx->payload_len == Size);
        CHECK(in_charset(tx->from, tx->from_len) && in_charset(tx->to, tx->to_len) &&
              in_charset(tx->domain, tx->domain_len));
        CHECK(tx->type == Data[0]);
    }

    /* 2. Charset validator against the reference predicate. */
    rc = wire_validate_charset_strict(Data, Size, WIRE_MAX_DOMAIN_LEN);
    CHECK((rc == WIRE_OK) == (Size <= WIRE_MAX_DOMAIN_LEN && in_charset(Data, Size)));

    /* 3. Block header deserializer: exactly WIRE_BLOCK_HEADER_LEN bytes. */
    rc = wire_parse_block_header(Data, Size, &s_fuzz_hdr);
    CHECK((rc == WIRE_OK) == (Size == WIRE_BLOCK_HEADER_LEN));

    /* 4. VDF input bundle: [BE32(len_a)][a][BE32(len_b)][b]. */
    if (Size >= 2) {
        size_t half = Size / 2;
        size_t written = 0;
        rc = wire_bundle_vdf_input(Data, (uint32_t)half,
                                   Data + half, (uint32_t)(Size - half),
                                   s_fuzz_bundle, sizeof(s_fuzz_bundle),
                                   &written);
        if (Size - half <= WIRE_MAX_PAYLOAD_LEN) {
            size_t b = Size - half;
            CHECK(rc == WIRE_OK && written == 8 + Size);
            CHECK(be32_is(s_fuzz_bundle, half) && memcmp(s_fuzz_bundle + 4, Data, half) == 0);
            CHECK(be32_is(s_fuzz_bundle + 4 + half, b));
            CHECK(memcmp(s_fuzz_bundle + 8 + half, Data + half, b) == 0);
        }
    }

    return 0;
}

#ifndef LIBFUZZER_ENABLED
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

static uint8_t *s_guard_end; /* first byte of the inaccessible page */
static size_t s_guard_room;  /* readable bytes before it */

static void guard_init(void) {
    uint8_t *base;
    size_t page;
#if defined(_WIN32)
    SYSTEM_INFO info;
    DWORD old;
    GetSystemInfo(&info);
    page = (size_t)info.dwPageSize;
    base = (uint8_t *)VirtualAlloc(NULL, 2 * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(base != NULL);
    CHECK(VirtualProtect(base + page, page, PAGE_NOACCESS, &old));
#else
    long size = sysconf(_SC_PAGESIZE);
    void *map;
    CHECK(size > 0);
    page = (size_t)size;
#if defined(MAP_ANON)
    map = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
#else
    {
        int fd = open("/dev/zero", O_RDWR);
        CHECK(fd >= 0);
        map = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        CHECK(close(fd) == 0);
    }
#endif
    CHECK(map != MAP_FAILED);
    base = (uint8_t *)map;
    CHECK(mprotect(base + page, page, PROT_NONE) == 0);
#endif
    s_guard_end = base + page;
    s_guard_room = page;
}

/* Copy len bytes to end exactly at the inaccessible page. */
static const uint8_t *guarded(const uint8_t *src, size_t len) {
    uint8_t *dst;
    CHECK(len <= s_guard_room);
    dst = s_guard_end - len;
    if (len > 0) memcpy(dst, src, len);
    return dst;
}

static wire_status_t parse_guarded(const uint8_t *frame, size_t len) {
    memset(&s_fuzz_tx, 0xA5, sizeof(s_fuzz_tx));
    return wire_parse_transaction(guarded(frame, len), len, &s_fuzz_tx);
}

/* type(1) + from(5) + to(3) + domain(4) + amount(8) + fee(8) + nonce(8) + payload(4) */
static const uint8_t valid_tx_frame[] = {
    0x01,                                            /* type: 1 */
    0x00, 0x05,                                      /* from_len: 5 */
    0x61, 0x6c, 0x69, 0x63, 0x65,                    /* from: alice */
    0x00, 0x03,                                      /* to_len: 3 */
    0x62, 0x6f, 0x62,                                /* to: bob */
    0x00, 0x04,                                      /* domain_len: 4 */
    0x74, 0x65, 0x73, 0x74,                          /* domain: test */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, /* amount: 1000 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, /* fee: 100 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* nonce: 1 */
    0x00, 0x00, 0x00, 0x04,                         /* payload_len: 4 */
    0x64, 0x61, 0x74, 0x61                          /* payload: data */
};

static void test_known_frame(void) {
    uint8_t frame[sizeof(valid_tx_frame) + 1];
    CHECK(parse_guarded(valid_tx_frame, sizeof(valid_tx_frame)) == WIRE_OK);
    CHECK(s_fuzz_tx.type == 1);
    CHECK(s_fuzz_tx.from_len == 5 && memcmp(s_fuzz_tx.from, "alice", 5) == 0);
    CHECK(s_fuzz_tx.to_len == 3 && memcmp(s_fuzz_tx.to, "bob", 3) == 0);
    CHECK(s_fuzz_tx.domain_len == 4 && memcmp(s_fuzz_tx.domain, "test", 4) == 0);
    CHECK(s_fuzz_tx.amount == 1000 && s_fuzz_tx.fee == 100 && s_fuzz_tx.nonce == 1);
    CHECK(s_fuzz_tx.payload_len == 4 && memcmp(s_fuzz_tx.payload, "data", 4) == 0);

    /* Every strict prefix is rejected, as is one trailing byte. */
    for (size_t len = 0; len < sizeof(valid_tx_frame); ++len)
        CHECK(parse_guarded(valid_tx_frame, len) != WIRE_OK);
    memcpy(frame, valid_tx_frame, sizeof(valid_tx_frame));
    frame[sizeof(valid_tx_frame)] = 0x00;
    CHECK(parse_guarded(frame, sizeof(frame)) != WIRE_OK);
    frame[sizeof(valid_tx_frame)] = 'a';
    CHECK(parse_guarded(frame, sizeof(frame)) != WIRE_OK);

    /* A NUL or an out-of-charset byte in from, to or domain is rejected. */
    {
        static const size_t at[] = { 4, 11, 16 }; /* 'l' of alice, 'o' of bob, 'e' of test */
        static const uint8_t bad[] = { 0x00, 'A', 0x80, ' ', '/' };
        for (size_t i = 0; i < sizeof(at) / sizeof(at[0]); ++i) {
            for (size_t j = 0; j < sizeof(bad); ++j) {
                memcpy(frame, valid_tx_frame, sizeof(valid_tx_frame));
                frame[at[i]] = bad[j];
                CHECK(parse_guarded(frame, sizeof(valid_tx_frame)) != WIRE_OK);
            }
        }
    }
    puts("PASS: known frame decodes to its fields; truncations, trailing bytes, NUL and charset violations rejected");
}

/* A declared length that runs past the input must be rejected without reading
 * past the input: each frame ends at the inaccessible page. */
static void test_length_overruns(void) {
    uint8_t frame[64];
    memset(frame, 'a', sizeof(frame));
    frame[0] = 1; frame[1] = 0x00; frame[2] = 0x80;          /* from_len 128, 32 bytes left */
    CHECK(parse_guarded(frame, MIN_TX_FRAME) != WIRE_OK);

    memset(frame, 'a', sizeof(frame));
    frame[0] = 1; frame[1] = 0; frame[2] = 0;
    frame[3] = 0x00; frame[4] = 0x80;                         /* to_len 128, 30 bytes left */
    CHECK(parse_guarded(frame, MIN_TX_FRAME) != WIRE_OK);

    memset(frame, 'a', sizeof(frame));
    frame[0] = 1; frame[1] = 0; frame[2] = 0; frame[3] = 0; frame[4] = 0;
    frame[5] = 0x00; frame[6] = 0xC8;                         /* domain_len 200, 28 bytes left */
    CHECK(parse_guarded(frame, MIN_TX_FRAME) != WIRE_OK);

    memset(frame, 0, sizeof(frame));
    frame[0] = 1;
    frame[34] = 16;                                           /* payload_len 16, 8 bytes left */
    CHECK(parse_guarded(frame, MIN_TX_FRAME + 8) != WIRE_OK);
    frame[34] = 8;                                            /* control: exactly 8 bytes */
    CHECK(parse_guarded(frame, MIN_TX_FRAME + 8) == WIRE_OK && s_fuzz_tx.payload_len == 8);
    puts("PASS: length fields that overrun the input are rejected without reading past it");
}

static void test_block_header_length(void) {
    wire_block_header_t hdr, out;
    uint8_t wire[WIRE_BLOCK_HEADER_LEN + 1];
    size_t len = 0;
    memset(&hdr, 0, sizeof(hdr));
    hdr.height = 0x0102030405060708ULL;
    memset(hdr.prev_hash, 0x11, 32);
    memset(hdr.tx_root, 0x22, 32);
    memset(hdr.dsso_root, 0x33, 32);
    hdr.timestamp = 1774000000ULL;
    memset(hdr.vrf_aggregator_proof, 0x44, 32);
    memset(hdr.vrf_contributor_proof, 0x55, 32);
    hdr.vdf_iterations = 1000;
    memset(hdr.vdf_proof, 0x66, 32);
    CHECK(wire_encode_block_header(&hdr, wire, sizeof(wire), &len) == WIRE_OK);
    CHECK(len == WIRE_BLOCK_HEADER_LEN);
    CHECK(wire[0] == 0x01 && wire[7] == 0x08); /* big-endian height */
    CHECK(wire_parse_block_header(guarded(wire, len), len, &out) == WIRE_OK);
    CHECK(out.height == hdr.height && out.timestamp == hdr.timestamp && out.vdf_iterations == 1000);
    CHECK(memcmp(out.vdf_proof, hdr.vdf_proof, 32) == 0 && memcmp(out.dsso_root, hdr.dsso_root, 32) == 0);
    wire[len] = 0x00;
    CHECK(wire_parse_block_header(guarded(wire, len + 1), len + 1, &out) != WIRE_OK);
    CHECK(wire_parse_block_header(guarded(wire, len - 1), len - 1, &out) != WIRE_OK);
    puts("PASS: block header round trip; one byte short or one trailing byte rejected");
}

static void test_random_sweep(void) {
    uint8_t fuzz_buf[512];
    (void)LLVMFuzzerTestOneInput(guarded(valid_tx_frame, sizeof(valid_tx_frame)), sizeof(valid_tx_frame));
    for (int iter = 0; iter < 10000; iter++) {
        size_t len = (size_t)(rand() % (int)sizeof(fuzz_buf));
        for (size_t i = 0; i < len; i++) {
            fuzz_buf[i] = (uint8_t)(rand() & 0xFF);
            if ((rand() % 5) == 0) fuzz_buf[i] = 0x00; /* Inject NUL bytes */
        }
        (void)LLVMFuzzerTestOneInput(guarded(fuzz_buf, len), len);
    }
    puts("PASS: 10000 random inputs; short frames rejected, accepted frames exactly consumed");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0); /* keep PASS lines if a guarded read faults */
    guard_init();
    test_known_frame();
    test_length_overruns();
    test_block_header_length();
    test_random_sweep();
    puts("PASS: fuzzer-parser");
    return 0;
}
#endif
