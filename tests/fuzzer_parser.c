/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * LLVM libFuzzer Target: C99 Binary Transaction Deserializer & Charset Defenses.
 *
 * Feeds raw, randomized fuzzer Data directly into the C99 binary transaction
 * deserializer (wire_parse_transaction) which checks the NUL-byte charset
 * constraints and enforces strict framing defenses.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "determ/wire/parser.h"

/* Static zero-allocation context */
static wire_tx_t s_fuzz_tx;
static wire_block_header_t s_fuzz_hdr;
static uint8_t s_fuzz_bundle[WIRE_MAX_VDF_BUNDLE_LEN];

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size == 0) {
        return 0;
    }

    /* 1. Feed raw, randomized fuzzer Data directly into the C99 binary transaction
     * deserializer (responsible for checking the NUL-byte charset constraints). */
    (void)wire_parse_transaction(Data, Size, &s_fuzz_tx);

    /* 2. Direct check of strict charset validator & NUL-byte ghost defense */
    (void)wire_validate_charset_strict(Data, Size, WIRE_MAX_DOMAIN_LEN);

    /* 3. Block header deserializer validation */
    (void)wire_parse_block_header(Data, Size, &s_fuzz_hdr);

    /* 4. VDF input safe bundler boundary fuzzing */
    if (Size >= 2) {
        size_t half = Size / 2;
        size_t written = 0;
        (void)wire_bundle_vdf_input(Data, (uint32_t)half,
                                    Data + half, (uint32_t)(Size - half),
                                    s_fuzz_bundle, sizeof(s_fuzz_bundle),
                                    &written);
    }

    return 0;
}

#ifndef LIBFUZZER_ENABLED
int main(void) {
    printf("[FUZZER_PARSER] Running standalone self-test sweep (Pure C99)...\n");

    /* Deterministic test vector: type(1) + from(5) + to(3) + domain(4) + amount(8) + fee(8) + nonce(8) + payload(4) */
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
    (void)LLVMFuzzerTestOneInput(valid_tx_frame, sizeof(valid_tx_frame));

    /* Randomized mutational sweep with NUL-byte injection */
    uint8_t fuzz_buf[512];
    for (int iter = 0; iter < 10000; iter++) {
        size_t len = (size_t)(rand() % sizeof(fuzz_buf));
        for (size_t i = 0; i < len; i++) {
            fuzz_buf[i] = (uint8_t)(rand() & 0xFF);
            if ((rand() % 5) == 0) fuzz_buf[i] = 0x00; /* Inject NUL bytes */
        }
        (void)LLVMFuzzerTestOneInput(fuzz_buf, len);
    }

    printf("[FUZZER_PARSER] PASS: 10,000 mutational iterations executed without memory faults.\n");
    return 0;
}
#endif
