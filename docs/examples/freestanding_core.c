/* SPDX-License-Identifier: Apache-2.0
 * See the header's object-lifetime, extent and exclusive-ownership preconditions.
 * No allocation, libc calls, native-struct decoding, or unaligned integer loads.
 */
#include "freestanding_core.h"

int fg_parse_frame(const unsigned char *bytes, size_t length,
                   struct fg_frame *out) {
    size_t available;
    size_t i;
    uint16_t payload_len;
    uint16_t shard;

    if (bytes == NULL || out == NULL) return 0; /* FG_NULL_CHECK */
    if (length < FG_HEADER_SIZE) return 0; /* FG_HEADER_CHECK */

    /* Subtract only after proving length >= 8. Unlike length + overhead,
     * this cannot wrap. The public length is checked before any input read.
     */
    available = length - FG_HEADER_SIZE;
    if (available > FG_PAYLOAD_CAP) return 0; /* FG_CAP_CHECK */

    if (bytes[0] != 0x51U || bytes[1] != 0x46U) return 0; /* FG_MAGIC_CHECK */
    if (bytes[2] != 1U) return 0; /* FG_VERSION_CHECK */
    if (bytes[3] < 1U || bytes[3] > 2U) return 0; /* FG_TYPE_CHECK */

    /* Cast BEFORE shifting: unsigned int has at least 16 bits even on a
     * target whose signed int cannot represent 255 << 8. No pointer cast
     * or host endianness/alignment assumption is involved.
     */
    payload_len = (uint16_t)(((unsigned int)bytes[4] << 8) |
                              (unsigned int)bytes[5]);
    if ((size_t)payload_len != available) return 0; /* FG_EXACT_CHECK */
    shard = (uint16_t)(((unsigned int)bytes[6] << 8) |
                        (unsigned int)bytes[7]);

    /* COMMIT POINT: every rejection is above this line. Exact length and
     * available <= 248 establish both the input and output copy bounds.
     * This is failure atomicity within a call, not a concurrent atomic update.
     */
    out->type = bytes[3];
    out->shard = shard;
    out->payload_len = payload_len;
    for (i = 0; i < (size_t)payload_len; ++i) {
        out->payload[i] = bytes[FG_HEADER_SIZE + i]; /* FG_PAYLOAD_COPY */
    }
    /* Give callers a defined tail rather than leaking an earlier frame's data.
     * Padding, if the implementation inserts any, remains outside the contract.
     */
    for (; i < FG_PAYLOAD_CAP; ++i) {
        out->payload[i] = 0U; /* FG_TAIL_ZERO */
    }
    return 1;
}

#ifdef FG_TEST_TRACE
size_t fg_test_equal_iterations;
size_t fg_test_equal_visits[32];
#endif

int fg_equal32(const unsigned char a[32], const unsigned char b[32]) {
    unsigned int difference = 0U;
    size_t i;

    for (i = 0; i < 32U; ++i) { /* FG_EQUAL_LOOP */
        difference |= (unsigned int)(a[i] ^ b[i]); /* FG_EQUAL_REDUCE */
#ifdef FG_TEST_TRACE
        fg_test_equal_iterations += 1U;
        fg_test_equal_visits[i] += 1U;
#endif
    }
    /* Each operand is one 8-bit byte, so the OR reduction is in 0..255.
     * Adding 255 is at most 510 (fits even a 16-bit unsigned int).
     * The shifted result is 0 exactly when difference is 0, otherwise 1.
     * No value-dependent control flow is introduced in this C source.
     */
    return (int)(1U ^ ((difference + 255U) >> 8)); /* FG_EQUAL_RESULT */
}

void fg_wipe(void *region, size_t length) {
    volatile unsigned char *bytes = region;
    size_t i;

    /* Conversion from void* to a character pointer is defined in C; character
     * access may visit an object's representation. length==0 dereferences
     * nothing, so NULL is permitted in that one case.
     */
    for (i = 0; i < length; ++i) {
        bytes[i] = 0U; /* FG_WIPE_STORE */
    }
}
