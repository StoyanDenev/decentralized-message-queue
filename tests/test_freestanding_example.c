/* Apache-2.0. HOSTED test apparatus only: malloc gives ASan exact input extents.
 * No allocator or libc function is used by the separately compiled example core.
 * Enter through tools/ci_local.sh --freestanding-examples, never a stale binary.
 */
#include "freestanding_core.h"
#include <stdio.h>
#include <stdlib.h>

static unsigned long checks;
#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "assertion failed at line %d: %s\n", __LINE__, #c); \
    return 1; } } while (0)

struct guarded_frame {
    unsigned char before[16];
    struct fg_frame value;
    unsigned char after[16];
};

static void fill(void *p, size_t n, unsigned char value) {
    unsigned char *b = p;
    size_t i;
    for (i = 0; i < n; ++i) b[i] = value;
}

static int same(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    size_t i;
    for (i = 0; i < n; ++i) if (x[i] != y[i]) return 0;
    return 1;
}

static int filled(const void *p, size_t n, unsigned char value) {
    const unsigned char *b = p;
    size_t i;
    for (i = 0; i < n; ++i) if (b[i] != value) return 0;
    return 1;
}

static void frame_bytes(unsigned char *b, size_t payload, unsigned int shard) {
    size_t i;
    b[0] = 0x51U; b[1] = 0x46U; b[2] = 1U; b[3] = 2U;
    b[4] = (unsigned char)(payload >> 8);
    b[5] = (unsigned char)payload;
    b[6] = (unsigned char)(shard >> 8);
    b[7] = (unsigned char)shard;
    for (i = 0; i < payload; ++i) b[8U + i] = (unsigned char)(i ^ 0xA7U);
}

static int rejected(const unsigned char *b, size_t n) {
    struct guarded_frame out, before;
    fill(&out, sizeof out, 0xA5U);
    fill(&before, sizeof before, 0xA5U);
    CHECK(fg_parse_frame(b, n, &out.value) == 0);
    /* Compare representation, including initialized padding and both canaries. */
    CHECK(same(&out, &before, sizeof out));
    return 0;
}

static int parser_tests(void) {
    unsigned char bytes[FG_FRAME_CAP + 1U];
    unsigned char saved[FG_FRAME_CAP + 1U];
    struct guarded_frame out;
    size_t n, i, j;
    unsigned long v;

    CHECK(rejected(NULL, 0U) == 0);
    CHECK(rejected(NULL, FG_FRAME_CAP) == 0);
    CHECK(fg_parse_frame(bytes, 0U, NULL) == 0);
    CHECK(fg_parse_frame(NULL, 0U, NULL) == 0);

    /* Every legal extent uses exactly that many allocated bytes, so ASan can
     * detect a read beyond the declared buffer instead of hidden spare capacity.
     */
    for (n = 0; n <= FG_PAYLOAD_CAP; ++n) {
        unsigned char *exact = malloc(FG_HEADER_SIZE + n);
        CHECK(exact != NULL);
        frame_bytes(exact, n, 0x1234U);
        fill(&out, sizeof out, 0xA5U);
        CHECK(fg_parse_frame(exact, FG_HEADER_SIZE + n, &out.value) == 1);
        CHECK(out.value.type == 2U && out.value.shard == 0x1234U);
        CHECK(out.value.payload_len == n);
        CHECK(filled(out.before, sizeof out.before, 0xA5U));
        CHECK(filled(out.after, sizeof out.after, 0xA5U));
        for (i = 0; i < n; ++i) CHECK(out.value.payload[i] == (unsigned char)(i ^ 0xA7U));
        for (; i < FG_PAYLOAD_CAP; ++i) CHECK(out.value.payload[i] == 0U);
        CHECK(exact[0] == 0x51U && exact[1] == 0x46U && exact[2] == 1U && exact[3] == 2U);
        CHECK(exact[4] == 0U && exact[5] == n && exact[6] == 0x12U && exact[7] == 0x34U);
        for (i = 0; i < n; ++i) CHECK(exact[8U + i] == (unsigned char)(i ^ 0xA7U));
        free(exact);
    }

    /* Short buffers have true tiny extents; the zero-length case uses a valid
     * one-byte allocation but declares no readable bytes to the parser.
     */
    for (n = 0; n < FG_HEADER_SIZE; ++n) {
        unsigned char *short_frame = malloc(n == 0U ? 1U : n);
        CHECK(short_frame != NULL);
        fill(short_frame, n, 0x51U);
        CHECK(rejected(short_frame, n) == 0);
        free(short_frame);
    }

    frame_bytes(bytes, FG_PAYLOAD_CAP + 1U, 1U);
    CHECK(rejected(bytes, sizeof bytes) == 0); /* actual 257-byte object */
    /* Exact maximum frame: every shorter declared prefix must be rejected. */
    frame_bytes(bytes, FG_PAYLOAD_CAP, 1U);
    for (n = 0; n < FG_FRAME_CAP; ++n) {
        unsigned char *prefix = malloc(n == 0U ? 1U : n);
        CHECK(prefix != NULL);
        for (i = 0; i < n; ++i) prefix[i] = bytes[i];
        CHECK(rejected(prefix, n) == 0);
        free(prefix);
    }
    frame_bytes(bytes, 1U, 1U);
    CHECK(rejected(bytes, FG_HEADER_SIZE) == 0); /* claimed byte absent */
    CHECK(rejected(bytes, FG_HEADER_SIZE + 2U) == 0); /* trailing byte */

    /* Enumerate all u16 length claims at an exact empty frame extent. */
    frame_bytes(bytes, 0U, 1U);
    for (v = 1UL; v <= 65535UL; ++v) {
        bytes[4] = (unsigned char)(v >> 8);
        bytes[5] = (unsigned char)v;
        CHECK(rejected(bytes, FG_HEADER_SIZE) == 0);
    }

    /* Every bad magic/version/type byte, with a valid peer field. */
    for (j = 0; j < 4U; ++j) {
        for (v = 0U; v < 256U; ++v) {
            frame_bytes(bytes, 0U, 0xABCDU);
            bytes[j] = (unsigned char)v;
            if ((j == 0U && v == 0x51U) || (j == 1U && v == 0x46U) ||
                (j == 2U && v == 1U) || (j == 3U && (v == 1U || v == 2U))) {
                CHECK(fg_parse_frame(bytes, FG_HEADER_SIZE, &out.value) == 1);
                CHECK(out.value.type == bytes[3]);
            } else CHECK(rejected(bytes, FG_HEADER_SIZE) == 0);
        }
    }
    /* All shard labels must retain their big-endian value, independently of host. */
    for (v = 0UL; v <= 65535UL; ++v) {
        frame_bytes(bytes, 0U, v);
        CHECK(fg_parse_frame(bytes, FG_HEADER_SIZE, &out.value) == 1);
        CHECK(out.value.shard == v);
    }
    /* An unaligned input remains byte-accessible; no integer overlay is allowed. */
    fill(bytes, sizeof bytes, 0x5CU);
    frame_bytes(bytes + 1U, 3U, 0xFEDCU);
    for (i = 0; i < sizeof bytes; ++i) saved[i] = bytes[i];
    CHECK(fg_parse_frame(bytes + 1U, 11U, &out.value) == 1);
    CHECK(out.value.shard == 0xFEDCU && out.value.payload_len == 3U);
    CHECK(same(bytes, saved, sizeof bytes));
    return 0;
}

static void trace_reset(void) {
#ifdef FG_TEST_TRACE
    size_t i;
    fg_test_equal_iterations = 0U;
    for (i = 0; i < 32U; ++i) fg_test_equal_visits[i] = 0U;
#endif
}

static int trace_complete(void) {
#ifdef FG_TEST_TRACE
    size_t i;
    CHECK(fg_test_equal_iterations == 32U);
    for (i = 0; i < 32U; ++i) CHECK(fg_test_equal_visits[i] == 1U);
#endif
    return 0;
}

static int equality_tests(void) {
    /* Hosted heap extents deliberately match the fixed contract exactly. */
    unsigned char *a = malloc(32U), *b = malloc(32U);
    size_t i, pos;
    unsigned int v;
    CHECK(a != NULL && b != NULL);
    for (i = 0; i < 32U; ++i) a[i] = b[i] = (unsigned char)(i * 7U);
    trace_reset();
    CHECK(fg_equal32(a, b) == 1);
    CHECK(trace_complete() == 0);
    trace_reset();
    CHECK(fg_equal32(a, a) == 1); /* read-only alias is permitted */
    CHECK(trace_complete() == 0);
    for (pos = 0; pos < 32U; ++pos) {
        for (v = 0; v < 256U; ++v) {
            b[pos] = (unsigned char)v;
            trace_reset();
            CHECK(fg_equal32(a, b) == (a[pos] == b[pos] ? 1 : 0));
            CHECK(trace_complete() == 0);
            CHECK(a[pos] == (unsigned char)(pos * 7U));
            b[pos] = a[pos];
        }
    }
    fill(a, 32U, 0U); fill(b, 32U, 255U);
    trace_reset();
    CHECK(fg_equal32(a, b) == 0);
    CHECK(trace_complete() == 0);
    free(a); free(b);
    return 0;
}

static int wipe_tests(void) {
    unsigned char guarded[274];
    size_t n;
    fg_wipe(NULL, 0U); /* the only valid NULL case */
    for (n = 0; n <= 256U; ++n) {
        fill(guarded, sizeof guarded, 0xB7U);
        fg_wipe(guarded + 9U, n);
        CHECK(filled(guarded, 9U, 0xB7U));
        CHECK(filled(guarded + 9U, n, 0U));
        CHECK(filled(guarded + 9U + n, sizeof guarded - 9U - n, 0xB7U));
        if (n != 0U) {
            unsigned char *exact = malloc(n);
            CHECK(exact != NULL);
            fill(exact, n, 0xE3U);
            fg_wipe(exact, n);
            CHECK(filled(exact, n, 0U));
            free(exact);
        }
    }
    return 0;
}

int main(void) {
    if (parser_tests() || equality_tests() || wipe_tests()) return 1;
    printf("PASS: %lu functional/source-trace assertions (not machine timing)\n", checks);
    return 0;
}
