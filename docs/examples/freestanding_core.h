/* SPDX-License-Identifier: Apache-2.0
 * Teaching example, NOT a Determ wire format or cryptographic primitive.
 * Requires C99 with 8-bit bytes and uint16_t. No hosted-library calls are used.
 */
#ifndef DETERM_EXAMPLE_FREESTANDING_CORE_H
#define DETERM_EXAMPLE_FREESTANDING_CORE_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#if CHAR_BIT != 8
#error "This octet-format example requires CHAR_BIT == 8"
#endif

#define FG_FRAME_CAP 256U
#define FG_HEADER_SIZE 8U
#define FG_PAYLOAD_CAP (FG_FRAME_CAP - FG_HEADER_SIZE)

struct fg_frame {
    unsigned char type;
    uint16_t shard;
    uint16_t payload_len;
    unsigned char payload[FG_PAYLOAD_CAP];
};

/* Toy bytes: [0x51 0x46][version=1][type=1 or 2][payload length BE16]
 *            [shard BE16][payload]. Total length must be EXACT, at most 256.
 * All 65536 shard labels are syntactically legal; none establishes ownership.
 *
 * Caller obligations for a non-NULL input: `length` is the actual readable
 * buffer extent supplied by its owner, not an untrusted header's length claim.
 * `out` points to a writable struct, disjoint from the complete input buffer.
 * Both objects remain alive and exclusively controlled during the call: DMA,
 * interrupts, other threads and aliases must not change them underneath it.
 * C cannot discover object extents, ownership or these synchronization facts.
 *
 * Return 1 on acceptance, 0 on rejection. NULL input/output is rejected.
 * Rejection leaves every output byte unchanged. Acceptance initializes all
 * members, including zeroing the unused payload tail; struct padding is NOT
 * a defined wire/storage representation. Serialize fields explicitly instead.
 */
int fg_parse_frame(const unsigned char *bytes, size_t length,
                   struct fg_frame *out);

/* Both pointers must name at least 32 stable readable bytes. Aliasing between
 * the two read-only arrays is permitted. Return exactly 1 for equal, else 0.
 * The source has 32 iterations and no secret-dependent addresses or branches.
 * This is NOT a universal constant-time guarantee: generated code and target
 * behavior must be reviewed. Do not replace protocol authentication with this.
 */
int fg_equal32(const unsigned char a[32], const unsigned char b[32]);

/* `region` names `length` writable bytes, exclusively owned throughout the call.
 * NULL is allowed only for length == 0. Volatile character stores touch each
 * requested byte. They do not erase compiler copies, registers, prior copies,
 * DMA devices, swap or storage, and are not a synchronization mechanism.
 */
void fg_wipe(void *region, size_t length);

#ifdef FG_TEST_TRACE
/* Test-only source-loop observations, absent from the ordinary build. Tests
 * reset these before each call. Not thread-safe; not machine timing evidence.
 */
extern size_t fg_test_equal_iterations;
extern size_t fg_test_equal_visits[32];
#endif

#endif
