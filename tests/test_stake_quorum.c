/* SPDX-License-Identifier: Apache-2.0
 * Predicate-level gate for src/consensus/stake_quorum.c (ADR-004 §9.7, FB76
 * Lemma Q). Every verdict is judged against an independent reference: the
 * canonical-certificate predicate (C1)-(C3) over a total the fixture sums
 * itself, with 128-bit arithmetic built from 32-bit halves and multiplication,
 * never the module's shift-and-add comparison. Real Ed25519 signatures come from the
 * hosted C99 library; the statement bytes here are test data, not the D5
 * encoding. An assertion failure prints SQ_TEST_MARKER and exits 1, which the
 * mutation gate requires, so a crash or signal is never counted as a kill.
 */
#include "determ/consensus/stake_quorum.h"
#include "determ/crypto/ed25519/ed25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SQ_TEST_MARKER "SQ-TEST ASSERTION FAILED"
static unsigned long checks;
#define CHECK(condition) do { ++checks; if (!(condition)) { \
    fprintf(stderr, SQ_TEST_MARKER " at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
    exit(1); } } while (0)

#define MAX_MEMBERS 64U

/* ---- independent arithmetic: 3 * x and 2 * y as 128-bit (hi, lo) pairs ---- */
static void mul_small(uint64_t x, uint64_t k, uint64_t *hi, uint64_t *lo) {
    uint64_t a = k * (x & 0xffffffffU), b = k * (x >> 32); /* each < 2^34 */
    *lo = a + (b << 32);
    *hi = (b >> 32) + (*lo < a ? 1U : 0U);
}
/* 3 * sum >= 2 * total, formulated independently of sq_is_quorum. */
static int is_quorum(uint64_t sum, uint64_t total) {
    uint64_t h1, l1, h2, l2;
    mul_small(sum, 3U, &h1, &l1);
    mul_small(total, 2U, &h2, &l2);
    return h1 > h2 || (h1 == h2 && l1 >= l2);
}

static uint64_t rng_state = 0x9E3779B97F4A7C15U;
static uint64_t rng(void) { /* xorshift64 */
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
    return rng_state;
}

/* ---- a deterministic fake signature scheme bound to key, message and length ---- */
typedef struct {
    unsigned long calls;
    const uint8_t *expect_msg;  /* the pointer sq_begin received */
    size_t expect_len;
    const uint8_t *keys;        /* the snapshot's key array */
    uint32_t count;
    long last_member;           /* member whose key the last call used */
} fake_ctx;

static void fake_sign(const uint8_t *key, const uint8_t *msg, size_t len, uint8_t sig[64]) {
    size_t i;
    memcpy(sig, key, 32);
    for (i = 0; i < 32; ++i) sig[32 + i] = (uint8_t)(0xA5U ^ (unsigned)(len * 131U + i * 7U));
    for (i = 0; i < len; ++i) sig[32 + (i % 32)] = (uint8_t)((sig[32 + (i % 32)] * 33U) ^ msg[i] ^ i);
}
static int fake_verify(void *context, const uint8_t *key, const uint8_t *msg,
                       size_t len, const uint8_t *sig) {
    fake_ctx *ctx = context;
    uint8_t expect[64];
    CHECK(ctx != NULL && sig != NULL); /* the caller's context, a real signature */
    ctx->calls += 1U;
    /* The accumulator must pass the statement it was given and a key that is
     * exactly one member's slot in the snapshot. */
    CHECK(msg == ctx->expect_msg && len == ctx->expect_len);
    CHECK(key >= ctx->keys && key < ctx->keys + (size_t)ctx->count * 32U &&
          (size_t)(key - ctx->keys) % 32U == 0U);
    ctx->last_member = (long)((size_t)(key - ctx->keys) / 32U);
    fake_sign(key, msg, len, expect);
    return memcmp(expect, sig, 64) == 0 ? 1 : 0;
}

/* ---- test fixture: keys, stakes and one statement ---- */
typedef struct {
    uint8_t keys[(MAX_MEMBERS + 1U) * 32U]; /* one spare slot: a sentinel member N */
    uint64_t stakes[MAX_MEMBERS + 1U];
    uint32_t count;
    uint64_t total;             /* summed here, never read from sq_snapshot_init */
    sq_snapshot snapshot;
    uint8_t msg[48];
    fake_ctx ctx;
} fixture;

static void fixture_init(fixture *f, const uint64_t *stakes, uint32_t count) {
    uint32_t i;
    size_t j;
    memset(f, 0, sizeof *f);
    for (i = 0; i <= MAX_MEMBERS; ++i)
        for (j = 0; j < 32U; ++j) f->keys[i * 32U + j] = (uint8_t)(i * 37U + j * 11U + 1U);
    for (i = 0; i < count; ++i) f->stakes[i] = stakes[i];
    f->stakes[count] = 1U; /* sentinel beyond the snapshot: must never be counted */
    f->count = count;
    for (i = 0; i < count; ++i) {
        CHECK(f->stakes[i] <= UINT64_MAX - f->total);
        f->total += f->stakes[i];
    }
    for (j = 0; j < sizeof f->msg; ++j) f->msg[j] = (uint8_t)(j * 5U + 3U);
    CHECK(sq_snapshot_init(&f->snapshot, f->keys, f->stakes, count) == SQ_OK);
    CHECK(f->snapshot.total == f->total && f->snapshot.count == count);
    f->ctx.expect_msg = f->msg;
    f->ctx.expect_len = sizeof f->msg;
    f->ctx.keys = f->keys;
    f->ctx.count = count + 1U; /* the sentinel slot is addressable, never valid */
}
static void sign_member(const fixture *f, uint32_t member, uint8_t sig[64]) {
    fake_sign(f->keys + (size_t)member * 32U, f->msg, sizeof f->msg, sig);
}
static sq_status begin(fixture *f, sq_accumulator *acc) {
    sq_status st = sq_begin(acc, &f->snapshot, f->msg, sizeof f->msg, fake_verify, &f->ctx);
    /* The accumulator must hold the snapshot as validated, field for field. */
    CHECK(st != SQ_OK || (acc->total == f->total && acc->count == f->count &&
                          acc->keys == f->keys && acc->stakes == f->stakes));
    return st;
}

/* Run a whole certificate of members (all validly signed) and return the verdict. */
static sq_status run_members(fixture *f, const uint32_t *members, size_t n) {
    sq_accumulator acc;
    uint8_t sig[64];
    size_t i;
    CHECK(begin(f, &acc) == SQ_OK);
    for (i = 0; i < n; ++i) {
        sq_status st;
        sign_member(f, members[i], sig);
        st = sq_absorb(&acc, members[i], sig);
        if (st != SQ_OK) return st;
    }
    return sq_finish(&acc);
}

static void test_is_quorum(void) {
    static const uint64_t edges[] = {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 0x5555555555555555U,
        0x5555555555555556U, 0x7FFFFFFFFFFFFFFFU, 0x8000000000000000U, 0xAAAAAAAAAAAAAAAAU,
        0xAAAAAAAAAAAAAAABU, UINT64_MAX - 2U, UINT64_MAX - 1U, UINT64_MAX};
    uint64_t w;
    size_t i, j;
    /* Every W up to 200,000: the boundary is ceil(2W/3), checked from both
     * sides; the formula is itself validated against is_quorum first. */
    for (w = 1U; w <= 200000U; ++w) {
        uint64_t t = w - w / 3U;
        CHECK(is_quorum(t, w) && !is_quorum(t - 1U, w));
        CHECK(sq_is_quorum(t, w) == 1 && sq_is_quorum(t - 1U, w) == 0);
        CHECK(sq_is_quorum(w, w) == 1 && sq_is_quorum(0U, w) == 0);
    }
    /* Edge pairs over the whole 64-bit range, including carries past 2^64. */
    for (i = 0; i < sizeof edges / sizeof edges[0]; ++i)
        for (j = 0; j < sizeof edges / sizeof edges[0]; ++j)
            CHECK(sq_is_quorum(edges[i], edges[j]) == is_quorum(edges[i], edges[j]));
    /* Random pairs, full width and shifted down to every magnitude. */
    for (i = 0; i < 2000000U; ++i) {
        uint64_t a = rng(), b = rng();
        if (i & 1U) { a >>= (unsigned)(rng() % 64U); b >>= (unsigned)(rng() % 64U); }
        CHECK(sq_is_quorum(a, b) == is_quorum(a, b));
    }
}

static void test_snapshot_init(void) {
    uint8_t keys[4 * 32] = {0};
    uint64_t stakes[4] = {5U, 6U, 7U, 8U};
    uint64_t big[3] = {UINT64_MAX / 2U, UINT64_MAX / 2U, 2U};
    sq_snapshot s, before;
    memset(&s, 0x5A, sizeof s);
    memcpy(&before, &s, sizeof s); /* bytes, padding included */
    CHECK(sq_snapshot_init(NULL, keys, stakes, 4U) == SQ_ERR_ARGUMENT);
    CHECK(sq_snapshot_init(&s, NULL, stakes, 4U) == SQ_ERR_ARGUMENT);
    CHECK(sq_snapshot_init(&s, keys, NULL, 4U) == SQ_ERR_ARGUMENT);
    CHECK(sq_snapshot_init(&s, keys, stakes, 0U) == SQ_ERR_SNAPSHOT);
    stakes[2] = 0U;
    CHECK(sq_snapshot_init(&s, keys, stakes, 4U) == SQ_ERR_SNAPSHOT);
    stakes[2] = 7U;
    stakes[0] = 0U; /* the first stake is checked too, alone or not */
    CHECK(sq_snapshot_init(&s, keys, stakes, 4U) == SQ_ERR_SNAPSHOT);
    CHECK(sq_snapshot_init(&s, keys, stakes, 1U) == SQ_ERR_SNAPSHOT);
    stakes[0] = 5U;
    CHECK(sq_snapshot_init(&s, keys, big, 3U) == SQ_ERR_SNAPSHOT); /* 2^64 - 1 + 2 */
    CHECK(memcmp(&s, &before, sizeof s) == 0); /* failures leave it unchanged */
    CHECK(sq_snapshot_init(&s, keys, big, 2U) == SQ_OK);
    CHECK(s.total == UINT64_MAX - 1U && s.count == 2U);
    CHECK(sq_snapshot_init(&s, keys, stakes, 4U) == SQ_OK);
    CHECK(s.total == 26U && s.count == 4U && s.keys == keys && s.stakes == stakes);
}

static void test_begin(void) {
    static const uint64_t stakes[3] = {1U, 1U, 1U};
    fixture f;
    sq_accumulator acc, before;
    sq_snapshot empty;
    fixture_init(&f, stakes, 3U);
    memset(&acc, 0x3C, sizeof acc);
    memcpy(&before, &acc, sizeof acc);
    CHECK(sq_begin(NULL, &f.snapshot, f.msg, 1U, fake_verify, &f.ctx) == SQ_ERR_ARGUMENT);
    CHECK(sq_begin(&acc, NULL, f.msg, 1U, fake_verify, &f.ctx) == SQ_ERR_ARGUMENT);
    CHECK(sq_begin(&acc, &f.snapshot, f.msg, 1U, NULL, &f.ctx) == SQ_ERR_ARGUMENT);
    CHECK(sq_begin(&acc, &f.snapshot, NULL, 1U, fake_verify, &f.ctx) == SQ_ERR_ARGUMENT);
    memset(&empty, 0, sizeof empty);
    CHECK(sq_begin(&acc, &empty, f.msg, 1U, fake_verify, &f.ctx) == SQ_ERR_SNAPSHOT);
    CHECK(memcmp(&acc, &before, sizeof acc) == 0); /* failures leave it unchanged */
    CHECK(sq_absorb(NULL, 0U, f.msg) == SQ_ERR_ARGUMENT);
    CHECK(sq_finish(NULL) == SQ_ERR_ARGUMENT);
    /* An empty statement is allowed (msg NULL with length 0). */
    CHECK(sq_begin(&acc, &f.snapshot, NULL, 0U, fake_verify, &f.ctx) == SQ_OK);
    CHECK(sq_finish(&acc) == SQ_ERR_BELOW_QUORUM);
}

static void test_boundaries(void) {
    static const uint64_t stakes[3] = {34U, 33U, 33U}; /* W = 100, threshold 67 */
    static const uint32_t m01[2] = {0U, 1U}, m12[2] = {1U, 2U}, m012[3] = {0U, 1U, 2U};
    static const uint32_t m0[1] = {0U};
    static const uint64_t equal[3] = {1U, 1U, 1U};  /* W = 3, threshold 2 */
    static const uint64_t skew[4] = {5U, 1U, 1U, 1U}; /* W = 8, threshold 6 */
    static const uint32_t s0[1] = {0U}, s01[2] = {0U, 1U}, s123[3] = {1U, 2U, 3U};
    fixture f;
    fixture_init(&f, stakes, 3U);
    CHECK(sq_is_quorum(67U, 100U) == 1 && sq_is_quorum(66U, 100U) == 0);
    CHECK(run_members(&f, m01, 2U) == SQ_OK);           /* 67: exactly two thirds */
    CHECK(run_members(&f, m12, 2U) == SQ_ERR_BELOW_QUORUM); /* 66 */
    CHECK(run_members(&f, m012, 3U) == SQ_OK);
    CHECK(run_members(&f, m0, 1U) == SQ_ERR_BELOW_QUORUM);
    CHECK(run_members(&f, NULL, 0U) == SQ_ERR_BELOW_QUORUM);
    fixture_init(&f, equal, 3U);
    CHECK(run_members(&f, m01, 2U) == SQ_OK && run_members(&f, m0, 1U) == SQ_ERR_BELOW_QUORUM);
    fixture_init(&f, skew, 4U);
    CHECK(run_members(&f, s0, 1U) == SQ_ERR_BELOW_QUORUM);  /* 5 < 6 */
    CHECK(run_members(&f, s01, 2U) == SQ_OK);               /* 6: stake, not head count */
    CHECK(run_members(&f, s123, 3U) == SQ_ERR_BELOW_QUORUM); /* three members, 3 < 6 */
}

static void test_order_range(void) {
    static const uint64_t stakes[4] = {1U, 1U, 1U, 1U};
    fixture f;
    sq_accumulator acc;
    uint8_t sig[64];
    unsigned long calls;
    fixture_init(&f, stakes, 4U);
    /* Duplicate: the second copy of member 1 is refused without verification. */
    CHECK(begin(&f, &acc) == SQ_OK);
    sign_member(&f, 1U, sig);
    CHECK(sq_absorb(&acc, 1U, sig) == SQ_OK);
    calls = f.ctx.calls;
    CHECK(sq_absorb(&acc, 1U, sig) == SQ_ERR_ORDER && f.ctx.calls == calls);
    CHECK(sq_finish(&acc) == SQ_ERR_ORDER);
    /* Decreasing order. */
    CHECK(begin(&f, &acc) == SQ_OK);
    sign_member(&f, 2U, sig);
    CHECK(sq_absorb(&acc, 2U, sig) == SQ_OK);
    sign_member(&f, 0U, sig);
    CHECK(sq_absorb(&acc, 0U, sig) == SQ_ERR_ORDER);
    /* Index N addresses the sentinel slot, whose signature is well formed, and
     * must still be refused (and never verified or counted). */
    CHECK(begin(&f, &acc) == SQ_OK);
    sign_member(&f, 4U, sig);
    calls = f.ctx.calls;
    CHECK(sq_absorb(&acc, 4U, sig) == SQ_ERR_RANGE && f.ctx.calls == calls);
    CHECK(begin(&f, &acc) == SQ_OK);
    CHECK(sq_absorb(&acc, UINT32_MAX, sig) == SQ_ERR_RANGE);
    /* A NULL signature fails closed. */
    CHECK(begin(&f, &acc) == SQ_OK);
    CHECK(sq_absorb(&acc, 0U, NULL) == SQ_ERR_ARGUMENT && sq_finish(&acc) == SQ_ERR_ARGUMENT);
}

static void test_signature_and_terminal(void) {
    static const uint64_t stakes[5] = {1U, 1U, 1U, 1U, 1U};
    fixture f;
    sq_accumulator acc;
    uint8_t sig[64];
    fixture_init(&f, stakes, 5U);
    /* A bad signature in the middle rejects for good. */
    CHECK(begin(&f, &acc) == SQ_OK);
    f.ctx.calls = 0U;
    sign_member(&f, 0U, sig);
    CHECK(sq_absorb(&acc, 0U, sig) == SQ_OK);
    sign_member(&f, 1U, sig);
    sig[40] ^= 0x01U;
    CHECK(sq_absorb(&acc, 1U, sig) == SQ_ERR_SIGNATURE && f.ctx.calls == 2U);
    sign_member(&f, 2U, sig);
    CHECK(sq_absorb(&acc, 2U, sig) == SQ_ERR_CLOSED && f.ctx.calls == 2U);
    CHECK(sq_finish(&acc) == SQ_ERR_SIGNATURE && sq_finish(&acc) == SQ_ERR_SIGNATURE);
    CHECK(acc.state == SQ_STATE_REJECTED);
    /* Another member's signature at this index, or a signature over another
     * statement, is refused: the key and the message are both bound. */
    CHECK(begin(&f, &acc) == SQ_OK);
    sign_member(&f, 3U, sig);
    CHECK(sq_absorb(&acc, 2U, sig) == SQ_ERR_SIGNATURE && f.ctx.last_member == 2);
    CHECK(begin(&f, &acc) == SQ_OK);
    fake_sign(f.keys, f.msg, sizeof f.msg - 1U, sig);
    CHECK(sq_absorb(&acc, 0U, sig) == SQ_ERR_SIGNATURE);
    /* After acceptance nothing more is absorbed and the verdict is stable. */
    CHECK(begin(&f, &acc) == SQ_OK);
    {
        uint32_t m;
        for (m = 0U; m < 4U; ++m) { sign_member(&f, m, sig); CHECK(sq_absorb(&acc, m, sig) == SQ_OK); }
    }
    CHECK(acc.signers == 4U && acc.sum == 4U);
    CHECK(sq_finish(&acc) == SQ_OK && acc.state == SQ_STATE_ACCEPTED);
    CHECK(sq_finish(&acc) == SQ_OK && acc.state == SQ_STATE_ACCEPTED); /* repeatable */
    /* An entry after an accepting finish means the caller finished early: the
     * verdict turns into SQ_ERR_CLOSED instead of standing. */
    sign_member(&f, 4U, sig);
    CHECK(sq_absorb(&acc, 4U, sig) == SQ_ERR_CLOSED && sq_finish(&acc) == SQ_ERR_CLOSED);
    CHECK(acc.state == SQ_STATE_REJECTED && sq_absorb(&acc, 4U, sig) == SQ_ERR_CLOSED);
    CHECK(acc.signers == 4U && acc.sum == 4U);
    /* The same holds for every kind of bad trailing entry: a duplicate, an
     * index at or beyond N, a NULL signature. A receiver that finished early
     * must not keep an acceptance that a full reading would reject. */
    {
        static const uint32_t late[4] = {0U, 3U, 5U, UINT32_MAX};
        size_t k;
        for (k = 0; k <= 4U; ++k) {
            uint32_t m;
            CHECK(begin(&f, &acc) == SQ_OK);
            for (m = 0U; m < 4U; ++m) { sign_member(&f, m, sig); CHECK(sq_absorb(&acc, m, sig) == SQ_OK); }
            CHECK(sq_finish(&acc) == SQ_OK);
            if (k < 4U) CHECK(sq_absorb(&acc, late[k], sig) == SQ_ERR_CLOSED);
            else CHECK(sq_absorb(&acc, 4U, NULL) == SQ_ERR_CLOSED);
            CHECK(sq_finish(&acc) == SQ_ERR_CLOSED && acc.state == SQ_STATE_REJECTED);
        }
    }
    /* After a below-quorum verdict the same holds. */
    CHECK(begin(&f, &acc) == SQ_OK);
    sign_member(&f, 0U, sig);
    CHECK(sq_absorb(&acc, 0U, sig) == SQ_OK && sq_finish(&acc) == SQ_ERR_BELOW_QUORUM);
    sign_member(&f, 1U, sig);
    CHECK(sq_absorb(&acc, 1U, sig) == SQ_ERR_CLOSED && sq_finish(&acc) == SQ_ERR_BELOW_QUORUM);
}

static void test_snapshot_changed(void) {
    static const uint64_t stakes[3] = {10U, 10U, 10U};
    fixture f;
    sq_accumulator acc;
    uint8_t sig[64];
    fixture_init(&f, stakes, 3U);
    CHECK(begin(&f, &acc) == SQ_OK);
    sign_member(&f, 0U, sig);
    CHECK(sq_absorb(&acc, 0U, sig) == SQ_OK);
    f.stakes[1] = 21U; /* 10 + 21 > 30: impossible for a validated snapshot */
    sign_member(&f, 1U, sig);
    CHECK(sq_absorb(&acc, 1U, sig) == SQ_ERR_SNAPSHOT);
    f.stakes[1] = UINT64_MAX; /* would wrap the sum */
    CHECK(begin(&f, &acc) == SQ_OK);
    sign_member(&f, 0U, sig);
    CHECK(sq_absorb(&acc, 0U, sig) == SQ_OK);
    sign_member(&f, 1U, sig);
    CHECK(sq_absorb(&acc, 1U, sig) == SQ_ERR_SNAPSHOT);
    f.stakes[1] = 10U;
    CHECK(begin(&f, &acc) == SQ_OK);
    sign_member(&f, 0U, sig);
    CHECK(sq_absorb(&acc, 0U, sig) == SQ_OK);
    /* sq_begin copied the snapshot's fields: changing or reusing the
     * sq_snapshot object afterwards does not change this certificate. */
    f.snapshot.total = 5U;
    f.snapshot.count = 1U;
    sign_member(&f, 1U, sig);
    CHECK(sq_absorb(&acc, 1U, sig) == SQ_OK && sq_finish(&acc) == SQ_OK); /* 20 of 30 */
    f.snapshot.total = 30U;
    f.snapshot.count = 3U;
    CHECK(begin(&f, &acc) == SQ_OK);
    sign_member(&f, 0U, sig);
    CHECK(sq_absorb(&acc, 0U, sig) == SQ_OK);
    {
        static const uint64_t one[1] = {1U};
        CHECK(sq_snapshot_init(&f.snapshot, f.keys, one, 1U) == SQ_OK); /* reuse the object */
    }
    CHECK(sq_finish(&acc) == SQ_ERR_BELOW_QUORUM); /* still judged against 10 of 30 */
}

/* ---- the reference predicate over a whole entry list ---- */
typedef struct { uint32_t index; int valid; } entry;

/* Returns the expected verdict and the number of verifier calls it implies. */
static sq_status reference(const fixture *f, const entry *e, size_t n, unsigned long *calls) {
    uint64_t sum = 0U;
    uint32_t next = 0U;
    size_t i;
    *calls = 0U;
    for (i = 0; i < n; ++i) {
        if (e[i].index < next) return SQ_ERR_ORDER;
        if (e[i].index >= f->count) return SQ_ERR_RANGE;
        *calls += 1U;
        if (!e[i].valid) return SQ_ERR_SIGNATURE;
        sum += f->stakes[e[i].index]; /* distinct members: bounded by the total */
        next = e[i].index + 1U;
    }
    return is_quorum(sum, f->total) ? SQ_OK : SQ_ERR_BELOW_QUORUM;
}
static sq_status run_entries(fixture *f, const entry *e, size_t n, unsigned long *calls) {
    sq_accumulator acc;
    uint8_t sig[64];
    size_t i;
    CHECK(begin(f, &acc) == SQ_OK);
    f->ctx.calls = 0U;
    for (i = 0; i < n; ++i) {
        sq_status st;
        sign_member(f, e[i].index < f->count ? e[i].index : f->count, sig);
        if (!e[i].valid) sig[5] ^= 0x80U;
        st = sq_absorb(&acc, e[i].index, sig);
        if (st != SQ_OK) {
            *calls = f->ctx.calls;
            CHECK(sq_finish(&acc) == st); /* the rejection reason is stored */
            return st;
        }
    }
    *calls = f->ctx.calls;
    return sq_finish(&acc);
}

static void test_exhaustive_small(void) {
    uint32_t n, code, mask, bad;
    for (n = 1U; n <= 5U; ++n) {
        uint32_t combos = 1U;
        uint32_t k;
        for (k = 0; k < n; ++k) combos *= 3U;
        for (code = 0U; code < combos; ++code) {
            uint64_t stakes[5];
            fixture f;
            uint32_t c = code;
            for (k = 0; k < n; ++k) { stakes[k] = 1U + c % 3U; c /= 3U; }
            fixture_init(&f, stakes, n);
            for (mask = 0U; mask < (1U << n); ++mask) {
                /* bad = n: every signature valid; otherwise corrupt entry `bad`. */
                for (bad = 0U; bad <= n; ++bad) {
                    entry e[5];
                    size_t count = 0;
                    unsigned long got_calls, want_calls;
                    sq_status want, got;
                    for (k = 0; k < n; ++k)
                        if (mask & (1U << k)) { e[count].index = k; e[count].valid = 1; ++count; }
                    if (bad < n) { if (bad >= count) continue; e[bad].valid = 0; }
                    want = reference(&f, e, count, &want_calls);
                    got = run_entries(&f, e, count, &got_calls);
                    CHECK(got == want && got_calls == want_calls);
                }
            }
        }
    }
}

static void test_randomized(void) {
    unsigned iteration;
    for (iteration = 0U; iteration < 30000U; ++iteration) {
        fixture f;
        uint64_t stakes[MAX_MEMBERS];
        entry e[MAX_MEMBERS + 4U];
        uint32_t n = 1U + (uint32_t)(rng() % MAX_MEMBERS), k;
        size_t count = 0;
        unsigned long got_calls, want_calls;
        uint64_t budget = UINT64_MAX;
        int huge = (rng() % 4U) == 0U;
        for (k = 0; k < n; ++k) {
            /* Huge stakes push the total toward 2^64 - 1 without exceeding it. */
            uint64_t limit = huge ? budget / (uint64_t)(n - k) : 1000U;
            stakes[k] = 1U + (limit > 1U ? rng() % limit : 0U);
            budget -= stakes[k];
        }
        fixture_init(&f, stakes, n);
        for (k = 0; k < n; ++k)
            if (rng() % 3U != 0U) { e[count].index = k; e[count].valid = 1; ++count; }
        if (count > 0U && rng() % 8U == 0U) e[rng() % count].valid = 0;
        if (count > 1U && rng() % 8U == 0U) { /* swap two entries */
            size_t a = rng() % count, b = rng() % count;
            entry t = e[a]; e[a] = e[b]; e[b] = t;
        }
        if (count > 0U && rng() % 8U == 0U) { /* duplicate one entry */
            size_t a = rng() % count;
            memmove(&e[a + 1U], &e[a], (count - a) * sizeof e[0]);
            ++count;
        }
        if (rng() % 16U == 0U) { e[count].index = n + (uint32_t)(rng() % 3U); e[count].valid = 1; ++count; }
        CHECK(reference(&f, e, count, &want_calls) == run_entries(&f, e, count, &got_calls));
        CHECK(got_calls == want_calls);
    }
}

/* The contract accepts exactly 1 as "valid"; any other return rejects. */
static int verifier_result;
static int fixed_verify(void *context, const uint8_t *key, const uint8_t *msg,
                        size_t len, const uint8_t *sig) {
    (void)context; (void)key; (void)msg; (void)len; (void)sig;
    return verifier_result;
}
static void test_verifier_contract(void) {
    static const uint64_t stakes[1] = {1U};
    static const int rejected[4] = {0, -1, 2, 255};
    fixture f;
    sq_accumulator acc;
    uint8_t sig[64];
    size_t i;
    fixture_init(&f, stakes, 1U);
    sign_member(&f, 0U, sig);
    for (i = 0; i < sizeof rejected / sizeof rejected[0]; ++i) {
        verifier_result = rejected[i];
        CHECK(sq_begin(&acc, &f.snapshot, f.msg, sizeof f.msg, fixed_verify, NULL) == SQ_OK);
        CHECK(sq_absorb(&acc, 0U, sig) == SQ_ERR_SIGNATURE);
    }
    verifier_result = 1;
    CHECK(sq_begin(&acc, &f.snapshot, f.msg, sizeof f.msg, fixed_verify, NULL) == SQ_OK);
    CHECK(sq_absorb(&acc, 0U, sig) == SQ_OK && sq_finish(&acc) == SQ_OK);
}

static int ed25519_verify(void *context, const uint8_t *key, const uint8_t *msg,
                          size_t len, const uint8_t *sig) {
    (void)context;
    return determ_ed25519_verify(key, msg, len, sig) == 0 ? 1 : 0;
}

static void test_real_ed25519(void) {
    /* Seven members; W = 11, threshold 8; member 0 holds 5. */
    static const uint64_t stakes[7] = {5U, 1U, 1U, 1U, 1U, 1U, 1U};
    static const char tag[] = "FB76 test statement (not the D5 encoding)";
    uint8_t seeds[7][32], keys[7 * 32], stmt[64], other[64], sigs[7][64], bad[64];
    sq_snapshot s;
    sq_accumulator acc;
    uint32_t i;
    size_t j;
    memset(stmt, 0, sizeof stmt);
    memcpy(stmt, tag, sizeof tag - 1U);
    stmt[48] = 7U;               /* stands in for (height, attempt, parent) */
    memcpy(other, stmt, sizeof other);
    other[48] = 8U;              /* the next attempt's statement */
    for (i = 0; i < 7U; ++i) {
        for (j = 0; j < 32U; ++j) seeds[i][j] = (uint8_t)(i * 29U + j + 1U);
        determ_ed25519_pubkey_from_seed(seeds[i], keys + i * 32U);
        CHECK(determ_ed25519_sign(seeds[i], keys + i * 32U, stmt, sizeof stmt, sigs[i]) == 0);
    }
    CHECK(sq_snapshot_init(&s, keys, stakes, 7U) == SQ_OK && s.total == 11U);
    CHECK(sq_begin(&acc, &s, stmt, sizeof stmt, ed25519_verify, NULL) == SQ_OK);
    for (i = 0; i < 3U; ++i) CHECK(sq_absorb(&acc, i, sigs[i]) == SQ_OK);
    CHECK(sq_finish(&acc) == SQ_ERR_BELOW_QUORUM);      /* 7 < 8 */
    CHECK(sq_begin(&acc, &s, stmt, sizeof stmt, ed25519_verify, NULL) == SQ_OK);
    for (i = 0; i < 4U; ++i) CHECK(sq_absorb(&acc, i, sigs[i]) == SQ_OK);
    CHECK(sq_finish(&acc) == SQ_OK);                     /* 8 */
    memcpy(bad, sigs[2], sizeof bad);
    bad[10] ^= 0x04U;
    CHECK(sq_begin(&acc, &s, stmt, sizeof stmt, ed25519_verify, NULL) == SQ_OK);
    CHECK(sq_absorb(&acc, 0U, sigs[0]) == SQ_OK && sq_absorb(&acc, 2U, bad) == SQ_ERR_SIGNATURE);
    CHECK(sq_begin(&acc, &s, other, sizeof other, ed25519_verify, NULL) == SQ_OK);
    CHECK(sq_absorb(&acc, 0U, sigs[0]) == SQ_ERR_SIGNATURE); /* statement is bound */
    CHECK(sq_begin(&acc, &s, stmt, sizeof stmt, ed25519_verify, NULL) == SQ_OK);
    CHECK(sq_absorb(&acc, 4U, sigs[3]) == SQ_ERR_SIGNATURE); /* key is bound */
}

static int any_verify(void *context, const uint8_t *key, const uint8_t *msg,
                      size_t len, const uint8_t *sig) {
    const uint8_t *keys = context;
    (void)msg; (void)len; (void)sig;
    CHECK(key >= keys && (size_t)(key - keys) % 32U == 0U);
    return 1;
}

static void test_extremes(void) {
    static const uint64_t wmax[2] = {0x8000000000000000U, 0x7FFFFFFFFFFFFFFFU};
    static const uint64_t one[1] = {1U};
    uint8_t keys[2 * 32], sig[64], m[1] = {0};
    sq_snapshot s, hand;
    sq_accumulator acc;
    uint32_t n = 70000U, i;
    uint8_t *big_keys;
    uint64_t *big_stakes;
    memset(keys, 7, sizeof keys);
    memset(sig, 0, sizeof sig);
    /* W = 2^64 - 1 exactly: accepted as a total, and quorum arithmetic holds. */
    CHECK(sq_snapshot_init(&s, keys, wmax, 2U) == SQ_OK && s.total == UINT64_MAX);
    CHECK(sq_begin(&acc, &s, m, 1U, any_verify, keys) == SQ_OK && sq_absorb(&acc, 0U, sig) == SQ_OK);
    CHECK(sq_finish(&acc) == SQ_ERR_BELOW_QUORUM);           /* 2^63 of 2^64 - 1 */
    CHECK(sq_begin(&acc, &s, m, 1U, any_verify, keys) == SQ_OK && sq_absorb(&acc, 1U, sig) == SQ_OK);
    CHECK(sq_finish(&acc) == SQ_ERR_BELOW_QUORUM);           /* 2^63 - 1 */
    CHECK(sq_begin(&acc, &s, m, 1U, any_verify, keys) == SQ_OK && sq_absorb(&acc, 0U, sig) == SQ_OK &&
          sq_absorb(&acc, 1U, sig) == SQ_OK && sq_finish(&acc) == SQ_OK);
    /* Hand-built snapshots: each of sq_begin's defensive checks on its own. */
    hand.keys = keys; hand.stakes = one; hand.count = 1U; hand.total = 0U;
    CHECK(sq_begin(&acc, &hand, m, 1U, any_verify, keys) == SQ_ERR_SNAPSHOT);
    hand.total = 1U; hand.count = 0U;
    CHECK(sq_begin(&acc, &hand, m, 1U, any_verify, keys) == SQ_ERR_SNAPSHOT);
    hand.count = 1U; hand.stakes = NULL;
    CHECK(sq_begin(&acc, &hand, m, 1U, any_verify, keys) == SQ_ERR_SNAPSHOT);
    hand.stakes = one; hand.keys = NULL;
    CHECK(sq_begin(&acc, &hand, m, 1U, any_verify, keys) == SQ_ERR_SNAPSHOT);
    hand.keys = keys;
    CHECK(sq_begin(&acc, &hand, m, 1U, any_verify, keys) == SQ_OK && sq_absorb(&acc, 0U, sig) == SQ_OK &&
          sq_finish(&acc) == SQ_OK);
    /* More than 2^16 members: counters and the next index are full width. */
    big_keys = calloc(n, 32U);
    big_stakes = malloc(n * sizeof *big_stakes);
    CHECK(big_keys != NULL && big_stakes != NULL);
    for (i = 0; i < n; ++i) big_stakes[i] = 1U;
    CHECK(sq_snapshot_init(&s, big_keys, big_stakes, n) == SQ_OK && s.total == n);
    CHECK(sq_begin(&acc, &s, m, 1U, any_verify, big_keys) == SQ_OK);
    CHECK(sq_absorb(&acc, 65535U, sig) == SQ_OK && sq_absorb(&acc, 0U, sig) == SQ_ERR_ORDER);
    CHECK(sq_begin(&acc, &s, m, 1U, any_verify, big_keys) == SQ_OK);
    for (i = 0; i < 46667U; ++i) CHECK(sq_absorb(&acc, i * 3U / 2U, sig) == SQ_OK);
    CHECK(sq_finish(&acc) == SQ_OK && acc.signers == 46667U); /* ceil(2 * 70000 / 3) */
    CHECK(sq_begin(&acc, &s, m, 1U, any_verify, big_keys) == SQ_OK);
    for (i = 0; i < 46666U; ++i) CHECK(sq_absorb(&acc, i, sig) == SQ_OK);
    CHECK(sq_finish(&acc) == SQ_ERR_BELOW_QUORUM);
    CHECK(sq_begin(&acc, &s, m, 1U, any_verify, big_keys) == SQ_OK);
    for (i = 0; i < n; ++i) CHECK(sq_absorb(&acc, i, sig) == SQ_OK);
    CHECK(sq_finish(&acc) == SQ_OK && acc.signers == n && acc.sum == n);
    free(big_keys);
    free(big_stakes);
}

int main(void) {
    test_is_quorum();
    test_snapshot_init();
    test_begin();
    test_boundaries();
    test_order_range();
    test_signature_and_terminal();
    test_snapshot_changed();
    test_verifier_contract();
    test_exhaustive_small();
    test_randomized();
    test_real_ed25519();
    test_extremes();
    printf("PASS: test-stake-quorum (%lu checks)\n", checks);
    return 0;
}
