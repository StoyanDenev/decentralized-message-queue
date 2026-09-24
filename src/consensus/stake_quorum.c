/* SPDX-License-Identifier: Apache-2.0
 * Streaming stake-quorum verification. The contract, and the proof that
 * sq_finish accepts exactly the canonical certificates (FB76 Lemma Q), are in
 * the header and in docs/proofs/OneShardReceiverContract.md §2.
 */
#include "determ/consensus/stake_quorum.h"

int sq_is_quorum(uint64_t sum, uint64_t total) {
    /* Compare 3 * sum with 2 * total as 128-bit (high, low) pairs, using only
     * shifts, additions and comparisons. 3 * sum = 2 * sum + sum: the doubling
     * moves bit 63 into the high word, and the addition carries exactly when
     * the low result wraps below its first operand. */
    uint64_t sum2_low = sum << 1;
    uint64_t sum3_low = sum2_low + sum;
    uint64_t sum3_high = (sum >> 63) + (sum3_low < sum2_low ? 1U : 0U); /* SQ_CARRY */
    uint64_t total2_low = total << 1;
    uint64_t total2_high = total >> 63;
    return sum3_high > total2_high ||
           (sum3_high == total2_high && sum3_low >= total2_low); /* SQ_QUORUM_COMPARE */
}

sq_status sq_snapshot_init(sq_snapshot *snapshot, const uint8_t *keys,
                           const uint64_t *stakes, uint32_t count) {
    uint64_t total = 0U;
    uint32_t i;

    if (snapshot == NULL || keys == NULL || stakes == NULL) return SQ_ERR_ARGUMENT;
    if (count == 0U) return SQ_ERR_SNAPSHOT;
#if SIZE_MAX / SQ_KEY_BYTES < UINT32_MAX
    /* Key offsets are index * 32 in size_t. Where size_t is narrower than
     * 37 bits, refuse counts whose key array it cannot address; on a 64-bit
     * target every uint32_t count is addressable and this test is compiled
     * out. */
    if (count > SIZE_MAX / SQ_KEY_BYTES) return SQ_ERR_SNAPSHOT;
#endif
    for (i = 0U; i < count; ++i) {
        if (stakes[i] == 0U) return SQ_ERR_SNAPSHOT; /* SQ_ZERO_STAKE */
        if (stakes[i] > UINT64_MAX - total) return SQ_ERR_SNAPSHOT; /* SQ_TOTAL_OVERFLOW */
        total += stakes[i];
    }
    /* Only a validated snapshot is written, so a failure leaves it unchanged. */
    snapshot->keys = keys;
    snapshot->stakes = stakes;
    snapshot->count = count;
    snapshot->total = total;
    return SQ_OK;
}

sq_status sq_begin(sq_accumulator *acc, const sq_snapshot *snapshot,
                   const uint8_t *msg, size_t msg_len,
                   sq_verify_fn verify, void *verify_context) {
    if (acc == NULL || snapshot == NULL || verify == NULL) return SQ_ERR_ARGUMENT;
    if (msg == NULL && msg_len != 0U) return SQ_ERR_ARGUMENT;
    if (snapshot->keys == NULL) return SQ_ERR_SNAPSHOT; /* SQ_BEGIN_KEYS */
    if (snapshot->stakes == NULL) return SQ_ERR_SNAPSHOT; /* SQ_BEGIN_STAKES */
    if (snapshot->count == 0U) return SQ_ERR_SNAPSHOT; /* SQ_BEGIN_COUNT */
    if (snapshot->total == 0U) return SQ_ERR_SNAPSHOT; /* SQ_BEGIN_TOTAL */
    /* Copy the snapshot's fields, field by field (no struct copy that a
     * compiler could turn into memcpy), so later reuse of the sq_snapshot
     * object cannot change this certificate's verdict. */
    acc->keys = snapshot->keys;
    acc->stakes = snapshot->stakes;
    acc->count = snapshot->count;
    acc->total = snapshot->total;
    acc->msg = msg;
    acc->msg_len = msg_len;
    acc->verify = verify;
    acc->verify_context = verify_context;
    acc->next = 0U;
    acc->signers = 0U;
    acc->sum = 0U;
    acc->state = SQ_STATE_OPEN;
    acc->verdict = SQ_OK;
    return SQ_OK;
}

static sq_status sq_reject(sq_accumulator *acc, sq_status reason) {
    acc->state = SQ_STATE_REJECTED;
    acc->verdict = reason;
    return reason;
}

sq_status sq_absorb(sq_accumulator *acc, uint32_t index, const uint8_t *signature) {
    uint64_t stake;

    if (acc == NULL) return SQ_ERR_ARGUMENT;
    /* An entry after an accepting finish means the caller finished early. */
    if (acc->state == SQ_STATE_ACCEPTED) return sq_reject(acc, SQ_ERR_CLOSED); /* SQ_LATE_ENTRY */
    if (acc->state != SQ_STATE_OPEN) return SQ_ERR_CLOSED; /* SQ_TERMINAL */
    if (signature == NULL) return sq_reject(acc, SQ_ERR_ARGUMENT);

    /* (C1): strictly increasing indices, so no member is counted twice. */
    if (index < acc->next) return sq_reject(acc, SQ_ERR_ORDER); /* SQ_ORDER_CHECK */
    if (index >= acc->count) return sq_reject(acc, SQ_ERR_RANGE); /* SQ_RANGE_CHECK */

    /* Distinct members sum to at most the validated total, so this guard only
     * fires when the caller changed the stakes after sq_snapshot_init; it also
     * keeps the addition below from wrapping. */
    stake = acc->stakes[index];
    if (stake > acc->total - acc->sum) return sq_reject(acc, SQ_ERR_SNAPSHOT); /* SQ_SUM_GUARD */

    /* (C2): index < count, so the key offset stays inside the caller's array. */
    if (acc->verify(acc->verify_context, acc->keys + (size_t)index * SQ_KEY_BYTES,
                    acc->msg, acc->msg_len, signature) != 1)
        return sq_reject(acc, SQ_ERR_SIGNATURE); /* SQ_SIGNATURE_CHECK */

    acc->sum += stake; /* SQ_SUM_UPDATE */
    acc->next = index + 1U; /* SQ_NEXT_UPDATE: index < count <= UINT32_MAX */
    acc->signers += 1U;
    return SQ_OK;
}

sq_status sq_finish(sq_accumulator *acc) {
    if (acc == NULL) return SQ_ERR_ARGUMENT;
    if (acc->state != SQ_STATE_OPEN) return acc->verdict;
    /* (C3). */
    if (sq_is_quorum(acc->sum, acc->total)) { /* SQ_QUORUM_CHECK */
        acc->state = SQ_STATE_ACCEPTED;
        acc->verdict = SQ_OK;
        return SQ_OK;
    }
    return sq_reject(acc, SQ_ERR_BELOW_QUORUM);
}
