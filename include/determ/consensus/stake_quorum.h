/* SPDX-License-Identifier: Apache-2.0
 * Streaming stake-quorum verification (ADR-004 §9.7; FB76 Lemma Q).
 *
 * Decides whether a certificate, a list of (member index, signature) entries
 * over one statement, is canonical for an eligibility snapshot:
 *   (C1) the indices strictly increase and stay below the member count;
 *   (C2) every signature verifies for its member's key over the statement;
 *   (C3) the signers hold at least two thirds of the snapshot's stake,
 *        3 * sum >= 2 * total, compared exactly in 128 bits.
 * Entries are absorbed one at a time with O(1) state; the list is never
 * buffered, so a certificate can be streamed from storage or the network.
 * It serves H3's failure certificates under either carriage rule, and H12's
 * checkpoint links if their encoding is a plain-signature list; either way
 * only if the encoding presents entries in snapshot-index order (ADR-004 §9.7).
 *
 * Freestanding C99: only <stddef.h> and <stdint.h>, no library call, no
 * allocation and no global state. The source has no 64-bit division or
 * multiplication (the size_t key offset is a shift by 5), yet a compiler may
 * still call a helper: Clang 18 turns sq_is_quorum's shift-and-add into a
 * 64-bit multiply that calls __aeabi_lmul on ARMv6-M and ARMv8-M Baseline.
 * The build's nm audit (C99-MINIX-PORT §13.1) decides each target profile.
 *
 * What this module does NOT decide is the caller's obligation (ADR-004 §9.5,
 * §9.7): the canonical statement bytes (D5), which snapshot weights the
 * certificate and its member order (D6), that no snapshot key is a
 * small-order point, which Ed25519 verification variant every receiver uses
 * (the callback), and that sq_finish is called only after the last entry of
 * the certificate's framing (FB76 §2).
 *
 * Ownership: the key and stake arrays are borrowed. They must stay alive and
 * unchanged from sq_snapshot_init until the last sq_finish of a certificate
 * that uses them. sq_begin copies the sq_snapshot fields, so the sq_snapshot
 * object itself may be reused afterwards. The statement bytes are borrowed
 * from sq_begin until sq_finish. Every signature pointer names 64 bytes. All
 * inputs are public; nothing here needs constant-time treatment.
 */
#ifndef DETERM_CONSENSUS_STAKE_QUORUM_H
#define DETERM_CONSENSUS_STAKE_QUORUM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SQ_KEY_BYTES 32U
#define SQ_SIGNATURE_BYTES 64U

/* Must return exactly 1 when `signature` is valid for `key` over
 * msg[0..msg_len), and any other value otherwise. It must be deterministic and
 * must not keep the pointers after it returns. */
typedef int (*sq_verify_fn)(void *context, const uint8_t *key,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *signature);

typedef enum {
    SQ_OK = 0,
    SQ_ERR_ARGUMENT,     /* a NULL pointer where a value is required */
    SQ_ERR_SNAPSHOT,     /* empty snapshot, zero stake, overflowing total, too
                            many members to address, or a snapshot whose
                            stakes changed after sq_snapshot_init */
    SQ_ERR_ORDER,        /* index not above the previous one: duplicate or unsorted */
    SQ_ERR_RANGE,        /* index not below the member count */
    SQ_ERR_SIGNATURE,    /* the verifier rejected the entry */
    SQ_ERR_BELOW_QUORUM, /* the signers hold less than two thirds of the stake */
    SQ_ERR_CLOSED        /* the certificate already has a verdict */
} sq_status;

/* Member i's key is keys[i * SQ_KEY_BYTES .. +32) and its stake stakes[i]. */
typedef struct {
    const uint8_t *keys;
    const uint64_t *stakes;
    uint32_t count;      /* N >= 1 */
    uint64_t total;      /* W = sum of stakes, computed by sq_snapshot_init */
} sq_snapshot;

enum { SQ_STATE_OPEN = 0, SQ_STATE_ACCEPTED = 1, SQ_STATE_REJECTED = 2 };

typedef struct {
    const uint8_t *keys;     /* copied from the snapshot at sq_begin */
    const uint64_t *stakes;
    uint32_t count;
    uint64_t total;
    const uint8_t *msg;
    size_t msg_len;
    sq_verify_fn verify;
    void *verify_context;
    uint32_t next;       /* smallest index the next entry may use */
    uint32_t signers;    /* entries accepted so far, for the caller's accounting */
    uint64_t sum;        /* stake of those signers */
    int state;           /* SQ_STATE_* */
    sq_status verdict;   /* SQ_OK once accepted; the reason once rejected */
} sq_accumulator;

/* 1 when 3 * sum >= 2 * total, else 0: exact for all 64-bit inputs. */
int sq_is_quorum(uint64_t sum, uint64_t total);

/* Validate stakes[0..count): count >= 1, count * SQ_KEY_BYTES addressable,
 * every stake >= 1 and the total below 2^64. Record the total. On failure
 * *snapshot is left unchanged. */
sq_status sq_snapshot_init(sq_snapshot *snapshot, const uint8_t *keys,
                           const uint64_t *stakes, uint32_t count);

/* Start one certificate over msg[0..msg_len); msg may be NULL only when
 * msg_len is 0. The snapshot must be one that sq_snapshot_init accepted, or
 * a copy of its fields: sq_begin checks only that its fields are set, and
 * trusts its count and total. On failure *acc is left unchanged. */
sq_status sq_begin(sq_accumulator *acc, const sq_snapshot *snapshot,
                   const uint8_t *msg, size_t msg_len,
                   sq_verify_fn verify, void *verify_context);

/* Absorb one entry. SQ_OK means it was accepted. Any other result is final:
 * a rejected certificate keeps its first reason, and an entry offered after
 * an accepting sq_finish turns the verdict into SQ_ERR_CLOSED. A caller that
 * finished early is thus told so if it offers a further entry, but not if it
 * stops reading, so sq_finish must follow the last framed entry. Order and
 * range are checked before the signature, so an out-of-order or out-of-range
 * entry costs no verification. */
sq_status sq_absorb(sq_accumulator *acc, uint32_t index, const uint8_t *signature);

/* Close the certificate: SQ_OK exactly when every absorbed entry was accepted
 * and 3 * sum >= 2 * total. Later calls return the stored verdict. */
sq_status sq_finish(sq_accumulator *acc);

#ifdef __cplusplus
}
#endif

#endif
