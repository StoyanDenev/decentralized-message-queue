/* A1 per-epoch view-key derivation (pre-launch register A1, ratified
 * 2026-07-09: Option C) — CRYPTO-C99-SPEC §3.24.
 *
 *   vk_epoch_n = HKDF-SHA256(salt = "determ-view-key-v1",
 *                            IKM  = view_master_sk (32 bytes),
 *                            info = len64_be(chain_id) || chain_id
 *                                || len64_be(addr)     || addr
 *                                || epoch_u64_be,
 *                            L    = 32)
 *
 * The exact RFC 5869 mapping was frozen python-first (tools/verify_view_key.py
 * + tools/vectors/view_key.json — the independent oracle this implementation
 * is byte-gated against by `determ test-view-key-c99`). The length-prefixed
 * big-endian info encoding is byte-identical to the unshield_spend_ctx_hash
 * convention (include/determ/chain/shielded.hpp): the prefix kills
 * concatenation ambiguity, so distinct (chain_id, addr) pairs can never alias.
 *
 * FAIL-CLOSED edges (return -1, output untouched): empty chain_id (a
 * chain-less key would be replayable across networks), empty addr (an
 * ownerless key any integration bug could silently fall into), and
 * chain_id/addr longer than DETERM_VIEW_KEY_MAX_FIELD (wire addresses are
 * <= 66 chars; chain ids are short — the cap bounds the stack buffer and a
 * pathological input is a caller bug, not a use case).
 *
 * PERMANENCE: this formula is permanent once accounts exist (no-migrations).
 * Any change is a "-v2" DST, never an in-place edit. */
#ifndef DETERM_CRYPTO_VIEWKEY_H
#define DETERM_CRYPTO_VIEWKEY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DETERM_VIEW_KEY_LEN        32
#define DETERM_VIEW_KEY_MAX_FIELD  256

/* Derive vk_epoch for (view_master_sk, chain_id, addr, epoch).
 * Returns 0 on success, -1 on any fail-closed edge (see header comment). */
int determ_view_key_derive(const uint8_t view_master_sk[32],
                           const uint8_t *chain_id, size_t chain_id_len,
                           const uint8_t *addr,     size_t addr_len,
                           uint64_t epoch,
                           uint8_t vk_out[32]);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_CRYPTO_VIEWKEY_H */
