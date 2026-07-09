/* A1 per-epoch view-key derivation — see include/determ/crypto/viewkey/viewkey.h
 * for the frozen RFC 5869 mapping, rationale, and fail-closed contract.
 * Byte-gated against the python-first oracle (tools/verify_view_key.py /
 * tools/vectors/view_key.json) by `determ test-view-key-c99`. */
#include <determ/crypto/viewkey/viewkey.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/secure_zero.h>

#include <string.h>

/* salt / domain-separation tag — must match tools/verify_view_key.py DST
 * byte-for-byte (pinned by the vector corpus). */
static const uint8_t kViewKeyDst[] = "determ-view-key-v1";
#define VIEW_KEY_DST_LEN (sizeof(kViewKeyDst) - 1)   /* no NUL on the wire */

static void put_u64_be(uint8_t out[8], uint64_t v) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

int determ_view_key_derive(const uint8_t view_master_sk[32],
                           const uint8_t *chain_id, size_t chain_id_len,
                           const uint8_t *addr,     size_t addr_len,
                           uint64_t epoch,
                           uint8_t vk_out[32]) {
    if (view_master_sk == NULL || vk_out == NULL) return -1;
    /* Fail closed: empty chain_id (cross-network replay) / empty addr
     * (ownerless key) / over-cap fields (caller bug; bounds the buffer). */
    if (chain_id == NULL || chain_id_len == 0
        || chain_id_len > DETERM_VIEW_KEY_MAX_FIELD) return -1;
    if (addr == NULL || addr_len == 0
        || addr_len > DETERM_VIEW_KEY_MAX_FIELD) return -1;

    /* info = len64_be(chain_id) || chain_id || len64_be(addr) || addr
     *     || epoch_u64_be  — byte-identical to the python oracle. */
    uint8_t info[8 + DETERM_VIEW_KEY_MAX_FIELD + 8 + DETERM_VIEW_KEY_MAX_FIELD + 8];
    size_t  off = 0;
    put_u64_be(info + off, (uint64_t)chain_id_len); off += 8;
    memcpy(info + off, chain_id, chain_id_len);     off += chain_id_len;
    put_u64_be(info + off, (uint64_t)addr_len);     off += 8;
    memcpy(info + off, addr, addr_len);             off += addr_len;
    put_u64_be(info + off, epoch);                  off += 8;

    int rc = determ_hkdf_sha256(kViewKeyDst, VIEW_KEY_DST_LEN,
                                view_master_sk, 32,
                                info, off,
                                vk_out, DETERM_VIEW_KEY_LEN);
    /* info carries no secret (chain_id/addr/epoch are public), but scrub
     * anyway — uniform hygiene with the rest of the C99 stack. */
    determ_secure_zero(info, sizeof(info));
    return rc == 0 ? 0 : -1;
}
