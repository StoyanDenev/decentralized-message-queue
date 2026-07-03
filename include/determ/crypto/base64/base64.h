/* Determ C99 Base64 (RFC 4648 §4, standard alphabet, '=' padding).
 *
 * Shipped for the §3.15/1c wallet migration: the wallet's keyfile/backup
 * envelopes base64-wrap their binary payloads, previously via OpenSSL
 * EVP_EncodeBlock/EVP_DecodeBlock — the last non-crypto OpenSSL dependency
 * in determ-wallet. Not a cryptographic primitive (no secrets, no timing
 * concern beyond hygiene): a plain, strict codec.
 *
 * Encode is total. Decode is STRICT: standard alphabet only, correct '='
 * padding, length % 4 == 0, no embedded whitespace — anything else returns
 * -1 (fail-closed; a corrupted envelope must not silently decode). This is
 * deliberately stricter than OpenSSL's EVP_DecodeBlock (which tolerates and
 * mis-reports padding); the wallet re-validates decoded payloads by AEAD
 * tag anyway, so strictness only ever rejects malformed input earlier.
 */
#ifndef DETERM_CRYPTO_BASE64_H
#define DETERM_CRYPTO_BASE64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Exact encoded length (INCLUDING '=' padding, EXCLUDING any NUL): 4*ceil(n/3). */
#define DETERM_BASE64_ENC_LEN(n) ((((n) + 2u) / 3u) * 4u)

/* Encode `in[0..inlen)` into `out` (caller provides >= DETERM_BASE64_ENC_LEN(inlen)
 * bytes; no NUL is written). Returns the number of bytes written. */
size_t determ_base64_encode(const uint8_t *in, size_t inlen, char *out);

/* Strict decode of `in[0..inlen)` into `out` (caller provides >= 3*(inlen/4)
 * bytes). Returns the decoded byte count, or -1 on malformed input (bad
 * character, bad padding, inlen % 4 != 0). inlen == 0 decodes to 0 bytes. */
long determ_base64_decode(const char *in, size_t inlen, uint8_t *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DETERM_CRYPTO_BASE64_H */
