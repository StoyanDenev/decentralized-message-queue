/* dsso_jose — the bounded external-format readers DSSO's wallet-relying-party
 * surface is built on: base64url, JSON, and the JOSE framing of an ES256
 * signature.
 *
 * THIS FILE IS THE ATTACK SURFACE OF THE WHOLE SERVICE. Everything a hostile
 * wallet can reach passes through these three readers before any signature has
 * been checked, so they are written to be fuzzed: every loop is bounded by a
 * compile-time cap from dsso.h, recursion depth is capped at
 * DSSO_JSON_MAX_DEPTH (so the C stack footprint is a constant, not a function
 * of input), no reader allocates, and a reader that fails leaves its outputs
 * untouched and returns a negative dsso_status.
 *
 * STRICTNESS IS A SECURITY PROPERTY HERE, not fastidiousness. Two presentations
 * that differ in bytes but are "equivalent" under a lenient reader are exactly
 * how a signature ends up covering different bytes than the ones acted on. So:
 *   - base64url has ONE encoding of a given byte string. Padding is rejected,
 *     the standard-alphabet '+' and '/' are rejected, whitespace is rejected,
 *     and the unused low bits of a final partial group MUST be zero (a
 *     non-canonical tail such as "QR" for the byte "QQ" decodes to the same
 *     byte under a lenient decoder and is rejected here).
 *   - JSON duplicate member names are rejected outright rather than resolved
 *     first-wins or last-wins, because the choice of rule is precisely what
 *     lets a signer and a verifier read two different documents out of one
 *     byte string.
 *   - a document with trailing data after the top-level value is rejected.
 *
 * The readers are deliberately SEPARATE from the PID logic in dsso_pid.*: the
 * parser can be fuzzed on its own, and the PID rules can be read without the
 * encoding details. */
#ifndef DETERM_DSSO_JOSE_H
#define DETERM_DSSO_JOSE_H

#include "dsso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── base64url (RFC 4648 §5, unpadded — the JOSE profile of RFC 7515 §2) ─────
 * Decodes `in` into `out` (capacity `cap`). On success writes the byte count to
 * *outlen and returns DSSO_OK. Returns DSSO_E_FORMAT for: any character outside
 * A-Za-z0-9-_ (so '=', '+', '/', whitespace and NUL all fail), a length ≡ 1 mod
 * 4 (no such encoding exists), or a non-canonical final group whose unused low
 * bits are set. Returns DSSO_E_ARG when the output would exceed `cap`, or on a
 * NULL argument. `out` is untouched on every failure. An empty input decodes to
 * zero bytes and succeeds. */
int dsso_b64url_decode(dsso_slice in, uint8_t *out, size_t cap, size_t *outlen);

/* ── bounded JSON reader (RFC 8259 subset, strict) ──────────────────────────*/
typedef enum {
    DSSO_JSON_NULL = 0,
    DSSO_JSON_BOOL,
    DSSO_JSON_NUMBER,
    DSSO_JSON_STRING,
    DSSO_JSON_ARRAY,
    DSSO_JSON_OBJECT
} dsso_json_type;

/* Validate a complete JSON document: one top-level value, no trailing data
 * (whitespace excepted), nesting ≤ DSSO_JSON_MAX_DEPTH, ≤ DSSO_JSON_MAX_ELEMS
 * members/elements per container, ≤ DSSO_JSON_MAX_KEYS member names in the
 * whole document, NO duplicate member name within one object, well-formed
 * string escapes (including surrogate pairs) and no raw control character below
 * 0x20 inside a string, RFC 8259 numbers only (no leading '+', no leading zero,
 * no bare '.', no NaN/Infinity/hex). On success *root is the top-level value's
 * span and *type its type. Returns DSSO_E_FORMAT on any violation.
 *
 * Every accessor below REQUIRES a span that came from a document this function
 * accepted (directly, or via another accessor). That contract is what lets the
 * accessors stay small; they are nevertheless individually bounded, so a misuse
 * is a wrong answer, never a memory error. */
int dsso_json_validate(dsso_slice doc, dsso_slice *root, dsso_json_type *type);

/* Member lookup on an OBJECT span. `key` is a NUL-terminated ASCII literal and
 * is compared against the member name AFTER unescaping, so a name written with
 * backslash-u escapes matches the same name written plainly. A lookup that
 * compared raw bytes would disagree with the duplicate-key detector, and the
 * gap between the two is where a hidden second `aud` lives. Returns DSSO_OK and
 * fills the value span and its type, or DSSO_E_FORMAT when the member is absent
 * or `obj` is not an object. */
int dsso_json_member(dsso_slice obj, const char *key,
                     dsso_slice *out, dsso_json_type *type);

/* Element count / indexed element of an ARRAY span. */
int dsso_json_array_len(dsso_slice arr, size_t *n);
int dsso_json_element(dsso_slice arr, size_t idx,
                      dsso_slice *out, dsso_json_type *type);

/* Unescape a STRING span (which includes its quotes) into `out`. UTF-16 escape
 * pairs are decoded to UTF-8; an unpaired surrogate is DSSO_E_FORMAT. Returns
 * DSSO_E_ARG if the result would exceed `cap`. */
int dsso_json_string(dsso_slice str, uint8_t *out, size_t cap, size_t *outlen);

/* 1 iff a STRING span unescapes to exactly the NUL-terminated ASCII `lit`.
 * Constant-time in neither operand — both are public-format material — but it
 * never reads outside the span. */
int dsso_json_string_equals(dsso_slice str, const char *lit);

/* A NUMBER span that is an INTEGER in int64 range. A fraction or exponent is
 * DSSO_E_FORMAT: every number DSSO reads is a POSIX timestamp or a status-list
 * index, and "1e309" or "3.0" as a timestamp is an ambiguity this service has
 * no reason to carry. */
int dsso_json_int(dsso_slice num, int64_t *out);

/* ── JOSE ───────────────────────────────────────────────────────────────────*/
/* Split a compact-serialization JWT `h.p.s` into its three base64url spans plus
 * the SIGNING INPUT — the exact bytes `h.p`, taken from the wire rather than
 * re-encoded. Re-encoding is the classic way a verifier ends up checking a
 * signature over bytes that are not the ones it parsed. Exactly two '.' are
 * required; an empty header or payload segment is DSSO_E_FORMAT. */
int dsso_jwt_split(dsso_slice jwt, dsso_slice *hdr_b64, dsso_slice *pl_b64,
                   dsso_slice *sig_b64, dsso_slice *signing_input);

/* ES256 (RFC 7515 §3.4): ECDSA on P-256 with SHA-256, signature = R || S, each
 * a 32-byte big-endian scalar.
 *
 * Accepts only a 64-byte signature whose r and s are both in [1, n-1]; a short,
 * long, zero or ≥ n scalar is DSSO_E_FORMAT. A verification that does not hold
 * is DSSO_E_CRYPTO. `pk65` is SEC1 uncompressed and is re-validated on the
 * curve here, so a caller cannot smuggle an off-curve point past the check.
 *
 * MALLEABILITY, STATED PLAINLY. ECDSA is signature-malleable by construction:
 * if (r, s) verifies then so does (r, n − s), and RFC 7515 does not mandate the
 * low-S form, so REJECTING high-S would reject conforming wallets. This verifier
 * therefore accepts both, and the property DSSO needs instead is that nothing
 * downstream is keyed on signature bytes: the replay key is the DSSO-issued
 * nonce (single-use), the holder binding is the KB-JWT's sd_hash over the
 * presented credential and disclosures, and the account pseudonym is derived
 * from the subject material — never from a signature. A malleated re-presentation
 * therefore buys an attacker a second byte string and no second acceptance.
 *
 * There is no ECDSA verifier in determ::c99 to call; this one is composed from
 * the shipped P-256 primitives (scalar inverse and multiply mod n, and the
 * constant-time two-term multi-scalar multiplication), so the increment adds no
 * dependency and no new hardness assumption. */
int dsso_es256_verify(const uint8_t pk65[65], dsso_slice msg,
                      const uint8_t sig[64]);

/* Decode a JWK `{"kty":"EC","crv":"P-256","x":…,"y":…}` object span into a SEC1
 * uncompressed point, rejecting any other kty/crv, a coordinate that is not
 * exactly 32 bytes of canonical base64url, and a point not on the curve. */
int dsso_jwk_p256(dsso_slice jwk, uint8_t out65[65]);

/* ── bounded DEFLATE (RFC 1950 zlib wrapper over RFC 1951) ──────────────────
 * The Token Status List bitstring is zlib-compressed, so a relying party has to
 * inflate attacker-influenced bytes. This is a from-scratch, allocation-free
 * inflate with a hard output ceiling: it writes at most `cap` bytes and returns
 * DSSO_E_FORMAT the moment a stream would exceed it, so a compression bomb
 * costs O(cap) and nothing more. Stored, fixed-Huffman and dynamic-Huffman
 * blocks are all supported; a truncated stream, a bad zlib header, a preset
 * dictionary, an invalid code length set, a distance past the start of the
 * output, or trailing data after the final block are each DSSO_E_FORMAT. The
 * Adler-32 trailer is verified. */
int dsso_inflate(dsso_slice in, uint8_t *out, size_t cap, size_t *outlen);

#ifdef __cplusplus
}
#endif

#endif /* DETERM_DSSO_JOSE_H */
