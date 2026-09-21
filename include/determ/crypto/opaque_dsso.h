/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 OPAQUE Distributed Single-Sign On (DSSO) Engine
 *
 * Implements the IETF OPAQUE Asymmetric Password-Authenticated Key Exchange (aPAKE)
 * with Oblivious Pseudorandom Functions (OPRF) to mathematically prevent offline
 * dictionary attacks against distributed identity verifiers.
 *
 * Guarantees:
 *   - Zero-Knowledge identity authentication without a central identity authority.
 *   - Blind evaluation: the K=2 Aggregator never unblinds or learns user passwords.
 *   - Constant-time verification to prevent timing side channels.
 *   - Zero dynamic memory allocations (pure stack/arena).
 */

#ifndef DETERMINISTIC_CRYPTO_OPAQUE_DSSO_H
#define DETERMINISTIC_CRYPTO_OPAQUE_DSSO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPAQUE_OPRF_ELEMENT_LEN     33U /* SEC1 compressed P-256 point */
#define OPAQUE_OPRF_SCALAR_LEN      32U /* P-256 scalar */
#define OPAQUE_OPRF_OUTPUT_LEN      32U /* SHA-256 output length */

#define OPAQUE_ENVELOPE_NONCE_LEN   12U /* ChaCha20 96-bit nonce */
#define OPAQUE_ENVELOPE_TAG_LEN     16U /* Poly1305 128-bit MAC tag */
#define OPAQUE_ENVELOPE_DATA_MAX    64U /* Encrypted credential capacity */
#define OPAQUE_ID_LEN               32U

#if defined(__GNUC__) || defined(__clang__)
#define OPAQUE_PACKED __attribute__((packed))
#else
#define OPAQUE_PACKED
#endif

/*
 * ── 1. The OPRF Handshake Structures ────────────────────────────────────────
 */

/* Client -> Server: Blinded password element */
typedef struct OPAQUE_PACKED {
    uint8_t blinded_element[OPAQUE_OPRF_ELEMENT_LEN];
} opaque_oprf_request_t;

/* Server -> Client: Evaluated element under server OPRF key */
typedef struct OPAQUE_PACKED {
    uint8_t evaluated_element[OPAQUE_OPRF_ELEMENT_LEN];
} opaque_oprf_response_t;

/*
 * ── 2. The OPAQUE Encrypted Envelope Struct ─────────────────────────────────
 * Contains the client's encrypted private credentials / wallet seed.
 * Sealed with ChaCha20-Poly1305 under an envelope key derived from the OPRF output.
 */
typedef struct OPAQUE_PACKED {
    uint8_t  nonce[OPAQUE_ENVELOPE_NONCE_LEN];
    uint8_t  ciphertext[OPAQUE_ENVELOPE_DATA_MAX];
    uint32_t ciphertext_len;
    uint8_t  tag[OPAQUE_ENVELOPE_TAG_LEN];
    uint8_t  client_public_key[OPAQUE_ID_LEN];
    uint8_t  server_public_key[OPAQUE_ID_LEN];
} opaque_envelope_t;

/*
 * ── 3. Client AKE Authorization Request ─────────────────────────────────────
 */
typedef struct OPAQUE_PACKED {
    uint8_t account_id[OPAQUE_ID_LEN];
    uint8_t client_identity_proof[32]; /* Client AKE MAC proof */
} opaque_auth_request_t;

/*
 * ── 4. OPRF Handshake API ───────────────────────────────────────────────────
 */

/*
 * Client side: Blind password using random blind scalar.
 * Produces blinded_element = blind * HashToGroup(pwd).
 * Returns 0 on success, -1 on invalid input.
 */
int opaque_dsso_oprf_blind(const uint8_t *pwd, size_t pwd_len,
                           const uint8_t blind_scalar[OPAQUE_OPRF_SCALAR_LEN],
                           opaque_oprf_request_t *out_req);

/*
 * Server / Aggregator side: Blind evaluation.
 * Evaluates evaluated_element = oprf_key * blinded_element.
 * The Aggregator never unblinds or learns the password or blind scalar.
 * Returns 0 on success, -1 on error.
 */
int opaque_dsso_oprf_evaluate(const uint8_t oprf_key[OPAQUE_OPRF_SCALAR_LEN],
                              const opaque_oprf_request_t *req,
                              opaque_oprf_response_t *out_resp);

/*
 * Client side: Finalize OPRF.
 * Inverts the blind scalar and produces the unblinded pseudorandom output:
 * oprf_output = Hash(pwd, blind^-1 * evaluated_element).
 * Returns 0 on success, -1 on error.
 */
int opaque_dsso_oprf_finalize(const uint8_t *pwd, size_t pwd_len,
                              const uint8_t blind_scalar[OPAQUE_OPRF_SCALAR_LEN],
                              const opaque_oprf_response_t *resp,
                              uint8_t out_oprf_output[OPAQUE_OPRF_OUTPUT_LEN]);

/*
 * ── 5. Key Derivation & Credential Envelope API ─────────────────────────────
 */

/*
 * Derive the envelope encryption key and the identity proof key from OPRF output.
 */
int opaque_dsso_derive_keys(const uint8_t oprf_output[OPAQUE_OPRF_OUTPUT_LEN],
                            uint8_t out_envelope_key[32],
                            uint8_t out_identity_proof[32]);

/*
 * Seal user private credentials into the OPAQUE encrypted envelope using ChaCha20-Poly1305.
 * AAD is bound to client_public_key || server_public_key.
 * Returns 0 on success, -1 on error.
 */
int opaque_dsso_seal_envelope(const uint8_t envelope_key[32],
                              const uint8_t nonce[OPAQUE_ENVELOPE_NONCE_LEN],
                              const uint8_t *payload, size_t payload_len,
                              const uint8_t client_pk[OPAQUE_ID_LEN],
                              const uint8_t server_pk[OPAQUE_ID_LEN],
                              opaque_envelope_t *out_envelope);

/*
 * Unseal user private credentials from the OPAQUE encrypted envelope.
 * Returns 0 on success (authenticated), -1 on forgery / decryption failure.
 */
int opaque_dsso_unseal_envelope(const uint8_t envelope_key[32],
                                const opaque_envelope_t *envelope,
                                uint8_t *out_payload,
                                size_t *out_payload_len);

/*
 * ── 6. Zero-Knowledge Authorization ─────────────────────────────────────────
 */

/*
 * Multi-Party Zero-Knowledge Identity Verification:
 * Verifies the client's identity proof against the expected proof in constant time.
 * Returns true (1) and releases the stored encrypted envelope into out_released_envelope
 * ONLY IF the cryptographic identity proof matches perfectly.
 * If authentication fails, out_released_envelope is securely zeroed and returns false (0).
 */
bool opaque_dsso_verify_and_release(const uint8_t expected_identity_proof[32],
                                    const opaque_auth_request_t *auth_req,
                                    const opaque_envelope_t *stored_envelope,
                                    opaque_envelope_t *out_released_envelope);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_CRYPTO_OPAQUE_DSSO_H */
