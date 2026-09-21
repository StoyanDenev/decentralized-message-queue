/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Bare-Metal C99 OPAQUE Distributed Single-Sign On (DSSO) Implementation
 */

#include <determ/crypto/opaque_dsso.h>
#include <determ/crypto/p256/p256.h>
#include <determ/crypto/chacha20/chacha20.h>
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/ct.h>
#include <determ/crypto/secure_zero.h>
#include <string.h>

int opaque_dsso_oprf_blind(const uint8_t *pwd, size_t pwd_len,
                           const uint8_t blind_scalar[OPAQUE_OPRF_SCALAR_LEN],
                           opaque_oprf_request_t *out_req) {
    if (!pwd || !blind_scalar || !out_req) {
        return -1;
    }
    return determ_p256_oprf_blind(out_req->blinded_element, pwd, pwd_len, blind_scalar, 0x00);
}

int opaque_dsso_oprf_evaluate(const uint8_t oprf_key[OPAQUE_OPRF_SCALAR_LEN],
                              const opaque_oprf_request_t *req,
                              opaque_oprf_response_t *out_resp) {
    if (!oprf_key || !req || !out_resp) {
        return -1;
    }
    return determ_p256_oprf_evaluate(out_resp->evaluated_element, oprf_key, req->blinded_element);
}

int opaque_dsso_oprf_finalize(const uint8_t *pwd, size_t pwd_len,
                              const uint8_t blind_scalar[OPAQUE_OPRF_SCALAR_LEN],
                              const opaque_oprf_response_t *resp,
                              uint8_t out_oprf_output[OPAQUE_OPRF_OUTPUT_LEN]) {
    if (!pwd || !blind_scalar || !resp || !out_oprf_output) {
        return -1;
    }
    return determ_p256_oprf_finalize(out_oprf_output, pwd, pwd_len, blind_scalar, resp->evaluated_element);
}

int opaque_dsso_derive_keys(const uint8_t oprf_output[OPAQUE_OPRF_OUTPUT_LEN],
                            uint8_t out_envelope_key[32],
                            uint8_t out_identity_proof[32]) {
    if (!oprf_output || !out_envelope_key || !out_identity_proof) {
        return -1;
    }

    static const char env_tag[] = "DTM-OPAQUE-ENVELOPE-KEY-v1";
    static const char auth_tag[] = "DTM-OPAQUE-IDENTITY-PROOF-v1";

    determ_hmac_sha256(oprf_output, OPAQUE_OPRF_OUTPUT_LEN,
                       (const uint8_t *)env_tag, strlen(env_tag),
                       out_envelope_key);

    determ_hmac_sha256(oprf_output, OPAQUE_OPRF_OUTPUT_LEN,
                       (const uint8_t *)auth_tag, strlen(auth_tag),
                       out_identity_proof);

    return 0;
}

int opaque_dsso_seal_envelope(const uint8_t envelope_key[32],
                              const uint8_t nonce[OPAQUE_ENVELOPE_NONCE_LEN],
                              const uint8_t *payload, size_t payload_len,
                              const uint8_t client_pk[OPAQUE_ID_LEN],
                              const uint8_t server_pk[OPAQUE_ID_LEN],
                              opaque_envelope_t *out_envelope) {
    if (!envelope_key || !nonce || !payload || !client_pk || !server_pk || !out_envelope) {
        return -1;
    }
    if (payload_len == 0 || payload_len > OPAQUE_ENVELOPE_DATA_MAX) {
        return -1;
    }

    memset(out_envelope, 0, sizeof(*out_envelope));
    memcpy(out_envelope->nonce, nonce, OPAQUE_ENVELOPE_NONCE_LEN);
    memcpy(out_envelope->client_public_key, client_pk, OPAQUE_ID_LEN);
    memcpy(out_envelope->server_public_key, server_pk, OPAQUE_ID_LEN);
    out_envelope->ciphertext_len = (uint32_t)payload_len;

    /* AAD commits directly to client_public_key || server_public_key */
    uint8_t aad[64];
    memcpy(aad, client_pk, 32);
    memcpy(aad + 32, server_pk, 32);

    int rc = determ_chacha20_poly1305_encrypt(envelope_key, nonce,
                                              aad, sizeof(aad),
                                              payload, payload_len,
                                              out_envelope->ciphertext,
                                              out_envelope->tag);
    determ_secure_zero(aad, sizeof(aad));
    return rc;
}

int opaque_dsso_unseal_envelope(const uint8_t envelope_key[32],
                                const opaque_envelope_t *envelope,
                                uint8_t *out_payload,
                                size_t *out_payload_len) {
    if (!envelope_key || !envelope || !out_payload || !out_payload_len) {
        return -1;
    }
    if (envelope->ciphertext_len == 0 || envelope->ciphertext_len > OPAQUE_ENVELOPE_DATA_MAX) {
        return -1;
    }

    uint8_t aad[64];
    memcpy(aad, envelope->client_public_key, 32);
    memcpy(aad + 32, envelope->server_public_key, 32);

    int rc = determ_chacha20_poly1305_decrypt(envelope_key, envelope->nonce,
                                              aad, sizeof(aad),
                                              envelope->ciphertext,
                                              envelope->ciphertext_len,
                                              envelope->tag,
                                              out_payload);
    determ_secure_zero(aad, sizeof(aad));
    if (rc == 0) {
        *out_payload_len = envelope->ciphertext_len;
    } else {
        *out_payload_len = 0;
        determ_secure_zero(out_payload, OPAQUE_ENVELOPE_DATA_MAX);
    }
    return rc;
}

bool opaque_dsso_verify_and_release(const uint8_t expected_identity_proof[32],
                                    const opaque_auth_request_t *auth_req,
                                    const opaque_envelope_t *stored_envelope,
                                    opaque_envelope_t *out_released_envelope) {
    if (!expected_identity_proof || !auth_req || !stored_envelope || !out_released_envelope) {
        if (out_released_envelope) {
            determ_secure_zero(out_released_envelope, sizeof(*out_released_envelope));
        }
        return false;
    }

    /* Constant-time verification of AKE identity proof */
    if (determ_ct_memcmp(expected_identity_proof, auth_req->client_identity_proof, 32) != 0) {
        determ_secure_zero(out_released_envelope, sizeof(*out_released_envelope));
        return false;
    }

    /* Authentication succeeded: release encrypted envelope */
    memcpy(out_released_envelope, stored_envelope, sizeof(opaque_envelope_t));
    return true;
}
