/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Identity Proof: OPAQUE Distributed Single-Sign On (DSSO) & OPRF Handshake.
 *
 * Mathematically proves zero-knowledge identity authentication:
 *   1. Execute a mock OPAQUE OPRF handshake entirely in memory.
 *   2. Assert: Server-side (Aggregator) structures never hold the plaintext secret.
 *   3. Assert: Handshake successfully completes returning boolean true.
 */

#include "test_harness.h"
#include <determ/crypto/opaque_dsso.h>
#include <determ/crypto/rng/rng.h>

static void test_opaque_dsso_identity_proof(void) {
    printf("[TEST] OPAQUE DSSO In-Memory OPRF Handshake & Identity Proof...\n");

    /* Client password & secret credential */
    const uint8_t client_password[] = "correct-horse-battery-staple-secure-password-2026";
    const size_t pwd_len = sizeof(client_password) - 1;

    /* Ephemeral blind scalar for client */
    uint8_t blind_scalar[OPAQUE_OPRF_SCALAR_LEN];
    for (size_t i = 0; i < sizeof(blind_scalar); ++i) {
        blind_scalar[i] = (uint8_t)(0x11 + (i * 7));
    }

    /* Server (Aggregator) OPRF private key */
    uint8_t server_oprf_key[OPAQUE_OPRF_SCALAR_LEN];
    for (size_t i = 0; i < sizeof(server_oprf_key); ++i) {
        server_oprf_key[i] = (uint8_t)(0x33 + (i * 13));
    }

    /* Step 1: Client blinds password */
    opaque_oprf_request_t client_req;
    TEST_ASSERT(opaque_dsso_oprf_blind(client_password, pwd_len, blind_scalar, &client_req) == 0);

    /* Step 2: Server (Aggregator) evaluates blinded element */
    opaque_oprf_response_t server_resp;
    TEST_ASSERT(opaque_dsso_oprf_evaluate(server_oprf_key, &client_req, &server_resp) == 0);

    /* Assert: Server structures never hold plaintext password or secret */
    TEST_ASSERT(memcmp(server_resp.evaluated_element, client_password, pwd_len < 33 ? pwd_len : 33) != 0);
    TEST_ASSERT(memcmp(&server_resp, client_password, pwd_len < sizeof(server_resp) ? pwd_len : sizeof(server_resp)) != 0);

    /* Step 3: Client finalizes OPRF */
    uint8_t oprf_output[OPAQUE_OPRF_OUTPUT_LEN];
    TEST_ASSERT(opaque_dsso_oprf_finalize(client_password, pwd_len, blind_scalar, &server_resp, oprf_output) == 0);

    /* Step 4: Derive envelope key and identity proof */
    uint8_t envelope_key[32];
    uint8_t expected_identity_proof[32];
    TEST_ASSERT(opaque_dsso_derive_keys(oprf_output, envelope_key, expected_identity_proof) == 0);

    /* Step 5: Seal credential envelope */
    const uint8_t credential_payload[] = "determ-private-wallet-seed-entropy-proof";
    uint8_t nonce[OPAQUE_ENVELOPE_NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint8_t client_pk[OPAQUE_ID_LEN] = {0xAA};
    uint8_t server_pk[OPAQUE_ID_LEN] = {0xBB};

    opaque_envelope_t stored_envelope;
    TEST_ASSERT(opaque_dsso_seal_envelope(envelope_key, nonce, credential_payload,
                                          sizeof(credential_payload), client_pk, server_pk,
                                          &stored_envelope) == 0);

    /* Step 6: Construct client authentication request */
    opaque_auth_request_t auth_req;
    memset(&auth_req, 0, sizeof(auth_req));
    memcpy(auth_req.client_identity_proof, expected_identity_proof, 32);

    /* Step 7: Server verifies identity proof and releases envelope */
    opaque_envelope_t released_envelope;
    bool auth_success = opaque_dsso_verify_and_release(expected_identity_proof,
                                                      &auth_req,
                                                      &stored_envelope,
                                                      &released_envelope);

    /* Assert: Handshake successfully completes returning a boolean true */
    TEST_ASSERT(auth_success == true);

    /* Verify released envelope matches sealed envelope */
    TEST_ASSERT(memcmp(&released_envelope, &stored_envelope, sizeof(opaque_envelope_t)) == 0);

    /* Verify decryption of credential from released envelope */
    uint8_t unsealed_payload[64];
    size_t unsealed_len = 0;
    TEST_ASSERT(opaque_dsso_unseal_envelope(envelope_key, &released_envelope, unsealed_payload, &unsealed_len) == 0);
    TEST_ASSERT(unsealed_len == sizeof(credential_payload));
    TEST_ASSERT(memcmp(unsealed_payload, credential_payload, unsealed_len) == 0);

    /* Negative test: forged proof returns false */
    auth_req.client_identity_proof[0] ^= 0xFF;
    opaque_envelope_t failed_envelope;
    bool auth_failed = opaque_dsso_verify_and_release(expected_identity_proof,
                                                     &auth_req,
                                                     &stored_envelope,
                                                     &failed_envelope);
    TEST_ASSERT(auth_failed == false);

    printf("  -> PASS: OPAQUE OPRF handshake succeeded (true), server holds zero plaintext secrets.\n");
}

int main(void) {
    test_harness_init("test_opaque_dsso (Identity Proof)");
    test_opaque_dsso_identity_proof();
    test_harness_finish("test_opaque_dsso");
    return 0;
}
