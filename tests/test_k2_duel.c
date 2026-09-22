/* SPDX-License-Identifier: Apache-2.0 */
#include <determ/consensus/duel_state.h>
#include <determ/crypto/sha2/sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); abort(); } } while (0)
static const uint8_t a[] = "aggregator payload";
static const uint8_t b[] = "contributor payload";
static void commit_pair(duel_state_machine_t *sm) {
    uint8_t hash[32];
    determ_sha256(a, sizeof(a), hash);
    CHECK(duel_submit_aggregator_commit(sm, hash) == DUEL_SUCCESS);
    determ_sha256(b, sizeof(b), hash);
    CHECK(duel_submit_contributor_commit(sm, hash) == DUEL_SUCCESS);
}

#include <determ/crypto/vdf.h>
#include <determ/wire/parser.h>
static duel_state_machine_t sm;
static vdf_context_t vdf;
static wire_tx_t tx;
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)wire_parse_transaction(data, size, &tx);
    return 0;
}
#ifndef LIBFUZZER_ENABLED
int main(void) {
    uint8_t output[32];
    uint8_t expected[sizeof(a) + sizeof(b) + 8];
    size_t len = 0;
    CHECK(duel_state_init(&sm) == DUEL_SUCCESS);
    CHECK(duel_state_start_commitment_phase(&sm) == DUEL_SUCCESS);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_ERR_INVALID_STATE);
    commit_pair(&sm);
    CHECK(duel_state_start_reveal_window(&sm) == DUEL_SUCCESS);
    CHECK(duel_submit_aggregator_reveal(&sm, a, sizeof(a)) == DUEL_SUCCESS);
    CHECK(duel_submit_contributor_reveal(&sm, b, sizeof(b), true) == DUEL_SUCCESS);
    CHECK(duel_submit_contributor_reveal(&sm, b, sizeof(b), true) == DUEL_ERR_ALREADY_REVEALED);
    CHECK(duel_state_poll_buzzer(&sm) == DUEL_SUCCESS);
    CHECK(sm.state == DUEL_STATE_VDF_EVALUATION);
    CHECK(wire_bundle_vdf_input(a, sizeof(a), b, sizeof(b), expected, sizeof(expected), &len) == WIRE_OK);
    CHECK(sm.vdf_input_len == len && memcmp(expected, sm.vdf_input_buffer, len) == 0);
    CHECK(vdf_init(&vdf, sm.vdf_input_buffer, sm.vdf_input_len, 2000) == 0);
    CHECK(vdf_evaluate(&vdf, output) == 0);
    CHECK(vdf_verify(&vdf, sm.vdf_input_buffer, sm.vdf_input_len, 2000, output) == 1);
    output[0] ^= 1;
    CHECK(vdf_verify(&vdf, sm.vdf_input_buffer, sm.vdf_input_len, 2000, output) == 0);
    puts("PASS: local commit/reveal and AES output re-evaluation; no consensus-security claim");
    return 0;
}
#endif
