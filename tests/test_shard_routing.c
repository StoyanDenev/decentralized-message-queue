/* SPDX-License-Identifier: Apache-2.0 */
#include <determ/ledger/shard_routing.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "routing check failed at line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

int main(void) {
    const uint32_t counts[] = {1, 3, 7, 65536, UINT32_MAX};
    /* Independent fixed oracle: Python 3 hashlib.sha256(salt + b'shard-route' +
     * ('0x' + key.hex()).encode('ascii')), int.from_bytes(digest[:8], 'big') % S.
     * Rows are (zero,zero), (ramp,ramp), (ff,ff), (ramp,zero), (zero,ramp).
     * Production hashing/routing code is never used to generate expectations.
     */
    const uint32_t expected[5][5] = {
        {0, 2, 6, 15314, 2926516859U},
        {0, 0, 4, 45587, 715922670U},
        {0, 0, 2, 58009, 1711102701U},
        {0, 2, 5, 12649, 4219033016U},
        {0, 1, 4, 22563, 685901173U}
    };
    uint8_t key[33] = {0}, salt[32] = {0};
    shard_routing_config_t config, snapshot;
    uint32_t result = 123;
    for (size_t row = 0; row < 5; ++row) {
        for (size_t i = 0; i < 32; ++i) {
            salt[i] = row == 2 ? 255 : (row == 1 || row == 3 ? (uint8_t)i : 0);
            key[i] = row == 2 ? 255 : (row == 1 || row == 4 ? (uint8_t)i : 0);
        }
        for (size_t column = 0; column < 5; ++column) {
            CHECK(shard_routing_init(&config, counts[column], salt) == 0);
            memcpy(&snapshot, &config, sizeof(config));
            CHECK(shard_routing_for_pubkey(&config, key, 32, &result) == 0);
            CHECK(result == expected[row][column]);
            CHECK(result < counts[column]);
            CHECK(memcmp(&snapshot, &config, sizeof(config)) == 0);
        }
    }
    memset(&config, 0xa5, sizeof(config));
    memcpy(&snapshot, &config, sizeof(config));
    CHECK(shard_routing_init(&config, 0, salt) == -1);
    CHECK(memcmp(&snapshot, &config, sizeof(config)) == 0);
    CHECK(shard_routing_init(&config, 7, NULL) == -1);
    CHECK(memcmp(&snapshot, &config, sizeof(config)) == 0);
    CHECK(shard_routing_init(NULL, 7, salt) == -1);
    CHECK(shard_routing_init(&config, 7, salt) == 0);
    memcpy(&snapshot, &config, sizeof(config));
    memset(salt, 0xff, sizeof(salt));
    CHECK(memcmp(&snapshot, &config, sizeof(config)) == 0);
    result = 123;
    CHECK(shard_routing_for_pubkey(NULL, key, 32, &result) == -1 && result == 123);
    CHECK(shard_routing_for_pubkey(&config, NULL, 32, &result) == -1 && result == 123);
    CHECK(shard_routing_for_pubkey(&config, key, 0, &result) == -1 && result == 123);
    CHECK(shard_routing_for_pubkey(&config, key, 31, &result) == -1 && result == 123);
    CHECK(shard_routing_for_pubkey(&config, key, 33, &result) == -1 && result == 123);
    CHECK(shard_routing_for_pubkey(&config, key, 32, NULL) == -1);
    config.shard_count = 0;
    CHECK(shard_routing_for_pubkey(&config, key, 32, &result) == -1 && result == 123);
    config.shard_count = 1;
    CHECK(shard_routing_for_pubkey(&config, key, 31, &result) == -1 && result == 123);
    CHECK(shard_routing_for_pubkey(&config, key, 32, &result) == 0 && result == 0);
    puts("PASS: shard routing fixed vectors and fail-closed configuration");
    return 0;
}
