#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_keys, gen_keys_from_master_key) {
    char *master_key = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    unsigned char master_key_hex[MASTER_KEY_LEN];
    memset(master_key_hex, 0, MASTER_KEY_LEN);
    hex_to_bytes(master_key, master_key_hex, strlen(master_key));

    unsigned char result_keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    memset(result_keys, 0, ITER_KEYS_COUNT * ITER_KEY_LEN);

    get_keys_from_master_key(master_key_hex, result_keys);

    char expected_keys[ITER_KEYS_COUNT][8] = {
        "ffeeddcc",
        "bbaa9988",
        "77665544",
        "33221100",
        "f0f1f2f3",
        "f4f5f6f7",
        "f8f9fafb",
        "fcfdfeff",
        "ffeeddcc",
        "bbaa9988",
        "77665544",
        "33221100",
        "f0f1f2f3",
        "f4f5f6f7",
        "f8f9fafb",
        "fcfdfeff",
        "ffeeddcc",
        "bbaa9988",
        "77665544",
        "33221100",
        "f0f1f2f3",
        "f4f5f6f7",
        "f8f9fafb",
        "fcfdfeff",
        "fcfdfeff",
        "f8f9fafb",
        "f4f5f6f7",
        "f0f1f2f3",
        "33221100",
        "77665544",
        "bbaa9988",
        "ffeeddc"
    };

    for (int i = 0; i < ITER_KEYS_COUNT; i++) {
        char iter_key[8];
        bytes_to_hex(result_keys[i], iter_key, 8);

        cr_assert(strcmp(iter_key, expected_keys[i]));
    }
}
