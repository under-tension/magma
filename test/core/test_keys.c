#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_keys, key_expand_success) {
    char *master_key = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    unsigned char master_key_hex[MASTER_KEY_LEN] = {0};
    hex_to_bytes(master_key, master_key_hex, strlen(master_key));

    unsigned char result_keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};

    MagmaResult key_result = key_expand(master_key_hex, result_keys);
    cr_assert(key_result == MAGMA_SUCCESS);

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

Test(test_keys, key_expand_error_null_pointer) {
    char *master_key = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    unsigned char master_key_hex[MASTER_KEY_LEN] = {0};
    hex_to_bytes(master_key, master_key_hex, strlen(master_key));

    unsigned char result_keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};

    MagmaResult result_code = key_expand(NULL, result_keys);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = key_expand(master_key_hex, NULL);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}