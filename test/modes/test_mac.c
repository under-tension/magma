#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include "modes/mac.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_mac, calc_additional_keys) {
    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char K1[8] = {0};
    unsigned char K2[8] = {0};

    calc_additional_keys(K1, K2, keys);

    char K1_str[16] = {0};
    bytes_to_hex(K1, K1_str, 8);

    char K2_str[16] = {0};
    bytes_to_hex(K2, K2_str, 8);

    char expected_K1[] = "5f459b3342521424";
    char expected_K2[] = "be8b366684a42848";
    
    cr_assert(memcmp(K1_str, expected_K1, 16) == 0);
    cr_assert(memcmp(K2_str, expected_K2, 16) == 0);
}

Test(test_mac, mac_success) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char mac[4] = {0};

    MagmaResult encrypt_result = magma_mac(keys, 4, plain_text, mac, 32);
    cr_assert(encrypt_result == MAGMA_SUCCESS);

    char result_str[8] = {0};
    bytes_to_hex(mac, result_str, 4);

    char expected_mac[8] = "154e7210";
    
    cr_assert(memcmp(result_str, expected_mac, 8) == 0);
}

Test(test_mac, mac_success_not_multiple_block_size) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char mac[4] = {0};

    MagmaResult encrypt_result = magma_mac(keys, 4, plain_text, mac, 31);
    cr_assert(encrypt_result == MAGMA_SUCCESS);

    char result_str[8] = {0};
    bytes_to_hex(mac, result_str, 4);

    char expected_mac[8] = "2ea68340";
    
    cr_assert(memcmp(result_str, expected_mac, 8) == 0);
}

Test(test_mac, mac_error_null_pointer) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char mac[4] = {0};

    MagmaResult result_code = magma_mac(NULL, 4, plain_text, mac, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_mac(keys, 4, NULL, mac, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_mac(keys, 4, plain_text, NULL, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}

Test(test_mac, mac_error_invalid_length) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char mac[4] = {0};

    MagmaResult result_code = magma_mac(keys, 0, plain_text, mac, 32);
    cr_assert(result_code == MAGMA_ERROR_INVALID_LENGTH);

    result_code = magma_mac(keys, 4, plain_text, mac, 0);
    cr_assert(result_code == MAGMA_ERROR_INVALID_LENGTH);
}