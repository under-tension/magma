#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include "modes/ecb.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_ecb, encrypt_success) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);    

    unsigned char result[32] = {0};

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    MagmaResult encrypt_result = magma_encrypt_ecb(keys, plain_text, result, 32);
    cr_assert(encrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ecb, decrypt_success) {
    
    unsigned char plain_text[32];
    hex_to_bytes("2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);    

    unsigned char result[32] = {0};

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    MagmaResult decrypt_result = magma_decrypt_ecb(keys, plain_text, result, 32);
    cr_assert(decrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ecb, encrypt_error_null_pointer) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);    

    unsigned char result[32] = {0};

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    MagmaResult result_code = magma_encrypt_ecb(NULL, plain_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_ecb(keys, NULL, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_ecb(keys, plain_text, NULL, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}

Test(test_ecb, decrypt_error_null_pointer) {
    
    unsigned char plain_text[32];
    hex_to_bytes("2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);    

    unsigned char result[32] = {0};

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    MagmaResult result_code = magma_decrypt_ecb(NULL, plain_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_ecb(keys, NULL, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_ecb(keys, plain_text, NULL, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}

Test(test_ecb, encrypt_error_invalid_length) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);    

    unsigned char result[32] = {0};

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    MagmaResult result_code = magma_encrypt_ecb(keys, plain_text, result, 33);
    cr_assert(result_code == MAGMA_ERROR_INVALID_LENGTH);

    result_code = magma_encrypt_ecb(keys, plain_text, result, 0);
    cr_assert(result_code == MAGMA_ERROR_INVALID_LENGTH);
}

Test(test_ecb, decrypt_error_invalid_length) {
    
    unsigned char plain_text[32];
    hex_to_bytes("2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);    

    unsigned char result[32] = {0};

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    MagmaResult result_code = magma_decrypt_ecb(keys, plain_text, result, 33);
    cr_assert(result_code == MAGMA_ERROR_INVALID_LENGTH);

    result_code = magma_decrypt_ecb(keys, plain_text, result, 0);
    cr_assert(result_code == MAGMA_ERROR_INVALID_LENGTH);
}