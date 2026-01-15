#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include "modes/ctr.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_ctr, encrypt_success) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[4];
    hex_to_bytes("12345678", iv, 8);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult encrypt_result = magma_encrypt_ctr(keys, iv, plain_text, result, 32);
    cr_assert(encrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ctr, encrypt_success_not_multiple_block_size) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[4];
    hex_to_bytes("12345678", iv, 8);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult encrypt_result = magma_encrypt_ctr(keys, iv, plain_text, result, 31);
    cr_assert(encrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a100";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ctr, decrypt_success) {
    
    unsigned char cipher_text[32];
    hex_to_bytes("4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[4];
    hex_to_bytes("12345678", iv, 8);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult decrypt_result = magma_decrypt_ctr(keys, iv, cipher_text, result, 32);
    cr_assert(decrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ctr, decrypt_success_not_multiple_block_size) {
    
    unsigned char cipher_text[32];
    hex_to_bytes("4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[4];
    hex_to_bytes("12345678", iv, 8);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult decrypt_result = magma_decrypt_ctr(keys, iv, cipher_text, result, 31);
    cr_assert(decrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e00";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ctr, encrypt_error_null_pointer) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[4];
    hex_to_bytes("12345678", iv, 8);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult result_code = magma_encrypt_ctr(NULL, iv, plain_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_ctr(keys, NULL, plain_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_ctr(keys, iv, NULL, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_ctr(keys, iv, plain_text, NULL, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}

Test(test_ctr, decrypt_error_null_pointer) {
    
    unsigned char cipher_text[32];
    hex_to_bytes("4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[4];
    hex_to_bytes("12345678", iv, 8);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult result_code = magma_decrypt_ctr(NULL, iv, cipher_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_ctr(keys, NULL, cipher_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_ctr(keys, iv, NULL, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_ctr(keys, iv, cipher_text, NULL, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}

