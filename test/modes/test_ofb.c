#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include "modes/ofb.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_ofb, encrypt_success) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[16];
    hex_to_bytes("1234567890abcdef234567890abcdef1", iv, 32);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult encrypt_result = magma_encrypt_ofb(keys, iv, 16, plain_text, result, 32);
    cr_assert(encrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ofb, encrypt_success_not_multiple_block_size) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[16];
    hex_to_bytes("1234567890abcdef234567890abcdef1", iv, 32);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult encrypt_result = magma_encrypt_ofb(keys, iv, 16, plain_text, result, 31);
    cr_assert(encrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb00";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ofb, decrypt_success) {
    unsigned char cipher_text[32];
    hex_to_bytes("db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[16];
    hex_to_bytes("1234567890abcdef234567890abcdef1", iv, 32);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult decrypt_result = magma_decrypt_ofb(keys, iv, 16, cipher_text, result, 32);
    cr_assert(decrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ofb, decrypt_success_not_multiple_block_size) {
    unsigned char cipher_text[32];
    hex_to_bytes("db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[16];
    hex_to_bytes("1234567890abcdef234567890abcdef1", iv, 32);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult decrypt_result = magma_decrypt_ofb(keys, iv, 16, cipher_text, result, 31);
    cr_assert(decrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e00";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ofb, encrypt_error_null_pointer) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[16];
    hex_to_bytes("1234567890abcdef234567890abcdef1", iv, 32);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult result_code = magma_encrypt_ofb(NULL, iv, 16, plain_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_ofb(keys, NULL, 16, plain_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_ofb(keys, iv, 16, NULL, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_ofb(keys, iv, 16, plain_text, NULL, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}

Test(test_ofb, decrypt_error_null_pointer) {
    unsigned char cipher_text[32];
    hex_to_bytes("db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bd4fdb05", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[16];
    hex_to_bytes("1234567890abcdef234567890abcdef1", iv, 32);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult result_code = magma_decrypt_ofb(NULL, iv, 16, cipher_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_ofb(keys, NULL, 16, cipher_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_ofb(keys, iv, 16, NULL, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_ofb(keys, iv, 16, cipher_text, NULL, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}