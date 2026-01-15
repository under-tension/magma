#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include "modes/cbc.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_cbc, encrypt_success) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[24];
    hex_to_bytes("1234567890abcdef234567890abcdef134567890abcdef12", iv, 48);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult encrypt_result = magma_encrypt_cbc(keys, iv, 24, plain_text, result, 32);

    cr_assert(encrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_cbc, decrypt_success) {
    unsigned char cipher_text[32];
    hex_to_bytes("96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[24];
    hex_to_bytes("1234567890abcdef234567890abcdef134567890abcdef12", iv, 48);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult decrypt_result = magma_decrypt_cbc(keys, iv, 24, cipher_text, result, 32);
    cr_assert(decrypt_result == MAGMA_SUCCESS);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_cbc, encrypt_error_null_pointer) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[24];
    hex_to_bytes("1234567890abcdef234567890abcdef134567890abcdef12", iv, 48);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult result_code = magma_encrypt_cbc(NULL, iv, 24, plain_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_cbc(keys, NULL, 24, plain_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_cbc(keys, iv, 24, NULL, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_encrypt_cbc(keys, iv, 24, plain_text, NULL, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}

Test(test_cbc, decrypt_error_null_pointer) {
    unsigned char cipher_text[32];
    hex_to_bytes("96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[24];
    hex_to_bytes("1234567890abcdef234567890abcdef134567890abcdef12", iv, 48);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult result_code = magma_decrypt_cbc(NULL, iv, 24, cipher_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_cbc(keys, NULL, 24, cipher_text, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_cbc(keys, iv, 24, NULL, result, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);

    result_code = magma_decrypt_cbc(keys, iv, 24, cipher_text, NULL, 32);
    cr_assert(result_code == MAGMA_ERROR_NULL_POINTER);
}

Test(test_cbc, encrypt_error_invalid_length) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[24];
    hex_to_bytes("1234567890abcdef234567890abcdef134567890abcdef12", iv, 48);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult result_code = magma_encrypt_cbc(keys, iv, 24, plain_text, result, 31);
    cr_assert(result_code == MAGMA_ERROR_INVALID_LENGTH);
}

Test(test_cbc, decrypt_error_invalid_length) {
    unsigned char cipher_text[32];
    hex_to_bytes("96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[24];
    hex_to_bytes("1234567890abcdef234567890abcdef134567890abcdef12", iv, 48);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[32] = {0};

    MagmaResult result_code = magma_decrypt_cbc(keys, iv, 24, cipher_text, result, 31);
    cr_assert(result_code == MAGMA_ERROR_INVALID_LENGTH);
}