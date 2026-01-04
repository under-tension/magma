#include <stdint.h>
#include "core/crypt.h"
#include "core/utils.h"
#include <criterion/criterion.h>
#include <string.h>

Test(crypt, trans) {
    char expected_result[TRANSPOSITION_BLOCK_SIZE * 2] = "2a196f34";

    unsigned char input[TRANSPOSITION_BLOCK_SIZE];
    hex_to_bytes("fdb97531", input, TRANSPOSITION_BLOCK_SIZE*2);

    unsigned char result[TRANSPOSITION_BLOCK_SIZE];
    memset(result, 0, TRANSPOSITION_BLOCK_SIZE);

    uint32_t iter_trans = T(bytes_to_uint32_be(input));
    uint32_to_bytes_be(iter_trans, result);

    char result_str[TRANSPOSITION_BLOCK_SIZE*2];
    bytes_to_hex(result, result_str, TRANSPOSITION_BLOCK_SIZE);

    cr_assert(memcmp(result_str, expected_result, TRANSPOSITION_BLOCK_SIZE*2) == 0);
}

Test(crypt, feistel) {
    char expected_result[8] = "fdcbc20c";

    unsigned char iter_key[4];
    hex_to_bytes("87654321", iter_key, 8);

    unsigned char input[4];
    hex_to_bytes("fedcba98", input, 8);

    unsigned char result[4];
    memset(result, 0, 4);

    uint32_t iter_f = feistel(bytes_to_uint32_be(input), bytes_to_uint32_be(iter_key));
    uint32_to_bytes_be(iter_f, result);

    char result_str[8];
    bytes_to_hex(result, result_str, 4);

    cr_assert(memcmp(result_str, expected_result, 8) == 0);
}

Test(crypt, encode) {
    unsigned char plain_text[8];
    hex_to_bytes("fedcba9876543210", plain_text, 16);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[8] = {0};

    magma_encrypt_block(plain_text, result, keys);

    char result_str[16];
    bytes_to_hex(result, result_str, 8);

    char expected_result[16] = "4ee901e5c2d8ca3d";
    
    cr_assert(memcmp(result_str, expected_result, 16) == 0);
}

Test(crypt, decode) {
    unsigned char plain_text[8];
    hex_to_bytes("4ee901e5c2d8ca3d", plain_text, 16);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    MagmaResult key_result = key_expand(master_key, keys);
    cr_assert(key_result == MAGMA_SUCCESS);

    unsigned char result[8] = {0};

    magma_decrypt_block(plain_text, result, keys);

    char result_str[16];
    bytes_to_hex(result, result_str, 8);

    char expected_result[16] = "fedcba9876543210";
    
    cr_assert(memcmp(result_str, expected_result, 16) == 0);
}