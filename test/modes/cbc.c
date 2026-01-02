#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include "modes/cbc.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_ctr, cbc_crypt) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[24];
    hex_to_bytes("1234567890abcdef234567890abcdef134567890abcdef12", iv, 48);

    CbcCtx *ctx = calloc(1, sizeof(CbcCtx));
    ctx->lenght = 32;
    ctx->iv = iv;
    ctx->iv_lenght = 24;

    get_keys_from_master_key(master_key, ctx->keys);

    unsigned char result[32] = {0};

    cbc_crypt(plain_text, result, ctx);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ctr, cbc_decrypt) {
    unsigned char cipher_text[32];
    hex_to_bytes("96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667", cipher_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[24];
    hex_to_bytes("1234567890abcdef234567890abcdef134567890abcdef12", iv, 48);

    CbcCtx *ctx = calloc(1, sizeof(CbcCtx));
    ctx->lenght = 32;
    ctx->iv = iv;
    ctx->iv_lenght = 24;

    get_keys_from_master_key(master_key, ctx->keys);

    unsigned char result[32] = {0};

    cbc_decrypt(cipher_text, result, ctx);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}
