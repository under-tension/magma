#include "modes/cbc.h"

void magma_encrypt_cbc(CbcCtx *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
    size_t shift_register = 0;
    unsigned char reg[ctx->iv_length];
    memcpy(reg, ctx->iv, ctx->iv_length);

    for (size_t i = 0; i < (length / 8); i++) {
        unsigned char prepared_block[8] = {0};
        unsigned char cipher_block[8] = {0};

        for (size_t j = 0; j < 8; j++) {
            prepared_block[j] = input[i * 8 + j] ^ reg[shift_register + j];
        }

        magma_encrypt_block(prepared_block, cipher_block, ctx->keys);

        memcpy(output + i * 8, cipher_block, 8);

        memcpy(reg + shift_register, cipher_block, 8);

        shift_register += 8;

        if (shift_register >= ctx->iv_length) {
            shift_register = 0;
        }
    }
}

void magma_decrypt_cbc(CbcCtx *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
    size_t shift_register = 0;
    unsigned char reg[ctx->iv_length];
    memcpy(reg, ctx->iv, ctx->iv_length);

    for (size_t i = 0; i < (length / 8); i++) {
        unsigned char plain_block[8] = {0};
        unsigned char decode_block[8] = {0};

        magma_decrypt_block(input + i * 8, decode_block, ctx->keys);

        for (size_t j = 0; j < 8; j++) {
            plain_block[j] = decode_block[j] ^ reg[shift_register + j];
        }

        memcpy(output + i * 8, plain_block, 8);

        memcpy(reg + shift_register, input + i * 8, 8);

        shift_register += 8;

        if (shift_register >= ctx->iv_length) {
            shift_register = 0;
        }
    }
}