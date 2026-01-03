#include "modes/ofb.h"

void magma_encrypt_ofb(OfbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
    size_t shift_register = 0;
    unsigned char reg[ctx->iv_length];
    memcpy(reg, ctx->iv, ctx->iv_length);

    for (size_t i = 0; i < (length / 8); i++) {
        unsigned char cipher_block[8] = {0};

        magma_encrypt_block(reg + shift_register, cipher_block, ctx->keys);

        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = input[i * 8 + j] ^ cipher_block[j];
        }

        memcpy(reg + shift_register, cipher_block, 8);

        shift_register += 8;

        if (shift_register >= ctx->iv_length) {
            shift_register = 0;
        }
    }
}

void magma_decrypt_ofb(OfbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
    return magma_encrypt_ofb(ctx, input, output, length);
}