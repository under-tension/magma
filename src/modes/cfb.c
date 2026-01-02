#include "modes/cfb.h"

void cfb_crypt(unsigned char *input, unsigned char *output, CfbCtx *ctx)
{
    size_t shift_register = 0;
    unsigned char reg[ctx->iv_lenght];
    memcpy(reg, ctx->iv, ctx->iv_lenght);

    for (size_t i = 0; i < (ctx->lenght / 8); i++) {
        unsigned char cipher_block[8] = {0};

        encode(reg + shift_register, cipher_block, ctx->keys);

        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = input[i * 8 + j] ^ cipher_block[j];
        }

        memcpy(reg + shift_register, output + i * 8, 8);

        shift_register += 8;

        if (shift_register >= ctx->iv_lenght) {
            shift_register = 0;
        }
    }
}

void cfb_decrypt(unsigned char *input, unsigned char *output, CfbCtx *ctx)
{
    size_t shift_register = 0;
    unsigned char reg[ctx->iv_lenght];
    memcpy(reg, ctx->iv, ctx->iv_lenght);

    for (size_t i = 0; i < (ctx->lenght / 8); i++) {
        unsigned char decode_block[8] = {0};

        encode(reg + shift_register, decode_block, ctx->keys);

        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = input[i * 8 + j] ^ decode_block[j];
        }

        memcpy(reg + shift_register, input + i * 8, 8);

        shift_register += 8;

        if (shift_register >= ctx->iv_lenght) {
            shift_register = 0;
        }
    }
}