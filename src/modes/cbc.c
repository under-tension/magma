#include "modes/cbc.h"

void cbc_crypt(unsigned char *input, unsigned char *output, CbcCtx *ctx)
{
    size_t shift_register = 0;
    unsigned char reg[ctx->iv_lenght];
    memcpy(reg, ctx->iv, ctx->iv_lenght);

    for (size_t i = 0; i < (ctx->lenght / 8); i++) {
        unsigned char prepared_block[8] = {0};
        unsigned char cipher_block[8] = {0};

        for (size_t j = 0; j < 8; j++) {
            prepared_block[j] = input[i * 8 + j] ^ reg[shift_register + j];
        }

        encode(prepared_block, cipher_block, ctx->keys);

        memcpy(output + i * 8, cipher_block, 8);

        memcpy(reg + shift_register, cipher_block, 8);

        shift_register += 8;

        if (shift_register >= ctx->iv_lenght) {
            shift_register = 0;
        }
    }
}

void cbc_decrypt(unsigned char *input, unsigned char *output, CbcCtx *ctx)
{
    size_t shift_register = 0;
    unsigned char reg[ctx->iv_lenght];
    memcpy(reg, ctx->iv, ctx->iv_lenght);

    for (size_t i = 0; i < (ctx->lenght / 8); i++) {
        unsigned char plain_block[8] = {0};
        unsigned char decode_block[8] = {0};

        decode(input + i * 8, decode_block, ctx->keys);

        for (size_t j = 0; j < 8; j++) {
            plain_block[j] = decode_block[j] ^ reg[shift_register + j];
        }

        memcpy(output + i * 8, plain_block, 8);

        memcpy(reg + shift_register, input + i * 8, 8);

        shift_register += 8;

        if (shift_register >= ctx->iv_lenght) {
            shift_register = 0;
        }
    }
}