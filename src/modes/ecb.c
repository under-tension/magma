#include "modes/ecb.h"

void ecb_crypt(unsigned char *input, unsigned char *output, EcbCtx *ctx)
{
    for (unsigned i = 0; i < (ctx->lenght / 8); i++) {
        unsigned char plain_block[8] = {0};
        unsigned char cipher_block[8] = {0};

        memcpy(plain_block, input + (i * 8), 8);

        encode(plain_block, cipher_block, ctx->keys);

        for (unsigned j = 0; j < 8; j++) {
            output[(i * 8) + j] = cipher_block[j];
        }
    }
}

void ecb_decrypt(unsigned char *input, unsigned char *output, EcbCtx *ctx)
{
    for (unsigned i = 0; i < (ctx->lenght / 8); i++) {
        unsigned char plain_block[8] = {0};
        unsigned char cipher_block[8] = {0};

        memcpy(plain_block, input + (i * 8), 8);

        decode(plain_block, cipher_block, ctx->keys);

        for (unsigned j = 0; j < 8; j++) {
            output[(i * 8) + j] = cipher_block[j];
        }
    }
}