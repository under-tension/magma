#include "modes/ecb.h"

void magma_encrypt_ecb(EcbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
    for (unsigned i = 0; i < (length / 8); i++) {
        unsigned char plain_block[8] = {0};
        unsigned char cipher_block[8] = {0};

        memcpy(plain_block, input + (i * 8), 8);

        magma_encrypt_block(plain_block, cipher_block, ctx->keys);

        for (unsigned j = 0; j < 8; j++) {
            output[(i * 8) + j] = cipher_block[j];
        }
    }
}

void magma_decrypt_ecb(EcbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
    for (unsigned i = 0; i < (length / 8); i++) {
        unsigned char plain_block[8] = {0};
        unsigned char cipher_block[8] = {0};

        memcpy(plain_block, input + (i * 8), 8);

        magma_decrypt_block(plain_block, cipher_block, ctx->keys);

        for (unsigned j = 0; j < 8; j++) {
            output[(i * 8) + j] = cipher_block[j];
        }
    }
}