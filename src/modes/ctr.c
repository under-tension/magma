#include "modes/ctr.h"

void magma_encrypt_ctr(CtrCtx *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
    uint32_t counter = 0;

    for (unsigned i = 0; i < (length / 8); i++) {
        unsigned char cipher_block[8] = {0};

        unsigned char counter_bytes[8] = {0};
        uint32_t hight = ctx->iv;
        uint32_t low  = counter;

        uint32_to_bytes(hight, counter_bytes);
        uint32_to_bytes_be(low, counter_bytes + 4);

        magma_encrypt_block(counter_bytes, cipher_block, ctx->keys);

        for (unsigned j = 0; j < 8; j++) {
            output[(i * 8) + j] = input[(i * 8) + j] ^ cipher_block[j];
        }

        counter++;
    }
}

void magma_decrypt_ctr(CtrCtx *ctx, const unsigned char *input, unsigned char *output, size_t length)
{
    return magma_encrypt_ctr(ctx, input, output, length);
}

