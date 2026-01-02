#include "modes/ctr.h"

void ctr_crypt(unsigned char *input, unsigned char *output, CtrCtx *ctx)
{
    uint32_t counter = 0;

    for (unsigned i = 0; i < (ctx->lenght / 8); i++) {
        unsigned char cipher_block[8] = {0};

        unsigned char counter_bytes[8] = {0};
        uint32_t hight = ctx->iv;
        uint32_t low  = counter;

        uint32_to_bytes(hight, counter_bytes);
        uint32_to_bytes_be(low, counter_bytes + 4);

        encode(counter_bytes, cipher_block, ctx->keys);

        for (unsigned j = 0; j < 8; j++) {
            output[(i * 8) + j] = input[(i * 8) + j] ^ cipher_block[j];
        }

        counter++;
    }
}

void ctr_decrypt(unsigned char *input, unsigned char *output, CtrCtx *ctx)
{
    return ctr_crypt(input, output, ctx);
}

