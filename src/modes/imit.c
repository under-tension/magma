#include "modes/imit.h"

void magma_encrypt_imit(unsigned char *input, ImitCtx *ctx)
{
    unsigned char previous_cipher_block[8] = {0};
    unsigned char result[8] = {0};
    unsigned char first_plain_block[8] = {0};

    memcpy(first_plain_block, input, 8);

    magma_encrypt_block(first_plain_block, previous_cipher_block, ctx->keys);

    memcpy(result, previous_cipher_block, 8);

    unsigned i = 1;
    for (;i < (ctx->length / 8) - 1; i++) {
        unsigned char plain_block[8] = {0};
        unsigned char cipher_block[8] = {0};

        memcpy(plain_block, input + (i * 8), 8);

        for (unsigned j = 0; j < 8; j++) {
            plain_block[j] ^= previous_cipher_block[j];
        }

        magma_encrypt_block(plain_block, cipher_block, ctx->keys);

        for (unsigned j = 0; j < 8; j++) {
            previous_cipher_block[j] = cipher_block[j];
        }
    }

    unsigned char K1[8] = {0};
    unsigned char K2[8] = {0};

    calc_additional_keys(K1, K2, ctx->keys);

    const unsigned char *lastKey = ctx->length % 8 == 0 ? K1 : K2;

    if (i <= ctx->length / 8) {
        unsigned char plain_block[8] = {0};
        unsigned char cipher_block[8] = {0};

        memcpy(plain_block, input + (i * 8), 8);

        for (unsigned j = 0; j < 8; j++) {
            plain_block[j] ^= previous_cipher_block[j];
        }

        for (unsigned j = 0; j < 8; j++) {
            plain_block[j] ^= lastKey[j];
        }

        magma_encrypt_block(plain_block, cipher_block, ctx->keys);

        for (unsigned j = 0; j < 8; j++) {
            result[j] = cipher_block[j];
        }
    }

    for (unsigned j = 0; j < 4; j++) {
        ctx->mac[j] = result[j];
    }
}

void calc_additional_keys(unsigned char K1_output[8], unsigned char K2_output[8], const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN])
{
    unsigned char zero[8] = {0};
    unsigned char R[8];

    magma_encrypt_block(zero, R, keys);

    int msb_r = (R[0] & 0x80) != 0;

    unsigned char K1[8] = {0};
    memcpy(K1, R, 8);
    shift_left_one(K1, 8);

    if(msb_r) {
        K1[7] ^= 0x1B;
    }

    unsigned char K2[8] = {0};
    memcpy(K2, K1, 8);

    int msb_k1 = (K1[0] & 0x80) != 0;

    shift_left_one(K2, 8);

    if (msb_k1) {
        K2[7] ^= 0x1B;
    }

    memcpy(K1_output, K1, 8);
    memcpy(K2_output, K2, 8);
}