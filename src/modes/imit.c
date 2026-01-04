#include "modes/imit.h"

void magma_encrypt_imit(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const size_t mac_size,
    const unsigned char *input,
    unsigned char *mac,
    const size_t length
)
{
    unsigned char previous_cipher_block[MAGMA_BLOCK_SIZE] = {0};
    unsigned char result[MAGMA_BLOCK_SIZE] = {0};
    unsigned char first_plain_block[MAGMA_BLOCK_SIZE] = {0};

    memcpy(first_plain_block, input, MAGMA_BLOCK_SIZE);

    magma_encrypt_block(first_plain_block, previous_cipher_block, keys);

    memcpy(result, previous_cipher_block, MAGMA_BLOCK_SIZE);

    unsigned i = 1;
    for (;i < (length / MAGMA_BLOCK_SIZE) - 1; i++) {
        unsigned char plain_block[MAGMA_BLOCK_SIZE] = {0};
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        memcpy(plain_block, input + (i * MAGMA_BLOCK_SIZE), MAGMA_BLOCK_SIZE);

        for (unsigned j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            plain_block[j] ^= previous_cipher_block[j];
        }

        magma_encrypt_block(plain_block, cipher_block, keys);

        for (unsigned j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            previous_cipher_block[j] = cipher_block[j];
        }
    }

    unsigned char K1[MAGMA_BLOCK_SIZE] = {0};
    unsigned char K2[MAGMA_BLOCK_SIZE] = {0};

    calc_additional_keys(K1, K2, keys);

    const unsigned char *lastKey = length % 8 == 0 ? K1 : K2;

    if (i <= length / MAGMA_BLOCK_SIZE) {
        unsigned char plain_block[MAGMA_BLOCK_SIZE] = {0};
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        memcpy(plain_block, input + (i * MAGMA_BLOCK_SIZE), MAGMA_BLOCK_SIZE);

        for (unsigned j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            plain_block[j] ^= previous_cipher_block[j];
        }

        for (unsigned j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            plain_block[j] ^= lastKey[j];
        }

        magma_encrypt_block(plain_block, cipher_block, keys);

        for (unsigned j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            result[j] = cipher_block[j];
        }
    }

    memcpy(mac, result, mac_size);
}

void calc_additional_keys(unsigned char K1_output[MAGMA_BLOCK_SIZE], unsigned char K2_output[MAGMA_BLOCK_SIZE], const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN])
{
    unsigned char zero[MAGMA_BLOCK_SIZE] = {0};
    unsigned char R[MAGMA_BLOCK_SIZE] = {0};

    magma_encrypt_block(zero, R, keys);

    int msb_r = (R[0] & 0x80) != 0;

    unsigned char K1[MAGMA_BLOCK_SIZE] = {0};
    memcpy(K1, R, MAGMA_BLOCK_SIZE);
    shift_left_one(K1, MAGMA_BLOCK_SIZE);

    if(msb_r) {
        K1[MAGMA_BLOCK_SIZE - 1] ^= 0x1B;
    }

    unsigned char K2[MAGMA_BLOCK_SIZE] = {0};
    memcpy(K2, K1, MAGMA_BLOCK_SIZE);

    int msb_k1 = (K1[0] & 0x80) != 0;

    shift_left_one(K2, MAGMA_BLOCK_SIZE);

    if (msb_k1) {
        K2[MAGMA_BLOCK_SIZE - 1] ^= 0x1B;
    }

    memcpy(K1_output, K1, MAGMA_BLOCK_SIZE);
    memcpy(K2_output, K2, MAGMA_BLOCK_SIZE);
}