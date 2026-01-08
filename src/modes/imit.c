#include "modes/imit.h"

MagmaResult magma_encrypt_imit(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const size_t mac_size,
    const unsigned char *input,
    unsigned char *mac,
    const size_t length
)
{
    if (keys == NULL || input == NULL || mac == NULL) {
        return MAGMA_ERROR_NULL_POINTER;
    }

    if (mac_size == 0 || length == 0) {
        return MAGMA_ERROR_INVALID_LENGTH;
    }

    unsigned char previous_cipher_block[MAGMA_BLOCK_SIZE] = {0};
    unsigned char result[MAGMA_BLOCK_SIZE] = {0};

    unsigned char K1[MAGMA_BLOCK_SIZE] = {0};
    unsigned char K2[MAGMA_BLOCK_SIZE] = {0};
    calc_additional_keys(K1, K2, keys);

    size_t full_blocks = length / MAGMA_BLOCK_SIZE;
    size_t remainder   = length % MAGMA_BLOCK_SIZE;
    size_t total_blocks = full_blocks + (remainder ? 1 : 0);

    for (size_t i = 0; i < total_blocks; i++) {
        unsigned char plain_block[MAGMA_BLOCK_SIZE] = {0};
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        if (i < full_blocks) {
            memcpy(plain_block, input + i * MAGMA_BLOCK_SIZE, MAGMA_BLOCK_SIZE);
        } else if (remainder > 0) {
            memcpy(plain_block, input + i * MAGMA_BLOCK_SIZE, remainder);
            plain_block[remainder] = 0x80;
        }

        if (i > 0) {
            for (size_t j = 0; j < MAGMA_BLOCK_SIZE; j++) {
                plain_block[j] ^= previous_cipher_block[j];
            }
        }

        if (i == total_blocks - 1) {
            const unsigned char *lastKey = (remainder == 0) ? K1 : K2;
            for (size_t j = 0; j < MAGMA_BLOCK_SIZE; j++) {
                plain_block[j] ^= lastKey[j];
            }
        }

        MagmaResult encrypt_result = magma_encrypt_block(plain_block, cipher_block, keys);
        if (encrypt_result != MAGMA_SUCCESS) {
            return encrypt_result;
        }

        memcpy(previous_cipher_block, cipher_block, MAGMA_BLOCK_SIZE);
        memcpy(result, cipher_block, MAGMA_BLOCK_SIZE);
    }

    memcpy(mac, result, mac_size < MAGMA_BLOCK_SIZE ? mac_size : MAGMA_BLOCK_SIZE);
    return MAGMA_SUCCESS;
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