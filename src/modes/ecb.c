#include "modes/ecb.h"

MagmaResult magma_encrypt_ecb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *input,
    unsigned char *output,
    const size_t length
)
{
    if (keys == NULL || input == NULL || output == NULL) {
        return MAGMA_ERROR_NULL_POINTER;
    }

    for (unsigned i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char plain_block[MAGMA_BLOCK_SIZE] = {0};
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        memcpy(plain_block, input + (i * MAGMA_BLOCK_SIZE), MAGMA_BLOCK_SIZE);

        MagmaResult encrypt_block_result = magma_encrypt_block(plain_block, cipher_block, keys);

        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }

        for (unsigned j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            output[(i * MAGMA_BLOCK_SIZE) + j] = cipher_block[j];
        }
    }

    return MAGMA_SUCCESS;
}

MagmaResult magma_decrypt_ecb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *input,
    unsigned char *output,
    const size_t length
)
{
    if (keys == NULL || input == NULL || output == NULL) {
        return MAGMA_ERROR_NULL_POINTER;
    }

    for (unsigned i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char plain_block[MAGMA_BLOCK_SIZE] = {0};
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        memcpy(plain_block, input + (i * MAGMA_BLOCK_SIZE), MAGMA_BLOCK_SIZE);

        MagmaResult decrypt_block_result = magma_decrypt_block(plain_block, cipher_block, keys);

        if (decrypt_block_result != MAGMA_SUCCESS) {
            return decrypt_block_result;
        }

        for (unsigned j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            output[(i * MAGMA_BLOCK_SIZE) + j] = cipher_block[j];
        }
    }

    return MAGMA_SUCCESS;
}