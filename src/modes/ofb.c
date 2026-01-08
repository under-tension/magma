#include "modes/ofb.h"

MagmaResult magma_encrypt_ofb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *iv, 
    const size_t iv_length,
    const unsigned char *input,
    unsigned char *output,
    const size_t length
)
{
    if (keys == NULL || iv == NULL || input == NULL || output == NULL) {
        return MAGMA_ERROR_NULL_POINTER;
    }

    size_t shift_register = 0;
    unsigned char reg[iv_length];
    memcpy(reg, iv, iv_length);

    size_t offset = 0;

    for (size_t i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        MagmaResult encrypt_block_result = magma_encrypt_block(reg + shift_register, cipher_block, keys);

        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }

        for (int j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            output[offset + j] = input[offset + j] ^ cipher_block[j];
        }

        memcpy(reg + shift_register, cipher_block, MAGMA_BLOCK_SIZE);

        shift_register += MAGMA_BLOCK_SIZE;

        if (shift_register >= iv_length) {
            shift_register = 0;
        }

        offset += MAGMA_BLOCK_SIZE;
    }

    if (length % MAGMA_BLOCK_SIZE > 0) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        MagmaResult encrypt_block_result = magma_encrypt_block(reg + shift_register, cipher_block, keys);

        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }

        for (size_t j = 0; j < length % MAGMA_BLOCK_SIZE; j++) {
            output[offset + j] = input[offset + j] ^ cipher_block[j];
        }
    }

    return MAGMA_SUCCESS;
}

MagmaResult magma_decrypt_ofb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *iv, 
    const size_t iv_length,
    const unsigned char *input,
    unsigned char *output,
    const size_t length)
{
    return magma_encrypt_ofb(keys, iv, iv_length, input, output, length);
}