#include "modes/cfb.h"

MagmaResult magma_encrypt_cfb(
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

    for (size_t i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        MagmaResult encrypt_block_result = magma_encrypt_block(reg + shift_register, cipher_block, keys);

        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }

        for (int j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            output[(i * MAGMA_BLOCK_SIZE) + j] = input[(i * MAGMA_BLOCK_SIZE) + j] ^ cipher_block[j];
        }

        memcpy(reg + shift_register, output + (i * MAGMA_BLOCK_SIZE), MAGMA_BLOCK_SIZE);

        shift_register += MAGMA_BLOCK_SIZE;

        if (shift_register >= iv_length) {
            shift_register = 0;
        }
    }

    return MAGMA_SUCCESS;
}

MagmaResult magma_decrypt_cfb(
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

    for (size_t i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char decode_block[MAGMA_BLOCK_SIZE] = {0};

        MagmaResult encrypt_block_result = magma_encrypt_block(reg + shift_register, decode_block, keys);

        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }

        for (int j = 0; j < 8; j++) {
            output[(i * MAGMA_BLOCK_SIZE) + j] = input[(i * MAGMA_BLOCK_SIZE) + j] ^ decode_block[j];
        }

        memcpy(reg + shift_register, input + (i * MAGMA_BLOCK_SIZE), MAGMA_BLOCK_SIZE);

        shift_register += MAGMA_BLOCK_SIZE;

        if (shift_register >= iv_length) {
            shift_register = 0;
        }
    }

    return MAGMA_SUCCESS;
}