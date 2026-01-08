#include "modes/cbc.h"

MagmaResult magma_encrypt_cbc(
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

    if (length == 0 || length % MAGMA_BLOCK_SIZE != 0) {
        return MAGMA_ERROR_INVALID_LENGTH;
    }

    size_t shift_register = 0;
    unsigned char reg[iv_length];
    memcpy(reg, iv, iv_length);

    for (size_t i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char prepared_block[MAGMA_BLOCK_SIZE] = {0};
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        for (size_t j = 0; j < 8; j++) {
            prepared_block[j] = input[(i * MAGMA_BLOCK_SIZE) + j] ^ reg[shift_register + j];
        }

        MagmaResult encrypt_block_result = magma_encrypt_block(prepared_block, cipher_block, keys);

        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }

        memcpy(output + (i * MAGMA_BLOCK_SIZE), cipher_block, MAGMA_BLOCK_SIZE);

        memcpy(reg + shift_register, cipher_block, MAGMA_BLOCK_SIZE);

        shift_register += MAGMA_BLOCK_SIZE;

        if (shift_register >= iv_length) {
            shift_register = 0;
        }
    }

    return MAGMA_SUCCESS;
}

MagmaResult magma_decrypt_cbc(
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

    if (length == 0 || length % MAGMA_BLOCK_SIZE != 0) {
        return MAGMA_ERROR_INVALID_LENGTH;
    }

    size_t shift_register = 0;
    unsigned char reg[iv_length];
    memcpy(reg, iv, iv_length);

    for (size_t i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char plain_block[MAGMA_BLOCK_SIZE] = {0};
        unsigned char decode_block[MAGMA_BLOCK_SIZE] = {0};

        MagmaResult decrypt_block_result = magma_decrypt_block(input + (i * MAGMA_BLOCK_SIZE), decode_block, keys);

        if (decrypt_block_result != MAGMA_SUCCESS) {
            return decrypt_block_result;
        }

        for (size_t j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            plain_block[j] = decode_block[j] ^ reg[shift_register + j];
        }

        memcpy(output + (i * MAGMA_BLOCK_SIZE), plain_block, MAGMA_BLOCK_SIZE);

        memcpy(reg + shift_register, input + (i * MAGMA_BLOCK_SIZE), MAGMA_BLOCK_SIZE);

        shift_register += MAGMA_BLOCK_SIZE;

        if (shift_register >= iv_length) {
            shift_register = 0;
        }
    }

    return MAGMA_SUCCESS;
}