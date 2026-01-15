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

    size_t offset = 0;

    for (size_t i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        MagmaResult encrypt_block_result = magma_encrypt_block(reg + shift_register, cipher_block, keys);

        // GCOVR_EXCL_START
        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }
        // GCOVR_EXCL_STOP

        for (int j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            output[offset + j] = input[offset + j] ^ cipher_block[j];
        }

        memcpy(reg + shift_register, output + offset, MAGMA_BLOCK_SIZE);

        shift_register += MAGMA_BLOCK_SIZE;

        if (shift_register >= iv_length) {
            shift_register = 0;
        }

        offset += MAGMA_BLOCK_SIZE;
    }

    if (length % MAGMA_BLOCK_SIZE > 0) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        MagmaResult encrypt_block_result = magma_encrypt_block(reg + shift_register, cipher_block, keys);

        // GCOVR_EXCL_START
        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }
        // GCOVR_EXCL_STOP

        for (size_t j = 0; j < length % MAGMA_BLOCK_SIZE; j++) {
            output[offset + j] = input[offset + j] ^ cipher_block[j];
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

    size_t offset = 0;

    for (size_t i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char decode_block[MAGMA_BLOCK_SIZE] = {0};

        MagmaResult encrypt_block_result = magma_encrypt_block(reg + shift_register, decode_block, keys);

        // GCOVR_EXCL_START
        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }
        // GCOVR_EXCL_STOP

        for (size_t j = 0; j < 8; j++) {
            output[offset + j] = input[offset + j] ^ decode_block[j];
        }

        memcpy(reg + shift_register, input + offset, MAGMA_BLOCK_SIZE);

        shift_register += MAGMA_BLOCK_SIZE;

        if (shift_register >= iv_length) {
            shift_register = 0;
        }

        offset += MAGMA_BLOCK_SIZE;
    }

    if (length % MAGMA_BLOCK_SIZE > 0) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        MagmaResult encrypt_block_result = magma_encrypt_block(reg + shift_register, cipher_block, keys);

        // GCOVR_EXCL_START
        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }
        // GCOVR_EXCL_STOP

        for (size_t j = 0; j < length % MAGMA_BLOCK_SIZE; j++) {
            output[offset + j] = input[offset + j] ^ cipher_block[j];
        }
    }

    return MAGMA_SUCCESS;
}