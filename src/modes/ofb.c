#include "modes/ofb.h"

void magma_encrypt_ofb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *iv, 
    const size_t iv_length,
    const unsigned char *input,
    unsigned char *output,
    const size_t length
)
{
    size_t shift_register = 0;
    unsigned char reg[iv_length];
    memcpy(reg, iv, iv_length);

    for (size_t i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        magma_encrypt_block(reg + shift_register, cipher_block, keys);

        for (int j = 0; j < 8; j++) {
            output[i * MAGMA_BLOCK_SIZE + j] = input[i * MAGMA_BLOCK_SIZE + j] ^ cipher_block[j];
        }

        memcpy(reg + shift_register, cipher_block, MAGMA_BLOCK_SIZE);

        shift_register += MAGMA_BLOCK_SIZE;

        if (shift_register >= iv_length) {
            shift_register = 0;
        }
    }
}

void magma_decrypt_ofb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *iv, 
    const size_t iv_length,
    const unsigned char *input,
    unsigned char *output,
    const size_t length)
{
    return magma_encrypt_ofb(keys, iv, iv_length, input, output, length);
}