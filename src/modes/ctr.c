#include "modes/ctr.h"

void magma_encrypt_ctr(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char iv[CTR_IV_LENGTH], 
    const unsigned char *input,
    unsigned char *output,
    const size_t length
)
{
    uint32_t counter = 0;
    unsigned char counter_bytes[MAGMA_BLOCK_SIZE] = {0};
    memcpy(counter_bytes, iv, CTR_IV_LENGTH);

    for (unsigned i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        uint32_to_bytes_be(counter, counter_bytes + 4);

        magma_encrypt_block(counter_bytes, cipher_block, keys);

        for (unsigned j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            output[(i * MAGMA_BLOCK_SIZE) + j] = input[(i * MAGMA_BLOCK_SIZE) + j] ^ cipher_block[j];
        }

        counter++;
    }
}

void magma_decrypt_ctr(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char iv[CTR_IV_LENGTH], 
    const unsigned char *input,
    unsigned char *output,
    const size_t length
)
{
    return magma_encrypt_ctr(keys, iv, input, output, length);
}

