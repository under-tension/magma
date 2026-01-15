#include "modes/ctr.h"

MagmaResult magma_encrypt_ctr(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char iv[CTR_IV_LENGTH], 
    const unsigned char *input,
    unsigned char *output,
    const size_t length
)
{
    if (keys == NULL || iv == NULL || input == NULL || output == NULL) {
        return MAGMA_ERROR_NULL_POINTER;
    }

    uint32_t counter = 0;
    unsigned char counter_bytes[MAGMA_BLOCK_SIZE] = {0};
    memcpy(counter_bytes, iv, CTR_IV_LENGTH);
    
    size_t offset = 0;

    for (unsigned i = 0; i < (length / MAGMA_BLOCK_SIZE); i++) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        uint32_to_bytes_be(counter, counter_bytes + 4);

        MagmaResult encrypt_block_result = magma_encrypt_block(counter_bytes, cipher_block, keys);

        // GCOVR_EXCL_START
        if (encrypt_block_result != MAGMA_SUCCESS) {
            return encrypt_block_result;
        }
        // GCOVR_EXCL_STOP

        for (unsigned j = 0; j < MAGMA_BLOCK_SIZE; j++) {
            output[offset + j] = input[offset + j] ^ cipher_block[j];
        }

        offset += MAGMA_BLOCK_SIZE;
        counter++;
    }

    if (length % MAGMA_BLOCK_SIZE > 0) {
        unsigned char cipher_block[MAGMA_BLOCK_SIZE] = {0};

        uint32_to_bytes_be(counter, counter_bytes + 4);

        MagmaResult encrypt_block_result = magma_encrypt_block(counter_bytes, cipher_block, keys);

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

MagmaResult magma_decrypt_ctr(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char iv[CTR_IV_LENGTH], 
    const unsigned char *input,
    unsigned char *output,
    const size_t length
)
{
    return magma_encrypt_ctr(keys, iv, input, output, length);
}

