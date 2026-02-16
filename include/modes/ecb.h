#ifndef MAGMA_ECB_H
#define MAGMA_ECB_H

#include <stddef.h>
#include <stdint.h>
#include "core/keys.h"
#include "core/crypt.h"
#include "core/utils.h"

/**
 * @brief Encrypts data using the ECB (Electronic Codebook) mode of operation.
 * @param keys Expanded iteration keys.
 * @param input Pointer to the input data.
 * @param output Pointer to the output data.
 * @param length Length of the input data in bytes. Must be a multiple of MAGMA_BLOCK_SIZE.
 * @return MAGMA_SUCCESS on success, error code otherwise.
 */
MagmaResult magma_encrypt_ecb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

/**
 * @brief Decrypts data using the ECB (Electronic Codebook) mode of operation.
 * @param keys Expanded iteration keys.
 * @param input Pointer to the input data.
 * @param output Pointer to the output data.
 * @param length Length of the input data in bytes. Must be a multiple of MAGMA_BLOCK_SIZE.
 * @return MAGMA_SUCCESS on success, error code otherwise.
 */
MagmaResult magma_decrypt_ecb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

#endif