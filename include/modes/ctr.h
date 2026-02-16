#ifndef MAGMA_CTR_H
#define MAGMA_CTR_H

#include <stddef.h>
#include <stdint.h>
#include "core/keys.h"
#include "core/crypt.h"
#include "core/utils.h"

#define CTR_IV_LENGTH 4

/**
 * @param keys Expanded iteration keys.
 * @param iv Pointer to the IV (initialization vector).
 * @param input Pointer to the input data.
 * @param output Pointer to the output data.
 * @param length Length of the input data in bytes.
 * @return MAGMA_SUCCESS on success, error code otherwise.
 */
MagmaResult magma_encrypt_ctr(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char iv[CTR_IV_LENGTH], 
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

/**
 * @param keys Expanded iteration keys.
 * @param iv Pointer to the IV (initialization vector).
 * @param input Pointer to the input data.
 * @param output Pointer to the output data.
 * @param length Length of the input data in bytes.
 * @return MAGMA_SUCCESS on success, error code otherwise.
 */
MagmaResult magma_decrypt_ctr(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char iv[CTR_IV_LENGTH], 
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

#endif