#ifndef MAGMA_OFB_H
#define MAGMA_OFB_H

#include <stddef.h>
#include <stdint.h>
#include "core/keys.h"
#include "core/crypt.h"
#include "core/utils.h"

/**
 * @param keys Expanded iteration keys.
 * @param iv Pointer to the IV (initialization vector).
 * @param iv_length Length of the IV in bytes.
 * @param input Pointer to the input data.
 * @param output Pointer to the output data.
 * @param length Length of the input data in bytes.
 * @return MAGMA_SUCCESS on success, error code otherwise.
 */
MagmaResult magma_encrypt_ofb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *iv, 
    const size_t iv_length,
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

/**
 * @param keys Expanded iteration keys.
 * @param iv Pointer to the IV (initialization vector).
 * @param iv_length Length of the IV in bytes.
 * @param input Pointer to the input data.
 * @param output Pointer to the output data.
 * @param length Length of the input data in bytes.
 * @return MAGMA_SUCCESS on success, error code otherwise.
 */
MagmaResult magma_decrypt_ofb(    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *iv, 
    const size_t iv_length,
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

#endif
