#ifndef MAGMA_MAC_H
#define MAGMA_MAC_H

#include <stddef.h>
#include <stdint.h>
#include "core/keys.h"
#include "core/crypt.h"
#include "core/utils.h"

/**
 * @brief Processing data to produce a Message Authentication Code (MAC) using the specified keys.
 * @param keys Expanded iteration keys.
 * @param mac_size Size of the MAC in bytes.
 * @param input Pointer to the input data.
 * @param mac Pointer to the output MAC.
 * @param length Length of the input data in bytes.
 * @return MAGMA_SUCCESS on success, error code otherwise.
 */
MagmaResult magma_mac(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const size_t mac_size,
    const unsigned char *input,
    unsigned char *mac,
    const size_t length
);

/**
 * @brief Calculates additional keys K1 and K2 used in the MAC generation process.
 * 
 * @note Using in function @ref magma_mac
 * 
 * @param K1_output Pointer to the output buffer for K1.
 * @param K2_output Pointer to the output buffer for K2.
 * @param keys Expanded iteration keys.
 * @return MAGMA_SUCCESS on success, error code otherwise.
 */
MagmaResult calc_additional_keys(
    unsigned char K1_output[MAGMA_BLOCK_SIZE],
    unsigned char K2_output[MAGMA_BLOCK_SIZE],
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN]
);

#endif