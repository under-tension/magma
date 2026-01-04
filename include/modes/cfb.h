#ifndef MAGMA_CFB_H
#define MAGMA_CFB_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

void magma_encrypt_cfb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *iv, 
    const size_t iv_length,
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

void magma_decrypt_cfb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *iv, 
    const size_t iv_length,
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

#endif
