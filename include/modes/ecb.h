#ifndef MAGMA_ECB_H
#define MAGMA_ECB_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

MagmaResult magma_encrypt_ecb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

MagmaResult magma_decrypt_ecb(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

#endif