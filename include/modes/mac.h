#ifndef MAGMA_MAC_H
#define MAGMA_MAC_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

MagmaResult magma_mac(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const size_t mac_size,
    const unsigned char *input,
    unsigned char *mac,
    const size_t length
);

void calc_additional_keys(unsigned char K1_output[8], unsigned char K2_output[8], const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN]);

#endif