#ifndef MAGMA_IMIT_H
#define MAGMA_IMIT_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

typedef struct {
    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    size_t lenght;
    unsigned char mac[4];
} ImitCtx;

void imit_crypt(unsigned char *input, ImitCtx *ctx);
void calc_additional_keys(unsigned char K1_output[8], unsigned char K2_output[8], const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN]);

#endif