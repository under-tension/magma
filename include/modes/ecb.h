#ifndef MAGMA_ECB_H
#define MAGMA_ECB_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

typedef struct {
    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    size_t lenght;
} EcbCtx;

void ecb_crypt(unsigned char *input, unsigned char *output, EcbCtx *ctx);
void ecb_decrypt(unsigned char *input, unsigned char *output, EcbCtx *ctx);

#endif