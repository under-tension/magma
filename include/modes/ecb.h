#ifndef MAGMA_ECB_H
#define MAGMA_ECB_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

typedef struct {
    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
} EcbCtx;

void magma_encrypt_ecb(EcbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length);
void magma_decrypt_ecb(EcbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length);

#endif