#ifndef MAGMA_OFB_H
#define MAGMA_OFB_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

typedef struct {
    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    unsigned char *iv;
    size_t iv_length;
} OfbCtx;

void magma_encrypt_ofb(OfbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length);
void magma_decrypt_ofb(OfbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length);

#endif
