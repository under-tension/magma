#ifndef MAGMA_CFB_H
#define MAGMA_CFB_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

typedef struct {
    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    unsigned char *iv;
    size_t iv_length;
} CfbCtx;

void magma_encrypt_cfb(CfbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length);
void magma_decrypt_cfb(CfbCtx *ctx, const unsigned char *input, unsigned char *output, size_t length);

#endif
