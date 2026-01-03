#ifndef MAGMA_CTR_H
#define MAGMA_CTR_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

typedef struct {
    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    uint32_t iv;
} CtrCtx;

void magma_encrypt_ctr(CtrCtx *ctx, const unsigned char *input, unsigned char *output, size_t length);
void magma_decrypt_ctr(CtrCtx *ctx, const unsigned char *input, unsigned char *output, size_t length);

#endif