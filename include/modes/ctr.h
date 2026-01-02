#ifndef MAGMA_CTR_H
#define MAGMA_CTR_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

typedef struct {
    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    size_t lenght;
    uint32_t iv;
} CtrCtx;

void ctr_crypt(unsigned char *input, unsigned char *output, CtrCtx *ctx);
void ctr_decrypt(unsigned char *input, unsigned char *output, CtrCtx *ctx);

#endif