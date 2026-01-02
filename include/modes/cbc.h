#ifndef MAGMA_CBC_H
#define MAGMA_CBC_H

#include <stddef.h>
#include <stdint.h>
#include "../core/keys.h"
#include "../core/crypt.h"
#include "../core/utils.h"

typedef struct {
    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    size_t lenght;
    unsigned char *iv;
    size_t iv_lenght;
} CbcCtx;

void cbc_crypt(unsigned char *input, unsigned char *output, CbcCtx *ctx);
void cbc_decrypt(unsigned char *input, unsigned char *output, CbcCtx *ctx);

#endif
