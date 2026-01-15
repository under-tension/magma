#ifndef MAGMA_KEYS_H
#define MAGMA_KEYS_H

#include "types.h"
#include <stdlib.h>
#include <string.h>

#define MASTER_KEY_LEN 32
#define ITER_KEYS_COUNT 32
#define ITER_KEY_LEN 4

MagmaResult key_expand(const unsigned char master_key[MASTER_KEY_LEN], unsigned char result_keys[ITER_KEYS_COUNT][ITER_KEY_LEN]);

#endif