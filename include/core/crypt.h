#ifndef MAGMA_CRYPT_H
#define MAGMA_CRYPT_H

#include "keys.h"
#include "utils.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TRANSPOSITION_BLOCK_SIZE 4
#define FEISTEL_INPUT_AND_OUTPUT_LEN 4
#define MAGMA_BLOCK_SIZE 8

uint32_t T(const uint32_t input);
uint32_t feistel(const uint32_t plaintext, const uint32_t key);
void magma_encrypt_block(const unsigned char plain_text[8], unsigned char cipher_text[8], const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN]);
void magma_decrypt_block(const unsigned char plain_text[8], unsigned char cipher_text[8], const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN]);

#endif