#include "core/crypt.h"

static int Pi[8][16] = {
    {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
    {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
    {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
    {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
    {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
    {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
    {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
    {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}

};

uint32_t T(const uint32_t input)
{
    uint32_t result = 0;

    for (int i = 0; i < 8; i++) {
      unsigned shift_bits = i * 4;
      unsigned value = (input >> shift_bits) & 0x0f;
      uint32_t replace = Pi[i][value];

      result |= replace << shift_bits;
    }

    return result;
}

uint32_t feistel(const uint32_t plaintext, const uint32_t key)
{
    uint32_t text = plaintext + key;
    uint32_t trans = T(text);
    uint32_t result = (trans << 11) | (trans >> 21);

    return result;
}

void magma_encrypt_block(const unsigned char plain_text[MAGMA_BLOCK_SIZE], unsigned char cipher_text[MAGMA_BLOCK_SIZE], const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN])
{
  uint32_t left = bytes_to_uint32_be(plain_text);
  uint32_t right = bytes_to_uint32_be(plain_text + 4);

  for (int i = 0; i < 31; i++) {
    uint32_t iter_left = right;
    uint32_t round_result = feistel(right, bytes_to_uint32_be(keys[i]));
    uint32_t sum_result = left ^ round_result;

    left = iter_left;
    right = sum_result;
  }

  uint32_t round_result = feistel(right, bytes_to_uint32_be(keys[31]));
  left ^= round_result;

  uint32_to_bytes_be(left, cipher_text);
  uint32_to_bytes_be(right, cipher_text+4);
}

void magma_decrypt_block(const unsigned char plain_text[8], unsigned char cipher_text[8], const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN])
{
  uint32_t left = bytes_to_uint32_be(plain_text);
  uint32_t right = bytes_to_uint32_be(plain_text + 4);

  for (int i = 31; i > 0; i--) {
    uint32_t iter_left = right;
    uint32_t round_result = feistel(right, bytes_to_uint32_be(keys[i]));
    uint32_t sum_result = left ^ round_result;

    left = iter_left;
    right = sum_result;
  }

  uint32_t round_result = feistel(right, bytes_to_uint32_be(keys[0]));
  left ^= round_result;

  uint32_to_bytes_be(left, cipher_text);
  uint32_to_bytes_be(right, cipher_text+4);
}
