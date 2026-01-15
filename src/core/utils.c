#include "core/utils.h"

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len)
{
    for (size_t i = 0; i < len; i += 2) {
        sscanf(hex + i, "%2hhx", &bytes[i/2]);
    }
}

// GCOVR_EXCL_START
void print_hex(unsigned char *bytes, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) printf(" ");
        printf("%02X", bytes[i]);
    }
    printf("\n");
}
// GCOVR_EXCL_STOP

int bytes_to_hex(const unsigned char *input, char *output, size_t len)
{
    static const char hex[16] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        unsigned char swap_char = input[i];
        output[2 * i] = hex[swap_char >> 4];
        output[(2 * i) + 1] = hex[swap_char & 0xf];
    }

    return 0;
}

uint32_t bytes_to_uint32(const unsigned char *input) {
    return ((uint32_t)input[0] << 0)  |
           ((uint32_t)input[1] << 8)  |
           ((uint32_t)input[2] << 16) |
           ((uint32_t)input[3] << 24);
}

void shift_left_one(unsigned char *input, size_t length)
{
     for(size_t i = 0; i < length - 1 ; i++)
     {
          input[i] <<= 1;
          input[i] &= 0xfe;
          input[i] |= ((input[i+1]>>7)&0x1);
     }

     input[length - 1] <<= 1;
     input[length - 1] &= 0xfe;
}

void uint32_to_bytes(const uint32_t input, unsigned char *output) {
    output[0] = (input >> 0) & 0xFF;
    output[1] = (input >> 8) & 0xFF;
    output[2] = (input >> 16) & 0xFF;
    output[3] = (input >> 24) & 0xFF;
}

uint32_t bytes_to_uint32_be(const unsigned char *input)
{
     uint32_t result = ((input[3]) | (input[2] << 8) | (input[1] << 16) | (input[0] << 24));
     return result;
}

void uint32_to_bytes_be(const uint32_t input, unsigned char *output)
{
  for(int i = 0; i < 4; i++) {
      output[3-i] = (input >> (8*i)) & 0b11111111;
  }
}
