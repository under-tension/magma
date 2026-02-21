#ifndef MAGMA_UTILS_H
#define MAGMA_UTILS_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len);
void print_hex(const unsigned char *bytes, size_t len);
int bytes_to_hex(const unsigned char *input, char *output, size_t len);
uint32_t bytes_to_uint32(const unsigned char *input);
void uint32_to_bytes(const uint32_t input, unsigned char *output);
uint32_t bytes_to_uint32_be(const unsigned char *input);
void uint32_to_bytes_be(const uint32_t input, unsigned char *output);
void shift_left_one(unsigned char *input, size_t length);

#endif