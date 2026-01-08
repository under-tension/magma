#include <criterion/criterion.h>
#include <criterion/parameterized.h>
#include <string.h>
#include <stdint.h>
#include "core/utils.h"

typedef struct hex_test_case {
    char hex[32];
    size_t hex_len;
    unsigned char expected[16];
    size_t bytes_len;
} hex_test_case;

ParameterizedTestParameters(utils, hex_roundtrip) {
    static hex_test_case cases[] = {
        {"", 0, "", 0},
        {"00", 2, {0x00}, 1},
        {"ff", 2, {0xff}, 1},
        {"dead", 4, {0xde, 0xad}, 2},
        {"beef", 4, {0xBE, 0xEF}, 2},
        {"a1b2c3d4e5f60718", 16, {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18}, 8},
        {"0102030405060708090a0b0c0d0e0f", 30, {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}, 15},
    };

    return cr_make_param_array(hex_test_case, cases, sizeof(cases) / sizeof(cases[0]));
}

ParameterizedTest(hex_test_case *param, utils, hex_roundtrip) {
    unsigned char *bytes = calloc(sizeof(unsigned char), param->bytes_len);
    char *hex_back = calloc(sizeof(char), param->hex_len);
    
    hex_to_bytes(param->hex, bytes, param->hex_len);

    cr_assert_eq(memcmp(bytes, param->expected, param->bytes_len), 0);

    bytes_to_hex(bytes, hex_back, param->bytes_len);

    free(bytes);
    bytes = NULL;

    cr_assert_eq(memcmp(hex_back, param->hex, param->hex_len), 0);

    free(hex_back);
    hex_back = NULL;
}

typedef struct {
    unsigned char bytes[4];
    uint32_t value;
} bytes_to_uint32_le_test_case;

ParameterizedTestParameters(utils, bytes_to_uint32_le) {
    static bytes_to_uint32_le_test_case cases[] = {
        {{0x00, 0x00, 0x00, 0x00}, 0x00000000U},
        {{0x01, 0x00, 0x00, 0x00}, 0x00000001U},
        {{0x01, 0x02, 0x03, 0x04}, 0x04030201U},
        {{0xFF, 0xFF, 0xFF, 0xFF}, 0xFFFFFFFFU},
    };

    return cr_make_param_array(bytes_to_uint32_le_test_case, cases, sizeof(cases) / sizeof(cases[0]));
}

ParameterizedTest(bytes_to_uint32_le_test_case *param, utils, bytes_to_uint32_le) {
    uint32_t val = bytes_to_uint32(param->bytes);
    cr_assert_eq(val, param->value);

    unsigned char out[4];
    uint32_to_bytes(param->value, out);
    cr_assert_eq(memcmp(out, param->bytes, 4), 0);
}

typedef struct {
    unsigned char bytes[4];
    uint32_t value;
} bytes_to_uint32_be_test_case;

ParameterizedTestParameters(utils, bytes_to_uint32_be) {
    static bytes_to_uint32_be_test_case cases[] = {
        {{0x00, 0x00, 0x00, 0x00}, 0x00000000U},
        {{0x01, 0x00, 0x00, 0x00}, 0x01000000U},
        {{0x01, 0x02, 0x03, 0x04}, 0x01020304U},
        {{0xFF, 0xFF, 0xFF, 0xFF}, 0xFFFFFFFFU},
    };
    return cr_make_param_array(bytes_to_uint32_be_test_case, cases, sizeof(cases) / sizeof(cases[0]));
}

ParameterizedTest(bytes_to_uint32_be_test_case *param, utils, bytes_to_uint32_be) {
    uint32_t val = bytes_to_uint32_be(param->bytes);
    cr_assert_eq(val, param->value);

    unsigned char out[4];
    uint32_to_bytes_be(param->value, out);
    cr_assert_eq(memcmp(out, param->bytes, 4), 0);
}

typedef struct {
    unsigned char input[8];
    unsigned char expected[8];
    size_t len;
} shift_left_one_test_case;

ParameterizedTestParameters(utils, shift_left_one) {
    static shift_left_one_test_case cases[] = {
        {{0x80}, {0x00}, 1},
        {{0xC0}, {0x80}, 1},
        {{0xFF}, {0xFE}, 1},
        {{0xC0, 0x80}, {0x81, 0x00}, 2},
        {{0xFF, 0xFF}, {0xFF, 0xFE}, 2},
        {{0x01, 0x00}, {0x02, 0x00}, 2},
        {{0x80, 0x00, 0x01}, {0x00, 0x00, 0x02}, 3},
    };
    return cr_make_param_array(shift_left_one_test_case, cases, sizeof(cases) / sizeof(cases[0]));
}

ParameterizedTest(shift_left_one_test_case *param, utils, shift_left_one) {
    unsigned char buf[8];
    memcpy(buf, param->input, param->len);

    shift_left_one(buf, param->len);

    cr_assert_eq(memcmp(buf, param->expected, param->len), 0);
}