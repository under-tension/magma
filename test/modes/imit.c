#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include "modes/imit.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_modes, calc_additional_keys) {
    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN];
    get_keys_from_master_key(master_key, keys);

    unsigned char K1[8] = {0};
    unsigned char K2[8] = {0};

    calc_additional_keys(K1, K2, keys);

    char K1_str[16] = {0};
    bytes_to_hex(K1, K1_str, 8);

    char K2_str[16] = {0};
    bytes_to_hex(K2, K2_str, 8);

    char expected_K1[] = "5f459b3342521424";
    char expected_K2[] = "be8b366684a42848";
    
    cr_assert(memcmp(K1_str, expected_K1, 16) == 0);
    cr_assert(memcmp(K2_str, expected_K2, 16) == 0);
}

Test(test_modes, magma_encrypt_imit) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    get_keys_from_master_key(master_key, keys);

    unsigned char mac[4] = {0};

    magma_encrypt_imit(keys, 4, plain_text, mac, 32);

    char result_str[8] = {0};
    bytes_to_hex(mac, result_str, 4);

    char expected_mac[8] = "154e7210";
    
    cr_assert(memcmp(result_str, expected_mac, 8) == 0);
}