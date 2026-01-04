#include <stdint.h>
#include "core/keys.h"
#include "core/utils.h"
#include "modes/ecb.h"
#include <criterion/criterion.h>
#include <string.h>

Test(test_ecb, magma_encrypt_ecb) {
    
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);    

    unsigned char result[32] = {0};

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    get_keys_from_master_key(master_key, keys);

    magma_encrypt_ecb(keys, plain_text, result, 32);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}

Test(test_ecb, magma_decrypt_ecb) {
    
    unsigned char plain_text[32];
    hex_to_bytes("2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);    

    unsigned char result[32] = {0};

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    get_keys_from_master_key(master_key, keys);

    magma_decrypt_ecb(keys, plain_text, result, 32);

    char result_str[64];
    bytes_to_hex(result, result_str, 32);

    char expected_result[64] = "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41";
    
    cr_assert(memcmp(result_str, expected_result, 64) == 0);
}
