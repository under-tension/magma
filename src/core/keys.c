#include "core/keys.h"

void get_keys_from_master_key(const unsigned char master_key[MASTER_KEY_LEN], unsigned char result_keys[ITER_KEYS_COUNT][ITER_KEY_LEN])
{
    memcpy(result_keys[0], master_key, 4);
    memcpy(result_keys[1], master_key + 4, 4);
    memcpy(result_keys[2], master_key + 8, 4);
    memcpy(result_keys[3], master_key + 12, 4);
    memcpy(result_keys[4], master_key + 16, 4);
    memcpy(result_keys[5], master_key + 20, 4);
    memcpy(result_keys[6], master_key + 24, 4);
    memcpy(result_keys[7], master_key + 28, 4);

    memcpy(result_keys[8], master_key, 4);
    memcpy(result_keys[9], master_key + 4, 4);
    memcpy(result_keys[10], master_key + 8, 4);
    memcpy(result_keys[11], master_key + 12, 4);
    memcpy(result_keys[12], master_key + 16, 4);
    memcpy(result_keys[13], master_key + 20, 4);
    memcpy(result_keys[14], master_key + 24, 4);
    memcpy(result_keys[15], master_key + 28, 4);

    memcpy(result_keys[16], master_key, 4);
    memcpy(result_keys[17], master_key + 4, 4);
    memcpy(result_keys[18], master_key + 8, 4);
    memcpy(result_keys[19], master_key + 12, 4);
    memcpy(result_keys[20], master_key + 16, 4);
    memcpy(result_keys[21], master_key + 20, 4);
    memcpy(result_keys[22], master_key + 24, 4);
    memcpy(result_keys[23], master_key + 28, 4);


    memcpy(result_keys[24], master_key + 28, 4);
    memcpy(result_keys[25], master_key + 24, 4);
    memcpy(result_keys[26], master_key + 20, 4);
    memcpy(result_keys[27], master_key + 16, 4);
    memcpy(result_keys[28], master_key + 12, 4);
    memcpy(result_keys[29], master_key + 8, 4);
    memcpy(result_keys[30], master_key + 4, 4);
    memcpy(result_keys[31], master_key, 4);
}