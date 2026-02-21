## 💻 Using

Header files for different encryption modes are located in the include/modes

Most of the functions for encryption and decryption are named according to the pattern magma_encrypt_<mode_name> and magma_decrypt_<mode_name>

## 🔍 Examples

> [!WARNING]
> Don't forget to replace the "path_to_project" string with the path to this project.

#### Use dynamic library for counter (CTR) mode

📄 main.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "path_to_project/include/modes/ctr.h"

typedef MagmaResult (*magma_encrypt_ctr_t)(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char iv[CTR_IV_LENGTH], 
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

typedef MagmaResult (*magma_decrypt_ctr_t)(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const unsigned char iv[CTR_IV_LENGTH], 
    const unsigned char *input,
    unsigned char *output,
    const size_t length
);

typedef MagmaResult (*key_expand_t)(const unsigned char master_key[MASTER_KEY_LEN], unsigned char result_keys[ITER_KEYS_COUNT][ITER_KEY_LEN]); 

typedef void (*hex_to_bytes_t)(const char *hex, unsigned char *bytes, size_t len);
typedef int (*bytes_to_hex_t)(const unsigned char *input, char *output, size_t len); 

int main (void) {
    void *handle = dlopen("path_to_project/lib/libmagma.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Loading error: %s\n", dlerror());
        return 1;
    }

    dlerror();
    
    magma_encrypt_ctr_t encrypt = dlsym(handle, "magma_encrypt_ctr");
    magma_decrypt_ctr_t decrypt = dlsym(handle, "magma_decrypt_ctr");
    key_expand_t key_expand = dlsym(handle, "key_expand");

    hex_to_bytes_t hex_to_bytes = dlsym(handle, "hex_to_bytes");
    bytes_to_hex_t bytes_to_hex = dlsym(handle, "bytes_to_hex");

    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[4];
    hex_to_bytes("12345678", iv, 8);

    // key preparation

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);

    if (key_result != MAGMA_SUCCESS) {
        fprintf(stderr, "Error key expand: %d\n", key_result);
        dlclose(handle);
        return 1;
    }

    // Example of encryption

    unsigned char result[32] = {0};

    MagmaResult encrypt_result = encrypt(keys, iv, plain_text, result, 32);

    if (encrypt_result != MAGMA_SUCCESS) {
        fprintf(stderr, "Error encrypt: %d\n", encrypt_result);
        dlclose(handle);
        return 1;
    }

    char result_str[65] = {0};
    bytes_to_hex(result, result_str, 32);

    // Example of decryption

    unsigned char decrypt_result[32] = {0};

    MagmaResult decrypt_result_val = decrypt(keys, iv, result, decrypt_result, 32);

    if (decrypt_result_val != MAGMA_SUCCESS) {
        fprintf(stderr, "Error decrypt: %d\n", decrypt_result_val);
        dlclose(handle);
        return 1;
    }

    char decrypt_str[65] = {0};
    bytes_to_hex(decrypt_result, decrypt_str, 32);

    // Print results

    printf("Cipher text: %s\n", result_str);
    printf("Decrypted text: %s\n", decrypt_str);

    return 0;
}
```

📄 Makefile

```
all:
	gcc -o main main.c -Ipath_to_project/include/
```

<br>

#### Use static library for counter (CTR) mode

📄 main.c

```c
#include <stdio.h>
#include <stdlib.h>
#include "path_to_project/include/modes/ctr.h"

int main (void) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char iv[4];
    hex_to_bytes("12345678", iv, 8);

    // key preparation

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);

    if (key_result != MAGMA_SUCCESS) {
        fprintf(stderr, "Error key expand: %d\n", key_result);
        return 1;
    }

    // Example of encryption

    unsigned char result[32] = {0};

    MagmaResult encrypt_result = magma_encrypt_ctr(keys, iv, plain_text, result, 32);

    if (encrypt_result != MAGMA_SUCCESS) {
        fprintf(stderr, "Error encrypt: %d\n", encrypt_result);
        return 1;
    }

    char result_str[65] = {0};
    bytes_to_hex(result, result_str, 32);
    
    // Example of decryption

    unsigned char decrypt_result[32] = {0};

    MagmaResult decrypt_result_val = magma_decrypt_ctr(keys, iv, result, decrypt_result, 32);

    if (decrypt_result_val != MAGMA_SUCCESS) {
        fprintf(stderr, "Error decrypt: %d\n", decrypt_result_val);
        return 1;
    }

    char decrypt_str[65] = {0};
    bytes_to_hex(decrypt_result, decrypt_str, 32);

    // Print results

    printf("Cipher text: %s\n", result_str);
    printf("Decrypted text: %s\n", decrypt_str);

    return 0;
}
```

📄 Makefile

```
all:
	gcc -o main main.c -Ipath_to_project/include/ path_to_project/lib/libmagma.a
```

<br>

#### Use dynamic library for MAC mode

📄 main.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "path_to_project/include/modes/mac.h"

typedef MagmaResult (*magma_mac_t)(
    const unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN],
    const size_t mac_size,
    const unsigned char *input,
    unsigned char *mac,
    const size_t length
);

typedef MagmaResult (*key_expand_t)(const unsigned char master_key[MASTER_KEY_LEN], unsigned char result_keys[ITER_KEYS_COUNT][ITER_KEY_LEN]); 

typedef void (*hex_to_bytes_t)(const char *hex, unsigned char *bytes, size_t len);
typedef int (*bytes_to_hex_t)(const unsigned char *input, char *output, size_t len); 

int main (void) {
    void *handle = dlopen("path_to_project/lib/libmagma.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Loading error: %s\n", dlerror());
        return 1;
    }

    dlerror();

    magma_mac_t magma_mac = dlsym(handle, "magma_mac");
    key_expand_t key_expand = dlsym(handle, "key_expand");

    hex_to_bytes_t hex_to_bytes = dlsym(handle, "hex_to_bytes");
    bytes_to_hex_t bytes_to_hex = dlsym(handle, "bytes_to_hex");

    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);

    if (key_result != MAGMA_SUCCESS) {
        fprintf(stderr, "Error key expand: %d\n", key_result);
        dlclose(handle);
        return 1;
    }

    unsigned char mac[4] = {0};

    MagmaResult encrypt_result = magma_mac(keys, 4, plain_text, mac, 32);
    
    if (encrypt_result != MAGMA_SUCCESS) {
        fprintf(stderr, "Error encrypt: %d\n", encrypt_result);
        dlclose(handle);
        return 1;
    }

    char result_str[9] = {0};
    bytes_to_hex(mac, result_str, 4);

    printf("MAC: %s\n", result_str);

    return 0;
}
```

📄 Makefile

```
all:
	gcc -o main main.c -Ipath_to_project/include/
```

<br>

#### Use static library for MAC mode

📄 main.c

```c
#include <stdio.h>
#include <stdlib.h>
#include "path_to_project/include/modes/mac.h" 

int main (void) {
    unsigned char plain_text[32];
    hex_to_bytes("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", plain_text, 64);

    unsigned char master_key[32];
    hex_to_bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", master_key, 64);

    unsigned char keys[ITER_KEYS_COUNT][ITER_KEY_LEN] = {0};
    MagmaResult key_result = key_expand(master_key, keys);

    if (key_result != MAGMA_SUCCESS) {
        fprintf(stderr, "Error key expand: %d\n", key_result);
        return 1;
    }

    unsigned char mac[4] = {0};

    MagmaResult encrypt_result = magma_mac(keys, 4, plain_text, mac, 32);
    
    if (encrypt_result != MAGMA_SUCCESS) {
        fprintf(stderr, "Error encrypt: %d\n", encrypt_result);
        return 1;
    }

    char result_str[9] = {0};
    bytes_to_hex(mac, result_str, 4);

    printf("MAC: %s\n", result_str);

    return 0;
}
```

📄 Makefile

```
all:
    gcc -o main main.c -Ipath_to_project/include/ path_to_project/lib/libmagma.a
```