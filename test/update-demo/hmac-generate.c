#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/ssl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <stdio.h>

void print_hex(const byte *data, int len, FILE *fp) {
    for (int i = 0; i < len; i++) {
        fprintf(fp, "%02x", data[i]);
    }
}

int main() {
    int ret = 0;
     WC_RNG     rng;
     byte hmacKey[32];  // HMAC-SHA-256 key is 32 bytes long
     char filename[256];

    for (int key_num = 1; key_num <= 1000; key_num++) {
    if (wolfCrypt_Init() != 0) {
        //printf("wolfCrypt_Init failed\n");
        return -1;
    }

    if (wc_InitRng(&rng) != 0) {
        //printf("wc_InitRng failed\n");
        return -1;
    }

    if (wc_RNG_GenerateBlock(&rng, hmacKey, sizeof(hmacKey)) != 0) {
        //printf("wc_RNG_GenerateBlock failed\n");
        ret = -1;
    } 
     // Save key to file in hexadecimal format
        snprintf(filename, sizeof(filename), "hmac_keys/hmac_key_%d.txt", key_num);
        FILE *fp = fopen(filename, "w");
        if (fp == NULL) {
            printf("Failed to open file for writing: %s\n", filename);
            return -1;
        }
        print_hex(hmacKey, sizeof(hmacKey), fp);
        fclose(fp);
    
    }

    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    return ret;
}

