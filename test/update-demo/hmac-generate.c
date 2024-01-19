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

int main() {
    int ret = 0;
     WC_RNG     rng;
     byte hmacKey[32];  // HMAC-SHA-256 key is 32 bytes long

    /* Initialize wolfCrypt and the random number generator */
    if (wolfCrypt_Init() != 0) {
        //printf("wolfCrypt_Init failed\n");
        return -1;
    }

    if (wc_InitRng(&rng) != 0) {
        //printf("wc_InitRng failed\n");
        return -1;
    }

    /* Generate a random HMAC key */
    if (wc_RNG_GenerateBlock(&rng, hmacKey, sizeof(hmacKey)) != 0) {
        //printf("wc_RNG_GenerateBlock failed\n");
        ret = -1;
    } else {
        //printf("Generated HMAC-SHA-256 Key: ");
        for (int i = 0; i < sizeof(hmacKey); i++) {
            printf("%02x", hmacKey[i]);
        }
        printf("\n");
    }

    /* Clean up resources */
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    return ret;
}

