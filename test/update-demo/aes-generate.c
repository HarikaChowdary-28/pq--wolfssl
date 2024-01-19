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
/*wolfssl*/
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/ssl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

int main() {
    byte aesKey[32];  // AES-256 key is 32 bytes long
    WC_RNG     rng;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        //printf("wolfSSL_Init failed\n");
        return -1;
    }

    if (wc_InitRng(&rng) != 0) {
        //printf("wc_InitRng failed\n");
        return -1;
    }

    if (wc_RNG_GenerateBlock(&rng, aesKey, sizeof(aesKey)) != 0) {
        //printf("wc_RNG_GenerateBlock failed\n");
        return -1;
    }

    //printf("Generated AES-256 Key: ");
    for (int i = 0; i < sizeof(aesKey); i++) {
        printf("%02x", aesKey[i]);
    }
    printf("\n");

    wc_FreeRng(&rng);
    wolfSSL_Cleanup();

    return 0;
}

