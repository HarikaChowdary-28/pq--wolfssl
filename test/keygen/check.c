#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/ssl.h>
#include <sys/types.h>
#include <sys/stat.h>


/*#if defined(HAVE_SPHINCS)
    #include <wolfssl/wolfcrypt/sphincs.h>
#endif
#if defined(HAVE_XMSS)
    #include <wolfssl/wolfcrypt/xmss.h>
#endif
#if defined(HAVE_FALCON)
    #include <wolfssl/wolfcrypt/falcon.h>
#endif
#if defined(HAVE_DILITHIUM)
    #include <wolfssl/wolfcrypt/dilithium.h>
#endif
#if defined(HAVE_ECC)
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

*/

#ifndef WOLFSSL_DEBUG_TLS
    #define WOLFSSL_DEBUG_TLS   /* enable full debugging */
#endif
#ifndef DEBUG_WOLFSSL
    #define DEBUG_WOLFSSL
#endif
#ifndef WOLFSSL_CERT_EXT
    #define WOLFSSL_CERT_EXT
#endif

#if defined(HAVE_DILITHIUM)
#include <stdint.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/dilithium_packing.h>
#include <wolfssl/wolfcrypt/dilithium_polynoms.h>
#include <wolfssl/wolfcrypt/dilithium_symmetric.h>
#define MAX_MESSAGE_LEN 1024
#define BUFFER_SZ 60000

int keygen(const char* msg_file) {
int ret=0;
      DilithiumKey key;
    byte signature[DILITHIUM_SIG_SIZE];
    word32 signature_len = sizeof(signature); 
    
    byte file_msg[BUFFER_SZ];
    size_t file_msg_len = 0;
    
    // Initialize key object
    wc_InitDilithiumKey(&key);

    // Generate key pair
    WC_RNG rng;
    wc_InitRng(&rng);
    if (wc_DilithiumKeyGen(&key, &rng) != 0) {
        printf("Error generating key pair.\n");
        return -1;
    }

      // Load and sign the message 
    if (ret == 0) {
        FILE* msg_file_fp = fopen(msg_file, "rb");
        if (msg_file_fp) {
            file_msg_len = fread(file_msg, 1, BUFFER_SZ, msg_file_fp);
            fclose(msg_file_fp);
            ret = file_msg_len > 0 ? 0 : -1;
        } else {
            ret = -1;
           
        }
    }

    // Sign message
    printf("hi");
    if (wc_DilithiumSign(signature, (long long unsigned int *)&signature_len, file_msg, file_msg_len ,&key.sk, &rng) != 0) {
        printf("Error signing message.\n");
        printf("hi");
        return -1;
    }

    // Verify signature
    
    byte   msg[BUFFER_SZ];
       /* make dummy msg */
        for (int i = 0; i < (int)sizeof(msg); i++)
           msg[i] = (byte)i;
    
       //long long unsigned int* outlen;
    if (wc_DilithiumVerify(msg, DILITHIUM_CRYPTO_BYTES, signature, signature_len, &key.pk) != 0) {
        printf("Signature verification failed.\n");
        return -1;
    } else {
        printf("Signature verified successfully.\n");
    }

    // Clean up
    wc_FreeDilithiumKey(&key);
    wc_FreeRng(&rng);
    return 0;
}

int main(){
keygen("demo.txt");
}
#endif

