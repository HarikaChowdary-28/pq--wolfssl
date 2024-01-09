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

//enable ECC
#if defined(HAVE_ECC)
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#ifndef WOLFSSL_DEBUG_TLS
    #define WOLFSSL_DEBUG_TLS   /* enable full debugging */
#endif
#ifndef DEBUG_WOLFSSL
    #define DEBUG_WOLFSSL
#endif
#ifndef WOLFSSL_CERT_EXT
    #define WOLFSSL_CERT_EXT
#endif
//enable XMSS 
// ... All necessary defines ...
#if defined(HAVE_XMSS)
    #include <stdint.h>
    #include <wolfssl/wolfcrypt/error-crypt.h>
    #include <wolfssl/wolfcrypt/xmss_hash.h>
    #include <wolfssl/wolfcrypt/xmss_hash_address.h>
    #include <wolfssl/wolfcrypt/xmss.h>
    #include <wolfssl/wolfcrypt/xmss_wots.h>
    #include <wolfssl/wolfcrypt/xmss_utils.h>
    #include <wolfssl/wolfcrypt/xmss_core.h>

#define BUFFER_SZ 60000    
#define MAX_PEM_CERT_SIZE 60000
#define MAX_DER_KEY_SIZE  60000

//to check if every function is working 
static void check_ret(char *func_name, int ret) {
    if (ret != 0) {
        fprintf(stderr, "ERROR: %s() returned %d\n", func_name, ret);
    }
}

//to write contents to sig file
void write_buffer_to_file(const char* filename, const uint8_t* buffer, size_t len) {
    FILE *file = fopen(filename, "w");
    if (file) {
        for (size_t i = 0; i < len; i++) {
            fprintf(file, "%02x", buffer[i]);
        }
        fclose(file);
    }
}

int process_signature(const char* cert_file, const char* key_file, const char* msg_file, const char* sig_file) {
    int ret = 0;

    byte pem_buf[MAX_PEM_CERT_SIZE];
    word32 pem_len = sizeof(pem_buf);

    byte priv_der_buf[MAX_DER_KEY_SIZE];
    word32 priv_der_len = sizeof(priv_der_buf);

    byte signature[XMSS_MAX_SIG_SIZE];
    word32 signature_len = sizeof(signature); 

    byte file_msg[BUFFER_SZ];
    size_t file_msg_len = 0;

    word32 idx = 0;
    WC_RNG rng;
    XmssKey priv_key;

    // Initialize the key and RNG
    ret = wc_InitRng(&rng);
    check_ret("wc_InitRng", ret);

    if (ret == 0) {
        ret = wc_InitXmssKey(&priv_key);
        check_ret("wc_InitXmssKey", ret);
    }

    // Load the private key
    if (ret == 0) {
        FILE* file = fopen(key_file, "rb");
        if (file) {
            pem_len = fread(pem_buf, 1, sizeof(pem_buf), file);
            fclose(file);
            ret = pem_len > 0 ? 0 : -1;
            check_ret("fread key", ret);
        } else {
            ret = -1;
            check_ret("fopen key", ret);
        }
    }

    // Convert PEM to DER
  if (ret == 0) {
        ret = wc_KeyPemToDer((const byte*)pem_buf, pem_len, 
                  priv_der_buf, priv_der_len, NULL);
        if (ret > 0) {
            priv_der_len = ret;
            ret = 0;
        } else {
            check_ret("wc_KeyPemToDer", ret);
            /* In case ret = 0. */
            ret = -1;
        }
    }
    // Decode the private key
    if (ret == 0) {
        ret = wc_XmssPrivateKeyDecode(priv_der_buf, &idx, &priv_key, &priv_der_len);
        check_ret("wc_XmssPrivateKeyDecode", ret);
    }

    // Load and sign the message
    if (ret == 0) {
        FILE* msg_file_fp = fopen(msg_file, "rb");
        if (msg_file_fp) {
            file_msg_len = fread(file_msg, 1, BUFFER_SZ, msg_file_fp);
            fclose(msg_file_fp);
            ret = file_msg_len > 0 ? 0 : -1;
            check_ret("fread message", ret);
        } else {
            ret = -1;
            check_ret("fopen message", ret);
        }
    }

    if (ret == 0) {
    
        ret = wc_XmssSign(signature, (long long unsigned int *)&signature_len, file_msg, file_msg_len, &priv_key);
        check_ret("wc_XmssSign", ret);
    }

    // Write signature to file
    if (ret == 0) {
        write_buffer_to_file(sig_file, signature, signature_len);
        printf("generated signature successfully");
    }
     printf("\n");
    // Free resources
    wc_FreeXmssKey(&priv_key);
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    return ret;
}

int main(int argc, char** argv) {
    int ret;

    // Process the first set of files
    clock_t start, end;
    double cpu_time_used;
    start = clock();
    ret = process_signature("rootcert.pem", "rootkey.pem", "f0.zip", "signature1.txt");
    if (ret != 0) return ret;

    // Process the second set of files
    ret = process_signature("icacert.pem", "icakey.pem", "f1.img.xz", "signature2.txt");
    if (ret != 0) return ret;

     // Process the second set of files
    ret = process_signature("servercert.pem", "serverkey.pem", "f2.zip", "signature3.txt");
    if (ret != 0) return ret;
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("Time taken for signature generation: %f seconds\n", cpu_time_used);

    //
}
#endif