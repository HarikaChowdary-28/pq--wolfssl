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
#include <wolfssl/test.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#define BUFFER_SZ 60000

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

//enable dilithium
#if defined(HAVE_DILITHIUM)
#include <stdint.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/dilithium_packing.h>
#include <wolfssl/wolfcrypt/dilithium_polynoms.h>
#include <wolfssl/wolfcrypt/dilithium_symmetric.h>


#define MAX_PEM_CERT_SIZE 60000
#define MAX_DER_KEY_SIZE  60000


static void check_ret(char *func_name, int ret) {
    if (ret != 0) {
        fprintf(stderr, "ERROR: %s() returned %d\n", func_name, ret);
    }
}

// Function to write buffer content to file in hex format
void write_buffer_to_file(const char* filename, const uint8_t* buffer, size_t len) {
    FILE *file = fopen(filename, "w");
    if (file) {
        for (size_t i = 0; i < len; i++) {
            fprintf(file, "%02x", buffer[i]); // Removed the space after %02x
        }
        fclose(file);
    }
}
// Function to read buffer content from file in hex format
size_t read_buffer_from_file(const char* filename, uint8_t* buffer, size_t max_len) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "ERROR: Unable to open file %s for reading.\n", filename);
        return 0;
    }

    size_t len = 0;
    unsigned int byte;
    while (fscanf(file, "%02x", &byte) == 1 && len < max_len) {
        buffer[len++] = (uint8_t)byte;
    }

    fclose(file);
    return len; // Return the number of bytes read
}


//to verify the signatures generated at root, ica and leaf level in a cerificate chain
int process_verification(const char* cert_file, const char* key_file, const char* msg_file, const char* sig_file)
{
    
    int ret = 0;
    int verify_result = -1;
    FILE *file = (byte*)XMALLOC(BUFFER_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    byte pem_buf[MAX_PEM_CERT_SIZE];
    word32 pem_len = sizeof(pem_buf);

    byte priv_der_buf[MAX_DER_KEY_SIZE];
    word32 priv_der_len = sizeof(priv_der_buf);

    byte cert_der_buf[MAX_PEM_CERT_SIZE];
    word32 cert_der_len = sizeof(cert_der_buf);

    byte pub_der_buf[MAX_DER_KEY_SIZE];
    word32 pub_der_len = sizeof(pub_der_buf);

    byte signature[DILITHIUM_SIG_SIZE];
    word32 signature_len  = sizeof(signature); 
    
    WC_RNG rng;

    DilithiumKey priv_key;
    DilithiumKey pub_key;
    DecodedCert decodedCert;
    word32 idx;

    byte file_msg[BUFFER_SZ];
    size_t file_msg_len = 0;

    /* Initialize Rng */
     ret = wc_InitRng(&rng);
     if (ret != 0) {
        printf("failed");
    }

    if (ret == 0) {
        ret = wc_InitDilithiumKey(&pub_key);
        check_ret("wc_Dilithium_init", ret);
    }

    if (ret == 0) {
        file = fopen(key_file, "rb");
        ret = fread(pem_buf, 1, sizeof(pem_buf), file);
        fclose(file);
        file = NULL;
        if (ret > 0) {
            pem_len = ret;
            ret = 0;
        } else {
            check_ret("fread", ret);
            ret = -1;
        }
    }
    
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
      
    if (ret == 0) {
        file = fopen(cert_file, "rb");
        ret = fread(pem_buf, 1, sizeof(pem_buf), file);
        fclose(file);
        file = NULL;
        if (ret > 0) {
            pem_len = ret;
            ret = 0;
        } else {
            check_ret("fread", ret);
            ret = -1;
        }
    }
     //to convert a pem certficate which we give as input to der format
    if (ret == 0) {
        ret = wc_CertPemToDer((const byte*)pem_buf, pem_len, cert_der_buf,
                  cert_der_len, CERT_TYPE);
        if (ret > 0) {
            cert_der_len = ret;
            ret = 0;
        } else {
            check_ret("wc_CertPemToDer", ret);
            /* In case ret = 0. */
            ret = -1;
        }
    }
 
    if (ret == 0) {
       //to initialize the decoded certficate which converted to der format
        InitDecodedCert(&decodedCert, cert_der_buf, cert_der_len, 0);
        //to parse the decoded certificate 
        ret = ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
        check_ret("ParseCert", ret);
    }

    //to extract the puclic key available in certificate and use it for verification purpose
    if (ret == 0) {
        ret = wc_GetPubKeyDerFromCert(&decodedCert, pub_der_buf,
                  &pub_der_len);
        check_ret("wc_GetKey", ret);
    }

    //to import the public key that got extracted in der format and store it in pub_key
    if (ret == 0) {

        ret = wc_ImportDilithiumPublic(pub_der_buf, pub_der_len , &pub_key);
        check_ret("wc_dil_import_public", ret);
    }

    //to read the signature from the given input file and use the public key extracted from certificate and verify the signature using the public key
    if (ret == 0) {

       byte   msg[BUFFER_SZ];
       /* make dummy msg */
        for (int i = 0; i < (int)sizeof(msg); i++)
           msg[i] = (byte)i;
    
       long long unsigned int* outlen;
        // Write signature to file
       
        read_buffer_from_file(sig_file, signature, sizeof(msg)+DILITHIUM_SIG_SIZE);

        size_t signature_len = read_buffer_from_file(sig_file , signature, sizeof(msg)+DILITHIUM_SIG_SIZE);
        if (signature_len == 0) {
        fprintf(stderr, "Failed to read signature from file.\n");
        return -1; // Handle the error as needed
        }
        ret = wc_DilithiumVerify(msg, &outlen, signature, signature_len, &pub_key);
       check_ret("wc_dil_verify", ret);
    }

    printf("verify result: %s\n", ret == 0 ? "SUCCESS" : "FAILURE");

     wc_FreeDilithiumKey(&priv_key);
     wc_FreeDilithiumKey(&pub_key);
     wc_FreeRng(&rng);
    //wolfCrypt_Cleanup();

    return ret;


}
int main(int argc, char** argv) {
   
    int ret;
    clock_t start, end;
    double cpu_time_used;
        start = clock();
    // Process the first set of files
    ret = process_verification("servercert.pem", "serverkey.pem", "hmac-encrypted.txt", "upd-sign.txt");
    if (ret != 0) return ret;
     end = clock();
       cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("Time taken for signature verification: %f seconds\n", cpu_time_used);

}

#endif

