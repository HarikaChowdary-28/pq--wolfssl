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
#define BUFFER_SZ 100000

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
#if defined(HAVE_XMSS)
    #include <stdint.h>
    #include <wolfssl/wolfcrypt/error-crypt.h>
    #include <wolfssl/wolfcrypt/xmss_hash.h>
    #include <wolfssl/wolfcrypt/xmss_hash_address.h>
    #include <wolfssl/wolfcrypt/xmss.h>
    #include <wolfssl/wolfcrypt/xmss_wots.h>
    #include <wolfssl/wolfcrypt/xmss_utils.h>
    #include <wolfssl/wolfcrypt/xmss_core.h>

    
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


int main(int argc, char** argv)
{
    #define CERT_FILE "rootcert.pem"
    #define KEY_FILE  "rootkey.pem"

    #define MSG_FILE "f0.zip" // Define the file containing the message to sign
    int ret = 0;
    FILE *file = (byte*)XMALLOC(BUFFER_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    byte pem_buf[MAX_PEM_CERT_SIZE];
    word32 pem_len = sizeof(pem_buf);

    byte priv_der_buf[MAX_DER_KEY_SIZE];
    word32 priv_der_len = sizeof(priv_der_buf);

    byte cert_der_buf[MAX_PEM_CERT_SIZE];
    word32 cert_der_len = sizeof(cert_der_buf);

    byte signature[XMSS_MAX_SIG_SIZE];
    word32 signature_len  = sizeof(signature); 
    
    WC_RNG rng;

    XmssKey priv_key;
    XmssKey pub_key;
    DecodedCert decodedCert;
    word32 idx;

    /* Initialize Rng */
     ret = wc_InitRng(&rng);
     if (ret != 0) {
        printf("failed");
    }


    if (ret == 0) {
        ret = wc_InitXmssKey(&priv_key);
        check_ret("wc_xmss_init", ret);
    }
    //printf("%d\n",ret);

    if (ret == 0) {
        file = fopen(KEY_FILE, "rb");
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
    //printf("%d\n",ret);

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
    //printf("%d\n",ret);
      if (ret == 0) {
        file = fopen("key.der", "wb");
        if (file == NULL) {
            ret = -1;
            printf("failed to open key.der\n");
        }
    }

    if (ret == 0) {
        if ((fwrite(priv_der_buf, 1, priv_der_len, file)) != priv_der_len) {
            ret = -1;
            printf ("Failed to write the der file\n");
        }
    }

    if (ret == 0) {
        //printf ("Success\n");
    }
    
    if(ret==0){
        ret= wc_XmssPrivateKeyDecode(&priv_der_buf, &idx,
                            &priv_key, &priv_der_len);
        write_buffer_to_file("priv_der3.txt", priv_der_buf, priv_der_len);
    }
    //printf("%d\n",ret);

    if (ret == 0) {

    // Buffer to hold the message read from a file
    byte file_msg[BUFFER_SZ];
    size_t file_msg_len;

    // Open the file containing the message
    FILE* msg_file = fopen(MSG_FILE, "rb");
    if (msg_file == NULL) {
        perror("Failed to open message file");
        return -1; // or some error handling
    }

    // Read the message into the buffer
    file_msg_len = fread(file_msg, 1, BUFFER_SZ, msg_file);
    if (file_msg_len == 0 && !feof(msg_file)) {
        perror("Failed to read message file");
        fclose(msg_file);
        return -1; // or some error handling
    }
    fclose(msg_file);
        ret=wc_XmssSign(signature, (long long unsigned int*)&signature_len, file_msg, file_msg_len, &priv_key);
        
        check_ret("wc_xmss_sign_msg", ret);
        // Print the contents of the signature in hexadecimal format   bosch pqc
         /*printf("Signature Contents:\n");
        for (size_t i = 0; i < signature_len; i++) {
            printf("%02x ", signature[i]);
        }*/
        // After you've filled signature
        write_buffer_to_file("signature.txt", signature, signature_len);

        //printf("\n");
        // Truncate the last 4 bytes from the signature
        // Ensure signature is long enough to remove 4 bytes
      /*  if (signature_len <= 4) {
        // Handle error: signature too short to truncate
           fprintf(stderr, "Error: Signature too short to truncate the last 4 bytes\n");
           ret = -1; // Set to an error code indicating the signature is too short
           } else {
                signature_len -= 4; // Adjust length to remove the last 4 bytes
                  } */
        //msg
        //bosch pqc
   
    }
    //printf("%d\n",ret);
    FreeDecodedCert(&decodedCert);
    wc_FreeXmssKey(&priv_key);
    //wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    return ret;
}
    //
#endif

