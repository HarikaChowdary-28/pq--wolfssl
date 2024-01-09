/* dilthium_sign_verify.c
 *
 * Copyright (C) 2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
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

/* create new dirName */
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

#define CERT_FILE "icacert.pem"
#define KEY_FILE  "icakey.pem"

#define MSG_FILE "f1.img.xz" // Define the file containing the message to sign

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


int main(int argc, char** argv)
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

    byte signature[XMSS_MAX_SIG_SIZE];
    word32 signature_len  = sizeof(signature); 
    
    //size_t msgLen=sizeof(MESSAGE);
   /* uint8_t signature[XMSS_MAX_SIG_SIZE];
    long long unsigned int signature_len  = sizeof(signature);

    const uint8_t msg[] = {0x41, 0x42, 0x43, 0x44, 0x45}; // Represents "ABCDE" in ASCII
    size_t msgLen = sizeof(msg); */
 		

    WC_RNG rng;
   // void *key;
   // XmssKey* priv_key = (XmssKey*)key;
    //XmssKey* pub_key = (XmssKey*)key;
    XmssKey priv_key;
    XmssKey pub_key;
    DecodedCert decodedCert;

    /* Initialize Rng */
     ret = wc_InitRng(&rng);
     if (ret != 0) {
        printf("failed");
    }


    if (ret == 0) {
        ret = wc_InitXmssKey(&priv_key);
        check_ret("wc_xmss_init", ret);
    }
    printf("%d\n",ret);

    if (ret == 0) {
        ret = wc_InitXmssKey(&pub_key);
        check_ret("wc_xmss_init", ret);
    }
   printf("%d\n",ret);
    /* Get private key from key PEM file. */

   /* if (ret == 0) {
        ret = wc_dilithium_set_level(&priv_key, 5);
        check_ret("wc_dilithium_set_level", ret);
    } */

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
    printf("%d\n",ret);

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
    printf("%d\n",ret);
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
        printf ("Success\n");
    }

    
   /* if (ret == 0) {
        ret = wc_ImportXmssPrivate(priv_der_buf, priv_der_len,
                  &priv_key);
        check_ret("wc_xmss_import_private_only", ret);
        // After you've filled priv_der_buf
        write_buffer_to_file("priv_der4.txt", priv_der_buf, priv_der_len);
        }
    printf("%d\n",ret); */
    
    if(ret==0){
    
        word32 idx;
        ret= wc_XmssPrivateKeyDecode(&priv_der_buf, &idx,
                            &priv_key, &priv_der_len);
        write_buffer_to_file("priv_der3.txt", priv_der_buf, priv_der_len);
    }
    printf("%d\n",ret);
    /*if (ret == 0) {
        ret = wc_ImportXmssPrivate(priv_der_buf ,priv_der_len, &priv_key);
        check_ret("wc_xmss_import_private_only", ret);
        // After you've filled priv_der_buf
        write_buffer_to_file("priv_der3.txt", priv_der_buf, priv_der_len);
    } */
    
    // printf("%d\n",ret);
    /* Get public key from certificate PEM file. */

   /* if (ret == 0) {
        ret = wc_dilithium_set_level(&pub_key, 5);
        check_ret("wc_dilithium_set_level", ret);
    } */

    if (ret == 0) {
        file = fopen(CERT_FILE, "rb");
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
    printf("%d\n",ret);

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
    printf("%d\n",ret);
    
       if (ret == 0) {
        file = fopen("out.der", "wb");
        if (file == NULL) {
            ret = -1;
            printf("failed to open out.der\n");
        }
    }

    if (ret == 0) {
        if ((fwrite(cert_der_buf, 1, cert_der_len, file)) != cert_der_len) {
            ret = -1;
            printf ("Failed to write the der file\n");
        }
    }

    //if (ret == 0) {
      //  printf ("Success\n");
    //}

    if (ret == 0) {
        InitDecodedCert(&decodedCert, cert_der_buf, cert_der_len, 0);
        ret = ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
        check_ret("ParseCert", ret);
    }
    printf("%d\n",ret);

    if (ret == 0) {
        ret = wc_GetPubKeyDerFromCert(&decodedCert, pub_der_buf,
                  &pub_der_len);
        check_ret("wc_GetKey", ret);
        //bosch pqc
        printf("pub_der_buf Contents:\n");
        for (size_t i = 0; i < pub_der_len; i++) {
            //printf("%02x ", pub_der_buf[i]);
            //pub_der_buf2[i]=pub_der_buf[i];
            printf("%02x ", pub_der_buf[i]);
            
        }
        // After you've filled pub_der_buf
        write_buffer_to_file("pub_der3.txt", pub_der_buf, pub_der_len);
        printf("%d\n",pub_der_len);
        printf("\n"); 
        //bosch pqc
    }
    printf("%d\n",ret);

    if (ret == 0) {

        ret = wc_ImportXmssPublic(pub_der_buf, pub_der_len , &pub_key);
        check_ret("wc_xmss_import_public", ret);
    }
    printf("%d\n",ret);
    /* We now have the public and private key. Time to sign and verify the
     * message. */

    if (ret == 0) {
       /*ret = wc_dilithium_verify_msg(signature, signature_len,
                 (const byte *)MESSAGE, sizeof(MESSAGE), &verify_result,
                 &pub_key); */
       byte   msg[BUFFER_SZ];
       /* make dummy msg */
        for (int i = 0; i < (int)sizeof(msg); i++)
           msg[i] = (byte)i;
    
       long long unsigned int* outlen;
     size_t signature_len = read_buffer_from_file("signature.txt", signature, sizeof(msg)+XMSS_MAX_SIG_SIZE);
    if (signature_len == 0) {
        fprintf(stderr, "Failed to read signature from file.\n");
        return -1; // Handle the error as needed
    }
       ret = wc_XmssVerify(msg, &outlen, signature, signature_len, &pub_key);
       check_ret("wc_xmss_verify", ret);
       // Print the contents of the signature in hexadecimal format   bosch pqc
         printf("pub_der_buf in verify Contents:\n");
        
        printf("Signature Contents:\n");
        for (size_t i = 0; i < signature_len; i++) {
            printf("%02x ", signature[i]);
        }
        printf("\n");
        //bosch pqc
       printf("%d\n",ret);
    }

    printf("verify result: %s\n", ret == 0 ? "SUCCESS" : "FAILURE");
    printf("%d",ret);

    FreeDecodedCert(&decodedCert);
    wc_FreeXmssKey(&priv_key);
    wc_FreeXmssKey(&pub_key);
    //wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    return ret;
}
#endif

