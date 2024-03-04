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
#define BUFFER_SZ 80000

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

//enable falcon
#if defined(HAVE_FALCON)
#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/falcon_inner.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

    
#define MAX_PEM_CERT_SIZE 80000
#define MAX_DER_KEY_SIZE  80000


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

//to verify a certificate chain by taking root.pem(rootcert.pem+icacert.pem) + servercert.pem
int cert1(void)
   { 
    int ret;

    WOLFSSL_CERT_MANAGER* cm = NULL;
    

    const char* caCert     = "./FAL-1_FAL-1_FAL-1/certs/root.pem";
    const char* verifyCert = "./FAL-1_FAL-1_FAL-1/certs/servercert.pem";
    

    wolfSSL_Init();
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif
      
   cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        printf("wolfSSL_CertManagerNew() failed\n");
        return -1;
    }

   
    ret = wolfSSL_CertManagerLoadCA(cm, caCert,NULL);
    
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_CertManagerLoadCA() failed (%d): %s\n",
                ret, wolfSSL_ERR_reason_error_string(ret));
        ret = -1; goto exit;
    }
    
    ret = wolfSSL_CertManagerVerify(cm, verifyCert, WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_CertManagerVerify() failed (%d): %s\n",
                ret, wolfSSL_ERR_reason_error_string(ret));
        ret = -1; goto exit;
    }
    
    printf("Certificate Chain Verification Successful!\n");
  
exit:
    wolfSSL_CertManagerFree(cm);
    wolfSSL_Cleanup();
   return ret;
    }
   
//to take n iterations and calculate the avg time for certificate chain verification
int cert2(void)
{
    int i = 15;
    float sum = 0;
    float avg;
    float avg_t[i];
    
    while(i!=0)
    {
    clock_t t;
    t = clock();    
    cert1();
    i = i-1;   
    
    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds
    avg_t[i] = time_taken; 
 }
    for(i=0;i<15;i++)
    {
    sum = sum + avg_t[i];
    }
    avg = sum/i;
    printf("Average time taken for certificate chain verify to execute after %d iterations: %f seconds \n", i,avg);
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

    byte signature[FALCON_SIG_SIZE];
    word32 signature_len  = sizeof(signature); 
    
    WC_RNG rng;

    FalconKey priv_key;
    FalconKey pub_key;
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
        ret = wc_InitFalconKey(&pub_key);
        check_ret("wc_falcon_init", ret);
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

        ret = wc_ImportFalconPublic(pub_der_buf, pub_der_len , &pub_key);
        check_ret("wc_fal_import_public", ret);
    }
    
 //to read the signature from the given input file and use the public key extracted from certificate and verify the signature using the public key
    if (ret == 0) {

       byte   msg[BUFFER_SZ];
       /* make dummy msg */
        for (int i = 0; i < (int)sizeof(msg); i++)
           msg[i] = (byte)i;
    
       long long unsigned int* outlen;
        // Write signature to file
       
        read_buffer_from_file(sig_file, signature, sizeof(msg)+FALCON_SIG_SIZE);

       size_t signature_len = read_buffer_from_file(sig_file , signature, sizeof(msg)+FALCON_SIG_SIZE);
        if (signature_len == 0) {
        fprintf(stderr, "Failed to read signature from file.\n");
        return -1; // Handle the error as needed
        }
        ret = wc_FalconVerify(msg, &outlen, signature, signature_len, &pub_key);
       check_ret("wc_fal_verify", ret);
    }

    printf("verify result: %s\n", ret == 0 ? "SUCCESS" : "FAILURE");

     wc_FreeFalconKey(&priv_key);
     wc_FreeFalconKey(&pub_key);
     wc_FreeRng(&rng);
    //wolfCrypt_Cleanup();

    return ret;


}
int main(int argc, char** argv) {
    
    /*int ret;
    
    cert1();
    cert2();
    // Process the first set of files
    clock_t start, end;
    double cpu_time_used;
        start = clock();
    // Process the first set of files
    ret = process_verification("rootcert.pem", "rootkey.pem", "f0.zip", "signature1.txt");
    if (ret != 0) return ret;

    // Process the second set of files
    ret = process_verification("icacert.pem", "icakey.pem", "f1.img.xz", "signature2.txt");
    if (ret != 0) return ret;

     // Process the third set of files
    ret = process_verification("servercert.pem", "serverkey.pem", "f2.zip", "signature3.txt");
    if (ret != 0) return ret;
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("Time taken for signature verification: %f seconds\n", cpu_time_used); */
    int ret;
    clock_t start, end;
    double cpu_time_used_ms;
    
    clock_t start_total, end_total;
    double total_time_used_ms = 0.0;
    int num_iterations = 1000;
    
    // Open CSV file for writing
    FILE *csv_file = fopen("fal5_secboot_ver.csv", "w");
    if (csv_file == NULL) {
        printf("Failed to open CSV file for writing.\n");
        return -1;
    }
    
    // Write headers to CSV file
    fprintf(csv_file, "rootver[ms],icaver[ms],serverver[ms]\n");
    
    start_total = clock();
    for (int i = 1; i <= num_iterations; ++i) {
        char root_cert_path[BUFFER_SZ];
        char root_key_path[BUFFER_SZ];
        char ica_cert_path[BUFFER_SZ];
        char ica_key_path[BUFFER_SZ];
        char server_cert_path[BUFFER_SZ];
        char server_key_path[BUFFER_SZ];
        char msg_path[BUFFER_SZ];
        char root_sign[BUFFER_SZ];
        char ica_sign[BUFFER_SZ];
        char server_sign[BUFFER_SZ];

        // Construct file paths for each iteration
        sprintf(root_cert_path, "falcon5/it%d/certs/rootcert.pem", i);
        sprintf(root_key_path, "falcon5/it%d/certs/rootkey.pem", i);
        sprintf(ica_cert_path, "falcon5/it%d/certs/icacert.pem", i);
        sprintf(ica_key_path, "falcon5/it%d/certs/icakey.pem", i);
        sprintf(server_cert_path, "falcon5/it%d/certs/servercert.pem", i);
        sprintf(server_key_path, "falcon5/it%d/certs/serverkey.pem", i);
        sprintf(root_sign, "fal5_signs/root/sign_%d.txt", i);
        sprintf(ica_sign, "fal5_signs/ica/sign_%d.txt", i);
        sprintf(server_sign, "fal5_signs/server/sign_%d.txt", i);

        start = clock();
        ret = process_verification(root_cert_path, root_key_path, "f0.zip", root_sign);
        if (ret != 0) return ret;
        end = clock();
        cpu_time_used_ms = (((double) (end - start)) / CLOCKS_PER_SEC)* 1000.0;
        fprintf(csv_file, "%f,", cpu_time_used_ms);

        // Process and record icasign time
        start = clock();
        ret = process_verification(ica_cert_path, ica_key_path, "f1.img.xz", ica_sign);
        if (ret != 0) return ret;
        end = clock();
        cpu_time_used_ms = (((double) (end - start)) / CLOCKS_PER_SEC)* 1000.0;
        fprintf(csv_file, "%f,", cpu_time_used_ms);

        // Process and record serversign time
        start = clock();
        ret = process_verification(server_cert_path, server_key_path, "f2.zip", server_sign);
        if (ret != 0) return ret;
        end = clock();
        cpu_time_used_ms = (((double) (end - start)) / CLOCKS_PER_SEC)* 1000.0;
        fprintf(csv_file, "%f\n", cpu_time_used_ms);
    }
    end_total = clock(); 
    
    total_time_used_ms = (((double) (end_total - start_total)) / CLOCKS_PER_SEC)* 1000.0;

    printf("Total time for 1000 iterations: %f milliseconds\n", total_time_used_ms);
    
    fclose(csv_file);
    return 0;

    
}

#endif

