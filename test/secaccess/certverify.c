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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifndef WOLFSSL_DEBUG_TLS
    #define WOLFSSL_DEBUG_TLS  
#endif
#ifndef DEBUG_WOLFSSL
    #define DEBUG_WOLFSSL
#endif
#ifndef WOLFSSL_CERT_EXT
    #define WOLFSSL_CERT_EXT
#endif

#define BUFFER_SZ 60000
#define NUM_CERTS 100
#define CSV_FILENAME "exp/SP1-FAL1_certverify.csv"

#if defined(HAVE_SPHINCS)
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

int main()
{
    const char *rootCertFiles[NUM_CERTS];
    const char *icaCertFiles[NUM_CERTS];
    const char *serverCertFiles[NUM_CERTS];
    FILE *csvFile;
    WOLFSSL_X509 *rootCert;
    WOLFSSL_X509 *icaCert;
    WOLFSSL_X509 *serverCert;
    WOLFSSL_X509_STORE *store;
    WOLFSSL_X509_STORE_CTX *ctx;
    int verifyResult;
    clock_t startTime, endTime;
    double rootToIcaTime[NUM_CERTS], icaToServerTime[NUM_CERTS], totalTime[NUM_CERTS];

    // Populate file paths for root certificates, intermediate CA certificates, and server certificates
    for (int i = 0; i < NUM_CERTS; i++) {
        char filename[100];
        snprintf(filename, sizeof(filename), "mixed/sp1-fal1/it%d/certs/rootcert.pem", i + 1);
        rootCertFiles[i] = strdup(filename);
        snprintf(filename, sizeof(filename), "mixed/sp1-fal1/it%d/certs/icacert.pem", i + 1);
        icaCertFiles[i] = strdup(filename);
        snprintf(filename, sizeof(filename), "mixed/sp1-fal1/it%d/certs/servercert.pem", i + 1);
        serverCertFiles[i] = strdup(filename);
    }

    // Initialize WolfSSL
    if (wolfSSL_Init() != SSL_SUCCESS) {
        printf("Error initializing WolfSSL\n");
        return -1;
    }

    // Open CSV file for writing
    csvFile = fopen(CSV_FILENAME, "w");
    if (csvFile == NULL) {
        printf("Error opening CSV file\n");
        return -1;
    }

    // Write header to CSV file
    fprintf(csvFile, "RootToIca[ms], IcaToServer[ms], TotalTime[ms]\n");

    // Iterate over each set of certificates
    for (int i = 0; i < NUM_CERTS; i++) {
        // Load the root CA certificate
        store = wolfSSL_X509_STORE_new();
        if (store == NULL) {
            printf("Error creating X509 store\n");
            return -1;
        }

        if (wolfSSL_X509_STORE_load_locations(store, rootCertFiles[i], NULL) != SSL_SUCCESS) {
            printf("Error loading root CA certificate\n");
            wolfSSL_X509_STORE_free(store);
            return -1;
        }

        // Load the intermediate CA certificate
        rootCert = wolfSSL_X509_load_certificate_file(rootCertFiles[i], SSL_FILETYPE_PEM);
        if (rootCert == NULL) {
            printf("Error loading root CA certificate\n");
            wolfSSL_X509_STORE_free(store);
            return -1;
        }
        
         if (wolfSSL_X509_STORE_load_locations(store, icaCertFiles[i], NULL) != SSL_SUCCESS) {
            printf("Error loading ICA certificate\n");
            wolfSSL_X509_STORE_free(store);
            return -1;
        }

        icaCert = wolfSSL_X509_load_certificate_file(icaCertFiles[i], SSL_FILETYPE_PEM);
        if (icaCert == NULL) {
            printf("Error loading intermediate CA certificate\n");
            wolfSSL_X509_STORE_free(store);
            return -1;
        }

        // Load the end-entity server certificate
        serverCert = wolfSSL_X509_load_certificate_file(serverCertFiles[i], SSL_FILETYPE_PEM);
        if (serverCert == NULL) {
            printf("Error loading server certificate\n");
            wolfSSL_X509_STORE_free(store);
            wolfSSL_X509_free(icaCert);
            return -1;
        }

        // Measure time taken to verify ICACert by RootCert
        startTime = clock();
        // Initialize the X509 store context
        ctx = wolfSSL_X509_STORE_CTX_new();
        if (ctx == NULL) {
            printf("Error creating X509 store context\n");
            wolfSSL_X509_STORE_free(store);
            wolfSSL_X509_free(icaCert);
            wolfSSL_X509_free(serverCert);
            return -1;
        }
        // Add the root CA certificate to the store
        if (wolfSSL_X509_STORE_add_cert(store, rootCert) != SSL_SUCCESS) {
            printf("Error adding root CA certificate to store\n");
            wolfSSL_X509_STORE_CTX_free(ctx);
            wolfSSL_X509_STORE_free(store);
            wolfSSL_X509_free(icaCert);
            wolfSSL_X509_free(serverCert);
            return -1;
        }
        // Initialize the context with the intermediate CA certificate and perform the verification
        if (wolfSSL_X509_STORE_CTX_init(ctx, store, icaCert, NULL) != SSL_SUCCESS) {
            printf("Error initializing X509 store context\n");
            wolfSSL_X509_STORE_CTX_free(ctx);
            wolfSSL_X509_STORE_free(store);
            wolfSSL_X509_free(icaCert);
            wolfSSL_X509_free(serverCert);
            return -1;
        }
        // Verify the certificate chain
        verifyResult = wolfSSL_X509_verify_cert(ctx);
        if (verifyResult != SSL_SUCCESS) {
        printf("Certificate verification failed: %d\n", verifyResult);
    } else {
        printf("Certificate verification succeeded\n");
    }
        
        // Record end time
        endTime = clock();
        // Calculate elapsed time
       rootToIcaTime[i] = (((double)(endTime - startTime)) / CLOCKS_PER_SEC) * 1000.0;

        // Measure time taken to verify ServerCert by ICACert
        startTime = clock();
        // Initialize the context with the server certificate and perform the verification
        if (wolfSSL_X509_STORE_CTX_init(ctx, store, serverCert, icaCert) != SSL_SUCCESS) {
            printf("Error initializing X509 store context\n");
            wolfSSL_X509_STORE_CTX_free(ctx);
            wolfSSL_X509_STORE_free(store);
            wolfSSL_X509_free(icaCert);
            wolfSSL_X509_free(serverCert);
            return -1;
        }
        // Verify the certificate chain
        verifyResult = wolfSSL_X509_verify_cert(ctx);
        
       if (verifyResult != SSL_SUCCESS) {
        printf("Certificate verification failed: %d\n", verifyResult);
    } else {
        printf("Certificate verification succeeded\n");
    }
        
        // Record end time
        endTime = clock();
        // Calculate elapsed time
        icaToServerTime[i] = (((double)(endTime - startTime)) / CLOCKS_PER_SEC) * 1000.0;

        // Calculate total time taken for the entire chain verification
        totalTime[i] = rootToIcaTime[i] + icaToServerTime[i];

        // Write verification result and time taken to CSV file
        fprintf(csvFile, "%.6f, %.6f, %.6f\n", rootToIcaTime[i], icaToServerTime[i], totalTime[i]);

        // Clean up resources for this iteration
        wolfSSL_X509_STORE_CTX_free(ctx);
        wolfSSL_X509_free(rootCert);
        wolfSSL_X509_free(icaCert);
        wolfSSL_X509_free(serverCert);
        wolfSSL_X509_STORE_free(store);
    }

    // Close CSV file
    fclose(csvFile);

    // Clean up WolfSSL
    wolfSSL_Cleanup();

    return 0;
}
