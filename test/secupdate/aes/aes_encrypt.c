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

#if defined(HAVE_PBKDF2) && !defined(NO_PWDBASED)

#define KEY_SIZE 32 // 256 bits key size
#define SALT_SIZE 8

/*
 * Generates a cryptographically secure key by stretching a user entered key
 */
int GenerateKey(WC_RNG* rng, byte* key, int size, byte* salt, int pad)
{
    int ret;

    ret = wc_RNG_GenerateBlock(rng, salt, SALT_SIZE);
    if (ret != 0)
        return -1020;

    if (pad == 0)
        salt[0] = 0;
    /* salt[0] == 0 should only be used if pad == 0 */
    else if (salt[0] == 0)
        salt[0] = 1;

    /* stretches key */
    ret = wc_PBKDF2(key, key, strlen((const char*)key), salt, SALT_SIZE, 4096,
        size, WC_SHA256);
    if (ret != 0)
        return -1030;

    return 0;
}

/*
 * Encrypts a file using AES
 */
int AesEncrypt(Aes* aes, byte* key,int size, FILE* inFile, FILE* outFile)
{
    WC_RNG     rng;
    byte    iv[AES_BLOCK_SIZE];
    byte*   input;
    byte*   output;
    byte    salt[SALT_SIZE] = {0};

    int     ret = 0;
    int     inputLength;
    int     length;
    int     padCounter = 0;

    fseek(inFile, 0, SEEK_END);
    inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    length = inputLength;
    /* pads the length until it evenly matches a block / increases pad number*/
    while (length % AES_BLOCK_SIZE != 0) {
        length++;
        padCounter++;
    }

    input = malloc(length);
    output = malloc(length);

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize random number generator\n");
        return -1030;
    }

    /* reads from inFile and writes whatever is there to the input array */
    ret = fread(input, 1, inputLength, inFile);
    if (ret == 0) {
        printf("Input file does not exist.\n");
        return -1010;
    }
    for (int i = inputLength; i < length; i++) {
        /* pads the added characters with the number of pads */
        input[i] = padCounter;
    }

    ret = wc_RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);
    if (ret != 0)
        return -1020;

    /* generate and stretch key */
    ret = GenerateKey(&rng, key, KEY_SIZE, salt, padCounter);
    if (ret != 0)
        return -1040;

    /* set key */
    ret = wc_AesSetKey(aes, key, KEY_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0)
        return -1001;

    /* encrypts the message to the output based on input length + padding */
    ret = wc_AesCbcEncrypt(aes, output, input, length);
    if (ret != 0)
        return -1005;

    /* writes salt, iv, and encrypted data to outFile */
    fwrite(salt, 1, SALT_SIZE, outFile);
    fwrite(iv, 1, AES_BLOCK_SIZE, outFile);
    fwrite(output, 1, length, outFile);

    /* closes the opened files and frees the memory*/
    memset(input, 0, length);
    memset(output, 0, length);
    fclose(inFile);
    fclose(outFile);
    wc_FreeRng(&rng);

    return ret;
}

int main()
{

    Aes aes;
    byte key[KEY_SIZE]; // Fixed key size
    char keyFileName[100];
    char outputFileName[100];
    
    clock_t start, end;
    double cpu_time_used_ms;
    
    clock_t start_total, end_total;
    double total_time_used_ms = 0.0;
    int num_iterations = 1000;
    
        // Open CSV file for writing
    FILE *csv_file = fopen("exp/aes-enc.csv", "w");
    if (csv_file == NULL) {
        printf("Failed to open CSV file for writing.\n");
        return -1;
    }
    
    // Write header to CSV file
    fprintf(csv_file,"%s" ,"aes_encryption[ms]\n");


    start_total = clock();
    for (int i = 1; i <= 1000; i++) {
        sprintf(keyFileName, "sharedkeys/kyber_shared_secret_%d.txt", i);
        FILE* keyFile = fopen(keyFileName, "rb");
        if (keyFile == NULL) {
            printf("Error: Unable to open key file: %s\n", keyFileName);
            return -1;
        }
        
        if (fread(key, 1, KEY_SIZE, keyFile) != KEY_SIZE) {
            printf("Error: Unable to read key from file: %s\n", keyFileName);
            fclose(keyFile);
            return -1;
        }

        fclose(keyFile);
        
        sprintf(outputFileName, "output/output_%d.txt", i);

        FILE* inFile = fopen("input.txt", "rb");
        if (inFile == NULL) {
            printf("Error: Unable to open input file.\n");
            return -1;
        }

        FILE* outFile = fopen(outputFileName, "rb");
        if (outFile == NULL) {
            // If the output file doesn't exist, create it
            outFile = fopen(outputFileName, "wb");
            if (outFile == NULL) {
                printf("Error: Unable to create output file: %s\n", outputFileName);
                fclose(inFile);
                return -1;
            }
        } else {
            fclose(outFile);
            //printf("Output file already exists: %s\n", outputFileName);
            return -1;
        }
        
        start = clock();
        int ret = AesEncrypt(&aes, key, KEY_SIZE, inFile, outFile);
        end = clock();
        
        cpu_time_used_ms = ((double) (end - start)) * 1000.0 / CLOCKS_PER_SEC;
        
        // Write to CSV file
        fprintf(csv_file, "%f\n", cpu_time_used_ms);
        
        if (ret != 0) {
            printf("Encryption failed with error code %d\n", ret);
            return ret;
        }
    }
    end_total = clock(); // End total timing
    // Calculate average time per iteration
    total_time_used_ms = ((double) (end_total - start_total)) * 1000.0 / CLOCKS_PER_SEC;
     double avg_time_per_iteration_ms = total_time_used_ms / num_iterations;

    printf("Total time for 1000 iterations: %f milliseconds\n", total_time_used_ms);
    printf("Average time per iteration: %.2f milliseconds\n", avg_time_per_iteration_ms);
}
#endif
