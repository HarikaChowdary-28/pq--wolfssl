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
 * Decrypts a file using AES
 */
int AesDecrypt(Aes* aes, byte* key, int size, FILE* inFile, FILE* outFile)
{

    WC_RNG     rng;
    byte    iv[AES_BLOCK_SIZE];
    byte*   input;
    byte*   output;
    byte    salt[SALT_SIZE];
 
    int i;
    int     ret = 0;
    int     length;
    int     aSize;

    input = NULL;
    output = NULL;
    
    wc_InitRng(&rng);

    fseek(inFile, 0, SEEK_END);
    length = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    aSize = length;

    input = malloc(aSize);
    if (input == NULL) {
        printf("Failed to allocate memory for input buffer.\n");
        return -1;
    }
    
    output = malloc(aSize);
    if (output == NULL) {
        printf("Failed to allocate memory for output buffer.\n");
        free(input);
        return -1;
    }

    /* reads from inFile and writes whatever is there to the input array */
    ret = fread(input, 1, length, inFile);
    if (ret == 0) {
        printf("Input file does not exist.\n");
        free(input);
        free(output);
        return -1;
    }

     for (i = 0; i < SALT_SIZE; i++) {
        /* finds salt from input message */
        salt[i] = input[i];
    }
    for (i = SALT_SIZE; i < AES_BLOCK_SIZE + SALT_SIZE; i++) {
        /* finds iv from input message */
        iv[i - SALT_SIZE] = input[i];
    }

    /* replicates old key if keys match */
    ret = wc_PBKDF2(key, key, strlen((const char*)key), salt, SALT_SIZE, 4096,
        size, WC_SHA256);
    if (ret != 0)
        return -1050;

    /* set key */
    ret = wc_AesSetKey(aes, key, KEY_SIZE, iv, AES_DECRYPTION);
    if (ret != 0) {
        printf("Failed to set AES key.\n");
        free(input);
        free(output);
        return -1;
    }
    
    /* change length to remove salt/iv block from being decrypted */
    length -= (AES_BLOCK_SIZE + SALT_SIZE);
    for (i = 0; i < length; i++) {
        /* shifts message: ignores salt/iv on message*/
        input[i] = input[i + (AES_BLOCK_SIZE + SALT_SIZE)];
    }

    /* decrypts the message */
    ret = wc_AesCbcDecrypt(aes, output, input , length);
    if (ret != 0) {
        printf("Decryption failed.\n");
        free(input);
        free(output);
        return -1;
    }
     if (salt[0] != 0) {
        /* reduces length based on number of padded elements */
        length -= output[length-1];
    }
    /* writes output to the outFile based on shortened length */
    fwrite(output, 1, length, outFile);

    /* closes the opened files and frees the memory*/
    memset(input, 0, aSize);
    memset(output, 0, aSize);
    memset(key, 0, size);
    free(input);
    free(output);
    fclose(inFile);
    fclose(outFile);
     wc_FreeRng(&rng);
     
    return 0;
}

int main()
{
    Aes aes;
    byte key[KEY_SIZE]; // Fixed key size

     char keyFileName[50];
     char inputFileName[100];
     char outputFileName[100];

     clock_t start, end;
    double cpu_time_used_ms;
    
    clock_t start_total, end_total;
    double total_time_used_ms = 0.0;
    int num_iterations = 1000;
    
    // Open CSV file for writing
    FILE *csv_file = fopen("aes-dec.csv", "w");
    if (csv_file == NULL) {
        printf("Failed to open CSV file for writing.\n");
        return -1;
    }
    
    // Write header to CSV file
    fprintf(csv_file,"%s" ,"aes_decryption[ms]\n");


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

    sprintf(inputFileName, "output/output_%d.txt", i);
    FILE* inFile = fopen(inputFileName, "rb");
     if (inFile == NULL) {
            printf("Error: Unable to open input file.\n");
            return -1;
        }
        
      sprintf(outputFileName, "output-d/output-d_%d.txt", i);
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
        
    int ret = AesDecrypt(&aes, key, KEY_SIZE, inFile, outFile);
     end = clock();
        
        cpu_time_used_ms = ((double) (end - start)) * 1000.0 / CLOCKS_PER_SEC;
        
        // Write to CSV file
        fprintf(csv_file, "%f\n", cpu_time_used_ms);
        
    if (ret != 0) {
        printf("Decryption failed with error code %d\n", ret);
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
