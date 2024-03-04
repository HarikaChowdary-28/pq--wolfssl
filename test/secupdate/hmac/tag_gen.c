#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <stdio.h>
#include <stdlib.h> // Add this for memory allocation
#include <string.h> // Add this for string manipulation

#ifndef CHUNK_SIZE
#define CHUNK_SIZE 1024
#endif

#ifndef NO_SHA256
#ifndef NO_HMAC

void usage(void) {
    printf("Usage: ./hmac-example \n");
    exit(-99);
}

int main(int argc, char** argv) {

    clock_t start, end;
    double cpu_time_used_ms;
    
    clock_t start_total, end_total;
    double total_time_used_ms = 0.0;
    int num_iterations = 1000;
    
    int ret = -1;
    Hmac hmac;
    byte* key = NULL; // Change the key to a dynamically allocated buffer
    word32 keyLength;
    byte rawInput[CHUNK_SIZE];
    FILE* inputStream;
    char* fName = NULL;
    int fileLength = 0;
    int i, chunkSz;

    if (argc < 1)
        usage();

    char keyFilename[256];
    FILE* keyFile;

    // Open CSV file for writing
    FILE *csv_file = fopen("exp/hmac_tag.csv", "w");
    if (csv_file == NULL) {
        printf("Failed to open CSV file for writing.\n");
        return -1;
    }
    
    // Write header to CSV file
    fprintf(csv_file,"%s" ,"tag_gen[ms]\n");
    
    start_total = clock();

    // Iterate for 1000 times
    for (int key_num = 1; key_num <= 1000; key_num++) {
        // Read the key from the keyfile
        snprintf(keyFilename, sizeof(keyFilename), "hmac_keys/hmac_key_%d.txt", key_num);
        keyFile = fopen(keyFilename, "r");
        if (keyFile == NULL) {
            perror("Error opening keyfile");
            return -1;
        }

        fseek(keyFile, 0, SEEK_END);
        keyLength = ftell(keyFile) / 2; // Each byte is represented by 2 characters
        fseek(keyFile, 0, SEEK_SET);

        key = (byte*)malloc(keyLength);
        if (key == NULL) {
            perror("Memory allocation failed");
            fclose(keyFile);
            return -1;
        }

        for (i = 0; i < keyLength; i++) {
            if (fscanf(keyFile, "%2hhx", &key[i]) != 1) {
                perror("Error reading keyfile");
                fclose(keyFile);
                free(key);
                return -1;
            }
        }

        fclose(keyFile);

        // Open the input file
        fName = "input.txt"; // Input file name
        inputStream = fopen(fName, "rb");
        if (inputStream == NULL) {
            printf("ERROR: Unable to open file %s\n", fName);
            free(key);
            return -1;
        }

        /* Find the length of the file */
        fseek(inputStream, 0, SEEK_END);
        fileLength = (int)ftell(inputStream);
        fseek(inputStream, 0, SEEK_SET);

        /* Initialize HMAC context */
        wc_HmacInit(&hmac, NULL, 0); // No initialization required based on provided wc_HmacInit implementation

        /* Loop reading a block at a time, finishing with any excess */
        for (i = 0; i < fileLength; i += CHUNK_SIZE) {
            chunkSz = CHUNK_SIZE;
            if (chunkSz > fileLength - i)
                chunkSz = fileLength - i;

            ret = fread(rawInput, 1, chunkSz, inputStream);
            if (ret != chunkSz) {
                printf("ERROR: Failed to read the appropriate amount\n");
                ret = -1;
                break;
            }

            ret = wc_HmacSetKey(&hmac, WC_SHA256, key, keyLength);

            if (ret != 0) {
                printf("Failed to set the HMAC\n");
                break;
            }

            ret = wc_HmacUpdate(&hmac, rawInput, chunkSz);
            if (ret != 0) {
                printf("Failed to update the HMAC\n");
                break;
            }
        }

        if (ret == 0) {
            byte hmacResult[WC_SHA256_DIGEST_SIZE];
            start = clock();
            ret = wc_HmacFinal(&hmac, hmacResult);
            end = clock();
            
            cpu_time_used_ms = ((double) (end - start)) * 1000.0 / CLOCKS_PER_SEC;
         
             // Write to CSV file
             fprintf(csv_file, "%f\n", cpu_time_used_ms);
            if (ret == 0) {
                char tagFilename[256];
                snprintf(tagFilename, sizeof(tagFilename), "hmac_tags/hmac_tag_%d.txt", key_num);
                FILE* tagFile = fopen(tagFilename, "w");
                if (tagFile == NULL) {
                    printf("Failed to open file for writing: %s\n", tagFilename);
                    ret = -1;
                    break;
                }
                // Write the HMAC-SHA-256 result to the tag file
                for (i = 0; i < WC_SHA256_DIGEST_SIZE; i++)
                    fprintf(tagFile, "%02x", hmacResult[i]);
                fprintf(tagFile, "\n");
                fclose(tagFile);
            }
        }

        if (ret != 0) {
            printf("ERROR: HMAC operation failed\n");
        }

        fclose(inputStream);
        free(key); // Free the allocated key buffer
    }
    
    end_total = clock(); 
    
    total_time_used_ms = ((double) (end_total - start_total)) * 1000.0 / CLOCKS_PER_SEC;
     double avg_time_per_iteration_ms = total_time_used_ms / num_iterations;

    printf("Total time for 1000 iterations: %f milliseconds\n", total_time_used_ms);
    printf("Average time per iteration: %.2f milliseconds\n", avg_time_per_iteration_ms);

    return 0;
}
#else
int main(void) {
    printf("HMAC is disabled (NO_HMAC is defined).\n");
    return -1;
}
#endif
#else
int main(void) {
    printf("SHA-256 is disabled (NO_SHA256 is defined).\n");
    return -1;
}
#endif

