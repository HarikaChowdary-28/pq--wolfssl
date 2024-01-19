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
    printf("Usage: ./hmac-example <keyfile> <file to hash>\n");
    exit(-99);
}

int main(int argc, char** argv) {
    int ret = -1;
    Hmac hmac;
    byte* key = NULL; // Change the key to a dynamically allocated buffer
    word32 keyLength;
    byte rawInput[CHUNK_SIZE];
    FILE* inputStream;
    char* fName = NULL;
    int fileLength = 0;
    int i, chunkSz;

    if (argc < 3)
        usage();
    
    // Read the key from the keyfile
    char* keyFilename = argv[1];
    FILE* keyFile = fopen(keyFilename, "r");
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

    fName = argv[2];
    //printf("Hash input file %s\n", fName);

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
        ret = wc_HmacFinal(&hmac, hmacResult);
        if (ret == 0) {
           // printf("HMAC-SHA-256 result is: ");
            for (i = 0; i < WC_SHA256_DIGEST_SIZE; i++)
                printf("%02x", hmacResult[i]);
            printf("\n");
        }
    }

    if (ret != 0) {
        printf("ERROR: HMAC operation failed\n");
    }

    fclose(inputStream);
    free(key); // Free the allocated key buffer
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

