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

#include <cyassl/options.h>
#include <wolfssl/options.h>
    

/* enable kyber */ 

#if defined (HAVE_KYBER)

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

#include <wolfssl/wolfcrypt/kyber.h>
#include <wolfssl/wolfcrypt/kyber_memory.h>
#include <wolfssl/wolfcrypt/kyber_polynoms.h>
#include <wolfssl/wolfcrypt/kyber_symmetric.h>
#include <wolfssl/wolfcrypt/kyber_arithmetic.h>
    


// Function to print the content of a KyberKey byte objects without spaces
void printByteArray(const byte *array, size_t length, const char *label) 
{
    printf("%s:", label);
    for (size_t i = 0; i < length; ++i) 
    {
        printf("%02x", array[i]);
    }
    printf("\n");
}

// Function to store the content of a KyberKey byte objects without spaces
void writeByteArrayToFile(const byte *array, size_t length, const char *filename) 
{
    FILE *file = fopen(filename, "w"); 
    if (file != NULL) 
    {
        for (size_t i = 0; i < length; ++i) 
        {
            fprintf(file, "%02x", array[i]);
        }
        fprintf(file, "\n");
        fclose(file);
    } else 
    {
        printf("Failed to open the file.\n");
    }
}

// Funtion to read content of a KyberKey byte objects
int readByteArrayFromFile(byte *array, size_t length, const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file != NULL) 
    {
        for (size_t i = 0; i < length; ++i)
        {
            int value;
            if (fscanf(file, "%02x", &value) != 1)
            {
                fclose(file);
                printf("Error reading KyberKey from files\n");
                return -1; //  	Error reading from a file
            }
            array[i] = (byte)value;
        }
        fclose(file);
        // printf("Success\n");
        return 0; // Success 
    }
    else
    {
        printf("Failed to open file\n");
        return -2; // Failed to open the file
    }
}

int main() 
{
    int ret;
    clock_t start, end;
    double cpu_time_used_ms;
    
    clock_t start_total, end_total;
    double total_time_used_ms = 0.0;
    int num_iterations = 1000;
    
    WC_RNG rng;
    KyberKey key;
    
    // Intializing rng
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize RNG.\n");
        return -1;
    }
    
    // Open CSV file for writing
    FILE *csv_file = fopen("kyber_dec.csv", "w");
    if (csv_file == NULL) {
        printf("Failed to open CSV file for writing.\n");
        return -1;
    }
    
    // Write header to CSV file
    fprintf(csv_file,"%s" ,"decryption[ms]\n");
    
    // Loop to read from keys/kyber_private_key_1.txt to keys/kyber_private_key_1000.txt
    // and ciphertexts/kyber_cipher_text_1.txt to ciphertexts/kyber_cipher_text_1000.txt
    // and produce output in sharedkeys_match/kyber_shared_secret_to_match_1.txt to sharedkeys_match/kyber_shared_secret_to_match_1000.txt
    
    start_total = clock();
    for (int i = 1; i <= 1000; ++i) {
        // Generate input and output filenames dynamically
        char private_key_filename[100];
        char cipher_text_filename[100];
        char shared_secret_filename[100];
        sprintf(private_key_filename, "keys/kyber_private_key_%d.txt", i);
        sprintf(cipher_text_filename, "ciphertexts/kyber_cipher_text_%d.txt", i);
        sprintf(shared_secret_filename, "match/secret_to_match_%d.txt", i);

        // Read the private key from file
        ret = readByteArrayFromFile(key.priv, KYBER_SECRETKEYBYTES, private_key_filename);
        if (ret != 0) {
            printf("Failed to read private key from file %s.\n", private_key_filename);
            continue;
        }

        // Read the cipher text from file
        ret = readByteArrayFromFile(key.ct, KYBER_CIPHERTEXTBYTES, cipher_text_filename);
        if (ret != 0) {
            printf("Failed to read cipher text from file %s.\n", cipher_text_filename);
            continue;
        }


         start = clock();
        // Decrypting kyber
        ret = wc_KyberDecrypt(&key);
        end = clock();
        
        cpu_time_used_ms = ((double) (end - start)) * 1000.0 / CLOCKS_PER_SEC;
         
         // Write to CSV file
        fprintf(csv_file, "%f\n", cpu_time_used_ms);
        
        if (ret != 0) {
            printf("Failed to decrypt with Kyber for key pair %d.\n", i);
            continue;
        }

        // Save the shared secret to file
        writeByteArrayToFile(key.ss, KYBER_SSBYTES, shared_secret_filename);
    }

	end_total = clock(); 
    
    total_time_used_ms = ((double) (end_total - start_total)) * 1000.0 / CLOCKS_PER_SEC;
     double avg_time_per_iteration_ms = total_time_used_ms / num_iterations;

    printf("Total time for 1000 iterations: %f milliseconds\n", total_time_used_ms);
    printf("Average time per iteration: %.2f milliseconds\n", avg_time_per_iteration_ms);

    wc_FreeRng(&rng); // Free the RNG resource
    
    return 0;
}

#endif

