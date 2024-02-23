#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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

// Function to store the content of a KyberKey byte objects
void writeByteArrayToFile(const byte *array, size_t length, const char *filename) 
{
    char full_path[100];
    sprintf(full_path, "keys/%s", filename); // Prepend "keys/" to the filename
    FILE *file = fopen(full_path, "w"); 
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
    char full_path[100];
    sprintf(full_path, "keys/%s", filename); // Prepend "keys/" to the filename
    FILE *file = fopen(full_path, "r");
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
    FILE *csv_file = fopen("kyber.csv", "w");
    if (csv_file == NULL) {
        printf("Failed to open CSV file for writing.\n");
        return -1;
    }
    
    // Write header to CSV file
    fprintf(csv_file,"%s" ,"key_gen[ms]\n");
    
    // Loop to generate 1000 key pairs
    
    start_total = clock();
    for (int i = 1; i <= 1000; ++i) {
        // Initialize kyber key
        ret = wc_InitKyberKey(&key);
        if (ret != 0) {
            printf("Failed to initialize Kyber key.\n");
            wc_FreeRng(&rng);
            return -1;
        }


         start = clock();
        // Generating kyber key pair
        ret = wc_GenerateKyberKeyPair(&key, &rng);
        
        end = clock();
        
         cpu_time_used_ms = ((double) (end - start)) * 1000.0 / CLOCKS_PER_SEC;
        
        // Write to CSV file
        fprintf(csv_file, "%f\n", cpu_time_used_ms);
        
        if (ret != 0) {
            printf("Failed to generate Kyber key pair %d.\n", i);
            wc_FreeKyberKey(&key);
            continue;
        }
        
        // Generate filenames dynamically
        char public_key_filename[50];
        char private_key_filename[50];
        sprintf(public_key_filename, "kyber_public_key_%d.txt", i);
        sprintf(private_key_filename, "kyber_private_key_%d.txt", i);
        
        // Save the public and private keys to files
        writeByteArrayToFile(key.pub, KYBER_PUBLICKEYBYTES, public_key_filename);
        writeByteArrayToFile(key.priv, KYBER_SECRETKEYBYTES, private_key_filename);

        // Free the Kyber key
        wc_FreeKyberKey(&key);
    }
    end_total = clock(); // End total timing
    // Calculate average time per iteration
    total_time_used_ms = ((double) (end_total - start_total)) * 1000.0 / CLOCKS_PER_SEC;
     double avg_time_per_iteration_ms = total_time_used_ms / num_iterations;

    printf("Total time for 1000 iterations: %f milliseconds\n", total_time_used_ms);
    printf("Average time per iteration: %.2f milliseconds\n", avg_time_per_iteration_ms);


    wc_FreeRng(&rng); // Free the RNG resource
    
    return 0;
}

#endif

