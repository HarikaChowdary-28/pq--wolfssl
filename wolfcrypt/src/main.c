#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <xlsxwriter.h>

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
    


// Function to print the content of a KyberKey byte objects
void printByteArray(const byte *array, size_t length, const char *label) 
{
	printf("%s: ", label);
	for (size_t i = 0; i < length; ++i) 
	{
		printf("%02x ", array[i]);
	}
	printf("\n");
}


// Global Variable for folder path
const char *path1 = "/home/sqp1cob/Desktop/git/pq--wolfssl/wolfcrypt/src/KyberKeyGen";
const char *path2 = "/home/sqp1cob/Desktop/git/pq--wolfssl/wolfcrypt/src/KyberEncryption";


// Function to store the content of a KyberKey byte objects
void writeByteArrayToFile(const byte *array, size_t length, const char *filename, const char *folder) 
{
	char filepath[256];
	snprintf(filepath, sizeof(filepath), "%s/%s" , folder, filename);
	 
	FILE *file = fopen(filepath, "w"); 
	if (file != NULL) 
	{
		for (size_t i = 0; i < length; ++i) 
		{
			fprintf(file, "%02x ", array[i]);
        	}
		fprintf(file, "\n");
		fclose(file);
	} else 
	{
		printf("Failed to open the file.\n");
	}
}

// Funtion to read content of a KyberKey byte objects
int readByteArrayFromFile(byte *array, size_t length, const char *filename, const char *folder)
{
	char filepath[256];
	snprintf(filepath, sizeof(filepath), "%s/%s", folder, filename);
	
	FILE *file = fopen(filepath, "r");
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
	
	
	
	WC_RNG rng;
	KyberKey key;
	
	// Intializing rng
	ret = wc_InitRng(&rng);
	// printf("Integer: %d\n", ret);	IF 0 CONTINUE
	
	// Initializing kyber key
	ret = wc_InitKyberKey(&key);
	// printf("Integer: %d\n", ret);	IF 0 CONTINUE
	
	
	
	// Create Excel workbook and worksheet
	lxw_workbook *workbook = workbook_new("Keygen_Times.xlsx");
	lxw_worksheet *worksheet = workbook_add_worksheet(workbook, NULL);

	// Set up the first column headers
	lxw_format *bold = workbook_add_format(workbook);
	format_set_bold(bold);
	worksheet_write_string(worksheet, 0, 0, "KeyGen Time", bold);
	
	double total_time = 0.0;
	int count = 0;
	
	for (int i = 1; i <= 1000000; ++i)
	{	
		
		// Generating kyber key pair
		if(ret==0)
		{
			clock_t start, end;
			double cpu_time_used;
			
			start = clock();
			
			ret = wc_GenerateKyberKeyPair(&key, &rng);
			//printf("Integer: %d\n", ret);	IF 0 CONTINUE
			
			end = clock();
			
			// printByteArray(key.pub, KYBER_PUBLICKEYBYTES, "Public Key");
			// printByteArray(key.priv, KYBER_SECRETKEYBYTES, "Private Key");
			
			char pub_filename[256];
			char priv_filename[256];
			
			sprintf(pub_filename, "kyber_public_key_%03d.txt", i);
			sprintf(priv_filename, "kyber_private_key_%03d.txt", i);
			
			writeByteArrayToFile(key.pub, KYBER_PUBLICKEYBYTES, pub_filename, path1);
			writeByteArrayToFile(key.priv, KYBER_SECRETKEYBYTES, priv_filename, path1);
			
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			//printf("Time taken for KeyGen: %f seconds\n", cpu_time_used);
			
			worksheet_write_number(worksheet
			, i , 0, cpu_time_used, NULL);
			
			total_time += cpu_time_used;
			count ++;
		}
		
		
	}
	
	if(count > 0) 
	{
	
		double avg_time = total_time / count;
		worksheet_write_string(worksheet, 1, 0, "Average" , bold);
		worksheet_write_number(worksheet, 1, 1, avg_time, NULL);
		
	}
	
	workbook_close(workbook);
		
		
	/*
	
	
	
	
	lxw_workbook *workbook = workbook_new("Keygen_Times.xlsx");
    	if (!workbook) 
    	{
        	printf("Failed to open the existing Excel file\n");
        	return -1;
    	}
    
	// Add a new worksheet to the existing workbook
	lxw_worksheet *worksheet = workbook_add_worksheet(workbook, "Encryption Times");
	if (!worksheet) 
	{
		printf("Failed to add a new worksheet\n");
		return -1;
	}
	
	// Set up the first column headers
    	lxw_format *bold = workbook_add_format(workbook);
    	format_set_bold(bold);
    	worksheet_write_string(worksheet, 0, 0, "Encryption Time", bold);
    
    	double total_time = 0.0;
    	int count = 0;
    	
    	for (int i = 1; i <= 5; ++i)
	{
		WC_RNG rng;
		KyberKey key;
		
		// Intializing rng
		ret = wc_InitRng(&rng);
		// printf("Integer: %d\n", ret);	IF 0 CONTINUE
		
		// Initializing kyber key
		ret = wc_InitKyberKey(&key);
		// printf("Integer: %d\n", ret);	IF 0 CONTINUE
		
		char pub_filename[256];
		char priv_filename[256];
		
		sprintf(pub_filename, "kyber_public_key_%03d.txt", i);
		sprintf(priv_filename, "kyber_private_key_%03d.txt", i);
		
		ret = readByteArrayFromFile(key.pub, KYBER_SECRETKEYBYTES, pub_filename, path1);
		if (ret != 0) 
		{
		    	printf("Failed to read public key from file %s\n", pub_filename);
		    	continue;
        	}
		ret = readByteArrayFromFile(key.priv, KYBER_SECRETKEYBYTES, priv_filename, path1);
		if (ret != 0) 
		{
            		printf("Failed to read private key from file %s\n", priv_filename);
            		continue;
        	}
        	
        	// Encrypting kyber ----
		if(ret==0)
		{
			clock_t start, end;
			double cpu_time_used;
			
			start = clock();
			
			ret = wc_KyberEncrypt(&key, &rng);
			//printf("Integer: %d\n", ret);	IF 0 CONTINUE
			
			end = clock();
			
			//printByteArray(key.ss, KYBER_SSBYTES, "Shared Secret");
			//printByteArray(key.ct, KYBER_CIPHERTEXTBYTES, "Cipher Text");
			
			writeByteArrayToFile(key.pub, KYBER_SSBYTES, "kyber_shared_secret.txt", path2);
			writeByteArrayToFile(key.ct, KYBER_CIPHERTEXTBYTES, "kyber_cipher_text.txt", path2);
			
			cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
			//printf("Time taken for KeyGen: %f seconds\n", cpu_time_used);
			
			worksheet_write_number(worksheet
			, i , 0, cpu_time_used, NULL);
			
			total_time += cpu_time_used;
			count ++;
		}
		
		
	}
	
	
	if(count > 0) 
	{
	
		double avg_time = total_time / count;
		worksheet_write_string(worksheet, 1, 0, "Average" , bold);
		worksheet_write_number(worksheet, 1, 1, avg_time, NULL);
		
	}
	
	workbook_close(workbook);
	

	
	
	
	// ----------------------------------------------
	// ASSIGN THE CIPHER TEXT HARIKA GONNA SEND TO ME
	// ----------------------------------------------
	
	readByteArrayFromFile(key.ct, KYBER_CIPHERTEXTBYTES, "kyber_cipher_text.txt");
	// printByteArray(key.ct, KYBER_CIPHERTEXTBYTES, "Cipher Text");
	
	
	
	
	clock_t start, end;
	double cpu_time_used;
	
	double avg=0;
	
	for(int rep=0;rep<10; rep++)
	{
		
		start = clock();
	
		// Decrypting kyber ----
		if(ret==0)
		{
			ret = wc_KyberDecrypt(&key);
			printf("Integer: %d\n", ret);	// IF 0 CONTINUE
			
			// ---------------------------------------------------------
			// THIS PRODUCED SHARED SECRET WILL MATCH THE  SHARED SECRET
			// GENERATED BY HARIKA DURING TIME OF ENCRYPTION. WE'LL TAKE
			// THIS SS AND PUSH THRU KDF  AND THEN USING  AES DECRYPTION 
			// WE'LL GET THE FILE SHARED IN THE FIRST PLACE.
			// ---------------------------------------------------------
			
			writeByteArrayToFile(key.pub, KYBER_SSBYTES, "kyber_shared_secret_to_match.txt");
			
			
			// printByteArray(key.ss, KYBER_SSBYTES, "Shared Secret");
			// printByteArray(key.ct, KYBER_CIPHERTEXTBYTES, "Cipher Text");
			
			// writeByteArrayToFile(key.pub, KYBER_SSBYTES, "kyber_shared_secret.txt");
			// writeByteArrayToFile(key.priv, KYBER_CIPHERTEXTBYTES, "kyber_cipher_text.txt");
		}
		
		
		end = clock();
		cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
		
		avg+= cpu_time_used;

		
		printf("Time taken for decryption: %f seconds\n", cpu_time_used);
	
	
	}
	
	printf("Avg. Time taken for decryption: %f seconds\n", avg/10);
		
	
	*/
	
	// wc_FreeKyberKey(&key);
	
	
	
	return 0;
	
}

#endif

