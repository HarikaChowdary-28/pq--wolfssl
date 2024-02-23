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

// Function to store the content of a KyberKey byte objects
void writeByteArrayToFile(const byte *array, size_t length, const char *filename) 
{
	FILE *file = fopen(filename, "w"); 
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
	
	WC_RNG rng;
	KyberKey key;
	
	// Intializing rng
	ret = wc_InitRng(&rng);
	// printf("Integer: %d\n", ret);	IF 0 CONTINUE
	
	// Initializing kyber key
	ret = wc_InitKyberKey(&key);
	// printf("Integer: %d\n", ret);	IF 0 CONTINUE
	
	
	
	// Generating kyber key pair
	if(ret==0)
	{
		ret = wc_GenerateKyberKeyPair(&key, &rng);
		//printf("Integer: %d\n", ret);	IF 0 CONTINUE
		
		// printByteArray(key.pub, KYBER_PUBLICKEYBYTES, "Public Key");
		// printByteArray(key.priv, KYBER_SECRETKEYBYTES, "Private Key");
		
		writeByteArrayToFile(key.pub, KYBER_PUBLICKEYBYTES, "kyber_public_key.txt");
		writeByteArrayToFile(key.priv, KYBER_SECRETKEYBYTES, "kyber_private_key.txt");
	}
	

	// Assigning values to KyberKey Objects
	//readByteArrayFromFile(key.priv, KYBER_SECRETKEYBYTES, "kyber_private_key.txt");
	// printByteArray(key.priv, KYBER_SECRETKEYBYTES, "Secret Key");
	readByteArrayFromFile(key.pub, KYBER_PUBLICKEYBYTES, "kyber_public_key.txt");
	// printByteArray(key.pub, KYBER_PUBLICKEYBYTES, "Public Key");
	
	/*
	
	// Encrypting kyber ----
	if(ret==0)
	{
		ret = wc_KyberEncrypt(&key, &rng);
		//printf("Integer: %d\n", ret);	IF 0 CONTINUE
		
		//printByteArray(key.ss, KYBER_SSBYTES, "Shared Secret");
		//printByteArray(key.ct, KYBER_CIPHERTEXTBYTES, "Cipher Text");
		
		writeByteArrayToFile(key.pub, KYBER_SSBYTES, "kyber_shared_secret.txt");
		writeByteArrayToFile(key.ct, KYBER_CIPHERTEXTBYTES, "kyber_cipher_text.txt");
	}
	
	
	// ----------------------------------------------
	// ASSIGN THE CIPHER TEXT HARIKA GONNA SEND TO ME
	// ----------------------------------------------
	
	// readByteArrayFromFile(key.ct, KYBER_CIPHERTEXTBYTES, "kyber_updated_cipher_text.txt");
	// printByteArray(key.ct, KYBER_CIPHERTEXTBYTES, "Cipher Text");
	
	
	
	/*
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
	
	
	*/
	// wc_FreeKyberKey(&key);
	
	
	
	return 0;
	
}

#endif

