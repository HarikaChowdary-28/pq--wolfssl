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


/*#if defined(HAVE_SPHINCS)
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

*/

#ifndef WOLFSSL_DEBUG_TLS
    #define WOLFSSL_DEBUG_TLS   /* enable full debugging */
#endif
#ifndef DEBUG_WOLFSSL
    #define DEBUG_WOLFSSL
#endif
#ifndef WOLFSSL_CERT_EXT
    #define WOLFSSL_CERT_EXT
#endif

#if defined(HAVE_DILITHIUM)
#include <stdint.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/dilithium_packing.h>
#include <wolfssl/wolfcrypt/dilithium_polynoms.h>
#include <wolfssl/wolfcrypt/dilithium_symmetric.h>

#define BUFFER_SZ 60000 
#define MAX_PEM_CERT_SIZE 60000
#define MAX_DER_KEY_SIZE  60000   

static void check_ret(char *func_name, int ret) {
    if (ret != 0) {
        fprintf(stderr, "ERROR: %s() returned %d\n", func_name, ret);
    }
}
// Function to print the content of a Key byte objects
void printByteArray(const byte *array, size_t length, const char *label) 
{
	printf("%s: ", label);
	for (size_t i = 0; i < length; ++i) 
	{
		printf("%02x ", array[i]);
	}
	printf("\n");
}


//to write contents to sig file
void write_buffer_to_file(const char* filename, const uint8_t* buffer, size_t len) {
    FILE *file = fopen(filename, "w");
    if (file) {
        for (size_t i = 0; i < len; i++) {
            fprintf(file, "%02x", buffer[i]);
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

int key_gen(const char* key_file ,const char* msg_file , const char* sig_file){
	int ret=0;
	
	word32 idx=0;
	WC_RNG rng;
	DilithiumKey key;

	byte signature[DILITHIUM_SIG_SIZE];
	word32 signature_len = sizeof(signature); 

	byte file_msg[BUFFER_SZ];
        size_t file_msg_len = 0;
	
	// initializing rng and key
	ret=wc_InitRng(&rng);
	check_ret("wc_InitRng", ret);
	
	if(ret==0) {
		ret=wc_InitDilithiumKey(&key);
		check_ret("wc_Initdilkey", ret);
	}
	
	  // Load and sign the message 
    if (ret == 0) {
        FILE* msg_file_fp = fopen(msg_file, "rb");
        if (msg_file_fp) {
            file_msg_len = fread(file_msg, 1, BUFFER_SZ, msg_file_fp);
            fclose(msg_file_fp);
            ret = file_msg_len > 0 ? 0 : -1;
            check_ret("fread message", ret);
        } else {
            ret = -1;
            check_ret("fopen message", ret);
        }
    }

	
if (ret == 0) {
        //wrapper function to generate a signature by taking msg, msg length , priv key which we decoded from der format and rng. Writes the output buffer (signed message) to signature variable.
        
        read_buffer_from_file("dil_private_key.txt", &key.sk, DILITHIUM_CRYPTO_SECRETKEYBYTES);
        ret = wc_DilithiumSign(signature, (long long unsigned int *)&signature_len, file_msg, file_msg_len, &key.sk, &rng);
        check_ret("wc_dilSign", ret);
    }

    // Write signature to file
    if (ret == 0) {
        write_buffer_to_file(sig_file, signature, signature_len);
        printf("generated signature successfully");
    }
     printf("\n");
    // Free resources
    wc_FreeDilithiumKey(&key);
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    return ret;
	
}

int main(int argc , char** argv) {

	key_gen("dil_private_key.txt" ,"demo.txt" , "sign.txt" ); 

}

#endif
	
