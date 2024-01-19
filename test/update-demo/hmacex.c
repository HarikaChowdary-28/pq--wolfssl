#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>

int main() {
    wolfSSL_Init();
    
    Hmac hmac;
    byte key[] = "mySecretKey";
    int keyLength = sizeof(key) - 1;
    
    wc_HmacSetKey(&hmac, SHA256, key, keyLength);
    
    byte data[] = "Hello, World!";
    int dataLength = sizeof(data) - 1;
    wc_HmacUpdate(&hmac, data, dataLength);
    
    byte hmacResult[SHA256_DIGEST_SIZE];
    wc_HmacFinal(&hmac, hmacResult);
    
    // Print the HMAC result
    printf("HMAC Result: ");
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        printf("%02x", hmacResult[i]);
    }
    printf("\n");
    
    wc_HmacFree(&hmac);
    
    wolfSSL_Cleanup();
    
    return 0;
}


