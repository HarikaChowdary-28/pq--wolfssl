
#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/test.h>
#include <time.h>

#ifdef HAVE_XMSS

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/xmss_hash.h>
#include <wolfssl/wolfcrypt/xmss_hash_address.h>
#include <wolfssl/wolfcrypt/xmss.h>
#include <wolfssl/wolfcrypt/xmss_wots.h>
#include <wolfssl/wolfcrypt/xmss_utils.h>
#include <wolfssl/wolfcrypt/xmss_core.h> 

int cert1(void)
   { 
    int ret;

    WOLFSSL_CERT_MANAGER* cm = NULL;
    

    const char* caCert     = "./XMSS-1/certs/root.pem";
    const char* verifyCert = "./XMSS-1/certs/servercert.pem";
    

    wolfSSL_Init();
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif
      
   cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
        printf("wolfSSL_CertManagerNew() failed\n");
        return -1;
    }

   
    ret = wolfSSL_CertManagerLoadCA(cm, caCert,NULL);
    
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_CertManagerLoadCA() failed (%d): %s\n",
                ret, wolfSSL_ERR_reason_error_string(ret));
        ret = -1; goto exit;
    }
    
    ret = wolfSSL_CertManagerVerify(cm, verifyCert, WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        printf("wolfSSL_CertManagerVerify() failed (%d): %s\n",
                ret, wolfSSL_ERR_reason_error_string(ret));
        ret = -1; goto exit;
    }
    
    printf("Verification Successful!\n");
  
exit:
    wolfSSL_CertManagerFree(cm);
    wolfSSL_Cleanup();
   return ret;
    }
   

int main(void)
{
    int i = 100;
    float sum = 0;
    float avg;
    float avg_t[i];
    
    while(i!=0)
    {
    clock_t t;
    t = clock();    
    cert1();
    i = i-1;   
    
    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds
    avg_t[i] = time_taken; 
 }
    for(i=0;i<100;i++)
    {
    sum = sum + avg_t[i];
    }
    avg = sum/i;
    printf("Average time taken to execute after %d iterations: %f seconds \n", i,avg);
    }
    
#endif
