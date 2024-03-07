<div class="oranda-hide">

# Secure Access Demo
## Overview
1.In secure access demo, we first generate a certificate chain which has root certificate and the root secret key, ica certificate and the ica secret key and server certificate and the server secret key. 

2.The ica certificate is digitally signed by the root CA and server certificate is digitally signed by the ica CA. 

3.The main task we did here is to verify the certificates seperately and calculate the time taken at each level. 

### Implementation
1.To generate these keys and certificates follow secboot/README.md section 2(certgen) steps. 

2.In pq—wolfssl/test/secaccess run 
```bash
make 
```
3.In pq—wolfssl/test/secaccess run 
```bash
./certverify
```
to verify the certificates individually. We do not need to verify the root certificate because the root CA’s private key is integrated in HSM (it is trusted). 

4.If you want to verify certificates of XMSS, change the path of certificates to where XMSS certificates are present in code and follow the steps from step 2. 

