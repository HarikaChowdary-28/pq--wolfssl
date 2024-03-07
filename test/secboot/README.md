<div class="oranda-hide">

# Getting Started - Installation

</div>

1.Download wolfssl 5.5.1 version from the website <https://github.com/wolfSSL/wolfssl/tree/v5.5.1-stable>

2.After downloading wolfssl 5.5.1 Run 
```bash
./autogen.sh
```
3.If autogen.sh command does not work run
```bash
chmod u+x autogen.sh
```
4.Run
```bash
./configure --enable-all
```
5.Run 
```bash
make && sudo make install
```
6.Download and extract pq-wolfssl repository from here <https://github.com/boschresearch/pq-wolfSSL> in wolfssl directory.
In pq-wolfssl Run 
```bash
./autogen.sh
```
7.If autogen.sh command does not work run 
```bash
chmod u+x autogen.sh 
```
8.To build the library with necessary flags Run  
```bash
./configure --with-liboqs CFLAGS="-O2 -DWOLFSSL_HAVE_SP_ECC -DWOLFSSL_HAVE_SP_DH -DWC_NO_HARDEN" --enable-tls13 --disable-tlsv12 --disable-oldtls --enable-falcon --enable-dilithium --enable-xmss --enable-sphincs --enable-kyber --enable-keygen --enable-crypttests --disable-rsa --enable-dh --enable-aescbc --disable-poly1305 --disable-chacha --disable-des3 --disable-md5 --disable-sha --disable-sha224 --enable-sha384 --enable-sha512 --enable-sha3 --disable-eccshamir --enable-certreq --enable-certgen --enable-keygen --disable-fastmath --enable-sp-math-all --disable-asm --disable-errorstrings --enable-opensslextra --enable-pwdbased –disable-debug
```
9.After this Run 
```bash
sudo make && sudo make install
```
10.In case of any errors using ./configure run 
```bash
autoreconf -I
```
and retry from step 8 again. 
_Note:In case of any errors while running make command, remove -Werror (search for keyword) from Makefile.


## Certificate Generation --certgen

1.To generate a certificate chain from pq-wolfssl  library, download certgen folder which is available in pqc teams channel. 
2.If u want to generate a XMSS level 1 certficate chain where it have XMSS at root, ica and server with security level 1 according to NIST.
3.Run 
```bash
make
```
4.If there are any errors, run 
```bash
make clean
```
and run make again. 
5.To generate the certificate chain, run this following command:
```bash
./certgen out=XMSS-1_XMSS-1_XMSS-1 root=XMSS 1 ica=XMSS 1 leaf=XMSS 1 
```
6.Similarly if you want to generate a certificate chain of XMSS level-5 security, open settings.h file in pq-wolfSSL/wolfssl/wolfcrypt directory and change the mode of XMSS to 5 in line 71. 
7.Run this command after step 7 in pq-wolfssl
```bash
sudo make && sudo make install
```
8.For using different signature schemes please refer to the readme file in certgen/readme.md file.

### Client- server connection (Secure TLS with pqc) --client-server

1.If you want a secure connection establishment between client and server with XMSS level-1 scheme and with KEM being KYBER level-1, dump the certificates (certs àfolder) generated in certgen/XMSS-1_XMSS-1_XMSS-1 folder to certgen/certs folder.
2.If you want to use different level of kyber, make sure to do changes i.e. change the security level of kyber from 1 to 5 in pq-wolfssl/wolfssl/wolfcrypt/settings.h file, save the changes, run in pq-wolfssl
```bash
sudo make && sudo make install
```
3.In client-server run
```bash
make
```
4.If there are any errors, run 
```bash 
make clean 
```
and run make again. 
5.Open two terminals and in client-server run the following commands at the same time: 
```bash
./server out= XMSS-1_XMSS-1_XMSS-1_KYBER-1 root=XMSS 1 ica=XMSS 1 leaf=XMSS 1 kem=KYBER 1 
```
```bash
./client ip=127.0.0.1 out=XMSS-1_XMSS-1_XMSS-1_KYBER-1 root=XMSS 1 ica=XMSS 1 leaf=XMSS 1 kem=KYBER 1 iter=100 
```
_Note:You can the “iter” to however many iterations you want.The output results will be written to .csv files which have all the necessary calculations. 

####Secure Boot Demo
#Overview
1.In secure boot demo, we generate a certificate chain, and we sign different files at different stages (there can be n number of stages). 
2.We considered 3 stages, where at 0th stage we signed bootloader image(message) with rootkey.pem(privatekey) and extracted the public key associated with privatekey from the certificate and verified the signature. 
3.At the 1st stage we signed an OS Image with icakey.pem and verified the signature with public key from icacert.pem 
4.At the 2nd stage we signed application files which are compatible with OS with serverkey.pem and verified the signature with public key from servercert.pem. 
##Implementation
5.To generate these keys and certificates follow section 2 steps. 
6.In pq—wolfssl/test/secboot folder we have different folders. 
7.If you want to test the experiment by XMSS, then do the following steps. 
8.In secboot run 
```bash
make
```
9.In pq—wolfssl/test/secboot/xmss folder run 
```bash
./xmss_sign
```
to generate signatures at different stages (for messages f0.zip at 0th  stage, f1.img.xz at 1st stage, f2.zip at 2nd stage for 1000 iterations) 
10.For verification, In pq—wolfssl/test/secboot/xmss folder run 
```bash
./xmss_verify
```
if you get message as VERIFY: SUCCESS, your signature is verified successfully. 
11.This is the same process for using any scheme other than XMSS as well. 
12.This is the same process for using mixed certificates (pq—wolfssl/test/secboot/mixed/xmss-fal  run, 
```bash
./xmss_fal_sign 
```
for signature generation and 
```bash
./xmss_fal_verify
```
for signature verification.

 
