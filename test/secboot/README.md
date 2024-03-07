<div class="oranda-hide">

# Getting Started

</div>

1.Download wolfssl 5.5.1 version from the website <https://github.com/wolfSSL/wolfssl/tree/v5.5.1-stable>

2.After downloading wolfssl 5.5.1 Run 
```bash
./autogen.sh command
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


## Certificate Generation

