<div class="oranda-hide">

# Secure Update Demo
## Overview
1.In secure update demo, we first generate a kyber key pair(privatekey, publickey) which is used for secure key exchange mechanism. 

2.At sender side this publickey is used for kyber encryption and it gives the shared secretkey and ciphertext as output. 

3.At receiver side we take this ciphertext and use private key to get the shared secretkey(kyber decryption). 

4.Now this  shared secretkey Is used as an aeskey for aes encryption of the original message file. 

5.After encrypting the message file, we get the encrypted message file as output, we then generate a hmac key and use this key to generate the hmac tag for the original message file. 

6.We concatenate the hmac tag and encryted message file, and sign this component together with pqc digital signature scheme. 

7,This can include signing only the metadata and other components as well (depends on your requirements).

8.Now we send this signature to the receiver side.

9.Receiver will first verify the signature using the sender’s digital certificate (contains public key). 

10.After the signature verification, the receiver will verify the hmac tag for integrity and authentication. 

11.For decrypting the encrypted message, receiver will follow step 3 and get the original message. 

### Implementation
1.To generate these keys and certificates follow secboot/README.md section 2(certgen) steps. 

2.In pq—wolfssl/test/secupdate run 
```bash
make 
```
3.In pq—wolfssl/test/secupdate/kyber run 
```bash
./key_gen  
```
for generating a new key pair of kyber keys.

4.Run 
```bash
./encrypt
```
for generating a shared secret key and a cipher text. 

5.Run 
```bash
./decrypt
```
for getting a shared secret. 

6.In pq—wolfssl/test/secupdate/aes run 
```bash
./aes_encrypt 
```
for encrypting the message “input.txt” using the shared secretkey from kyber. 

7.In pq—wolfssl/test/secupdate/aes run 
```bash
./aes_decrypt 
```
for decrypting the message “input.txt” using the same shared secretkey from kyber. 

8.In pq—wolfssl/test/secupdate/hmac run 
```bash
./key_gen 
```
for generating the hmac key. 

9.In pq—wolfssl/test/secupdate/hmac run 
```bash
./tag_gen 
```
for generating the hmac tag for the message “input.txt”. 

10.In pq--wolfssl/test/secupdate/hmac run 
```bash
./hmac.sh 
```
for concatenating the encrypted msg with hmac tag. 

11.In pq—wolfssl/test/secupdate/xmss run 
```bash
./xmss_sign
```
for generating signature for the concatenated encrypted message. 

12.In pq—wolfssl/test/secupdate/xmss run 
```bash
./xmss_verify
```
for verifying the signature. If you get a message saying VERIFY RESULT: SUCCESS that means signature is verified correctly.

13.After signature verification, you can check the hmac tag for integrity, then decrypt the message using the same shared secret key which is shared using Kyber KEM in step 4.
