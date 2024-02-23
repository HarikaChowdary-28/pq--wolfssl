WOLF_INSTALL_DIR=/usr/local
CFLAGS=-I$(WOLF_INSTALL_DIR)/include -Wall
LIBS=-L$(WOLF_INSTALL_DIR)/lib -lwolfssl


all:dilithium/dil-combinedsign dilithium/dil-combinedverify falcon/fal-combinedsign falcon/fal-combinedverify sphincs/sp-combinedsign sphincs/sp-combinedverify xmss/xmss-combinedsign xmss/xmss-combinedverify xmss-dil/xmss-dil-combinedsign xmss-dil/xmss-dil-combinedverify xmss-fal/xmss-fal-combinedsign xmss-fal/xmss-fal-combinedverify xmss-sphincs/xmss-sp-combinedsign xmss-sphincs/xmss-sp-combinedverify update-demo/hmac-generate update-demo/aes-file-encrypt update-demo/hmacex_file update-demo/dil-updatesign update-demo/dil-updateverify dil-fal/dil-fal-combinedsign dil-fal/dil-fal-combinedverify update-demo/aes-encrypt update-demo/aes-decrypt update-demo/kymain-gen update-demo/kymain-encrypt update-demo/kymain-decrypt update-demo/fal-updatesign update-demo/fal-updatever update-demo/sp-updatesign update-demo/sp-updatever update-demo/xmss-updatesign update-demo/xmss-updatever

dilithium/dil-combinedsign:dilithium/dil-combinedsign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

dilithium/dil-combinedverify:dilithium/dil-combinedverify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
falcon/fal-combinedsign:falcon/fal-combinedsign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

falcon/fal-combinedverify:falcon/fal-combinedverify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

sphincs/sp-combinedsign:sphincs/sp-combinedsign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

sphincs/sp-combinedverify:sphincs/sp-combinedverify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
xmss/xmss-combinedsign:xmss/xmss-combinedsign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

xmss/xmss-combinedverify:xmss/xmss-combinedverify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
xmss-dil/xmss-dil-combinedsign:xmss-dil/xmss-dil-combinedsign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

xmss-dil/xmss-dil-combinedverify:xmss-dil/xmss-dil-combinedverify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
xmss-fal/xmss-fal-combinedsign:xmss-fal/xmss-fal-combinedsign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

xmss-fal/xmss-fal-combinedverify:xmss-fal/xmss-fal-combinedverify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

xmss-sphincs/xmss-sp-combinedsign:xmss-sphincs/xmss-sp-combinedsign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

xmss-sphincs/xmss-sp-combinedverify:xmss-sphincs/xmss-sp-combinedverify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
update-demo/hmac-generate: update-demo/hmac-generate.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
update-demo/aes-file-encrypt: update-demo/aes-file-encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

update-demo/hmacex_file: update-demo/hmacex_file.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
update-demo/dil-updatesign: update-demo/dil-updatesign.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

update-demo/dil-updateverify: update-demo/dil-updateverify.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
dil-fal/dil-fal-combinedsign:dil-fal/dil-fal-combinedsign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

dil-fal/dil-fal-combinedverify:dil-fal/dil-fal-combinedverify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
update-demo/aes-encrypt: update-demo/aes-encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
update-demo/aes-decrypt: update-demo/aes-decrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
update-demo/kymain-gen: update-demo/kymain-gen.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
update-demo/kymain-encrypt: update-demo/kymain-encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
update-demo/kymain-decrypt: update-demo/kymain-decrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
update-demo/fal-updatesign: update-demo/fal-updatesign.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

update-demo/fal-updatever: update-demo/fal-updatever.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
update-demo/sp-updatesign: update-demo/sp-updatesign.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

update-demo/sp-updatever: update-demo/sp-updatever.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	
update-demo/xmss-updatesign: update-demo/xmss-updatesign.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 

update-demo/xmss-updatever: update-demo/xmss-updatever.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
	

.PHONY: clean all

clean:
	rm -f *.o dilithium/dil-combinedsign dilithium/dil-combinedverify falcon/fal-combinedsign falcon/fal-combinedverify sphincs/sp-combinedsign sphincs/sp-combinedverify xmss/xmss-combinedsign xmss/xmss-combinedverify xmss-dil/xmss-dil-combinedsign xmss-dil/xmss-dil-combinedverify xmss-fal/xmss-fal-combinedsign xmss-fal/xmss-fal-combinedverify xmss-sphincs/xmss-sp-combinedsign xmss-sphincs/xmss-sp-combinedverify update-demo/hmac-generate update-demo/aes-file-encrypt update-demo/hmacex_file update-demo/dil-updatesign update-demo/dil-updateverify dil-fal/dil-fal-combinedsign dil-fal/dil-fal-combinedverify update-demo/aes-encrypt update-demo/aes-decrypt update-demo/kymain-gen update-demo/kymain-encrypt update-demo/kymain-decrypt update-demo/fal-updatesign update-demo/fal-updatever update-demo/sp-updatesign update-demo/sp-updatever update-demo/xmss-updatesign update-demo/xmss-updatever
