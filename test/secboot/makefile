WOLF_INSTALL_DIR=/usr/local
CFLAGS=-I$(WOLF_INSTALL_DIR)/include -Wall
LIBS=-L$(WOLF_INSTALL_DIR)/lib -lwolfssl


all:dilithium/dil_sign dilithium/dil_verify falcon/fal_sign falcon/fal_verify sphincs/sp_sign sphincs/sp_verify xmss/xmss_sign xmss/xmss_verify mixed/sp-fal/sp_fal_sign mixed/sp-fal/sp_fal_verify mixed/xmss-fal/xmss_fal_sign mixed/xmss-fal/xmss_fal_verify

dilithium/dil_sign:dilithium/dil_sign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

dilithium/dil_verify:dilithium/dil_verify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
falcon/fal_sign:falcon/fal_sign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

falcon/fal_verify:falcon/fal_verify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

sphincs/sp_sign:sphincs/sp_sign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

sphincs/sp_verify:sphincs/sp_verify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
xmss/xmss_sign:xmss/xmss_sign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)

xmss/xmss_verify:xmss/xmss_verify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
mixed/sp-fal/sp_fal_sign:mixed/sp-fal/sp_fal_sign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
mixed/sp-fal/sp_fal_verify:mixed/sp-fal/sp_fal_verify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
mixed/xmss-fal/xmss_fal_sign:mixed/xmss-fal/xmss_fal_sign.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
mixed/xmss-fal/xmss_fal_verify:mixed/xmss-fal/xmss_fal_verify.o 
	$(CC) -o $@ $^ $(CFLAGS) -O3 $(CPPFLAGS) $(LIBS)
	
	
.PHONY: clean all

clean:
	rm -f *.o dilithium/dil_sign dilithium/dil_verify falcon/fal_sign falcon/fal_verify sphincs/sp_sign sphincs/sp_verify xmss/xmss_sign xmss/xmss_verify mixed/sp-fal/sp_fal_sign mixed/sp-fal/sp_fal_verify mixed/xmss-fal/xmss_fal_sign mixed/xmss-fal/xmss_fal_verify
