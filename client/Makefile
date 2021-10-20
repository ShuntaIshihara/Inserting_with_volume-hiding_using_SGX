OPENSSL_DIR ?= /usr/local/opt/openssl@1.1
OPENSSL_SUPPORT ?= -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib

.PHONY: app
app: 
	g++ -Wall -std=c++11 App.cpp init.cpp Encrypt.cpp deserialize.cpp getKey.cpp rr.cpp select0.cpp sha256.cpp paillier.c -I/Users/ishihara/cereal-1.3.0/include $(OPENSSL_SUPPORT) -lgmp -lcrypto -lssl -o app


.PHONY: clean
clean:
	rm -f app *.o
