OPENSSL_DIR ?= /usr/local/opt/openssl@1.1
OPENSSL_SUPPORT ?= -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib

.PHONY: app
app: 
	g++ App.cpp Encrypt.cpp $(OPENSSL_SUPPORT) -lcrypto -lssl -o app


.PHONY: clean
clean:
	rm -f app *.o
