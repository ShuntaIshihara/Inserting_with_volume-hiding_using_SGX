OPENSSL_DIR ?= /usr/local/opt/openssl@1.1
OPENSSL_SUPPORT ?= -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib

app:
	g++ App.cpp $(OPENSSL_SUPPORT) -lcrypto -lssl -o app

.PHONY: clean
clean:
	rm -f app *.o
