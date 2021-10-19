COMPILER ?= g++
CFLAGS ?= -Wall -Wextra -g
CPPFLAGS ?= $(CFLAGS) -std=c++11
OPENSSL_DIR ?= /usr/local/opt/openssl@1.1
OPENSSL_SUPPORT ?= -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib
SERVER_FILE = init.cpp cuckoo.cpp

.PHONY: all
all: server client

.PHONY: server
server: server.cpp $(SERVER_FILE) 
	$(COMPILER) $(CPPFLAGS) -o $@ $^ $(OPENSSL_SUPPORT) -lcrypto -lssl

.PHONY: client
client: client.cpp
	$(COMPILER) $(CPPFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm client server 
