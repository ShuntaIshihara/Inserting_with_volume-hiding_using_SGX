COMPILER = $(CXX)
CPPFLAGS = -Wall -std=c++11 -g
LIBS = -lgmp -lcrypto 
INCLUDE = -I/home/kdeprivacy/cereal-1.3.0/include
OBJS = paillier.o deserialize.o
SERVEROBJS = getKey.o
CLIENTOBJS = getKey.o rr.o select0.o sha256.o

.PHONY: all

all: server client

server: server.cpp $(SERVEROBJS) $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(SERVEROBJS) $(OBJS) $< -o $@ $(LIBS) $(INCLUDE)

getKey.o: getKey.cpp
	$(COMPILER) $(CPPFLAGS) -c $< -o $@

deserialize.o: deserialize.cpp
	$(COMPILER) $(CPPFLAGS) -c $< $(INCLUDE) -o $@


client: client.cpp $(CLIENTOBJS) $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(CLIENTOBJS) $(OBJS) $< -o $@ $(LIBS) $(INCLUDE)

rr.o: rr.cpp
	$(COMPILER) $(CPPFLAGS) -c $< -o $@

select0.o: select0.cpp
	$(COMPILER) $(CPPFLAGS) -c $< -o $@

sha256.o: sha256.cpp
	$(COMPILER) $(CPPFLAGS) -c -lcrypto $< -o $@

paillier.o: paillier.c paillier.h
	$(COMPILER) $(CPPFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf server client $(OBJS) $(SERVEROBJS) $(CLIENTOBJS)
