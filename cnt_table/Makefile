COMPILER = $(CXX)
CPPFLAGS = -Wall -std=c++11
LIBS = -lgmp 
INCLUDE = -I/home/kdeprivacy/cereal-1.3.0/include
OBJS = paillier.o
SERVEROBJS = server_getKey.o deserialize.o updateCntTable.o
CLIENTOBJS = rr.o select0.o sha256ToString.cpp

.PHONY: all

all: server client

server: server.cpp $(SERVEROBJS) $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(SERVEROBJS) $(OBJS) $< -o $@ $(LIBS) $(INCLUDE)

server_getKey.o: server_getKey.cpp
	$(COMPILER) $(CPPFLAGS) $< -c

deserialize.o: deserialize.cpp
	$(COMPILER) $(CPPFLAGS) $< -c $(INCLUDE)

updateCntTable.o: updateCntTable.cpp
	$(COMPILER) $(CPPFLAGS) $< -c $(INCLUDE)


client: client.cpp $(CLIENTOBJS) $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(CLIENTOBJS) $(OBJS) $< -o $@ $(LIBS) $(INCLUDE)

rr.o: rr.cpp
	$(COMPILER) $(CPPFLAGS) $< -c

select0.o: select0.cpp
	$(COMPILER) $(CPPFLAGS) $< -c

sha256ToString.o: sha256ToString.cpp
	$(COMPILER) $(CPPFLAGS) $< -c

paillier.o: paillier.c paillier.h
	$(COMPILER) $(CPPFLAGS) $< -c

.PHONY: clean
clean:
	rm -rf server client $(OBJS) $(SERVEROBJS) $(CLIENTOBJS)
