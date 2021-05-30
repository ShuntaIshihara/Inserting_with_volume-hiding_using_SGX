.PHONY: test_cuckoo
test_cuckoo: test_cuckoo.o server/Enclave/enclave.o
	g++ -o $@ $^

server/Enclave/enclave.o: server/Enclave/enclave.cpp
	@[ -d ./server/Enclave ]
	g++ -o $@ -c $< -I /Users/ishihara/Desktop/Inserting_with_volume-hiding_using_SGX/server

test_cuckoo.o: test_cuckoo.cpp
	g++ -c $< -I /Users/ishihara/Desktop/Inserting_with_volume-hiding_using_SGX/server

.PHONY: clean
clean:
	rm -f *.o test_cuckoo
