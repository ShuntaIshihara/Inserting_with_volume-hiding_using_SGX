CXX := g++

.PHONY: test_stash
test_stash: test_stash.o ./server/Enclave/enclave.o
	$(CXX) -o $@ $^

./server/Enclave/enclave.o:
	$(CXX) -o $@ -I ./server -c ./server/Enclave/enclave.cpp

test_stash.o:
	$(CXX) -o $@ -I ./server -c test_stash.cpp
	
.PHONY: test_cuckoo
test_cuckoo: test_cuckoo.o server/Enclave/enclave.o
	$(CXX) -o $@ $^

#server/Enclave/enclave.o: server/Enclave/enclave.cpp
#	@[ -d ./server/Enclave ]
#	$(CXX) -o $@ -c $< -I /Users/ishihara/Desktop/Inserting_with_volume-hiding_using_SGX/server

test_cuckoo.o: test_cuckoo.cpp
	$(CXX) -c $< -I /Users/ishihara/Desktop/Inserting_with_volume-hiding_using_SGX/server

.PHONY: clean
clean:
	rm -f *.o server/Enclave/*.o test_cuckoo test_stash test_hash
