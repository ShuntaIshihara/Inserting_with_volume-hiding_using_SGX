#include "Enclave_t.h"
#include <sgx_trts.h>

template <typename KeyValue>
int ecall_start(KeyValue data, KeyValue table[][], int seed, int size)
{
    int rnd;
    stash = cuckoo(data, table, seed, 0, 0, 5);

    rnd = rand % size;
    stash 
    return 1;
}
