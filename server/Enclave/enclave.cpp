#include "Enclave_t.h"
#include <sgx_trts.h>

int ecall_start(KeyValue data, KeyValue table[][], long seed)
{
    stash = cuckoo(data, table, seed, 0, 0, 5);
    return 1;
}
