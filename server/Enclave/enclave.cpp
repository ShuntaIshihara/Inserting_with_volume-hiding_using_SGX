// #include "Enclave_t.h"
// #include <sgx_trts.h>
#include <random>
#include "classes.h"

template <class KeyValue> int ecall_start(KeyValue data, KeyValue table[][], int size)
{
    std::random_device rnd;
    stash.put(cuckoo(data, table, size, 0, 0, 5));
    
    std::string key = "dummy_";
    unsigned int r = rnd();
    key += std::to_string(r);
    KeyValue dummy(key);
    stash.put(cuckoo(dummy, table, size, 0, 0, 5));

    ocall_return_stash();
    return 1;
}

template <class KeyValue> KeyValue cuckoo(KeyValue data, KeyValue[][] table, int size, int tableID, int cnt, int limit)
{
    if (cnt == limit) return data;

    int pos[2];
    pos[0] = hash_1(decrypt(data.getKey()), size);
    pos[1] = hash_2(decrypt(data.getKey()), size);

    KeyValue w = table[tableID][pos[tableID]];
    table[tableID][pos[tableID]] = data;
    return cuckoo(w, table, size, (tableID+1)%2, cnt+1, limit);
}
