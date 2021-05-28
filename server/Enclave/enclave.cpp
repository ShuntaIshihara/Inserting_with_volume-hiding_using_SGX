// #include "Enclave_t.h"
// #include <sgx_trts.h>
#include <random>
#include "classes.h"

template <class KeyType> KeyType decrypt(KeyType key) {
    return key;
}

template <class KeyType> int hash_1(KeyType key) {
}

template <class KeyType> int hash_2(KeyType key) {
}

template <class KeyValue> KeyValue cuckoo(KeyValue data, KeyValue[][] table, int size, int tableID, int cnt, int limit)
{
    //再帰回数の上限に達したらreturnする
    if (cnt >= limit) return data;

    //T1, T2それぞれのhash値を得る
    int pos[2];
    pos[0] = hash_1(decrypt(data.getKey()), size);
    pos[1] = hash_2(decrypt(data.getKey()), size);

    //追い出し操作をする
    KeyValue w = table[tableID][pos[tableID]];
    table[tableID][pos[tableID]] = data;

    //追い出されたデータをもう一方のテーブルに移す（上の操作を再帰的に繰り返す）
    return cuckoo(w, table, size, (tableID+1)%2, cnt+1, limit);
}

template <class KeyValue> int ecall_start(KeyValue data, KeyValue table[][], int size)
{
    //新しいキーバリューデータを挿入し，托卵操作を行う
    stash.put(cuckoo(data, table, size, 0, 0, 5));
    
    //ランダムな名前のキーを生成する
    std::random_device rnd;
    unsigned int r = rnd();
    std::string key = "dummy_";
    key += std::to_string(r);
    KeyValue dummy(key);
    //ダミーデータを挿入し，托卵操作を行う
    stash.put(cuckoo(dummy, table, size, 0, 0, 5));

    //stashをenclave外に送る
    ocall_return_stash();
    return 1;
}


