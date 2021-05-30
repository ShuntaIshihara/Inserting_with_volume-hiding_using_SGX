// #include "Enclave_t.h"
// #include <sgx_trts.h>
#include <iostream>
#include <random>
#include <functional>
#include <cmath>
#include <string>
#include <set>
#include "keyvalue.hpp"

int ocall_return_stash(std::set<KV> *st);

std::string decrypt(std::string key)
{
    return key;
}

//keyはstring型として作成
int hash_1(std::string key, int size)
{
    return std::abs((int)std::hash<std::string>()(key)) % size;
}

int hash_2(std::string key, int size)
{
    key += "t2";
    return std::abs((int)std::hash<std::string>()(key)) % size;
}

KV cuckoo(KV *data, KV *table, int size, int tableID, int cnt, int limit)
{
    //再帰回数の上限に達したらreturnする
    if (cnt >= limit) return *data;

    //T1, T2それぞれのhash値を得る
    int pos[2];
    pos[0] = hash_1(decrypt(data->getKey()), size);
    pos[1] = hash_2(decrypt(data->getKey()), size);

    //追い出し操作をする
    //ポインタから二次元配列へ間接参照
    KV w = *(table+(tableID*size)+pos[tableID]);
    *(table+(tableID*size)+pos[tableID]) = *data;

    //追い出されたデータをもう一方のテーブルに移す（上の操作を再帰的に繰り返す）
    return cuckoo(&w, table, size, (tableID+1)%2, cnt+1, limit);
}

int ecall_start(KV *data, KV *table, int *size)
{
    std::set<KV> stash;

    //新しいキーバリューデータを挿入し，托卵操作を行う
    KV w = cuckoo(data, (KV*)table, *size, 0, 0, 5);
    std::string str = w.getKey();
    if (str.find("dummy_") == std::string::npos) {
        std::cout << w.getKey() << std::endl;
        stash.insert(w);
    }
    
    //ランダムな名前のキーを生成する
    std::random_device rnd;
    unsigned int r = rnd();
    std::string key = "dummy_";
    key += std::to_string(r);
    KV dummy(key);
    //ダミーデータを挿入し，托卵操作を行う
    w = cuckoo(&dummy, (KV*)table, *size, 0, 0, 5);
    str = w.getKey();
    if (str.find("dummy_") == std::string::npos) {
        std::cout << w.getKey() << std::endl;
        stash.insert(w);
    }

  //stashをenclave外に送る
    if (!stash.empty()) {
        int flag = ocall_return_stash(&stash);
        if (flag) std::cout << "ocall success" << std::endl;
        else std::cout << "ocall fail" << std::endl;
    }

    return 1;
}
