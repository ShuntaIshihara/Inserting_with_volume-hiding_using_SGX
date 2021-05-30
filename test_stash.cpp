#include <iostream>
#include <string>
#include <set>
#include "keyvalue.hpp"

std::set<KV> stash;

int ecall_start(KV *data, KV *table, int *size);

int ocall_return_stash(std::set<KV> *st)
{
    for (auto itr = st->begin(); itr != st->end(); ++itr) {
        if (stash.find(*itr) != stash.end()) {
            stash.erase(*itr);
            stash.insert(*itr);
        } else {
            stash.insert(*itr);
        }
    }
    return 1;
}

int main()
{
    int size = 10;
    KV table[2][size];
    for (int i = 0; i < size; i++) {
        std::string key = "dummy_";
        key += std::to_string(i);
        table[0][i].setKey(key);
        key += "1";
        table[1][i].setKey(key);
    }

    std::cout << "===Before===" << std::endl;
    std::cout << "T1 = {";
    for (int i = 0; i < size-1; i++) {
        std::cout << table[0][i].getKey() << ", ";
    }
    std::cout << table[0][size-1].getKey() << "}" << std::endl;

    std::cout << "T2 = {";
    for (int i = 0; i < size-1; i++) {
        std::cout << table[1][i].getKey() << ", ";
    }
    std::cout << table[1][size-1].getKey() << "}" << std::endl;

    std::cout << "stash = {";
    for (auto itr = stash.begin(); itr != stash.end(); itr++) {
        std::cout << itr->getKey() << ", ";
    }
    std::cout << "}" << std::endl;


    for (int i = 0; i < size; i++) {
        std::string key = "key";
        std::string value = "value";
        key += std::to_string(i);
        value += std::to_string(i);
        KV data(key, value);
        ecall_start(&data, (KV*)table, &size);
    }

    std::cout << "===After===" << std::endl;
    std::cout << "T1 = {";
    for (int i = 0; i < size-1; i++) {
        std::cout << table[0][i].getKey() << ", ";
    }
    std::cout << table[0][size-1].getKey() << "}" << std::endl;

    std::cout << "T2 = {";
    for (int i = 0; i < size-1; i++) {
        std::cout << table[1][i].getKey() << ", ";
    }
    std::cout << table[1][size-1].getKey() << "}" << std::endl;

    std::cout << "stash = {";
    for (auto itr = stash.begin(); itr != stash.end(); itr++) {
        std::cout << itr->getKey() << ", ";
    }
    std::cout << "}" << std::endl;

    return 0;
}
