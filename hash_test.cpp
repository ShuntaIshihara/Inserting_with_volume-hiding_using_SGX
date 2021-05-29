#include <iostream>
#include <functional>
#include <string>
#include <cmath>

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

int main()
{
    int h1 = hash_1("Hello world", 100);
    int h2 = hash_2("Hello world", 100);
    std::cout << "hash1: " << h1 << std::endl;
    std::cout << "hash2: " << h2 << std::endl;
    return 0;
}
