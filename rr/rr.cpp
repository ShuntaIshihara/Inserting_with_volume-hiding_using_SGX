#include <iostream>
#include <string>
#include <random>
#include <vector>


std::vector<unsigned int> randomized_response(double p, unsigned int key, unsigned int key_max)
{
    std::random_device rnd;
    std::vector<unsigned int> key_list;
    while((double)rnd()/std::random_device::max() >= p) {
        key_list.push_back((unsigned int)rnd() % key_max);
    }
    key_list.push_back(key);
    return key_list;
}

int main()
{
    std::vector<unsigned int> key_list = randomized_response(0.3, 1, 10000);
    for (int i = 0; i < key_list.size(); i++) {
        std::cout << key_list[i] << std::endl;
    }

    return 0;
}
