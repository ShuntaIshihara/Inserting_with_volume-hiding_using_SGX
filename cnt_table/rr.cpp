#include <random>
#include <vector>


std::vector<int> randomized_response(double p, int key, int key_max)
{
    std::random_device rnd;
    std::vector<int> key_list;
    while((double)rnd()/std::random_device::max() >= p) {
        key_list.push_back(rnd() % key_max);
    }
    key_list.push_back(key);
    return key_list;
}
