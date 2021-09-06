#include <random>
#include <vector>

std::vector<int> select_0(double p, int key_max)
{
    std::random_device rnd;
    std::vector<int> key_list;
    while((double)rnd()/std::random_device::max() >= p) {
        key_list.push_back((int)rnd() % key_max);
    }
    key_list.push_back((int)rnd() % key_max);
    return key_list;

}
