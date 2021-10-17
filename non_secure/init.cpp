#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <random>
#include <vector>
#include <unordered_map>
#include "structure.hpp"

void init_table(struct keyvalue *table, int size)
{
    for (int i = 0; i < size; ++i) {
        char key[15] = "dummy_";
        std::strcat((char *)key, std::to_string(i).c_str());
        std::strcat((char *)key, (char *)"0");
        std::strcat((char *)key, std::to_string(i).c_str());
        std::strcpy(table[i].key, key);

        key[7] = (unsigned char)'1';
        std::strcpy(table[size+i].key, key);


        char value[32] = "dummy_value_";
        std::strcat((char *)value, (char *)"0");
        std::random_device rnd;
        std::strcat((char *)value, std::to_string(rnd()).c_str());
        std::strcpy(table[i].value, value);

        value[12] = (unsigned char)'1';
        std::strcpy(table[size+i].value, value);

    }
        std::cout << "(init.cpp) check point_1" << std::endl;

}

void init_cnt(std::string filename, std::unordered_map<std::string, int>& indices, std::vector<int>& cnt_table)
{
    std::ifstream input_file(filename);
    if (!input_file.is_open()) {
        std::cerr << "Error: Could not open " << filename << std::endl;
        std::exit(EXIT_FAILURE);
    }

    std::string line;
    int index = 0;
    while (std::getline(input_file, line)) {
        indices[line] = index;
        index++;
        cnt_table.push_back(0); 
    }
}
