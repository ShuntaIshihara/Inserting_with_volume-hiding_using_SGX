#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <random>
#include <vector>
#include <unordered_map>
#include <string>


void init(std::string filename, std::unordered_map<std::string, int>& id_list, std::vector<std::string>& key_list)
{
    std::ifstream input_file(filename);
    if (!input_file.is_open()) {
        std::cerr << "Error: Could not open " << filename << std::endl;
        std::exit(EXIT_FAILURE);
    }

    std::string line;
    int index = 0;
    while (std::getline(input_file, line)) {
        id_list[line] = index;
        key_list.push_back(line);
        index++;
    }
    input_file.close();
}
