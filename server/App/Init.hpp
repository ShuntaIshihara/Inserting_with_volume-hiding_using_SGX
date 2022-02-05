#ifndef _INIT_HPP 
#define _INIT_HPP 

#include <string>
#include <vector>
#include "structure.hpp"

void table_init(struct keyvalue *table);
std::string sha256_hash(std::string m);
void init_cnt(std::string filename, std::unordered_map<std::string, int>& indices, std::vector<char*>& cnt_table);
std::vector<std::string> split(std::string& src, const char* delim);
void rr(std::vector<int>& list, double p, int key_id, int key_size);
void input_from_file(std::string filename, struct keyvalue *table, std::unordered_map<std::string, int>& indices, std::vector<char*>& cnt_table);


#endif // _INIT_HPP
