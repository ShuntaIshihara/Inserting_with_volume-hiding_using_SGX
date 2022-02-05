#ifndef _ENCLAVE_FUNC_HPP 
#define _ENCLAVE_FUNC_HPP 

#include "Enclave_t.h"
#include <sgx_trts.h>

void encrypt(unsigned char enc[256], unsigned char *data);
unsigned char* decrypt(unsigned char key[256]);
int hash_1(unsigned char* key, int size);
int hash_2(unsigned char* key, int size);
int is_dummy(unsigned char *k);
struct keyvalue cuckoo(struct keyvalue *table, struct keyvalue data, int tableID, int cnt, int limit);
void itoa(int num, char *str);

#endif // _ENCLAVE_FUNC_HPP
