#ifndef _PAILLIER_F_H
#define _PAILLIER_F_H

#include "paillier_s.hpp"

void paillier_create_keys(struct PPubKey* ppubkey, PPrvKey* pprvkey);
uint64_t paillier_encryption(int m, struct PPubKey* ppubkey);
int paillier_decryption(uint64_t c, struct PPubKey* ppubkey, PPrvKey* pprvkey);
uint64_t paillier_add(uint64_t c1, uint64_t c2, struct PPubKey* ppubkey);

#endif // _PAILLIER_F_H
