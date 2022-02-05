#ifndef _STRUCTURE_HPP
#define _STRUCTURE_HPP

#include <gmp.h>
#include "paillier.h"

typedef struct {
    std::string h;
    char byteEncryptedValue[256];

    template<class Archive>
    void serialize(Archive& archive)
    {
        archive(h, byteEncryptedValue);
    }
}cnt_data;

typedef struct {
    unsigned char key[256];
    unsigned char value[256];
    template<class Archive>
    void serialize(Archive& archive)
    {
        archive(key, value);
    }
}SKV;

#endif //  _STRUCTURE_HPP
