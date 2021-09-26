#pragma once 

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
