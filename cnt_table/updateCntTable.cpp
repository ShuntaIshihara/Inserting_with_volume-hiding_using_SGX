#include <unordered_map>
#include <gmp.h>
#include "paillier.h"
#include <cereal/cereal.hpp>
//#include <cereal/archives/json.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/memory.hpp>
#include "structure.hpp"


char* updateCntTable(paillier_pubkey_t* pubKey, char* cnt_t, cnt_data& cnt_d, std::unordered_map<std::string, int> indices, int* index)
{
    paillier_ciphertext_t* encryptedCnt;
    if(indices.find(cnt_d.h) == indices.end()) {
        *index += 1;
        indices[cnt_d.h] = *index;
        encryptedCnt = paillier_create_enc_zero();
    } else {
        encryptedCnt = paillier_ciphertext_from_bytes((void*)cnt_t, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    }

    paillier_ciphertext_t* encryptedSum = paillier_create_enc_zero();

    paillier_ciphertext_t* encryptedValue = paillier_ciphertext_from_bytes((void*)cnt_d.byteEncryptedValue, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

    paillier_mul(pubKey, encryptedSum, encryptedCnt, encryptedValue);

    char* byteEncryptedSum = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, encryptedSum);

    paillier_freeciphertext(encryptedValue);
    paillier_freeciphertext(encryptedCnt);
    paillier_freeciphertext(encryptedSum);

    return byteEncryptedSum;
}
