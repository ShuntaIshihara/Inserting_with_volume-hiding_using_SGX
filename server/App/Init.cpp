#include <cstdio>
#include <cstring>
#include <string>
#include <random>
#include <iostream> 
#include <fstream>
#include <stdlib.h>
#include <vector>
#include <unordered_map>
#include <gmp.h>
#include "paillier.h"
#include <cereal/cereal.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/array.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.h"
#include "structure.hpp"
#include "def.hpp"

extern sgx_enclave_id_t global_eid;
extern paillier_pubkey_t* pubKey;
extern paillier_prvkey_t* secKey;


//テーブルの初期化関数
void table_init(struct keyvalue *table)
{
    std::cout << "Start table init." << std::endl;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        for (int j = 0; j < TABLE_SIZE; j++) {
            unsigned char key[15] = "dummy_";
            std::strcat((char *)key, std::to_string(i).c_str());
            std::strcat((char *)key, (char *)"0");
            std::strcat((char *)key, std::to_string(j).c_str());
            sgx_status_t status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + j].key, key);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            key[7] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + TABLE_SIZE + j].key, key);
            if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
            }

            unsigned char value[32] = "dummy_value_";
            std::strcat((char *)value, (char *)"0");
            std::random_device rnd;
            std::strcat((char *)value, std::to_string(rnd()).c_str());
            status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + j].value, value);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            value[12] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + TABLE_SIZE + j].value, value);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }
        }
    }
    std::cout << "End init table." <<std::endl;
}

std::string sha256_hash(std::string m)
{
    SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
    //sha256ハッシュ値生成
    unsigned char digest[SHA256_DIGEST_LENGTH];


    SHA256_Update(&sha_ctx, m.c_str(), m.length());
    SHA256_Final(digest, &sha_ctx);


    // ハッシュ値(16進数)を文字列に変換
    std::string h = "";
    for (int j = 0; j < SHA256_DIGEST_LENGTH; ++j) {
        std::stringstream ss;
        ss << std::hex << (int)digest[j];
        h.append(ss.str());
    }

    return h;
}

void init_cnt(std::string filename, std::unordered_map<std::string, int>& indices, std::vector<char*>& cnt_table)
{
    std::cout << "Start init cnt_table." << std::endl;
    std::ifstream input_file(filename);
    if (!input_file.is_open()) {
        std::cerr << "Error: Could not open " << filename << std::endl;
        std::exit(EXIT_FAILURE);
    }

    std::string line;
    int index = 0;
    while (std::getline(input_file, line)) {
        std::string h = sha256_hash(line);
        indices[h] = index;
        index++;
        paillier_plaintext_t* m = paillier_plaintext_from_ui(0);
        paillier_ciphertext_t* ctxt;
        ctxt = paillier_enc(NULL, pubKey, m, paillier_get_rand_devurandom);
        cnt_table.push_back((char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ctxt));
    }

    input_file.close();
    std::cout << "End init cnt_table." << std::endl;
}

std::vector<std::string> split(std::string& src, const char* delim)
{
    std::vector<std::string> vec;
    std::string::size_type len = src.length();

    for (std::string::size_type i = 0, n; i < len; i = n + 1) {
        n = src.find_first_of(delim, i);
        if (n == std::string::npos) {
            n = len;
        }
        vec.push_back(src.substr(i, n - i));
    }

    return vec;
}

void rr(std::vector<int>& list, double p, int key_id, int key_size)
{
    std::random_device rnd;
    while((double)rnd()/std::random_device::max() >= p) {
        list.push_back(rnd() % key_size);
    }
    list.push_back(key_id);
}


void input_from_file(std::string filename, struct keyvalue *table, std::unordered_map<std::string, int>& indices, std::vector<char*>& cnt_table)
{
    std::cout << "Start input from file." << std::endl;
    int c = 0;
    struct keyvalue data;
    std::ifstream ifs(filename);
    if (!ifs.is_open()) {
        std::cerr << "Error: Could not open " << filename << std::endl;
        return;
    }
    std::string line;
    while (std::getline(ifs, line)) {
        std::vector<std::string> v = split(line, " ");
        std::string key = v[0];
        std::string val = v[1];
        std::string h = sha256_hash(key);

        std::vector<int> list;
        rr(list, 0.5, indices[h], cnt_table.size());
        for (auto itr = list.begin(); itr != list.end(); ++itr) {
            paillier_ciphertext_t* encryptedCnt = paillier_ciphertext_from_bytes((void*)cnt_table[*itr], PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
            paillier_ciphertext_t* encryptedSum = paillier_create_enc_zero();
            paillier_plaintext_t* m1 = paillier_plaintext_from_ui(1);
            paillier_ciphertext_t* ctxt1;
            ctxt1 = paillier_enc(NULL, pubKey, m1, paillier_get_rand_devurandom);
            paillier_mul(pubKey, encryptedSum, ctxt1, encryptedCnt);
            char* byteEncryptedSum = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, encryptedSum);
            std::memcpy(cnt_table[*itr], byteEncryptedSum, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
            paillier_freeplaintext(m1);
            paillier_freeciphertext(ctxt1);
            paillier_freeciphertext(encryptedSum);
            paillier_freeciphertext(encryptedCnt);
            free(byteEncryptedSum);
        }

        paillier_ciphertext_t* ctxt = paillier_ciphertext_from_bytes((void*)cnt_table[indices[h]], PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
        paillier_plaintext_t* dec;
        dec = paillier_dec(NULL, pubKey, secKey, ctxt);
        int index = mpz_get_si((mpz_srcptr)dec);
        paillier_freeplaintext(dec);
        paillier_freeciphertext(ctxt);

        std::string key_idx = key + ":" + std::to_string(index);
        struct keyvalue d;
        unsigned char *in_key = (unsigned char*)key_idx.c_str();
        sgx_status_t status = ecall_encrypt(global_eid, d.key, in_key);
        if (status != SGX_SUCCESS) {
            std::cerr << "Error: encrypt d.key." << std::endl;
            sgx_error_print(status);
            std::exit(EXIT_FAILURE);
        }

        unsigned char *in_val = (unsigned char*)val.c_str();
        status = ecall_encrypt(global_eid, d.value, in_val);
        if (status != SGX_SUCCESS) {
            std::cerr << "Error: encrypt d.value." << std::endl;
            sgx_error_print(status);
            std::exit(EXIT_FAILURE);
        }

        int block_size = BLOCK_SIZE;
        int block;
        status = ecall_hash_block(global_eid, &block, d.key, &block_size);

        status = ecall_insertion_start(global_eid, table+(block*2*TABLE_SIZE),
                sizeof(struct keyvalue)*2*TABLE_SIZE, &d);
        if (status != SGX_SUCCESS) {
            sgx_error_print(status);
            std::exit(EXIT_FAILURE);
        }
        
        c = (c+1)%TABLE_SIZE;
        if (c == 0) std::cout << "#";
    }
    std::cout << std::endl;
    std::cout << "End input from file." << std::endl;
}
