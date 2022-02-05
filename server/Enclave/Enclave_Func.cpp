#include "Enclave_t.h"
#include <sgx_trts.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_tcrypto.h>

#include "def.hpp"

extern int n_byte_size;
extern void *priv_key;
extern void *pub_key;

void encrypt(unsigned char enc[256], unsigned char *data)
{
    size_t size = 0;
    sgx_status_t status = sgx_rsa_pub_encrypt_sha256(pub_key, NULL, &size,
    (const unsigned char *)data, strlen((const char *)data)+1);
    if (status != SGX_SUCCESS) {
        ocall_print("encrypt");
        ocall_err_print(&status);
    }

    if (size == 256) {
        status = sgx_rsa_pub_encrypt_sha256(pub_key, enc, &size,
        (const unsigned char *)data, strlen((const char *)data)+1);
    } else {
        ocall_print("encrypt");
        ocall_err_different_size("different size");
    }
}

unsigned char* decrypt(unsigned char key[256])
{
    size_t enc_len = 256;
    size_t dec_len = 0;
    sgx_status_t status = sgx_rsa_priv_decrypt_sha256(priv_key, NULL, &dec_len,
    (const unsigned char *)key, enc_len);
    if (status != SGX_SUCCESS) {
        ocall_print("decrypt");
        ocall_err_print(&status);
    }

    unsigned char dec_key[dec_len];
    status = sgx_rsa_priv_decrypt_sha256(priv_key, dec_key, &dec_len,
    (const unsigned char *)key, enc_len);
    if (status != SGX_SUCCESS) {
        ocall_print("decrypt");
        ocall_err_print(&status);
    }

    unsigned char *cp = (unsigned char *)malloc(sizeof(unsigned char) * dec_len);
    strlcpy((char *)cp, (const char *)dec_key, dec_len);
    return cp;
}

int hash_1(unsigned char* key, int size)
{
    sgx_sha256_hash_t *hash = (sgx_sha256_hash_t *)malloc(sizeof(sgx_sha256_hash_t));
    sgx_status_t st = sgx_sha256_msg((const uint8_t *) key, strlen((const char *)key)+1, (sgx_sha256_hash_t *) hash);
    
    int *h = (int *)hash;
    free(hash);

    return abs(*h) % size;
}

int hash_2(unsigned char* key, int size)
{
    char key2[256] = "t2";
    strncat(key2, (const char *)key, 30);
    
    sgx_sha256_hash_t *hash = (sgx_sha256_hash_t *)malloc(sizeof(sgx_sha256_hash_t));
    sgx_status_t st = sgx_sha256_msg((const uint8_t *) key2, strlen((const char *)key2)+1, (sgx_sha256_hash_t *) hash);
    
    int *h = (int *)hash;
    free(hash);

    return abs(*h) % size;
}

int is_dummy(unsigned char *k)
{
    int check = strncmp((const char *)k, "dummy_", 6);
    if (check == 0) return 1;
    return 0;
}

struct keyvalue cuckoo(struct keyvalue *table, struct keyvalue data, int tableID, int cnt, int limit)
{
    if (cnt >= limit) return data;

    //T1, T2それぞれのハッシュ値を得る
    int pos[2];
    unsigned char *dec_key = decrypt(data.key);
    pos[0] = hash_1(dec_key, TABLE_SIZE);
    pos[1] = hash_2(dec_key, TABLE_SIZE);
    free(dec_key);

    //追い出し操作をする
    struct keyvalue w = table[tableID*TABLE_SIZE+pos[tableID]];
    table[tableID*TABLE_SIZE+pos[tableID]] = data;

//    unsigned char *k = decrypt(w.key);
//    if (is_dummy(k)) return w;
//    free(k);
    //追い出されたデータをもう一方のテーブルに移す
    return cuckoo(table, w, (tableID+1)%2, cnt+1, limit);
}

void itoa(int num, char *str)
{
    int i = 0;
    if (num < 0) {
        str[i] = '-';
        i++;
        num = abs(num);
    }
    int number = num;
    int digit = 0;
    while(number!=0){
        number = number / 10;
        ++digit;
    }
    int j;
    for (j = digit-1; j >= 0; j--) {
        str[i+j] = '0' + (num % 10);
        num = num / 10;
    }
}
