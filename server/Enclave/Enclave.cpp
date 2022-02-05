#include "Enclave_t.h"
#include <sgx_trts.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_tcrypto.h>

#include "def.hpp"
#include "Enclave_Func.hpp"



//公開鍵、秘密鍵の生成
int n_byte_size = 256;
void *priv_key = NULL;
void *pub_key = NULL;

void ecall_generate_keys(
unsigned char n[256],
unsigned char d[256],
unsigned char p[256],
unsigned char q[256],
unsigned char dmp1[256],
unsigned char dmq1[256],
unsigned char iqmp[256],
long *e
)
{
    //秘密鍵、公開鍵の成分を生成
    sgx_status_t st = sgx_create_rsa_key_pair(n_byte_size, sizeof(e),
    n, d, (unsigned char *)e, p, q, dmp1, dmq1, iqmp);

    if (st != SGX_SUCCESS) {
        ocall_print("generate keys");
        ocall_err_print(&st);
    }

    ocall_print_e(e);


    //秘密鍵生成
    st = sgx_create_rsa_priv2_key(n_byte_size, sizeof(long), (const unsigned char *)e,
            (const unsigned char *)p, (const unsigned char *)q, (const unsigned char *)dmp1,
            (const unsigned char *)dmq1, (const unsigned char *)iqmp, &priv_key);


    if (st != SGX_SUCCESS) {
        ocall_print("generate keys");
        ocall_err_print(&st);
    }

    //公開鍵生成
    st = sgx_create_rsa_pub1_key(n_byte_size, sizeof(long),
            (const unsigned char *)n, (const unsigned char *)e, &pub_key);

    if (st != SGX_SUCCESS) {
        ocall_print("generate keys");
        ocall_err_print(&st);
    }


}

void ecall_encrypt(unsigned char enc[256], unsigned char *data)
{
    encrypt(enc, data);
}

void ecall_decrypt(unsigned char dec[256], unsigned char enc[256])
{
    unsigned char *d;
    d = decrypt(enc);
    int dec_len = strlen((const char *)d);
    strlcpy((char *)dec, (const char *)d, dec_len+1);
}

int ecall_hash_block(unsigned char key[256], int *size)
{
    unsigned char *dec_key = decrypt(key);
    int h = hash_1(dec_key, *size);
    free(dec_key);
    return h;
}

void ecall_insertion_start(struct keyvalue *table, size_t t_size, struct keyvalue *data)
{
	struct keyvalue stash[2];

    //新しいキーバリューデータを挿入し、托卵操作を行う
    stash[0] = cuckoo(table, *data, 0, 0, 7);

    //ランダムなキーバリューデータ（ダミーデータ）を生成
    struct keyvalue dummy;
    unsigned char v[32] = "dummy_";
    int rand;
    sgx_status_t status = sgx_read_rand((unsigned char *)&rand, 4);
    if (status != SGX_SUCCESS) {
        ocall_print("random");
        ocall_err_print(&status);
    }
    wchar_t wc[32];
    swprintf(wc, sizeof(wc)/sizeof(wchar_t), L"%d", rand);
    strncat((char *)v, (const char *)wc, 26);
    v[31] = '\0';
    encrypt(dummy.key, v);
//    for (int i = 0; i < 10; i++) {
        v[6] = '\0';
        status = sgx_read_rand((unsigned char *)&rand, 4);
        if (status != SGX_SUCCESS) {
            ocall_print("random");
            ocall_err_print(&status);
        }
        swprintf(wc, sizeof(wc)/sizeof(wchar_t), L"%d", rand);
        strncat((char *)v, (const char *)wc, 26);
        encrypt(dummy.value, v);
        v[31] = '\0';
//    }
    //ダミーデータを挿入し、托卵操作を行う
    stash[1] = cuckoo(table, dummy, 0, 0, 7);

    //OCALLでstashに格納するものをクライアントに返す
    ocall_return_stash(stash);
}

int ecall_get_block(unsigned char enc_key[256], int *i, int *block_size)
{
    unsigned char *dec_key = decrypt(enc_key);
    int dec_len = strlen((const char*)dec_key)+1;
    int len = dec_len + 11;
    char key_idx[len];
    strlcpy(key_idx, (const char*)dec_key, dec_len);
    free(dec_key);
    strncat(key_idx, ":", 1);
    char idx[10];
    itoa(*i, idx);
    strncat(key_idx, idx, strlen((const char*)idx));
    return hash_1((unsigned char*)key_idx, *block_size);
}

void ecall_search(struct keyvalue kvs[2], struct keyvalue *table, size_t t_size, unsigned char enc_key[256], int *i)
{
    unsigned char *dec_key = decrypt(enc_key);
    int dec_len = strlen((const char*)dec_key)+1;
    int len = dec_len + 11;
    char key_idx[len];
    strlcpy(key_idx, (const char*)dec_key, dec_len);
    free(dec_key);
    strncat(key_idx, ":", 1);
    char idx[10];
    itoa(*i, idx);
    strncat(key_idx, idx, strlen((const char*)idx));
    int pos1 = hash_1((unsigned char*)key_idx, TABLE_SIZE);
    int pos2 = hash_2((unsigned char*)key_idx, TABLE_SIZE);
    kvs[0] = table[pos1];
    kvs[1] = table[TABLE_SIZE+pos2];
}
