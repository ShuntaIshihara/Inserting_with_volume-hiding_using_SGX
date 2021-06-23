#include "Enclave_t.h"
#include <sgx_trts.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_tcrypto.h>

//公開鍵、秘密鍵の生成
int n_byte_size = 256;
unsigned char n[256];
unsigned char d[256];
unsigned char p[256];
unsigned char q[256];
unsigned char dmp1[256];
unsigned char dmq1[256];
unsigned char iqmp[256];
long e = 65537;
void *priv_key = NULL;
void *pub_key = NULL;

void ecall_generate_keys()
{
    //秘密鍵、公開鍵の成分を生成
    sgx_status_t st = sgx_create_rsa_key_pair(n_byte_size, sizeof(e),
    n, d, (unsigned char *)&e, p, q, dmp1, dmq1, iqmp);

    if (st != SGX_SUCCESS) {
        ocall_err_print(&st);
    }

    //秘密鍵生成
    st = sgx_create_rsa_priv2_key(n_byte_size, sizeof(e), (const unsigned char *)&e,
    (const unsigned char *)p, (const unsigned char *)q, (const unsigned char *)dmp1,
    (const unsigned char *)dmq1, (const unsigned char *)iqmp, &priv_key);

    if (st != SGX_SUCCESS) {
        ocall_err_print(&st);
    }

    //公開鍵生成
    st = sgx_create_rsa_pub1_key(n_byte_size, sizeof(e),
    (const unsigned char *)n, (const unsigned char *)&e, &pub_key);

    if (st != SGX_SUCCESS) {
        ocall_err_print(&st);
    }
}

void ecall_encrypt(unsigned char *data, unsigned char t_data[256])
{
    size_t size = 0;
    sgx_status_t status = sgx_rsa_pub_encrypt_sha256(pub_key, NULL, &size,
    (const unsigned char *)data, strlen((const char *)data)+1);
    if (status != SGX_SUCCESS) {
        ocall_err_print(&status);
    }
    if (size == 256) {
        status = sgx_rsa_pub_encrypt_sha256(pub_key, t_data, &size,
        (const unsigned char *)data, strlen((const char *)data)+1);
    } else {
        ocall_print("different size");
    }
}

void ecall_decrypt(unsigned char dec[256], unsigned char enc[256])
{
    size_t enc_len = 256;
    size_t dec_len = 0;
    sgx_status_t status = sgx_rsa_priv_decrypt_sha256(priv_key, NULL, &dec_len,
    (const unsigned char *)enc, enc_len);
    if (status != SGX_SUCCESS) {
        ocall_err_print(&status);
    }

    unsigned char dec_key[dec_len];
    status = sgx_rsa_priv_decrypt_sha256(priv_key, dec_key, &dec_len,
    (const unsigned char *)enc, enc_len);
    if (status != SGX_SUCCESS) {
        ocall_err_print(&status);
    }

    strlcpy((char *)dec, (const char *)dec_key, dec_len);
}

unsigned char* decrypt(unsigned char key[256])
{
    size_t enc_len = 256;
    size_t dec_len = 0;
    sgx_status_t status = sgx_rsa_priv_decrypt_sha256(priv_key, NULL, &dec_len,
    (const unsigned char *)key, enc_len);
    if (status != SGX_SUCCESS) {
        ocall_err_print(&status);
    }

    unsigned char dec_key[dec_len];
    status = sgx_rsa_priv_decrypt_sha256(priv_key, dec_key, &dec_len,
    (const unsigned char *)key, enc_len);
    if (status != SGX_SUCCESS) {
        ocall_err_print(&status);
    }

    unsigned char *cp = (unsigned char *)malloc(sizeof(unsigned char) * dec_len);
    strlcpy((char *)cp, (const char *)dec_key, dec_len);
    return cp;
}

int hash_1(unsigned char* key, int size)
{
    sgx_sha256_hash_t *hash = (sgx_sha256_hash_t *)malloc(sizeof(sgx_sha256_hash_t));
    sgx_status_t st = sgx_sha256_msg((const uint8_t *) key, sizeof(key), (sgx_sha256_hash_t *) hash);
    
    int *h = (int *)hash;
    free(hash);
    free(key);

    return abs(*h) % size;
}

int hash_2(unsigned char* key, int size)
{
    char key2[32] = "t2";
    strncat(key2, (const char *)key, 30);
    
    sgx_sha256_hash_t *hash = (sgx_sha256_hash_t *)malloc(sizeof(sgx_sha256_hash_t));
    sgx_status_t st = sgx_sha256_msg((const uint8_t *) key2, sizeof(key2), (sgx_sha256_hash_t *) hash);
    
    int *h = (int *)hash;
    free(hash);
    free(key);

    return abs(*h) % size;
}

struct keyvalue cuckoo(struct keyvalue table[2][10], struct keyvalue data, int size, int tableID, int cnt, int limit)
{
    if (cnt >= limit) return data;

    //T1, T2それぞれのハッシュ値を得る
    int pos[2];
    pos[0] = hash_1(decrypt(data.key), size);
    pos[1] = hash_2(decrypt(data.key), size);

    //追い出し操作をする
    struct keyvalue w = table[tableID][pos[tableID]];
    table[tableID][pos[tableID]] = data;

    //追い出されたデータをもう一方のテーブルに移す
    return cuckoo(table, w, size, (tableID+1)%2, cnt+1, limit);
}

void ecall_insertion_start(struct keyvalue table[2][10], struct keyvalue *data, int *size)
{
	struct keyvalue stash[2];

    //新しいキーバリューデータを挿入し、托卵操作を行う
    stash[0] = cuckoo(table, *data, *size, 0, 0, 5);

    //ランダムなキーバリューデータ（ダミーデータ）を生成
    //ダミーデータを挿入し、托卵操作を行う

    //OCALLでstashに格納するものをクライアントに返す

}
