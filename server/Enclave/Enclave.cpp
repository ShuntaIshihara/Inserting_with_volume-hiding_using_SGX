#include "Enclave_t.h"
#include <sgx_trts.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_tcrypto.h>

#define TABLE_SIZE 10000


//公開鍵、秘密鍵の生成
int n_byte_size = 256;
//unsigned char n[256];
//unsigned char d[256];
//unsigned char p[256];
//unsigned char q[256];
//unsigned char dmp1[256];
//unsigned char dmq1[256];
//unsigned char iqmp[256];
//long e = 65537;
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
/*
void ecall_create_keys(unsigned char n[256],
        unsigned char d[256],
        unsigned char p[256],
        unsigned char q[256],
        unsigned char dmp1[256],
        unsigned char dmq1[256],
        unsigned char iqmp[256],
        long *e)
{
    //秘密鍵生成
    sgx_status_t status = sgx_create_rsa_priv2_key(n_byte_size, sizeof(e), (const unsigned char *)e,
            (const unsigned char *)p, (const unsigned char *)q, (const unsigned char *)dmp1,
            (const unsigned char *)dmq1, (const unsigned char *)iqmp, &priv_key);

    if (status != SGX_SUCCESS) {
        ocall_print("generate keys");
        ocall_err_print(&status);
    }

    //公開鍵生成
    status = sgx_create_rsa_pub1_key(n_byte_size, sizeof(long),
            (const unsigned char *)n, (const unsigned char *)&e, &pub_key);

    if (status != SGX_SUCCESS) {
        ocall_print("generate keys");
        ocall_err_print(&status);
    }

}
*/
void ecall_encrypt(unsigned char t_data[256], unsigned char *data)
{
    size_t size = 0;
    sgx_status_t status = sgx_rsa_pub_encrypt_sha256(pub_key, NULL, &size,
    (const unsigned char *)data, strlen((const char *)data)+1);
    if (status != SGX_SUCCESS) {
        ocall_print("ecall_encrypt");
        ocall_err_print(&status);
    }
    if (size == 256) {
        status = sgx_rsa_pub_encrypt_sha256(pub_key, t_data, &size,
        (const unsigned char *)data, strlen((const char *)data)+1);
    } else {
        ocall_print("ecall_encrypt");
        ocall_err_different_size("different size");
    }
}

void ecall_decrypt(unsigned char dec[256], unsigned char enc[256])
{
    size_t enc_len = 256;
    size_t dec_len = 0;
    sgx_status_t status = sgx_rsa_priv_decrypt_sha256(priv_key, NULL, &dec_len,
    (const unsigned char *)enc, enc_len);
    if (status != SGX_SUCCESS) {
        ocall_print("ecall_decrypt");
        ocall_err_print(&status);
    }

    unsigned char dec_key[dec_len];
    status = sgx_rsa_priv_decrypt_sha256(priv_key, dec_key, &dec_len,
    (const unsigned char *)enc, enc_len);
    if (status != SGX_SUCCESS) {
        ocall_print("ecall_decrypt");
        ocall_err_print(&status);
    }

    strlcpy((char *)dec, (const char *)dec_key, dec_len);
}

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

int ecall_hash_block(unsigned char key[256], int *size)
{
    unsigned char *dec_key = decrypt(key);
    int h = hash_1(dec_key, *size);
    free(dec_key);
    return h;
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

void itoa(int num, char *str, size_t size)
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
    itoa(*i, idx, 10);
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
    itoa(*i, idx, 10);
    strncat(key_idx, idx, strlen((const char*)idx));
    int pos1 = hash_1((unsigned char*)key_idx, TABLE_SIZE);
    int pos2 = hash_2((unsigned char*)key_idx, TABLE_SIZE);
    kvs[0] = table[pos1];
    kvs[1] = table[TABLE_SIZE+pos2];
}
