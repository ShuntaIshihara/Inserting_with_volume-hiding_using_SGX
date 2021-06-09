#include "Enclave_t.h"
#include <sgx_trts.h>
#include <stdlib.h>
#include <string.h>
//#include <openssl/sha.h>
#include <sgx_tcrypto.h>

char* decrypt(char* key)
{
    return key;
}

int hash_1(char* key, int size)
{
//    unsigned char digest[SHA256_DIGEST_LENGTH];

//    SHA256_CTX sha_ctx;
//    SHA256_Init(&sha_ctx);
//    SHA256_Update(&sha_ctx, key, sizeof(key));
//    SHA256_Final(digest, &sha_ctx);
    sgx_sha256_hash_t *hash = (sgx_sha256_hash_t *)malloc(sizeof(sgx_sha256_hash_t));
    sgx_status_t status = sgx_sha256_msg((const uint8_t *) key, sizeof(key), (sgx_sha256_hash_t *) hash);
    
    int *h = (int *)hash;
    free(hash);

//    ocall_check_hash(h, key);

    return abs(*h) % size;
}

int hash_2(char* key, int size)
{
    char key2[32] = "t2";
    strncat(key2, key, 30);
//    unsigned char digest[SHA256_DIGEST_LENGTH];
//
//    SHA256_CTX sha_ctx;
//    SHA256_Init(&sha_ctx);
//    SHA256_Update(&sha_ctx, key2, sizeof(key2));
//    SHA256_Final(digest, &sha_ctx);
    
    sgx_sha256_hash_t *hash = (sgx_sha256_hash_t *)malloc(sizeof(sgx_sha256_hash_t));
    sgx_status_t status = sgx_sha256_msg((const uint8_t *) key2, sizeof(key2), (sgx_sha256_hash_t *) hash);
    
    int *h = (int *)hash;
    free(hash);

//    ocall_check_hash(h, key2);

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
//    struct keyvalue w;
//    strlcpy(w.key, table[tableID][pos[tableID]].key, 32);
//    strlcpy(w.value, table[tableID][pos[tableID]].value, 32);
//    strlcpy(table[tableID][pos[tableID]].key, data.key, 32);
//    strlcpy(table[tableID][pos[tableID]].value, data.value, 32);

    //追い出されたデータをもう一方のテーブルに移す
    return cuckoo(table, w, size, (tableID+1)%2, cnt+1, limit);
}

int ecall_start(struct keyvalue table[2][10], struct keyvalue *data, int *size)
{
	struct keyvalue stash[2];

    //新しいキーバリューデータを挿入し、托卵操作を行う
    stash[0] = cuckoo(table, *data, *size, 0, 0, 5);

    //ランダムなキーバリューデータ（ダミーデータ）を生成
    //ダミーデータを挿入し、托卵操作を行う
    strlcpy(stash[1].key, "dummy", 32);
    strlcpy(stash[1].value, "dummy", 32);

    //OCALLでstashに格納するものをクライアントに返す
    ocall_return_stash(stash);

	return 1;
}
