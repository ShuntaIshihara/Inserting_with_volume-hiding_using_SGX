#include "Enclave_t.h"
#include <sgx_trts.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

char* decrypt(char* key)
{
    return key;
}

int hash_1(char* key, int size)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, key, sizeof(key));
    SHA256_Final(digest, &sha_ctx);
    
    int h = 0;
    for (int i = 0; i < sizeof(digest); i++) {
        h += (int)digest[i];
    }

    return h % size;
}

int hash_2(char* key, int size)
{
    char key2[30] = "t2";
    strcat(key2, key);
    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, key2, sizeof(key2));
    SHA256_Final(digest, &sha_ctx);
    
    int h = 0;
    for (int i = 0; i < sizeof(digest); i++) {
        h += (int)digest[i];
    }

    return h % size;
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

int ecall_start(struct keyvalue table[2][10], struct keyvalue *data, int *size)
{
	struct keyvalue stash;

    //新しいキーバリューデータを挿入し、托卵操作を行う
    stash = cuckoo(table, *data, *size, 0, 0, 5);

	return 1;
}
