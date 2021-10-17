#include <string>
#include <cstring>
#include <openssl/sha.h>
#include "structure.hpp"

int hash(char* key)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx); // コンテキストを初期化
	SHA256_Update(&sha_ctx, key, std::strlen(key)+1); // message を入力にする
	SHA256_Final(digest, &sha_ctx); // digest に出力
    
    int h = 0;
    // ハッシュ値(16進数)をsize範囲の数値に変換
    for (int j = 0; j < SHA256_DIGEST_LENGTH; ++j) {
        h += (int)digest[j];
    }

    return h;
}

int hash_1(char* key, int size)
{
    int h = hash(key);
    return h % size;
}

int hash_2(char* key, int size)
{
    std::string k = key;
    std::string str(k + "1");
    int h = hash((char*)str.c_str());
    return h % size;
}

struct keyvalue cuckoo(struct keyvalue data, struct keyvalue *table, int size, int tableID, int cnt, int limit)
{
    if (cnt >= limit) return data;

    //T1, T2それぞれのハッシュ値を得る
    int pos[2];
    pos[0] = hash_1(data.key, size);
    pos[1] = hash_2(data.key, size);

    //追い出し操作をする
    struct keyvalue w = table[tableID*size+pos[tableID]];
    table[tableID*size+pos[tableID]] = data;

    if (std::strncmp(w.key, "dummy_", 6) != 0) return w;

    //追い出されたデータをもう一方のテーブルに移す
    return cuckoo(w, table, size, (tableID+1)%2, cnt+1, limit);
}

struct keyvalue insert(struct keyvalue data, struct keyvalue *table, int size)
{
    return cuckoo(data, table, size, 0, 0, 12);
}
