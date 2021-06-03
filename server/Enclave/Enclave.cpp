#include "Enclave_t.h"
#include <sgx_trts.h>
#include <math>

char* decrypt(char* key)
{
    return key;
}

int hash_1(char* key, int size)
{
    return abs((int)std::hash<char*>()(key)) % size;
}

int hash_2(char* key, int size)
{
    
    return abs((int)std::hash<char*>()(key)) % size;
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
