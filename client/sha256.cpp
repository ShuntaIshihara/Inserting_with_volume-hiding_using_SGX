#include <stdio.h>
#include <cstring>
#include <openssl/sha.h>

int main(int argc, char *argv[])
{
	char *message = "Sample Message";
	unsigned char digest[SHA256_DIGEST_LENGTH];
	
	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx); // コンテキストを初期化
	SHA256_Update(&sha_ctx, message, sizeof(message)); // message を入力にする
	SHA256_Final(digest, &sha_ctx); // digest に出力

	printf("%s\n", message);
	
		printf("%d", digest[0]);
	printf("\n");

    printf("SHA256_DIGEST_LENGTH = %d\n", SHA256_DIGEST_LENGTH);

    return 0;
}
