#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <openssl/sha.h>

int main()
{
    //opnessl shaのコンテキスト初期化

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx); // コンテキストを初期化

    //sha256ハッシュ値生成
    unsigned char digest[SHA256_DIGEST_LENGTH];

    std::string key = "sample_key";

    std::cout << key << std::endl;


    SHA256_Update(&sha_ctx, key.c_str(), key.length());
    SHA256_Final(digest, &sha_ctx);

    // ハッシュ値(16進数)を文字列に変換
    std::string h = "";
    for (int j = 0; j < SHA256_DIGEST_LENGTH; ++j) {
        std::stringstream ss;
        ss << std::hex << (int)digest[j];
        h.append(ss.str());
    }
    // 確認
    std::cout << "ハッシュ値: ";
    std::cout << h << std::endl;

    std::string key1 = "sample_key";
    std::cout << key1 << std::endl;


    SHA256_Update(&sha_ctx, key1.c_str(), key1.length());
    SHA256_Final(digest, &sha_ctx);

    // ハッシュ値(16進数)を文字列に変換
    std::string h1 = "";
    for (int j = 0; j < SHA256_DIGEST_LENGTH; ++j) {
        std::stringstream ss;
        ss << std::hex << (int)digest[j];
        h1.append(ss.str());
    }
    // 確認
    std::cout << "ハッシュ値: ";
    std::cout << h1 << std::endl;




    return 0;
}
