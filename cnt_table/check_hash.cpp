#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <openssl/sha.h>

std::string sha256(SHA256_CTX sha_ctx, std::string m)
{
    SHA256_Init(&sha_ctx); // コンテキストを初期化

    //sha256ハッシュ値生成
    unsigned char digest[SHA256_DIGEST_LENGTH];


    SHA256_Update(&sha_ctx, m.c_str(), m.length());
    SHA256_Final(digest, &sha_ctx);
    

    // ハッシュ値(16進数)を文字列に変換
    std::string h = "";
    for (int j = 0; j < SHA256_DIGEST_LENGTH; ++j) {
        std::stringstream ss;
        ss << std::hex << (int)digest[j];
        h.append(ss.str());
    }

    return h;
}

int main()
{
    //opnessl shaのコンテキスト初期化

	SHA256_CTX sha_ctx;
/*	SHA256_Init(&sha_ctx); // コンテキストを初期化

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
*/
    std::string h = sha256(sha_ctx, "sample_key");
    // 確認
    std::cout << "ハッシュ値: ";
    std::cout << h << std::endl;
/*
	SHA256_Init(&sha_ctx); // コンテキストを初期化

    unsigned char digest1[SHA256_DIGEST_LENGTH];

    std::string key1 = "sample_key";
    std::cout << key1 << std::endl;


    SHA256_Update(&sha_ctx, key1.c_str(), key1.length());
    SHA256_Final(digest1, &sha_ctx);

    // ハッシュ値(16進数)を文字列に変換
    std::string h1 = "";
    for (int j = 0; j < SHA256_DIGEST_LENGTH; ++j) {
        std::stringstream ss;
        ss << std::hex << (int)digest1[j];
        h1.append(ss.str());
    }
*/
    std::string h1 = sha256(sha_ctx, "sample_key");
    // 確認
    std::cout << "ハッシュ値: ";
    std::cout << h1 << std::endl;




    return 0;
}
