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
