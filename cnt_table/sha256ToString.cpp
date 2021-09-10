#include <iostream>
#include <string>
#include <sstream>
#include <openssl/sha.h>


std::string sha256ToString(unsigned char digest[SHA256_DIGEST_LENGTH])
{
    std::string h = "";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        std::stringstream ss;
        ss << std::hex << digest[i];
        h.append(ss.str());
    }
    //確認
    std::cout << h << std::endl;

    return h;
}
