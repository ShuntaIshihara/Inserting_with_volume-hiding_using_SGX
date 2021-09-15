#include <fstream>
#include <string>

std::string getPubKey(std::string filename)
{
    std::fstream pubKeyFile(filename, std::fstream::in);
    std::string hexPubKey;
    std::getline(pubKeyFile, hexPubKey);
    pubKeyFile.close();

    return hexPubKey;
}

std::string getSecKey(std::string filename)
{
    std::fstream secKeyFile(filename, std::fstream::in);
    std::string hexSecKey;
    std::getline(secKeyFile, hexSecKey);
    secKeyFile.close();

    return hexSecKey;
}
