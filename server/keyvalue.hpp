#pragma once
#include <string>

class KV {
    std::string key;
    std::string value;

    public:
    KV() {
        this->key = "dummy";
        this->value = "dummy";
    }
    KV(std::string key) {
        this->key = key;
        this->value = "dummy";
    }

    KV(std::string key, std::string value) {
        this->key = key;
        this->value = "dummy";
    }

    void setKey(std::string key) {
        this->key = key;
    }

    void setValue(std::string value) {
        this->value = value;
    }
    
    std::string getKey()
    {
        return this->key;
    }

    std::string getValue()
    {
        return this->value;
    }

    bool operator < (const KV &obj) const
    {
        return this->key < obj.key;
    }
};
