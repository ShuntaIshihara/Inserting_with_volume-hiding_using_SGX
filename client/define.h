#pragma once

enum {
    SUCCESS,
    ERROR_UNEXPECTED,
    ERROR_INVALID_PARAMETER,
    ERROR_OUT_OF_MEMORY
};

struct keyvalue {
    unsigned char key[256];
    unsigned char value[256];
};


