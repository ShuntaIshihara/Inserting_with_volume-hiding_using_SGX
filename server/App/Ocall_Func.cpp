#include <iostream>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.h"

extern struct keyvalue stash[2];

//OCALL implementation

void ocall_return_stash(struct keyvalue st[2])
{
    stash[0] = st[0];
    stash[1] = st[1];
}

void ocall_err_different_size(const char *str)
{
    std::cerr << str << std::endl;
    //↓↓↓例外処理を入れる↓↓↓
}

void ocall_err_print(sgx_status_t *st)
{
    sgx_error_print(*st);
    //↓↓↓例外処理を入れる↓↓↓
}

void ocall_print(const char *str)
{
    std::cout << str << std::endl;
}

void ocall_print_e(long *e)
{
    std::cout << "e = " << *e << std::endl;
}


