#ifndef _OCALL_FUNC_HPP 
#define _OCALL_FUNC_HPP 

#include "Enclave_u.h"
#include <sgx_urts.h>

void ocall_return_stash(struct keyvalue st[2]);
void ocall_err_different_size(const char *str);
void ocall_err_print(sgx_status_t *st);
void ocall_print(const char *str);
void ocall_print_e(long *e);


#endif // _OCALL_FUNC_HPP
