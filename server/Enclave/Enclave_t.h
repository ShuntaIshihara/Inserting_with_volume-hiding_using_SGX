#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _keyvalue
#define _keyvalue
typedef struct keyvalue {
	unsigned char key[256];
	unsigned char value[256];
} keyvalue;
#endif

void ecall_generate_keys(unsigned char n[256], unsigned char d[256], unsigned char p[256], unsigned char q[256], unsigned char dmp1[256], unsigned char dmq1[256], unsigned char iqmp[256], long int* e);
void ecall_encrypt(unsigned char t_data[256], unsigned char* data);
void ecall_decrypt(unsigned char dec[256], unsigned char enc[256]);
void ecall_table_malloc(void);
void ecall_load(struct keyvalue* t, size_t table_size, int* head);
void ecall_insertion_start(struct keyvalue* data, int* size, int* block);
int ecall_hash_block(unsigned char key[256], int* size);

sgx_status_t SGX_CDECL ocall_err_different_size(const char* str);
sgx_status_t SGX_CDECL ocall_err_print(sgx_status_t* st);
sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_return_table(struct keyvalue* t, size_t table_size, int* block, int* head);
sgx_status_t SGX_CDECL ocall_return_stash(struct keyvalue stash[2]);
sgx_status_t SGX_CDECL ocall_print_e(long int* e);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
