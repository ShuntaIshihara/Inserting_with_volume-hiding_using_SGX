#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _keyvalue
#define _keyvalue
typedef struct keyvalue {
	unsigned char key[256];
	unsigned char value[10][256];
} keyvalue;
#endif

#ifndef OCALL_ERR_DIFFERENT_SIZE_DEFINED__
#define OCALL_ERR_DIFFERENT_SIZE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_err_different_size, (const char* str));
#endif
#ifndef OCALL_ERR_PRINT_DEFINED__
#define OCALL_ERR_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_err_print, (sgx_status_t* st));
#endif
#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef OCALL_RETURN_STASH_DEFINED__
#define OCALL_RETURN_STASH_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_return_stash, (struct keyvalue stash[2]));
#endif
#ifndef OCALL_PRINT_E_DEFINED__
#define OCALL_PRINT_E_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_e, (long int* e));
#endif

sgx_status_t ecall_generate_keys(sgx_enclave_id_t eid, unsigned char n[256], unsigned char d[256], unsigned char p[256], unsigned char q[256], unsigned char dmp1[256], unsigned char dmq1[256], unsigned char iqmp[256], long int* e);
sgx_status_t ecall_encrypt(sgx_enclave_id_t eid, unsigned char t_data[256], unsigned char* data);
sgx_status_t ecall_decrypt(sgx_enclave_id_t eid, unsigned char dec[256], unsigned char enc[256]);
sgx_status_t ecall_insertion_start(sgx_enclave_id_t eid, struct keyvalue* table, size_t table_size, struct keyvalue* data, int* size);
sgx_status_t ecall_hash_block(sgx_enclave_id_t eid, int* retval, unsigned char key[256], int* size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
