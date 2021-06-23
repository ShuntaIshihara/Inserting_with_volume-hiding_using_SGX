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
	unsigned char field0[256];
	unsigned char field1[256];
	unsigned char field2[256];
	unsigned char field3[256];
	unsigned char field4[256];
	unsigned char field5[256];
	unsigned char field6[256];
	unsigned char field7[256];
	unsigned char field8[256];
	unsigned char field9[256];
} keyvalue;
#endif

void ecall_generate_keys(void);
void ecall_encrypt(unsigned char* field, unsigned char t_field[256]);
void ecall_decrypt(unsigned char dec[256], unsigned char enc[256]);
void ecall_insertion_start(struct keyvalue table[2][10], struct keyvalue* data, int* size);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_err_print(sgx_status_t* st);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
