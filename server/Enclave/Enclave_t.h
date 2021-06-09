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
	char key[32];
	char value[32];
} keyvalue;
#endif

int ecall_start(struct keyvalue table[2][10], struct keyvalue* data, int* size);

sgx_status_t SGX_CDECL ocall_return_stash(struct keyvalue stash[2]);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
