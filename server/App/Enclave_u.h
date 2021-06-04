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
	char* key;
	char* value;
} keyvalue;
#endif


sgx_status_t ecall_start(sgx_enclave_id_t eid, int* retval, struct keyvalue table[2][10], struct keyvalue* data, int* size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
