#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_start_t {
	int ms_retval;
	struct keyvalue* ms_table;
	struct keyvalue* ms_data;
	int* ms_size;
} ms_ecall_start_t;

typedef struct ms_ocall_return_stash_t {
	struct keyvalue* ms_stash;
} ms_ocall_return_stash_t;

static sgx_status_t SGX_CDECL Enclave_ocall_return_stash(void* pms)
{
	ms_ocall_return_stash_t* ms = SGX_CAST(ms_ocall_return_stash_t*, pms);
	ocall_return_stash(ms->ms_stash);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_return_stash,
	}
};
sgx_status_t ecall_start(sgx_enclave_id_t eid, int* retval, struct keyvalue table[2][10], struct keyvalue* data, int* size)
{
	sgx_status_t status;
	ms_ecall_start_t ms;
	ms.ms_table = (struct keyvalue*)table;
	ms.ms_data = data;
	ms.ms_size = size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

