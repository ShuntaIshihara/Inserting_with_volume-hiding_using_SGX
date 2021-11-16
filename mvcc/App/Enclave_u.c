#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_test_t {
	int ms_retval;
	const char* ms_message;
	size_t ms_message_len;
} ms_ecall_test_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t ecall_test(sgx_enclave_id_t eid, int* retval, const char* message, size_t message_len)
{
	sgx_status_t status;
	ms_ecall_test_t ms;
	ms.ms_message = message;
	ms.ms_message_len = message_len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

