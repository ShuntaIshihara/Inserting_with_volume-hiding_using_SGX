#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_encrypt_t {
	unsigned char* ms_t_data;
	unsigned char* ms_data;
	size_t ms_data_len;
} ms_ecall_encrypt_t;

typedef struct ms_ecall_decrypt_t {
	unsigned char* ms_dec;
	unsigned char* ms_enc;
} ms_ecall_decrypt_t;

typedef struct ms_ecall_insertion_start_t {
	struct keyvalue* ms_table;
	struct keyvalue* ms_data;
	int* ms_size;
} ms_ecall_insertion_start_t;

typedef struct ms_ocall_err_different_size_t {
	const char* ms_str;
} ms_ocall_err_different_size_t;

typedef struct ms_ocall_err_print_t {
	sgx_status_t* ms_st;
} ms_ocall_err_print_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_return_stash_t {
	struct keyvalue* ms_stash;
} ms_ocall_return_stash_t;

static sgx_status_t SGX_CDECL Enclave_ocall_err_different_size(void* pms)
{
	ms_ocall_err_different_size_t* ms = SGX_CAST(ms_ocall_err_different_size_t*, pms);
	ocall_err_different_size(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_err_print(void* pms)
{
	ms_ocall_err_print_t* ms = SGX_CAST(ms_ocall_err_print_t*, pms);
	ocall_err_print(ms->ms_st);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_return_stash(void* pms)
{
	ms_ocall_return_stash_t* ms = SGX_CAST(ms_ocall_return_stash_t*, pms);
	ocall_return_stash(ms->ms_stash);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[4];
} ocall_table_Enclave = {
	4,
	{
		(void*)Enclave_ocall_err_different_size,
		(void*)Enclave_ocall_err_print,
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_return_stash,
	}
};
sgx_status_t ecall_generate_keys(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_encrypt(sgx_enclave_id_t eid, unsigned char t_data[256], unsigned char* data)
{
	sgx_status_t status;
	ms_ecall_encrypt_t ms;
	ms.ms_t_data = (unsigned char*)t_data;
	ms.ms_data = data;
	ms.ms_data_len = data ? strlen(data) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_decrypt(sgx_enclave_id_t eid, unsigned char dec[256], unsigned char enc[256])
{
	sgx_status_t status;
	ms_ecall_decrypt_t ms;
	ms.ms_dec = (unsigned char*)dec;
	ms.ms_enc = (unsigned char*)enc;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_insertion_start(sgx_enclave_id_t eid, struct keyvalue table[2][10], struct keyvalue* data, int* size)
{
	sgx_status_t status;
	ms_ecall_insertion_start_t ms;
	ms.ms_table = (struct keyvalue*)table;
	ms.ms_data = data;
	ms.ms_size = size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

