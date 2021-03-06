#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_generate_keys_t {
	unsigned char* ms_n;
	unsigned char* ms_d;
	unsigned char* ms_p;
	unsigned char* ms_q;
	unsigned char* ms_dmp1;
	unsigned char* ms_dmq1;
	unsigned char* ms_iqmp;
	long int* ms_e;
} ms_ecall_generate_keys_t;

typedef struct ms_ecall_encrypt_t {
	unsigned char* ms_enc;
	unsigned char* ms_data;
	size_t ms_data_len;
} ms_ecall_encrypt_t;

typedef struct ms_ecall_decrypt_t {
	unsigned char* ms_dec;
	unsigned char* ms_enc;
} ms_ecall_decrypt_t;

typedef struct ms_ecall_insertion_start_t {
	struct keyvalue* ms_table;
	size_t ms_t_size;
	struct keyvalue* ms_data;
} ms_ecall_insertion_start_t;

typedef struct ms_ecall_hash_block_t {
	int ms_retval;
	unsigned char* ms_key;
	int* ms_size;
} ms_ecall_hash_block_t;

typedef struct ms_ecall_get_block_t {
	int ms_retval;
	unsigned char* ms_enc_key;
	int* ms_i;
	int* ms_block_size;
} ms_ecall_get_block_t;

typedef struct ms_ecall_search_t {
	struct keyvalue* ms_kvs;
	struct keyvalue* ms_table;
	size_t ms_t_size;
	unsigned char* ms_enc_key;
	int* ms_i;
} ms_ecall_search_t;

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

typedef struct ms_ocall_print_e_t {
	long int* ms_e;
} ms_ocall_print_e_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_print_e(void* pms)
{
	ms_ocall_print_e_t* ms = SGX_CAST(ms_ocall_print_e_t*, pms);
	ocall_print_e(ms->ms_e);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_Enclave = {
	5,
	{
		(void*)Enclave_ocall_err_different_size,
		(void*)Enclave_ocall_err_print,
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_return_stash,
		(void*)Enclave_ocall_print_e,
	}
};
sgx_status_t ecall_generate_keys(sgx_enclave_id_t eid, unsigned char n[256], unsigned char d[256], unsigned char p[256], unsigned char q[256], unsigned char dmp1[256], unsigned char dmq1[256], unsigned char iqmp[256], long int* e)
{
	sgx_status_t status;
	ms_ecall_generate_keys_t ms;
	ms.ms_n = (unsigned char*)n;
	ms.ms_d = (unsigned char*)d;
	ms.ms_p = (unsigned char*)p;
	ms.ms_q = (unsigned char*)q;
	ms.ms_dmp1 = (unsigned char*)dmp1;
	ms.ms_dmq1 = (unsigned char*)dmq1;
	ms.ms_iqmp = (unsigned char*)iqmp;
	ms.ms_e = e;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_encrypt(sgx_enclave_id_t eid, unsigned char enc[256], unsigned char* data)
{
	sgx_status_t status;
	ms_ecall_encrypt_t ms;
	ms.ms_enc = (unsigned char*)enc;
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

sgx_status_t ecall_insertion_start(sgx_enclave_id_t eid, struct keyvalue* table, size_t t_size, struct keyvalue* data)
{
	sgx_status_t status;
	ms_ecall_insertion_start_t ms;
	ms.ms_table = table;
	ms.ms_t_size = t_size;
	ms.ms_data = data;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_hash_block(sgx_enclave_id_t eid, int* retval, unsigned char key[256], int* size)
{
	sgx_status_t status;
	ms_ecall_hash_block_t ms;
	ms.ms_key = (unsigned char*)key;
	ms.ms_size = size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_block(sgx_enclave_id_t eid, int* retval, unsigned char enc_key[256], int* i, int* block_size)
{
	sgx_status_t status;
	ms_ecall_get_block_t ms;
	ms.ms_enc_key = (unsigned char*)enc_key;
	ms.ms_i = i;
	ms.ms_block_size = block_size;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_search(sgx_enclave_id_t eid, struct keyvalue kvs[2], struct keyvalue* table, size_t t_size, unsigned char enc_key[256], int* i)
{
	sgx_status_t status;
	ms_ecall_search_t ms;
	ms.ms_kvs = (struct keyvalue*)kvs;
	ms.ms_table = table;
	ms.ms_t_size = t_size;
	ms.ms_enc_key = (unsigned char*)enc_key;
	ms.ms_i = i;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

