#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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
	int* ms_rnd;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL sgx_ecall_generate_keys(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_generate_keys();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_encrypt_t* ms = SGX_CAST(ms_ecall_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_t_data = ms->ms_t_data;
	size_t _len_t_data = 256 * sizeof(unsigned char);
	unsigned char* _in_t_data = NULL;
	unsigned char* _tmp_data = ms->ms_data;
	size_t _len_data = ms->ms_data_len ;
	unsigned char* _in_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_t_data, _len_t_data);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_t_data != NULL && _len_t_data != 0) {
		if ( _len_t_data % sizeof(*_tmp_t_data) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_t_data = (unsigned char*)malloc(_len_t_data);
		if (_in_t_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_t_data, _len_t_data, _tmp_t_data, _len_t_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_data != NULL && _len_data != 0) {
		_in_data = (unsigned char*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_data[_len_data - 1] = '\0';
		if (_len_data != strlen(_in_data) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_encrypt(_in_t_data, _in_data);
	if (_in_t_data) {
		if (memcpy_s(_tmp_t_data, _len_t_data, _in_t_data, _len_t_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_t_data) free(_in_t_data);
	if (_in_data) free(_in_data);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_decrypt_t* ms = SGX_CAST(ms_ecall_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_dec = ms->ms_dec;
	size_t _len_dec = 256 * sizeof(unsigned char);
	unsigned char* _in_dec = NULL;
	unsigned char* _tmp_enc = ms->ms_enc;
	size_t _len_enc = 256 * sizeof(unsigned char);
	unsigned char* _in_enc = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dec, _len_dec);
	CHECK_UNIQUE_POINTER(_tmp_enc, _len_enc);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dec != NULL && _len_dec != 0) {
		if ( _len_dec % sizeof(*_tmp_dec) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_dec = (unsigned char*)malloc(_len_dec);
		if (_in_dec == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dec, _len_dec, _tmp_dec, _len_dec)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_enc != NULL && _len_enc != 0) {
		if ( _len_enc % sizeof(*_tmp_enc) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_enc = (unsigned char*)malloc(_len_enc);
		if (_in_enc == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enc, _len_enc, _tmp_enc, _len_enc)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_decrypt(_in_dec, _in_enc);
	if (_in_dec) {
		if (memcpy_s(_tmp_dec, _len_dec, _in_dec, _len_dec)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dec) free(_in_dec);
	if (_in_enc) free(_in_enc);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_insertion_start(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_insertion_start_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_insertion_start_t* ms = SGX_CAST(ms_ecall_insertion_start_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct keyvalue* _tmp_table = ms->ms_table;
	size_t _len_table = 20 * sizeof(struct keyvalue);
	struct keyvalue* _in_table = NULL;
	struct keyvalue* _tmp_data = ms->ms_data;
	size_t _len_data = sizeof(struct keyvalue);
	struct keyvalue* _in_data = NULL;
	int* _tmp_size = ms->ms_size;
	size_t _len_size = sizeof(int);
	int* _in_size = NULL;

	CHECK_UNIQUE_POINTER(_tmp_table, _len_table);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_size, _len_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_table != NULL && _len_table != 0) {
		if ( _len_table % sizeof(*_tmp_table) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_table = (struct keyvalue*)malloc(_len_table);
		if (_in_table == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_table, _len_table, _tmp_table, _len_table)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_data != NULL && _len_data != 0) {
		_in_data = (struct keyvalue*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_data, _len_data, _tmp_data, _len_data)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_size != NULL && _len_size != 0) {
		if ( _len_size % sizeof(*_tmp_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_size = (int*)malloc(_len_size);
		if (_in_size == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_size, _len_size, _tmp_size, _len_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_insertion_start((struct keyvalue (*)[10])_in_table, _in_data, _in_size);
	if (_in_table) {
		if (memcpy_s(_tmp_table, _len_table, _in_table, _len_table)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_table) free(_in_table);
	if (_in_data) free(_in_data);
	if (_in_size) free(_in_size);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_keys, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_encrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_decrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_insertion_start, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][4];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_err_different_size(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_err_different_size_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_err_different_size_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_err_different_size_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_err_different_size_t));
	ocalloc_size -= sizeof(ms_ocall_err_different_size_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_err_print(sgx_status_t* st)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_st = sizeof(sgx_status_t);

	ms_ocall_err_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_err_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(st, _len_st);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (st != NULL) ? _len_st : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_err_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_err_print_t));
	ocalloc_size -= sizeof(ms_ocall_err_print_t);

	if (st != NULL) {
		ms->ms_st = (sgx_status_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, st, _len_st)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_st);
		ocalloc_size -= _len_st;
	} else {
		ms->ms_st = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print(int* rnd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_rnd = sizeof(int);

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(rnd, _len_rnd);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (rnd != NULL) ? _len_rnd : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (rnd != NULL) {
		ms->ms_rnd = (int*)__tmp;
		if (_len_rnd % sizeof(*rnd) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, rnd, _len_rnd)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_rnd);
		ocalloc_size -= _len_rnd;
	} else {
		ms->ms_rnd = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

