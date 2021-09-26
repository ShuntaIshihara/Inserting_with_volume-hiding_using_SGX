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

typedef struct ms_ecall_hash_block_t {
	int ms_retval;
	unsigned char* ms_key;
	int* ms_size;
} ms_ecall_hash_block_t;

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

static sgx_status_t SGX_CDECL sgx_ecall_generate_keys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_keys_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_keys_t* ms = SGX_CAST(ms_ecall_generate_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_n = ms->ms_n;
	size_t _len_n = 256 * sizeof(unsigned char);
	unsigned char* _in_n = NULL;
	unsigned char* _tmp_d = ms->ms_d;
	size_t _len_d = 256 * sizeof(unsigned char);
	unsigned char* _in_d = NULL;
	unsigned char* _tmp_p = ms->ms_p;
	size_t _len_p = 256 * sizeof(unsigned char);
	unsigned char* _in_p = NULL;
	unsigned char* _tmp_q = ms->ms_q;
	size_t _len_q = 256 * sizeof(unsigned char);
	unsigned char* _in_q = NULL;
	unsigned char* _tmp_dmp1 = ms->ms_dmp1;
	size_t _len_dmp1 = 256 * sizeof(unsigned char);
	unsigned char* _in_dmp1 = NULL;
	unsigned char* _tmp_dmq1 = ms->ms_dmq1;
	size_t _len_dmq1 = 256 * sizeof(unsigned char);
	unsigned char* _in_dmq1 = NULL;
	unsigned char* _tmp_iqmp = ms->ms_iqmp;
	size_t _len_iqmp = 256 * sizeof(unsigned char);
	unsigned char* _in_iqmp = NULL;
	long int* _tmp_e = ms->ms_e;
	size_t _len_e = sizeof(long int);
	long int* _in_e = NULL;

	CHECK_UNIQUE_POINTER(_tmp_n, _len_n);
	CHECK_UNIQUE_POINTER(_tmp_d, _len_d);
	CHECK_UNIQUE_POINTER(_tmp_p, _len_p);
	CHECK_UNIQUE_POINTER(_tmp_q, _len_q);
	CHECK_UNIQUE_POINTER(_tmp_dmp1, _len_dmp1);
	CHECK_UNIQUE_POINTER(_tmp_dmq1, _len_dmq1);
	CHECK_UNIQUE_POINTER(_tmp_iqmp, _len_iqmp);
	CHECK_UNIQUE_POINTER(_tmp_e, _len_e);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_n != NULL && _len_n != 0) {
		if ( _len_n % sizeof(*_tmp_n) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_n = (unsigned char*)malloc(_len_n);
		if (_in_n == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_n, _len_n, _tmp_n, _len_n)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_d != NULL && _len_d != 0) {
		if ( _len_d % sizeof(*_tmp_d) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_d = (unsigned char*)malloc(_len_d);
		if (_in_d == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_d, _len_d, _tmp_d, _len_d)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p != NULL && _len_p != 0) {
		if ( _len_p % sizeof(*_tmp_p) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_p = (unsigned char*)malloc(_len_p);
		if (_in_p == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p, _len_p, _tmp_p, _len_p)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_q != NULL && _len_q != 0) {
		if ( _len_q % sizeof(*_tmp_q) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_q = (unsigned char*)malloc(_len_q);
		if (_in_q == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_q, _len_q, _tmp_q, _len_q)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dmp1 != NULL && _len_dmp1 != 0) {
		if ( _len_dmp1 % sizeof(*_tmp_dmp1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_dmp1 = (unsigned char*)malloc(_len_dmp1);
		if (_in_dmp1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dmp1, _len_dmp1, _tmp_dmp1, _len_dmp1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dmq1 != NULL && _len_dmq1 != 0) {
		if ( _len_dmq1 % sizeof(*_tmp_dmq1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_dmq1 = (unsigned char*)malloc(_len_dmq1);
		if (_in_dmq1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dmq1, _len_dmq1, _tmp_dmq1, _len_dmq1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_iqmp != NULL && _len_iqmp != 0) {
		if ( _len_iqmp % sizeof(*_tmp_iqmp) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_iqmp = (unsigned char*)malloc(_len_iqmp);
		if (_in_iqmp == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_iqmp, _len_iqmp, _tmp_iqmp, _len_iqmp)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_e != NULL && _len_e != 0) {
		if ( _len_e % sizeof(*_tmp_e) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_e = (long int*)malloc(_len_e);
		if (_in_e == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_e, _len_e, _tmp_e, _len_e)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_generate_keys(_in_n, _in_d, _in_p, _in_q, _in_dmp1, _in_dmq1, _in_iqmp, _in_e);
	if (_in_n) {
		if (memcpy_s(_tmp_n, _len_n, _in_n, _len_n)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_d) {
		if (memcpy_s(_tmp_d, _len_d, _in_d, _len_d)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_p) {
		if (memcpy_s(_tmp_p, _len_p, _in_p, _len_p)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_q) {
		if (memcpy_s(_tmp_q, _len_q, _in_q, _len_q)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_dmp1) {
		if (memcpy_s(_tmp_dmp1, _len_dmp1, _in_dmp1, _len_dmp1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_dmq1) {
		if (memcpy_s(_tmp_dmq1, _len_dmq1, _in_dmq1, _len_dmq1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_iqmp) {
		if (memcpy_s(_tmp_iqmp, _len_iqmp, _in_iqmp, _len_iqmp)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_e) {
		if (memcpy_s(_tmp_e, _len_e, _in_e, _len_e)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_n) free(_in_n);
	if (_in_d) free(_in_d);
	if (_in_p) free(_in_p);
	if (_in_q) free(_in_q);
	if (_in_dmp1) free(_in_dmp1);
	if (_in_dmq1) free(_in_dmq1);
	if (_in_iqmp) free(_in_iqmp);
	if (_in_e) free(_in_e);
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
	size_t _len_table = 20000 * sizeof(struct keyvalue);
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

	ecall_insertion_start((struct keyvalue (*)[10000])_in_table, _in_data, _in_size);
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

static sgx_status_t SGX_CDECL sgx_ecall_hash_block(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_hash_block_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_hash_block_t* ms = SGX_CAST(ms_ecall_hash_block_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_key = ms->ms_key;
	size_t _len_key = 256 * sizeof(unsigned char);
	unsigned char* _in_key = NULL;
	int* _tmp_size = ms->ms_size;
	size_t _len_size = sizeof(int);
	int* _in_size = NULL;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);
	CHECK_UNIQUE_POINTER(_tmp_size, _len_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_key = (unsigned char*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
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

	ms->ms_retval = ecall_hash_block(_in_key, _in_size);

err:
	if (_in_key) free(_in_key);
	if (_in_size) free(_in_size);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_keys, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_encrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_decrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_insertion_start, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_hash_block, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][5];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

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
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_return_stash(struct keyvalue stash[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_stash = 2 * sizeof(struct keyvalue);

	ms_ocall_return_stash_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_return_stash_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(stash, _len_stash);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (stash != NULL) ? _len_stash : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_return_stash_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_return_stash_t));
	ocalloc_size -= sizeof(ms_ocall_return_stash_t);

	if (stash != NULL) {
		ms->ms_stash = (struct keyvalue*)__tmp;
		if (_len_stash % sizeof(*stash) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, stash, _len_stash)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_stash);
		ocalloc_size -= _len_stash;
	} else {
		ms->ms_stash = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_e(long int* e)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_e = sizeof(long int);

	ms_ocall_print_e_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_e_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(e, _len_e);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (e != NULL) ? _len_e : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_e_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_e_t));
	ocalloc_size -= sizeof(ms_ocall_print_e_t);

	if (e != NULL) {
		ms->ms_e = (long int*)__tmp;
		if (_len_e % sizeof(*e) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, e, _len_e)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_e);
		ocalloc_size -= _len_e;
	} else {
		ms->ms_e = NULL;
	}
	
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

