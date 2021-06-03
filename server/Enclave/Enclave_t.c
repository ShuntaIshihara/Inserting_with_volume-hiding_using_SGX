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


typedef struct ms_ecall_test_t {
	int ms_retval;
	struct keyvalue* ms_table;
	struct keyvalue* ms_data;
} ms_ecall_test_t;

static sgx_status_t SGX_CDECL sgx_ecall_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_test_t* ms = SGX_CAST(ms_ecall_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct keyvalue* _tmp_table = ms->ms_table;
	size_t _len_table = 20 * sizeof(struct keyvalue);
	struct keyvalue* _in_table = NULL;
	struct keyvalue* _tmp_data = ms->ms_data;
	size_t _len_data = sizeof(struct keyvalue);
	struct keyvalue* _in_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_table, _len_table);
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

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

	ms->ms_retval = ecall_test((struct keyvalue (*)[10])_in_table, _in_data);
	if (_in_table) {
		if (memcpy_s(_tmp_table, _len_table, _in_table, _len_table)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_table) free(_in_table);
	if (_in_data) free(_in_data);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_test, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


