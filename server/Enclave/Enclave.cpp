#include "Enclave_t.h"
#include <sgx_trts.h>

int ecall_test(struct keyvalue table[2][10], struct keyvalue *data)
{
	table[0][5] = *data;

	return 31337;
}
