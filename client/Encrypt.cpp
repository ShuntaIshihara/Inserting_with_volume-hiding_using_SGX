#include <iostream> //標準入出力
#include <cstring>
#include <cstdlib>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "define.h"


void *pub_key = NULL;
void *priv_key = NULL;


void client_err_print(int status)
{
    switch (status) {
        case ERROR_UNEXPECTED: std::cerr << "------------------------------" << std::endl;
        std::cerr << "ERROR UNEXPECTED" << std::endl;
        std::cerr << "status = " << (int)ERROR_UNEXPECTED << std::endl;
        std::cerr << "------------------------------" << std::endl;
        std::exit(1);
        case ERROR_INVALID_PARAMETER: std::cerr << "------------------------------" << std::endl;
        std::cerr << "ERROR INVALID PARAMETER" << std::endl;
        std::cerr << "status = " << (int)ERROR_INVALID_PARAMETER << std::endl;
        std::cerr << "------------------------------" << std::endl;
        std::exit(2);
        case ERROR_OUT_OF_MEMORY: std::cerr << "------------------------------" << std::endl;
        std::cerr << "ERROR_OUT_OF_MEMORY" << std::endl;
        std::cerr << "status = " << (int)ERROR_INVALID_PARAMETER << std::endl;
        std::cerr << "------------------------------" << std::endl;
        std::exit(3);
        default: break;
    }
}

int client_create_rsa_key_pair(int n_byte_size, int e_byte_size, unsigned char *p_n, unsigned char *p_d, unsigned char *p_e,
	unsigned char *p_p, unsigned char *p_q, unsigned char *p_dmp1,
	unsigned char *p_dmq1, unsigned char *p_iqmp)
{
	if (n_byte_size <= 0 || e_byte_size <= 0 || p_n == NULL || p_d == NULL || p_e == NULL ||
		p_p == NULL || p_q == NULL || p_dmp1 == NULL || p_dmq1 == NULL || p_iqmp == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	int ret_code = ERROR_UNEXPECTED;
	RSA* rsa_ctx = NULL;
	BIGNUM* bn_n = NULL;
	BIGNUM* bn_e = NULL;
	BIGNUM* tmp_bn_e = NULL;
	BIGNUM* bn_d = NULL;
	BIGNUM* bn_dmp1 = NULL;
	BIGNUM* bn_dmq1 = NULL;
	BIGNUM* bn_iqmp = NULL;
	BIGNUM* bn_q = NULL;
	BIGNUM* bn_p = NULL;

	do {
		//create new rsa ctx
		//
		rsa_ctx = RSA_new();
		if (rsa_ctx == NULL) {
			ret_code = ERROR_OUT_OF_MEMORY;
			break;
		}

		//generate rsa key pair, with n_byte_size*8 mod size and p_e exponent
		//
		tmp_bn_e = BN_lebin2bn(p_e, e_byte_size, tmp_bn_e);
		if (RSA_generate_key_ex(rsa_ctx, n_byte_size * 8, tmp_bn_e, NULL) != 1) {
			break;
		}

		//validate RSA key size match input parameter n size
		//
		int gen_rsa_size = RSA_size(rsa_ctx);
		if (gen_rsa_size != n_byte_size) {
			break;
		}

		//get RSA key internal values
		//
		RSA_get0_key(rsa_ctx, (const BIGNUM**)(&bn_n), (const BIGNUM**)(&bn_e), (const BIGNUM**)(&bn_d));
		RSA_get0_factors(rsa_ctx, (const BIGNUM**)(&bn_p), (const BIGNUM**)(&bn_q));
		RSA_get0_crt_params(rsa_ctx, (const BIGNUM**)(&bn_dmp1), (const BIGNUM**)(&bn_dmq1), (const BIGNUM**)(&bn_iqmp));

		//copy the generated key to input pointers
		//
		if (!BN_bn2lebinpad(bn_n, p_n, BN_num_bytes(bn_n)) ||
			!BN_bn2lebinpad(bn_d, p_d, BN_num_bytes(bn_d)) ||
			!BN_bn2lebinpad(bn_e, p_e, BN_num_bytes(bn_e)) ||
			!BN_bn2lebinpad(bn_p, p_p, BN_num_bytes(bn_p)) ||
			!BN_bn2lebinpad(bn_q, p_q, BN_num_bytes(bn_q)) ||
			!BN_bn2lebinpad(bn_dmp1, p_dmp1, BN_num_bytes(bn_dmp1)) ||
			!BN_bn2lebinpad(bn_dmq1, p_dmq1, BN_num_bytes(bn_dmq1)) ||
			!BN_bn2lebinpad(bn_iqmp, p_iqmp, BN_num_bytes(bn_iqmp))) {
			break;
		}

		ret_code = SUCCESS;
	} while (0);

	//free rsa ctx (RSA_free also free related BNs obtained in RSA_get functions)
	//
	RSA_free(rsa_ctx);
	BN_clear_free(tmp_bn_e);

	return ret_code;
}

int client_create_rsa_priv2_key(int mod_size, int exp_size, const unsigned char *p_rsa_key_e, const unsigned char *p_rsa_key_p, const unsigned char *p_rsa_key_q,
	const unsigned char *p_rsa_key_dmp1, const unsigned char *p_rsa_key_dmq1, const unsigned char *p_rsa_key_iqmp,
	void **new_pri_key2)
{
	if (mod_size <= 0 || exp_size <= 0 || new_pri_key2 == NULL ||
		p_rsa_key_e == NULL || p_rsa_key_p == NULL || p_rsa_key_q == NULL || p_rsa_key_dmp1 == NULL ||
		p_rsa_key_dmq1 == NULL || p_rsa_key_iqmp == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	bool rsa_memory_manager = 0;
	EVP_PKEY *rsa_key = NULL;
	RSA *rsa_ctx = NULL;
	int ret_code = ERROR_UNEXPECTED;
	BIGNUM* n = NULL;
	BIGNUM* e = NULL;
	BIGNUM* d = NULL;
	BIGNUM* dmp1 = NULL;
	BIGNUM* dmq1 = NULL;
	BIGNUM* iqmp = NULL;
	BIGNUM* q = NULL;
	BIGNUM* p = NULL;
	BN_CTX* tmp_ctx = NULL;

	do {
		tmp_ctx = BN_CTX_new();
		n = BN_new();

		// convert RSA params, factors to BNs
		//
		p = BN_lebin2bn(p_rsa_key_p, (mod_size / 2), p);
		q = BN_lebin2bn(p_rsa_key_q, (mod_size / 2), q);
		dmp1 = BN_lebin2bn(p_rsa_key_dmp1, (mod_size / 2), dmp1);
		dmq1 = BN_lebin2bn(p_rsa_key_dmq1, (mod_size / 2), dmq1);
		iqmp = BN_lebin2bn(p_rsa_key_iqmp, (mod_size / 2), iqmp);
		e = BN_lebin2bn(p_rsa_key_e, (exp_size), e);

		// calculate n value
		//
		if (!BN_mul(n, p, q, tmp_ctx)) {
			break;
		}

		//calculate d value
		//ϕ(n)=(p−1)(q−1)
		//d=(e^−1) mod ϕ(n)
		//
		d = BN_dup(n);

		//select algorithms with an execution time independent of the respective numbers, to avoid exposing sensitive information to timing side-channel attacks.
		//
		BN_set_flags(d, BN_FLG_CONSTTIME);
		BN_set_flags(e, BN_FLG_CONSTTIME);

		if (!BN_sub(d, d, p) || !BN_sub(d, d, q) || !BN_add_word(d, 1) || !BN_mod_inverse(d, e, d, tmp_ctx)) {
			break;
		}

		// allocates and initializes an RSA key structure
		//
		rsa_ctx = RSA_new();
		rsa_key = EVP_PKEY_new();

                //EVP_PKEY_assign_RSA() use the supplied key internally and so if this call succeed, key will be freed when the parent pkey is freed.
                //
		if (rsa_ctx == NULL || rsa_key == NULL || !EVP_PKEY_assign_RSA(rsa_key, rsa_ctx)) {
			RSA_free(rsa_ctx);
			rsa_key = NULL;
			break;
		}

		//setup RSA key with input values
		//Calling set functions transfers the memory management of the values to the RSA object,
		//and therefore the values that have been passed in should not be freed by the caller after these functions has been called.
		//
		if (!RSA_set0_factors(rsa_ctx, p, q)) {
			break;
		}
		rsa_memory_manager = 1;
		if (!RSA_set0_crt_params(rsa_ctx, dmp1, dmq1, iqmp)) {
			BN_clear_free(n);
			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(dmp1);
			BN_clear_free(dmq1);
			BN_clear_free(iqmp);
			break;
		}

		if (!RSA_set0_key(rsa_ctx, n, e, d)) {
			BN_clear_free(n);
			BN_clear_free(e);
			BN_clear_free(d);
			break;
		}

		*new_pri_key2 = rsa_key;
		ret_code = SUCCESS;
	} while (0);

	BN_CTX_free(tmp_ctx);

	//in case of failure, free allocated BNs and RSA struct
	//
	if (ret_code != SUCCESS) {
		//BNs were not assigned to rsa ctx yet, user code must free allocated BNs
		//
		if (!rsa_memory_manager) {
			BN_clear_free(n);
			BN_clear_free(e);
			BN_clear_free(d);
			BN_clear_free(dmp1);
			BN_clear_free(dmq1);
			BN_clear_free(iqmp);
			BN_clear_free(q);
			BN_clear_free(p);
		}
		EVP_PKEY_free(rsa_key);
	}

    std::cout << "Size of rsa_key = " << sizeof(rsa_key) << std::endl;
	return ret_code;
}

int client_create_rsa_pub1_key(int mod_size, int exp_size, const unsigned char *le_n, const unsigned char *le_e, void **new_pub_key1)
{
	if (new_pub_key1 == NULL || mod_size <= 0 || exp_size <= 0 || le_n == NULL || le_e == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	EVP_PKEY *rsa_key = NULL;
	RSA *rsa_ctx = NULL;
	int ret_code = ERROR_UNEXPECTED;
	BIGNUM* n = NULL;
	BIGNUM* e = NULL;

	do {
		//convert input buffers to BNs
		//
		n = BN_lebin2bn(le_n, mod_size, n);
		e = BN_lebin2bn(le_e, exp_size, e);

		// allocates and initializes an RSA key structure
		//
		rsa_ctx = RSA_new();
		rsa_key = EVP_PKEY_new();

		if (rsa_ctx == NULL || rsa_key == NULL || !EVP_PKEY_assign_RSA(rsa_key, rsa_ctx)) {
			RSA_free(rsa_ctx);
			rsa_ctx = NULL;
			break;
		}

		//set n, e values of RSA key
		//Calling set functions transfers the memory management of input BNs to the RSA object,
		//and therefore the values that have been passed in should not be freed by the caller after these functions has been called.
		//
		if (!RSA_set0_key(rsa_ctx, n, e, NULL)) {
			break;
		}
		*new_pub_key1 = rsa_key;
		ret_code = SUCCESS;
	} while (0);

	if (ret_code != SUCCESS) {
		EVP_PKEY_free(rsa_key);
		BN_clear_free(n);
		BN_clear_free(e);
	}

	return ret_code;
}

int client_rsa_encrypt_sha256(const void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len)
{

    if (rsa_key == NULL || pout_len == NULL || pin_data == NULL || pin_len < 1 || pin_len >= INT_MAX)
    {
        return ERROR_INVALID_PARAMETER;
    }

    EVP_PKEY_CTX *ctx = NULL;
    size_t data_len = 0;
    int ret_code = ERROR_UNEXPECTED;

    do
    {
        //allocate and init PKEY_CTX
        //
        ctx = EVP_PKEY_CTX_new((EVP_PKEY*)rsa_key, NULL);
        if ((ctx == NULL) || (EVP_PKEY_encrypt_init(ctx) < 1))
        {
            break;
        }

        //set the RSA padding mode, init it to use SHA256
        //
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

        if (EVP_PKEY_encrypt(ctx, NULL, &data_len, pin_data, pin_len) <= 0)
        {
            break;
        }

        if(pout_data == NULL)
        {
            *pout_len = data_len;
            ret_code = SUCCESS;
            break;
        }

        else if(*pout_len < data_len)
        {
            ret_code = ERROR_INVALID_PARAMETER;
            break;
        }

        if (EVP_PKEY_encrypt(ctx, pout_data, pout_len, pin_data, pin_len) <= 0)
        {
            break;
        }

        ret_code = SUCCESS;
    }
    while (0);

    EVP_PKEY_CTX_free(ctx);

    return ret_code;
}

int client_rsa_decrypt_sha256(const void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len)
{

    if (rsa_key == NULL || pout_len == NULL || pin_data == NULL || pin_len < 1 || pin_len >= INT_MAX)
    {
        return ERROR_INVALID_PARAMETER;
    }

    EVP_PKEY_CTX *ctx = NULL;
    size_t data_len = 0;
    int ret_code = ERROR_UNEXPECTED;

    do
    {
        //allocate and init PKEY_CTX
        //
        ctx = EVP_PKEY_CTX_new((EVP_PKEY*)rsa_key, NULL);
        if ((ctx == NULL) || (EVP_PKEY_decrypt_init(ctx) < 1))
        {
            break;
        }

        //set the RSA padding mode, init it to use SHA256
        //
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());

        if (EVP_PKEY_decrypt(ctx, NULL, &data_len, pin_data, pin_len) <= 0)
        {
            break;
        }
        if(pout_data == NULL)
        {
            *pout_len = data_len;
            ret_code = SUCCESS;
            break;
        }

        else if(*pout_len < data_len)
        {
            ret_code = ERROR_INVALID_PARAMETER;
            break;
        }

        if (EVP_PKEY_decrypt(ctx, pout_data, pout_len, pin_data, pin_len) <= 0)
        {
            break;
        }
        ret_code = SUCCESS;
    }
    while (0);

    EVP_PKEY_CTX_free(ctx);

    return ret_code;
}
