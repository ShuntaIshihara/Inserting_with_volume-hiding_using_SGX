#include <iostream> //標準入出力
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include <string> //string型
#include <cstring>
#include <cstdlib>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

enum {
    SUCCESS,
    ERROR_UNEXPECTED,
    ERROR_INVALID_PARAMETER,
    ERROR_OUT_OF_MEMORY
};

struct keyvalue {
    unsigned char key[256];
    unsigned char value[10][256];
};

void *pub_key = NULL;
void *priv_key = NULL;

void client_err_print(int status)
{
    switch (status) {
        case SUCCESS: std::cerr << "------------------------------" << std::endl;
        std::cerr << "SUCCESS" << std::endl;
        std::cerr << "status = " << (int)SUCCESS << std::endl;
        std::cerr << "------------------------------" << std::endl;
        break;
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

int main(){

	//ソケットの生成
	int sockfd = socket(AF_INET, SOCK_STREAM, 0); //アドレスドメイン, ソケットタイプ, プロトコル
	if(sockfd < 0){ //エラー処理

		std::cout << "Error socket:" << std::strerror(errno); //標準出力
		exit(1); //異常終了
	}

	//アドレスの生成
	struct sockaddr_in addr; //接続先の情報用の構造体(ipv4)
	memset(&addr, 0, sizeof(struct sockaddr_in)); //memsetで初期化
	addr.sin_family = AF_INET; //アドレスファミリ(ipv4)
	addr.sin_port = htons(8080); //ポート番号,htons()関数は16bitホストバイトオーダーをネットワークバイトオーダーに変換
	addr.sin_addr.s_addr = inet_addr("40.65.118.71"); //IPアドレス,inet_addr()関数はアドレスの翻訳

	//ソケット接続要求
	connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)); //ソケット, アドレスポインタ, アドレスサイズ


    //鍵の成分の生成
    int n_byte_size = 256;
    unsigned char n[256];
    unsigned char d[256];
    unsigned char p[256];
    unsigned char q[256];
    unsigned char dmp1[256];
    unsigned char dmq1[256];
    unsigned char iqmp[256];
    long e = 65537;
    void *pub_key = NULL;
    void *priv_key = NULL;

    //鍵のパーツを受信
    int count = 0;
    int bytes;
    do {
        bytes = recv(sockfd, n + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv n error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, d + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv d error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, p + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv p error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, q + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv q error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, dmp1 + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv q error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, dmq1 + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv dmq1 error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, iqmp + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv iqmp error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, &e + count, 8 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv e error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 8);


    //公開鍵、秘密鍵の生成
    int status =  client_create_rsa_priv2_key(n_byte_size, sizeof(e), (const unsigned char *)&e,
            (const unsigned char *)p, (const unsigned char *)q, (const unsigned char *)dmp1,
            (const unsigned char *)dmq1, (const unsigned char *)iqmp, &priv_key);
    client_err_print(status);
    
    status = client_create_rsa_pub1_key(n_byte_size, sizeof(e),
            (const unsigned char *)n, (const unsigned char *)&e, &pub_key);
    client_err_print(status);

/*
    //公開鍵、秘密鍵の受信
    unsigned char pub_key[8];
    unsigned char priv_key[8];

    int count = 0;
    int bytes;
    do {
        bytes = recv(sockfd, pub_key + count, 8 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv pub_key error\n";
            return 1;
        }
        count += bytes;
    }while(count < 8);

    count = 0;
    do {
        bytes = recv(sockfd, priv_key + count, 8 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv priv_key error\n";
            return 1;
        }
        count += bytes;
    }while(count < 8);
*/
    //データの挿入操作
    struct keyvalue data;
    unsigned char *in_key = (unsigned char *)"This is a key.";
    int size = 256;
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.key, (size_t *)&size, in_key, std::strlen((const char *)in_key)+1);
    client_err_print(status);

    size_t enc_len = 256;
    size_t dec_len = 0;
    status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
            (const unsigned char *)data.key, enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }

    unsigned char dec[dec_len];
    status = client_rsa_decrypt_sha256(priv_key, dec, &dec_len,
            (const unsigned char *)data.key, enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }

    std::cout << dec << std::endl;

    for (int i = 0; i < 10; ++i) {
        unsigned char *in_value = (unsigned char *)"This is a value.";
        status = client_rsa_encrypt_sha256((const void *)pub_key, 
                data.value[0], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
        client_err_print(status);
        std::cout << i << std::endl;
    }
    /*
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.value[1], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
    client_err_print(status);
    std::cout << "value1: " << data.value[1] << std::endl;
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.value[2], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
    client_err_print(status);
    std::cout << "value2: " << data.value[2] << std::endl;
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.value[3], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
    client_err_print(status);
    std::cout << "value3: " << data.value[3] << std::endl;
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.value[4], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
    client_err_print(status);
    std::cout << "value4: " << data.value[4] << std::endl;
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.value[5], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
    client_err_print(status);
    std::cout << "value5: " << data.value[5] << std::endl;
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.value[6], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
    client_err_print(status);
    std::cout << "value6: " << data.value[6] << std::endl;
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.value[7], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
    client_err_print(status);
    std::cout << "value7: " << data.value[7] << std::endl;
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.value[8], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
    client_err_print(status);
    std::cout << "value8: " << data.value[8] << std::endl;
    status = client_rsa_encrypt_sha256((const void *)pub_key, data.value[9], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
    client_err_print(status);
    std::cout << "value9: " << data.value[9] << std::endl;
*/

    send(sockfd, &data, sizeof(struct keyvalue), 0); //送信

	//stash受信
    struct keyvalue stash[2];
    count = 0;
    do {
        bytes = recv(sockfd, &stash[0], sizeof(struct keyvalue), 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv stash[0] error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, &stash[1], sizeof(struct keyvalue), 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv stash[1] error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    std::cout << "stash[0] = {";

    status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
            (const unsigned char *)stash[0].key, enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }

    unsigned char key0[dec_len];
    status = client_rsa_decrypt_sha256(priv_key, key0, &dec_len,
            (const unsigned char *)stash[0].key, enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }
    std::cout << "key(" << key0 << "), value(";

for (int i = 0; i < 9; ++i) {
    status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
            (const unsigned char *)stash[0].value[i], enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }

    unsigned char value0[dec_len];
    status = client_rsa_decrypt_sha256(priv_key, value0, &dec_len,
            (const unsigned char *)stash[0].value[i], enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }
    std::cout << value0 << ", ";
}
    status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
            (const unsigned char *)stash[0].value[9], enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }

    unsigned char value1[dec_len];
    status = client_rsa_decrypt_sha256(priv_key, value1, &dec_len,
            (const unsigned char *)stash[0].value[9], enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }
    std::cout << value1 << ")}\n";

    std::cout << "stash[1] = {";

    status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
            (const unsigned char *)stash[1].key, enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }

    unsigned char key1[dec_len];
    status = client_rsa_decrypt_sha256(priv_key, key1, &dec_len,
            (const unsigned char *)stash[1].key, enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }
    std::cout << "key(" << key1 << "), value(";

for (int i = 0; i < 9; ++i) {
    status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
            (const unsigned char *)stash[1].value[i], enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }

    unsigned char value2[dec_len];
    status = client_rsa_decrypt_sha256(priv_key, value2, &dec_len,
            (const unsigned char *)stash[1].value[i], enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }
    std::cout << value2 << ", ";
}
    status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
            (const unsigned char *)stash[1].value[9], enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }

    unsigned char value3[dec_len];
    status = client_rsa_decrypt_sha256(priv_key, value3, &dec_len,
            (const unsigned char *)stash[1].value[9], enc_len);
    if (status != SUCCESS) {
        std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
        client_err_print(status);
    }
    std::cout << value3 << ")}\n";


	//ソケットクローズ
	close(sockfd);

	return 0;
}
