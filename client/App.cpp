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
};

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
        default: break;
    }
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
	addr.sin_addr.s_addr = inet_addr("127.0.0.1"); //IPアドレス,inet_addr()関数はアドレスの翻訳

	//ソケット接続要求
	connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)); //ソケット, アドレスポインタ, アドレスサイズ

    //公開鍵、秘密鍵の受信
    void *pub_key = NULL;
    recv(sockfd, (char *)pub_key, 8, 0);
    std::cout << "public key: " << (char *)pub_key << std::endl;
    char priv_key = NULL;
    recv(sockfd, (char *)priv_key, 8, 0);
    std::cout << "private key: " << (char *)priv_key << std::endl;

    //データの挿入操作
    unsigned char key[256];
    unsigned char *in_key = (unsigned char *)"ishihara";
    int size = 256;
    int status = client_rsa_encrypt_sha256((const void *)pub_key, key, (size_t *)&size, in_key, std::strlen((const char *)in_key)+1);
    client_err_print(status);
	send(sockfd, (char *)key, size, 0); //送信
	std::cout << (char *)key << std::endl;

    for (int i = 0; i < 10; ++i) {
        unsigned char value[256];
        unsigned char *in_value = (unsigned char *)"This is value";
        status = client_rsa_encrypt_sha256((const void *)pub_key, value, (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
        client_err_print(status);
        send(sockfd, (char *)value, size, 0);
        std::cout << (char *)value << std::endl;
    }

	//データ受信
    for (int i = 0; i < 11; ++i) {
        unsigned char r_str[256]; //受信データ格納用
        recv(sockfd, (char *)r_str, 256, 0); //受信
        size = 0;
        status = client_rsa_decrypt_sha256((const void *)priv_key, NULL, (size_t *)&size, r_str, 256);
        client_err_print(status);
        unsigned char dec_str[size];
        status = client_rsa_decrypt_sha256((const void *)priv_key, dec_str, (size_t *)&size, r_str, 256);
        client_err_print(status);
        std::cout << (char *)dec_str << std::endl; //標準出力
    }

	//ソケットクローズ
	close(sockfd);

	return 0;
}
