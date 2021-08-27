#include <cstdio>
#include <cstring>
#include <string>
#include <random>
#include <iostream>
#include <iostream> //標準入出力
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.h"
#include <openssl/evp.h>


sgx_enclave_id_t global_eid = 0;
int n_table = 1;
int size = 10;

struct keyvalue stash[2];

//OCALL implementation
void ocall_return_stash(struct keyvalue st[2])
{
    stash[0] = st[0];
    stash[1] = st[1];
}

void ocall_err_different_size(const char *str)
{
    std::cerr << str << std::endl;
    //↓↓↓例外処理を入れる↓↓↓
}

void ocall_err_print(sgx_status_t *st)
{
    sgx_error_print(*st);
    //↓↓↓例外処理を入れる↓↓↓
}

void ocall_print(const char *str)
{
    std::cout << str << std::endl;
}

void ocall_print_e(long *e)
{
    std::cout << "e = " << *e << std::endl;
}

/* Enclave initialization function */
int initialize_enclave()
{
	std::string launch_token_path = "enclave.token";
	std::string enclave_name = "enclave.signed.so";
	const char* token_path = launch_token_path.c_str();

	sgx_launch_token_t token = {0};
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	int updated = 0;


	/*==============================================================*
	 * Step 1: Obtain enclave launch token                          *
	 *==============================================================*/
	
	/* If exist, load the enclave launch token */
	FILE *fp = fopen(token_path, "rb");

	/* If token doesn't exist, create the token */
	if(fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
	{		
		/* Storing token is not necessary, so file I/O errors here
		 * is not fatal
		 */
		std::cerr << "Warning: Failed to create/open the launch token file ";
		std::cerr << "\"" << launch_token_path << "\"." << std::endl;
	}


	if(fp != NULL)
	{
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);

		/* if token is invalid, clear the buffer */
		if(read_num != 0 && read_num != sizeof(sgx_launch_token_t))
		{
			memset(&token, 0x0, sizeof(sgx_launch_token_t));

			/* As aforementioned, if token doesn't exist or is corrupted,
			 * zero-flushed new token will be used for launch.
			 * So token error is not fatal.
			 */
			std::cerr << "Warning: Invalid launch token read from ";
			std::cerr << "\"" << launch_token_path << "\"." << std::endl;
		}
	}


	/*==============================================================*
	 * Step 2: Initialize enclave by calling sgx_create_enclave     *
	 *==============================================================*/

	status = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG_FLAG, &token,
		&updated, &global_eid, NULL);
	
	if(status != SGX_SUCCESS)
	{
		/* Defined at error_print.cpp */
		sgx_error_print(status);
		
		if(fp != NULL)
		{
			fclose(fp);
		}

		return -1;
	}

	/*==============================================================*
	 * Step 3: Save the launch token if it is updated               *
	 *==============================================================*/
	
	/* If there is no update with token, skip save */
	if(updated == 0 || fp == NULL)
	{
		if(fp != NULL)
		{
			fclose(fp);
		}

		return 0;
	}


	/* reopen with write mode and save token */
	fp = freopen(token_path, "wb", fp);
	if(fp == NULL) return 0;

	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);

	if(write_num != sizeof(sgx_launch_token_t))
	{
		std::cerr << "Warning: Failed to save launch token to ";
		std::cerr << "\"" << launch_token_path << "\"." << std::endl;
	}

	fclose(fp);

	return 0;
}

//テーブルの初期化関数
void table_init(struct keyvalue table[1][2][10])
{
    for (int i = 0; i < n_table; i++) {
        for (int j = 0; j < size; j++) {
            unsigned char key[15] = "dummy_";
            std::strcat((char *)key, std::to_string(i).c_str());
            std::strcat((char *)key, (char *)"0");
            std::strcat((char *)key, std::to_string(j).c_str());
            sgx_status_t status = ecall_encrypt(global_eid, table[i][0][j].key, key);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            key[7] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, table[i][1][j].key, key);
            if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
            }

            unsigned char value[32] = "dummy_value_";
            std::strcat((char *)value, (char *)"0");
            std::random_device rnd;
            std::strcat((char *)value, std::to_string(rnd()).c_str());
            status = ecall_encrypt(global_eid, table[i][0][j].value[0], value);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            value[12] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, table[i][1][j].value[0], value);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            for (int k = 1; k < 10; k++) {
                value[12] = (unsigned char)'0';
                value[13] = '\0';
                std::strcat((char *)value, std::to_string(rnd()).c_str());
                status = ecall_encrypt(global_eid, table[i][0][j].value[k], value);
                if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
                }

                value[12] = (unsigned char)'1';
                status = ecall_encrypt(global_eid, table[i][1][j].value[k], value);
                if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
                }
            }
        }
    }
}

void acpy(unsigned char cpy[], char data[])
{
    for (int i = 0; i < 256; ++i) {
        cpy[i] = data[i];
    }
}

int main()
{
	/* initialize enclave */
	if(initialize_enclave() < 0)
	{
		std::cerr << "App: fatal error: Failed to initialize enclave.";
		std::cerr << std::endl;
		return -1;
	}

    //暗号化キーの生成
    unsigned char n[256];    
    unsigned char d[256];
    unsigned char p[256];
    unsigned char q[256];
    unsigned char dmp1[256];
    unsigned char dmq1[256];
    unsigned char iqmp[256];
    long e = 65537;

    sgx_status_t status = ecall_generate_keys(global_eid,
            n, d, p, q, dmp1, dmq1, iqmp, &e);

    if(status != SGX_SUCCESS)
    {
        sgx_error_print(status);

        return -1;
    }


    //Tableの初期化
    struct keyvalue table[n_table][2][10];
    table_init(table);

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
	addr.sin_addr.s_addr = INADDR_ANY;
	//ソケット登録
	if(bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0){ //ソケット, アドレスポインタ, アドレスサイズ //エラー処理

		std::cout << "Error bind:" << std::strerror(errno); //標準出力
		exit(1); //異常終了
	}

	//受信待ち
	if(listen(sockfd,SOMAXCONN) < 0){ //ソケット, キューの最大長 //エラー処理

		std::cout << "Error listen:" << std::strerror(errno); //標準出力
		close(sockfd); //ソケットクローズ
		exit(1); //異常終了
	}

	//接続待ち
	struct sockaddr_in get_addr; //接続相手のソケットアドレス
	socklen_t len = sizeof(struct sockaddr_in); //接続相手のアドレスサイズ
	int connect = accept(sockfd, (struct sockaddr *)&get_addr, &len); //接続待ちソケット, 接続相手のソケットアドレスポインタ, 接続相手のアドレスサイズ

	if(connect < 0){ //エラー処理

		std::cout << "Error accept:" << std::strerror(errno); //標準出力
		exit(1); //異常終了
	}

    //鍵の成分を送信
    send(connect, n, 256, 0);
    send(connect, d, 256, 0);
    send(connect, p, 256, 0);
    send(connect, q, 256, 0);
    send(connect, dmp1, 256, 0);
    send(connect, dmq1, 256, 0);
    send(connect, iqmp, 256, 0);
    send(connect, &e, sizeof(e), 0);

    struct keyvalue data;

	//受信
    int count = 0;
    int bytes;
    for (int i = 0; i < 10; i++) {
    do {
        bytes = recv(connect, &data + count, sizeof(struct keyvalue) - count, 0);
        std::cout << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv data error\n";
            return 1;
        }
        count += bytes;
    }while(count < sizeof(struct keyvalue));


    status = ecall_insertion_start(global_eid, table[0], &data, &size);
    if (status != SGX_SUCCESS) {
        sgx_error_print(status);

        return -1;
    }

	//stash送信
	send(connect, &stash[0], sizeof(struct keyvalue), 0); //送信
    send(connect, &stash[1], sizeof(struct keyvalue), 0);

    unsigned char dec[256];
    std::cout << "T1 = {";
    for (int i = 0; i < 9; i++) {
        ecall_decrypt(global_eid, dec, table[0][0][i].key);
        std::cout << dec << ", ";
    }
    ecall_decrypt(global_eid, dec, table[0][0][9].key);
    std::cout << dec << "}" << std::endl;

    std::cout << "T2 = {";
    for (int i = 0; i < 9; i++) {
        ecall_decrypt(global_eid, dec, table[0][1][i].key);
        std::cout << dec << ", ";
    }
    ecall_decrypt(global_eid, dec, table[0][1][9].key);
    std::cout << dec << "}" << std::endl;
}
	//ソケットクローズ
	close(connect);
	close(sockfd);

	/* Destruct the enclave */
	sgx_destroy_enclave(global_eid);


	std::cout << "\nWhole operations have been executed correctly." << std::endl;

	return 0;
}
