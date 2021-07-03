#include <cstdio>
#include <cstring>
#include <string>
#include <random>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.h"

#define BUFFER_SIZE 256

sgx_enclave_id_t global_eid = 0;
int n_table = 1;
int size = 10;

//OCALL implementation
void ocall_return_stash(struct keyvalue stash[2])
{
    std::cout << "stash = {";
    std::cout << std::hex << stash[0].key << ", ";
    std::cout << std::hex << stash[1].key << "}" << std::endl;
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

void ocall_print(int *h)
{
    std::cout << "rnd = ";
    std::cout << *h << std::endl;
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
    sgx_status_t status = ecall_generate_keys(global_eid);

    if(status != SGX_SUCCESS)
    {
        sgx_error_print(status);

        return -1;
    }

    //Tableの初期化
    struct keyvalue table[n_table][2][10];
    table_init(table);

    //ポート番号、ソケット
    unsigned short port = 8080;
    int srcSocket;
    int dstSocket;

    //sockaddr_in 構造体
    struct sockaddr_in srcAddr;
    struct sockaddr_in dstAddr;
    int dstAddrSize = sizeof(dstAddr);

    //各種パラメータ
    int numrcv;
    char buffer[BUFFER_SIZE];

    //sockaddr_in 構造体のセット
    memset(&srcAddr, 0, sizeof(srcAddr));
    srcAddr.sin_port = htons(port);
    srcAddr.sin_family = AF_INET;
    srcAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    //ソケットの生成
    srcSocket = socket(AF_INET, SOCK_STREAM, 0);

    //ソケットのバインド
    bind(srcSocket, (struct sockaddr *) &srcAddr, sizeof(srcAddr));

    //接続準備
    listen(srcSocket, 1);

    //接続の受付
    std::cout << "Waiting for connection ..." << std::endl;
    dstSocket = accept(srcSocket, (struct sockaddr *) &dstAddr, (socklen_t *)&dstAddrSize);
    std::cout << "Connected from " << inet_ntoa(dstAddr.sin_addr) << std::endl;

    //パケット受信
    while(1) {
        numrcv = recv(dstSocket, buffer, BUFFER_SIZE, 0);
        if(numrcv == 0 || numrcv == -1) {
            close(dstSocket); break;
        }
        std::printf("received: %s\n", buffer);
    }

    //データの挿入操作
    struct keyvalue data;
    ecall_encrypt(global_eid, data.key, (unsigned char *)"key");
    for (int i = 0; i < 10; i++) {
        sgx_status_t status = ecall_encrypt(global_eid, data.value[i], (unsigned char *)"value");
        if (status != SGX_SUCCESS) {
            sgx_error_print(status);
            return -1;
        }
    }

    status = ecall_insertion_start(global_eid, table[0], &data, &size);
    if (status != SGX_SUCCESS) {
        sgx_error_print(status);

        return -1;
    }

    /* test
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

    ecall_decrypt(global_eid, dec, table[0][0][0].value[0]);
    std::cout << dec << std::endl;
    */

	/* Destruct the enclave */
	sgx_destroy_enclave(global_eid);


	std::cout << "\nWhole operations have been executed correctly." << std::endl;

	return 0;
}
