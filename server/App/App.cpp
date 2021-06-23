#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.h"



sgx_enclave_id_t global_eid = 0;
int n_table = 1;
int size = 10;

//OCALL implementation
void ocall_print(const char *str)
{
    std::cout << str << std::endl;
}

void ocall_err_print(sgx_status_t *st)
{
    sgx_error_print(*st);
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
            sgx_status_t status = ecall_encrypt(global_eid, key, table[i][0][j].key);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            key[7] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, key, table[i][1][j].key);
            if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
            }

            unsigned char field[30] = "dummy_value_";
            std::strcat((char *)field, std::to_string(i).c_str());
            std::strcat((char *)field, (char *)"0");
            std::strcat((char *)field, (char *)"0");
            std::strcat((char *)field, std::to_string(j).c_str());
            status = ecall_encrypt(global_eid, field, table[i][0][j].field0);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field0);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'0';
            field[14] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][0][j].field1);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field1);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'0';
            field[14] = (unsigned char)'2';
            status = ecall_encrypt(global_eid, field, table[i][0][j].field2);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field2);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'0';
            field[14] = (unsigned char)'3';
            status = ecall_encrypt(global_eid, field, table[i][0][j].field3);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field3);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'0';
            field[14] = (unsigned char)'4';
            status = ecall_encrypt(global_eid, field, table[i][0][j].field4);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field4);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'0';
            field[14] = (unsigned char)'5';
            status = ecall_encrypt(global_eid, field, table[i][0][j].field5);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field5);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'0';
            field[14] = (unsigned char)'6';
            status = ecall_encrypt(global_eid, field, table[i][0][j].field6);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field6);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'0';
            field[14] = (unsigned char)'7';
            status = ecall_encrypt(global_eid, field, table[i][0][j].field7);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field7);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'0';
            field[14] = (unsigned char)'8';
            status = ecall_encrypt(global_eid, field, table[i][0][j].field8);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field8);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'0';
            field[14] = (unsigned char)'9';
            status = ecall_encrypt(global_eid, field, table[i][0][j].field9);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            field[13] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, field, table[i][1][j].field9);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
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

    //データの挿入操作
    struct keyvalue data;
    ecall_encrypt(global_eid, (unsigned char *)"key", data.key);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field0);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field1);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field2);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field3);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field4);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field5);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field6);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field7);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field8);
    ecall_encrypt(global_eid, (unsigned char *)"field", data.field9);

    status = ecall_insertion_start(global_eid, table[0], &data, &size);
    if (status != SGX_SUCCESS) {
        sgx_error_print(status);

        return -1;
    }

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
 

	/* Destruct the enclave */
	sgx_destroy_enclave(global_eid);


	std::cout << "\nWhole operations have been executed correctly." << std::endl;

	return 0;
}
