#include <cstdio>
#include <cstring>
#include <string>
#include <random>
#include <iostream> 
#include <fstream>
#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.h"
#include <openssl/evp.h>
#include <gmp.h>
#include "paillier.h"


sgx_enclave_id_t global_eid = 0;
int n_table = 1;
int size = 10;

struct keyvalue stash[2];

struct homomorphism {
    int h;
    char* byteEncryptedOne;
};

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

    //sgxrsa暗号化キーの生成
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

    std::fstream pubKeyFile("pubkey.txt", std::fstream::in);
    std::fstream secKeyFile("seckey.txt", std::fstream::in);

    assert(pubKeyFile.is_open());
    assert(secKeyFile.is_open());

    std::string hexPubKey;
    std::string hexSecKey;
    std::getline(pubKeyFile, hexPubKey);
    std::getline(secKeyFile, hexSecKey);

    pubKeyFile.close();
    secKeyFile.close();

    paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);
    paillier_prvkey_t* secKey = paillier_prvkey_from_hex(&hexSecKey[0], pubKey);


    //Tableの初期化
    struct keyvalue table[n_table][2][10];
    table_init(table);

    paillier_ciphertext_t* ctable[2][size];
    for (int i = 0; i < size; i++) {
        ctable[0][i] = paillier_create_enc_zero();
        ctable[1][i] = paillier_create_enc_zero();
    }

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


	//受信
    for (int i = 0; i < 10; i++) {
        struct keyvalue data;
        struct homomorphism cdata;
        cdata.byteEncryptedOne = (char*)malloc(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

        int count = 0;
        int bytes;
        //count tabel の更新
        do {
            bytes = recv(connect, &cdata + count,
            sizeof(struct homomorphism) + PAILLIER_BITS_TO_BYTES(pubKey->bits)*2 - (count+1), 0);
            if (bytes < 0) {
                std::cerr << "recv cdata error!" << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < sizeof(struct homomorphism)+PAILLIER_BITS_TO_BYTES(pubKey->bits)*2-1);

        paillier_ciphertext_t* encryptedOne = paillier_ciphertext_from_bytes((void*)byteEncryptedOne, 
        PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

        paillier_ciphertext_t* encryptedSum1 = paillier_create_enc_zero();
        paillier_ciphertext_t* encryptedSum2 = paillier_create_enc_zero();


        //ハッシュテーブルにした方がよさげ
        paillier_mul(pubKey, encryptedSum1, ctable[0][cdata.h1], encryptedOne);
        paillier_mul(pubKey, encryptedSum2, ctable[1][cdata.h2], encryptedOne);
        std::memcpy(ctable[0][cdata.h1], encryptedSum1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
        std::memcpy(ctable[1][cdata.h2], encryptedSum2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

        // Decrypt the ciphertext (sum)
        paillier_plaintext_t* dec;
        dec = paillier_dec(NULL, pubKey, secKey, ctable[0][cdata.h1]);
        gmp_printf("Decrypted ctable[0][cdata.h1]: %Zd\n", dec);    

        paillier_freeciphertext(encryptedOne);
        paillier_freeciphertext(encryptedSum1);
        paillier_freeciphertext(encryptedSum2);
        paillier_freeplaintext(dec);
        free(cdata.byteEncryptedOne);
        


        //cuckoo hahsing の更新
        count = 0;
        do {
            bytes = recv(connect, &data + count, sizeof(struct keyvalue) - count, 0);
            std::cout << bytes << std::endl;
            if (bytes < 0) {
                std::cerr << "recv data error\n";
                return 1;
            }
            count += bytes;
        }while(count < sizeof(struct keyvalue));

        unsigned char check_data[256];
        status = ecall_decrypt(global_eid, check_data, data.key);
        std::cout << check_data << std::endl;


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

	//Cleaning up
    for (int i = 0; i < size; i++) {
        paillier_freeciphertext(ctable[0][i]);
        paillier_freeciphertext(ctable[1][i]);
    }
    paillier_freepubkey(pubKey);
    paillier_freeprvkey(secKey);
	close(connect);
	close(sockfd);

	/* Destruct the enclave */
	sgx_destroy_enclave(global_eid);


	std::cout << "\nWhole operations have been executed correctly." << std::endl;

	return 0;
}
