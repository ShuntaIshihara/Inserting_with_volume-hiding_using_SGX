#include <cstdio>
#include <cstring>
#include <string>
#include <random>
#include <iostream> 
#include <fstream>
#include <assert.h>
#include <stdlib.h>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.h"
#include <openssl/evp.h>
#include <gmp.h>
#include <cereal/cereal.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/array.hpp>
#include "structure.hpp"

#define BLOCK_SIZE 10
#define TABLE_SIZE 10000

#include "paillier.h"

sgx_enclave_id_t global_eid = 0;

std::string getPubKey(std::string filename);
std::string getSecKey(std::string filename);
std::vector<cnt_data> deserialize(char buffer[], int size);

struct keyvalue *table;
struct keyvalue stash[2];

//OCALL implementation
void ocall_return_table(struct keyvalue *t, size_t table_size, int *head, int *block)
{
    for (int i = 0; i < 2000; ++i) {
        table[(*block)*2*TABLE_SIZE+(*head)+i] = t[i];
    }
}

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
void table_init(struct keyvalue *table)
{
    for (int i = 0; i < BLOCK_SIZE; i++) {
        for (int j = 0; j < TABLE_SIZE; j++) {
            unsigned char key[15] = "dummy_";
            std::strcat((char *)key, std::to_string(i).c_str());
            std::strcat((char *)key, (char *)"0");
            std::strcat((char *)key, std::to_string(j).c_str());
            sgx_status_t status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + j].key, key);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            key[7] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + TABLE_SIZE + j].key, key);
            if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
            }

            unsigned char value[32] = "dummy_value_";
            std::strcat((char *)value, (char *)"0");
            std::random_device rnd;
            std::strcat((char *)value, std::to_string(rnd()).c_str());
            status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + j].value, value);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

            value[12] = (unsigned char)'1';
            status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + TABLE_SIZE + j].value, value);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
            }

/*            for (int k = 1; k < 10; k++) {
                value[12] = (unsigned char)'0';
                value[13] = '\0';
                std::strcat((char *)value, std::to_string(rnd()).c_str());
                status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + j].value[k], value);
                if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
                }

                value[12] = (unsigned char)'1';
                status = ecall_encrypt(global_eid, table[i*2*TABLE_SIZE + TABLE_SIZE + j].value[k], value);
                if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
                }
            }*/
        }
    }
}

void init_cnt(std::string filename, std::unordered_map<std::string, int>& indices, std::vector<char*>& cnt_table, paillier_pubkey_t *pubKey)
{
    std::ifstream input_file(filename);
    if (!input_file.is_open()) {
        std::cerr << "Error: Could not open " << filename << std::endl;
        std::exit(EXIT_FAILURE);
    }

    std::string line;
    int index = 0;
    while (std::getline(input_file, line)) {
        indices[line] = index;
        index++;
        paillier_plaintext_t* m = paillier_plaintext_from_ui(0);
        paillier_ciphertext_t* ctxt;
        ctxt = paillier_enc(NULL, pubKey, m, paillier_get_rand_devurandom);
        cnt_table.push_back((char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ctxt));
    }

    input_file.close();
}


int main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cerr << "Command line arguments are not enough." << std::endl;
        std::cerr << "$> ./app [time_result_outputfile] [key_list_file]" << std::endl;
        return 1;
    }
    std::string klfile = argv[2];

    std::ofstream ofs(argv[1]);
    if (!ofs)
    {
        std::cout << "ファイルが開けませんでした。" << std::endl;
        return 1;
    }
    auto sum = 0;
    auto sum_c = 0;
    auto sum_t = 0;

    

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

    //Tableの初期化
//    struct keyvalue table[BLOCK_SIZE][2][TABLE_SIZE];
    table = (struct keyvalue *)malloc(sizeof(struct keyvalue)*BLOCK_SIZE*2*TABLE_SIZE);
    table_init(table);


    //鍵の成分を送信
    send(connect, n, 256, 0);
    send(connect, d, 256, 0);
    send(connect, p, 256, 0);
    send(connect, q, 256, 0);
    send(connect, dmp1, 256, 0);
    send(connect, dmq1, 256, 0);
    send(connect, iqmp, 256, 0);
    send(connect, &e, sizeof(e), 0);


    std::string hexPubKey = getPubKey("App/pubkey.txt");
    std::string hexSecKey = getSecKey("App/seckey.txt");

    paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);
    paillier_prvkey_t* secKey = paillier_prvkey_from_hex(&hexSecKey[0], pubKey);


    int index = 0;
    std::unordered_map<std::string, int> indices;    //hash_mapから配列の添字を読み込む
    std::vector<char*> cnt_table;                    //hash_mapから読み込んだ添字の場所に格納する
    init_cnt(klfile, indices, cnt_table, pubKey);



    //受信
    int cnt = 0;
    while (1) {
        auto start = std::chrono::system_clock::now();
        int count = 0;
        int bytes;
        int flag;
        do {
            bytes = recv(connect, &flag + count, (int)sizeof(int) - count, 0);
            if (bytes < 0) {
                std::cerr << "recv flag error." << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < sizeof(int));

        if (flag) break;

        struct keyvalue data;

        count = 0;
        int bf_size;
        do {
            bytes = recv(connect, &bf_size + count, (int)sizeof(int) - count, 0);
            if (bytes < 0) {
                std::cerr << "recv data error0!" << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < (int)sizeof(int));


        char buffer[bf_size];
        count = 0;
        do {
            bytes = recv(connect, buffer + count, bf_size - count, 0);
            if (bytes < 0) {
                std::cerr << "recv data error1!" << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < bf_size);



        //デシリアライズ
        std::vector<cnt_data> cnt_list = deserialize(buffer, bf_size);

        std::vector<cnt_data> send_list;

        auto start_c = std::chrono::system_clock::now();
        for (int j = 0; j < cnt_list.size(); ++j) {
            if(indices.find(cnt_list[j].h) == indices.end()) {
                index++;
                indices[cnt_list[j].h] = index;
            }
            paillier_ciphertext_t* encryptedCnt = paillier_ciphertext_from_bytes((void*)cnt_table[indices[cnt_list[j].h]], PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);


            paillier_ciphertext_t* encryptedSum = paillier_create_enc_zero();

            paillier_ciphertext_t* encryptedValue = paillier_ciphertext_from_bytes((void*)cnt_list[j].byteEncryptedValue, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

 
            paillier_mul(pubKey, encryptedSum, encryptedCnt, encryptedValue);


            char* byteEncryptedSum = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, encryptedSum);

            cnt_data w;

            w.h = cnt_list[j].h;
            std::memcpy(w.byteEncryptedValue, byteEncryptedSum, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

            send_list.push_back(w);


            std::memcpy(cnt_table[indices[cnt_list[j].h]], byteEncryptedSum, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);


            // Decrypt the ciphertext (sum)
//            paillier_ciphertext_t* ctxt = paillier_ciphertext_from_bytes((void*)cnt_table[indices[cnt_list[j].h]], PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

            paillier_freeciphertext(encryptedValue);
            paillier_freeciphertext(encryptedCnt);
            paillier_freeciphertext(encryptedSum);
            free(byteEncryptedSum);

//            paillier_plaintext_t* dec;
//            dec = paillier_dec(NULL, pubKey, secKey, ctxt);
//            std::cout << "cnt_table[" << indices[cnt_list[j].h] << "] = ";
//            gmp_printf("Decrypted value: %Zd\n", dec);
//            paillier_freeplaintext(dec);


        }
        auto end_c = std::chrono::system_clock::now();

        std::stringstream ss;
        {
            cereal::PortableBinaryOutputArchive o_archive(ss, cereal::PortableBinaryOutputArchive::Options::LittleEndian());
            o_archive(send_list);
        }
        char bf[ss.str().size()];
        std::memcpy(bf, ss.str().data(), ss.str().size());

        int s = ss.str().size();
        send(connect, &s, sizeof(int), 0);
        send(connect, bf, s, 0);

        count = 0;
        do {
            bytes = recv(connect, &data + count, sizeof(struct keyvalue) - count, 0);
            if (bytes < 0) {
                std::cerr << "recv data error\n";
                return 1;
            }
            count += bytes;
        }while(count < sizeof(struct keyvalue));

        auto start_t = std::chrono::system_clock::now();
        unsigned char check_data[256];
        status = ecall_decrypt(global_eid, check_data, data.key);


        //blockの振り分け
        int block;
        int block_size = BLOCK_SIZE;
        status = ecall_hash_block(global_eid, &block, data.key, &block_size);


        int table_size = TABLE_SIZE;
        clock_t start_insertion = clock();
        status = ecall_table_malloc(global_eid);
        if (status != SGX_SUCCESS) {
            sgx_error_print(status);
            return -1;
        }
        for (int i = 0; i < 10; ++i) {
            int head = i*2000;
            status = ecall_load(global_eid, table+block*2*TABLE_SIZE+(i*2000), sizeof(struct keyvalue)*2000, &head);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
                return -1;
            }
            std::cout << "checkpoint1" << std::endl;
        }
        status = ecall_insertion_start(global_eid, &data, &table_size, &block);
        if (status != SGX_SUCCESS) {
            sgx_error_print(status);
            return -1;
        }
        auto end_t = std::chrono::system_clock::now();

        //stash送信
        send(connect, &stash[0], sizeof(struct keyvalue), 0); //送信
        send(connect, &stash[1], sizeof(struct keyvalue), 0);
        auto end = std::chrono::system_clock::now();

//        unsigned char dec[256];
//        std::cout << "T1 = {";
//        for (int i = 0; i < TABLE_SIZE - 1; i++) {
//            ecall_decrypt(global_eid, dec, table[block*2*TABLE_SIZE + i].key);
//            std::cout << dec << ", ";
//        }
//        ecall_decrypt(global_eid, dec, table[block*2*TABLE_SIZE+TABLE_SIZE-1].key);
//        std::cout << dec << "}" << std::endl;
//
//        std::cout << "T2 = {";
//        for (int i = 0; i < TABLE_SIZE - 1; i++) {
//            ecall_decrypt(global_eid, dec, table[block*2*TABLE_SIZE+TABLE_SIZE+i].key);
//            std::cout << dec << ", ";
//        }
//        ecall_decrypt(global_eid, dec, table[block*2*TABLE_SIZE+TABLE_SIZE+TABLE_SIZE-1].key);
//        std::cout << dec << "}" << std::endl;

        sum += std::chrono::duration_cast<std::chrono::microseconds>(end-start).count();
        sum_c += std::chrono::duration_cast<std::chrono::microseconds>(end_c-start_c).count();
        sum_t += std::chrono::duration_cast<std::chrono::microseconds>(end_t-start_t).count();

        cnt++;
    }

    double ave = (double)sum / cnt;
    double ave_c = (double)sum_c / cnt;
    double ave_t = (double)sum_t / cnt;

    ofs << "ボリューム更新の平均CPU使用時間: ";
    ofs << std::to_string(ave_c) << "micro s" << std::endl;

    ofs << "挿入の平均CPU使用時間: ";
    ofs << std::to_string(ave_t) << "micro s" << std::endl;

    ofs << "全体の処理時間: ";
    ofs << std::to_string(ave) << "micor s" << std::endl;

    free(table);

    paillier_freepubkey(pubKey);
    paillier_freeprvkey(secKey);


	close(connect);
	close(sockfd);
    ofs.close();

	/* Destruct the enclave */
	sgx_destroy_enclave(global_eid);


	std::cout << "\nWhole operations have been executed correctly." << std::endl;

	return 0;
}
