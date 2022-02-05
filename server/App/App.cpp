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
#include <openssl/sha.h>
#include <gmp.h>
#include "paillier.h"
#include <cereal/cereal.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/array.hpp>
#include "structure.hpp"
#include "def.hpp"
#include "Ocall_Func.hpp"
#include "Init.hpp"

sgx_enclave_id_t global_eid = 0;
paillier_pubkey_t* pubKey;
paillier_prvkey_t* secKey;


std::string getPubKey(std::string filename);
std::string getSecKey(std::string filename);
std::vector<cnt_data> deserialize(char buffer[], int size);
int initialize_enclave();

struct keyvalue *table;
struct keyvalue stash[2];

int main(int argc, char *argv[])
{
    int file_flag = 0;
    if (argc < 3 || argc > 4) {
        std::cerr << "Command line arguments are not enough." << std::endl;
        std::cerr << "$> ./app [time_result_outputfile] [key_list_file] [dataset_file]" << std::endl;
        std::cerr << "$> ./app [time_result_outputfile] [key_list_file]" << std::endl;
        return 1;
    } else if (argc == 3) {
        file_flag = 0;
    } else if (argc == 4) {
        file_flag = 1;
    }
    std::string klfile = argv[2];

    std::ofstream ofs(argv[1]);
    if (!ofs)
    {
        std::cout << "ファイルが開けませんでした。" << std::endl;
        return 1;
    }
    auto sum = 0.0;
    auto sum_c = 0.0;
    auto sum_t = 0.0;
    auto sum_search = 0;

    

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

    pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);
    secKey = paillier_prvkey_from_hex(&hexSecKey[0], pubKey);


    int index = 0;
    std::unordered_map<std::string, int> indices;    //hash_mapから配列の添字を読み込む
    std::vector<char*> cnt_table;                    //hash_mapから読み込んだ添字の場所に格納する
    init_cnt(klfile, indices, cnt_table);

    if (file_flag) input_from_file(argv[3], table, indices, cnt_table);


    //受信
    int cnt = 0;
    while (1) {
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

        if (flag == 0) break;
        if (flag == 2) {
            auto start = std::chrono::system_clock::now();


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


            //blockの振り分け
            int block;
            int block_size = BLOCK_SIZE;
            status = ecall_hash_block(global_eid, &block, data.key, &block_size);


            clock_t start_insertion = clock();
            status = ecall_insertion_start(global_eid, table+(block*2*TABLE_SIZE),
                    sizeof(struct keyvalue)*2*TABLE_SIZE, &data);
            if (status != SGX_SUCCESS) {
                sgx_error_print(status);
                return -1;
            }
            auto end_t = std::chrono::system_clock::now();

            //stash送信
            send(connect, &stash[0], sizeof(struct keyvalue), 0); //送信
            send(connect, &stash[1], sizeof(struct keyvalue), 0);
            auto end = std::chrono::system_clock::now();

            if (cnt > 0) {
                sum += std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count();
                sum_c += std::chrono::duration_cast<std::chrono::microseconds>(end_c-start_c).count();
                sum_t += std::chrono::duration_cast<std::chrono::microseconds>(end_t-start_t).count();
            }
        }

        if (flag == 1) {
            // Recv hash of key
            char c_h[65];
            count = 0;
            do {
                bytes = recv(connect, c_h + count, 65 - count, 0);
                if (bytes < 0) {
                    std::cerr << "Error: Recv 'c_h' failure." << std::endl;
                    std::cerr << "Error Code: " << std::strerror(errno);
                    return EXIT_FAILURE;
                }
                count += bytes;
            } while (count < 65);
            std::string h((const char*)c_h);
            send(connect, cnt_table[indices[h]], PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, 0);

            // Recv key
            unsigned char enc_key[256];
            count = 0;
            do {
                bytes = recv(connect, enc_key + count, sizeof(unsigned char)*256 - count, 0);
                if (bytes < 0) {
                    std::cerr << "Error: Recv 'enc_key' failure." << std::endl;
                    std::cerr << "Error Code: " << std::strerror(errno);
                    return EXIT_FAILURE;
                }
                count += bytes;
            } while (count < (int)sizeof(unsigned char)*256);

            int vol;
            count = 0;
            do {
                bytes = recv(connect, &vol + count, sizeof(int) - count, 0);
                if (bytes < 0) {
                    std::cerr << "Error: Recv 'vol' failure." << std::endl;
                    std::cerr << "Error Code: " << std::strerror(errno);
                    return EXIT_FAILURE;
                }
                count += bytes;
            } while (count < (int)sizeof(int));

            auto start_search = std::chrono::system_clock::now();

            std::vector<SKV> list;
            for (int i = 1; i <= vol; ++i) {
                int block_size = BLOCK_SIZE;
                int block;
                status = ecall_get_block(global_eid, &block, enc_key, &i, &block_size);
                if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
                    return EXIT_FAILURE;
                }
                struct keyvalue kvs[2];
                status = ecall_search(global_eid, kvs, table+(block*2*TABLE_SIZE),
                        sizeof(struct keyvalue)*2*TABLE_SIZE, enc_key, &i);
                if (status != SGX_SUCCESS) {
                    sgx_error_print(status);
                    return EXIT_FAILURE;
                }
                SKV w1;
                std::memcpy(w1.key, kvs[0].key, 256);
                std::memcpy(w1.value, kvs[0].value, 256);
                list.push_back(w1);

                SKV w2;
                std::memcpy(w2.key, kvs[1].key, 256);
                std::memcpy(w2.value, kvs[1].value, 256);

                list.push_back(w2);
            }
            auto end_search = std::chrono::system_clock::now();

            std::stringstream ss;
            {
                cereal::PortableBinaryOutputArchive o_archive(ss, cereal::PortableBinaryOutputArchive::Options::LittleEndian());
                o_archive(list);
            }
            char bf1[ss.str().size()];
            std::memcpy(bf1, ss.str().data(), ss.str().size());

            int bf1_size = ss.str().size();
            send(connect, &bf1_size, sizeof(int), 0);
            send(connect, bf1, bf1_size, 0);
            
            if (cnt > 0) {
                sum_search += std::chrono::duration_cast<std::chrono::microseconds>(end_search-start_search).count();
            }
        }
        cnt++;
    }

    double ave = (double)sum / (cnt-1);
    double ave_c = (double)sum_c / (cnt-1);
    double ave_t = (double)sum_t / (cnt-1);
    double ave_s = (double)sum_search / (cnt-1);

    ofs << "ボリューム更新の平均CPU使用時間: ";
    ofs << std::to_string(ave_c) << " us" << std::endl;

    ofs << "挿入の平均CPU使用時間: ";
    ofs << std::to_string(ave_t) << " us" << std::endl;

    ofs << "全体の処理時間: ";
    ofs << std::to_string(ave) << " ms" << std::endl;

    ofs << "検索処理の時間: ";
    ofs << std::to_string(ave_s) << " us" << std::endl;

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
