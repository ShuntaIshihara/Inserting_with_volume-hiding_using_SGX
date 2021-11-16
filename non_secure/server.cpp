#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <random>
#include <iostream> 
#include <fstream>
#include <assert.h>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include "structure.hpp"

#define TABLE_SIZE 1000003


void init_table(struct keyvalue *table, int size);
void init_cnt(std::string filename, std::unordered_map<std::string, int>& indices, std::vector<int>& cnt_table);
struct keyvalue insert(struct keyvalue data, struct keyvalue *table, int size);


int main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cerr << "Command line arguments are not enough." << std::endl; 
        std::cerr << "$> ./server [timeresult_file] [keylist_file]" << std::endl;
        return EXIT_FAILURE;
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


    //tableの宣言と初期化
    keyvalue *table = (struct keyvalue *)std::malloc(sizeof(struct keyvalue)*2*TABLE_SIZE);
    init_table(table, TABLE_SIZE);

    //ifstrem declaration
    std::string klfile = argv[2];

    //indices, cnt_table declaration
    std::unordered_map<std::string, int> indices;
    std::vector<int>  cnt_table;

    init_cnt(klfile, indices, cnt_table);

    auto sum = 0;
    auto sum_c = 0;
    auto sum_t = 0;
    int cnt = 0;
    int total_bytes = 0;

    while (true) {
        auto start = std::chrono::system_clock::now();
//        std::cout << "checkpoint1" << std::endl;
        int flag;
        int count = 0;
        int bytes;
        do {
            bytes = recv(connect, &flag + count, sizeof(int) - count, 0);
            if (bytes < 0) {
                std::cerr << "Error recv flag." << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < (int)sizeof(int));
        total_bytes += bytes;
        if (flag) break;
//        std::cout << "checkpoint2" << std::endl;

        count = 0;
        int key_len;
        do {
            bytes = recv(connect, &key_len + count, sizeof(int) - count, 0);
            if (bytes < 0) {
                std::cerr << "Error recv key_len." << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < (int)sizeof(int));
        total_bytes += bytes;

//        std::cout << "checkpoint1" << std::endl;

        count = 0;
        char keybf[256];
        do {
            bytes = recv(connect, &keybf + count, key_len - count, 0);
            if (bytes < 0) {
                std::cerr << "Error recv keybf." << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < key_len);
        total_bytes += bytes;

        std::string key = keybf;

        //update count table
        auto start_c = std::chrono::system_clock::now();
//        std::cout << "checkpoint3" << std::endl;
        cnt_table[indices[key]] += 1;
//        std::cout << "checkpoint4" << std::endl;
        auto end_c = std::chrono::system_clock::now();


        int index = cnt_table[indices[key]];
        send(connect, &index, sizeof(int), 0);
        total_bytes += sizeof(int);
//        std::cout << "checkpoint5" << std::endl;


        count = 0;
        struct keyvalue data;
        do {
            bytes = recv(connect, &data + count, sizeof(struct keyvalue) - count, 0);
            if (bytes < 0) {
                std::cerr << "Error recv data." << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < (int)sizeof(struct keyvalue));
        total_bytes += bytes;
//        std::cout << "checkpoint6" << std::endl;

        struct keyvalue stash;
        auto start_t = std::chrono::system_clock::now();
        stash = insert(data, table, TABLE_SIZE);
        auto end_t = std::chrono::system_clock::now();
//        std::cout << "checkpoint7" << std::endl;

        send(connect, &stash, sizeof(struct keyvalue), 0);
        total_bytes += sizeof(keyvalue);
//        std::cout << "checkpoint8" << std::endl;

        auto end = std::chrono::system_clock::now();
/*
        std::cout << "T1 = {";
        for (int i = 0; i < TABLE_SIZE-1; ++i) {
            std::cout << table[i].key << ", ";
        }
        std::cout << table[TABLE_SIZE-1].key << "}" << std::endl;

        std::cout << "T2 = {";
        for (int i = 0; i < TABLE_SIZE-1; ++i) {
            std::cout << table[TABLE_SIZE + i].key << ", ";
        }
        std::cout << table[TABLE_SIZE*2-1].key << "}" << std::endl;
*/

        if (cnt != 0) {
            sum += std::chrono::duration_cast<std::chrono::microseconds>(end-start).count();
            sum_c += std::chrono::duration_cast<std::chrono::microseconds>(end_c-start_c).count();
            sum_t += std::chrono::duration_cast<std::chrono::microseconds>(end_t-start_t).count();
        }
//        std::cout << "checkpoint9" << std::endl;

        cnt++;
    }

    free(table);
    close(connect);

    double ave = (double)sum / (cnt-1);
    double ave_c = (double)sum_c / (cnt-1);
    double ave_t = (double)sum_t / (cnt-1);
    double ave_bytes = (double)total_bytes / cnt;
    std::cout << ave_bytes << "bytes" << std::endl;

    std::ofstream f;
    std::string filename = argv[1];
    f.open(filename, std::ios::out);
    f << "Processing time (for updating cnt_table): " << ave_c << " micro s" << std::endl;
    f << "Processing time (for updating cuckoo hashing table): " << ave_t << "micro s" << std::endl;
    f << "Total average: " << ave << " micro s" << std::endl;

    f.close();

    return 0;
}
