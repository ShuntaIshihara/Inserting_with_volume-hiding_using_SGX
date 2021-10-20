#include <iostream> //標準入出力
#include <fstream>
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include <string> //string型
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <chrono>
#include "structure.hpp"


std::vector<struct keyvalue> stash;

int main(int argc, char *argv[]){
    if (argc < 2) {
        std::cerr << "Command line arguments are not enough." << std::endl;
        std::cerr << "$> ./client [output_filename] < [dataset_filename]" << std::endl;
        std::exit(1);
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
    addr.sin_addr.s_addr = inet_addr("40.65.118.71"); //IPアドレス,inet_addr()関数はアドレスの翻訳
//    addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	//ソケット接続要求
	connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)); //ソケット, アドレスポインタ, アドレスサイズ

    auto sum = 0;
    auto sum_cnt = 0;
    auto sum_data = 0;
    int cnt = 0;

    //データの挿入操作
    std::string line;
//    int id = 0;
//    int cnt = 0;
    while(std::cin >> line) {
        auto start = std::chrono::system_clock::now();

        int flag = 0;
        if (line == "quit" || line == "q") {
            flag = 1;
        }
        send(sockfd, &flag, sizeof(int), 0);
        if (flag) {
            break;
        }

        std::string key = line;
        int key_len = key.length()+1;
        auto lcstart = std::chrono::system_clock::now();
        send(sockfd, &key_len, sizeof(int), 0);
        send(sockfd, (char*)key.c_str(), key.length()+1, 0);

        //更新したカウントを受け取る
        int count = 0;
        int bytes;
        int index;
        do {
            bytes = recv(sockfd, &index + count, sizeof(int) - count, 0);
            if (bytes < 0) {
                std::cerr << "Error recv index." << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < (int)sizeof(int));
        auto lcend = std::chrono::system_clock::now();


        struct keyvalue data;
        std::stringstream iss;
        iss << index;
        key = key + "," + iss.str();
        std::strcpy(data.key, (char *)key.c_str());

        std::cin >> line;
        std::strcpy(data.value, (char *)line.c_str());

        auto ldstart = std::chrono::system_clock::now();
        send(sockfd, &data, sizeof(struct keyvalue), 0);


        //stashに格納する処理
        count = 0;
        struct keyvalue st;
        do {
            bytes = recv(sockfd, &st + count, sizeof(struct keyvalue) - count, 0);
            if (bytes < 0) {
                std::cerr << "Error recv stash." << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < (int)sizeof(struct keyvalue));
        auto ldend = std::chrono::system_clock::now();


        if (std::strncmp(st.key, (char*)"key_", 4) == 0) {
            stash.push_back(st);
            std::cout << "stash = key(" << st.key << ")" << std::endl;
        }

        
        auto end = std::chrono::system_clock::now();
        if (cnt != 0) {
            sum += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            sum_cnt = std::chrono::duration_cast<std::chrono::microseconds>(lcend - lcstart).count();
            sum_data = std::chrono::duration_cast<std::chrono::microseconds>(ldend - ldstart).count();

        }
        cnt++;
    }
    //ソケットクローズ
    close(sockfd);

    double ave = (double)sum / (cnt-1);
    double lcave = (double)sum_cnt / (cnt-1);
    double ldave = (double)sum_data / (cnt-1);

    std::ofstream f;
    std::string filename = argv[1];
    f.open(filename, std::ios::out);
    f << "Communication time (for updating count_table): " << lcave << " micro s" << std::endl;
    f << "Communication time (for updating cuckoo_hashing): " << ldave << " micro s" << std::endl;
    f << "Total average: " << ave << " micro s" << std::endl;

    f.close();
    
    return 0;
}
