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
#include <sys/time.h>
//#include <time.h>
#include "structure.hpp"


std::vector<struct keyvalue> stash;

int main(int argc, char *argv[]){


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
//    addr.sin_addr.s_addr = inet_addr("40.65.118.71"); //IPアドレス,inet_addr()関数はアドレスの翻訳
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	//ソケット接続要求
	connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)); //ソケット, アドレスポインタ, アドレスサイズ


    //データの挿入操作
    std::string line;
    int id = 0;
    int cnt = 0;
    while(std::cin >> line) {
        std::cout << "start" << std::endl;

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
        }while(count < sizeof(int));

        struct keyvalue data;
        std::stringstream iss;
        iss << index;
        key = key + "," + iss.str();
        std::strcpy(data.key, (char *)key.c_str());

        std::cin >> line;
        std::strcpy(data.value, (char *)line.c_str());

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
        }while(count < sizeof(struct keyvalue));


        if (std::strncmp(st.key, (char*)"key_", 4) == 0) {
            stash.push_back(st);
            std::cout << "stash = key(" << st.key << ")" << std::endl;
        }

        
    }
    //ソケットクローズ
    close(sockfd);
}
