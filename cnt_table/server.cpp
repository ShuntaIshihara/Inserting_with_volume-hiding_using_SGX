#include <iostream>
#include <vector>
#include <unordered_map>
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include <gmp.h>
#include "paillier.h"
#include <cereal/cereal.hpp>
//#include <cereal/archives/json.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/array.hpp>
#include <cereal/types/memory.hpp>
#include "structure.hpp"


std::string getPubKey(std::string filename);
std::string getSecKey(std::string filename);
std::vector<cnt_data> deserialize(char buffer[], int size);


int main()
{
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
	addr.sin_port = htons(8000); //ポート番号,htons()関数は16bitホストバイトオーダーをネットワークバイトオーダーに変換
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


    std::string hexPubKey = getPubKey("pubkey.txt");
    std::string hexSecKey = getSecKey("seckey.txt");

    paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);
    paillier_prvkey_t* secKey = paillier_prvkey_from_hex(&hexSecKey[0], pubKey);

    int index = 0;
    std::unordered_map<std::string, int> indices;    //hash_mapから配列の添字を読み込む
    char* cnt_table[10];                               //hash_mapから読み込んだ添字の場所に格納する
    for (int i = 0; i < 10; i++) {
        cnt_table[i] = (char*)malloc(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    }

    for (int i = 0; i < 10; i++) {
        //count tabel の更新情報を受信
        int bytes;
        int count = 0;
        int size;
        do {
            bytes = recv(connect, &size + count, (int)sizeof(int) - count, 0);
            if (bytes < 0) {
                std::cerr << "recv data error0!" << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < (int)sizeof(int));

        std::cout << size << std::endl;

        char buffer[size];
        count = 0;
        do {
            bytes = recv(connect, buffer + count, size - count, 0);
            if (bytes < 0) {
                std::cerr << "recv data error1!" << std::endl;
                return 1;
            }
            count += bytes;
        }while(count < size+1);

        //デシリアライズ
        std::vector<cnt_data> cnt_list = deserialize(buffer, size);
        for (int i = 0; i < (int)cnt_list.size(); ++i) {
            std::cout << cnt_list[i].h << std::endl;
        }


        for (int i = 0; i < cnt_list.size(); ++i) {
            paillier_ciphertext_t* encryptedCnt;
            if(indices.find(cnt_list[i].h) == indices.end()) {
                index++;
                indices[cnt_list[i].h] = index;
                encryptedCnt = paillier_create_enc_zero();
            } else {
                encryptedCnt = paillier_ciphertext_from_bytes((void*)cnt_table[i], PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
            }

            paillier_ciphertext_t* encryptedSum = paillier_create_enc_zero();

            paillier_ciphertext_t* encryptedValue = paillier_ciphertext_from_bytes((void*)cnt_list[i].byteEncryptedValue, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

            paillier_mul(pubKey, encryptedSum, encryptedCnt, encryptedValue);

            char* byteEncryptedSum = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, encryptedSum);


            std::memmove(cnt_table[indices[cnt_list[i].h]], byteEncryptedSum, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);


            // Decrypt the ciphertext (sum)
            paillier_ciphertext_t* ctxt = paillier_ciphertext_from_bytes((void*)cnt_table[indices[cnt_list[i].h]], PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

            paillier_plaintext_t* dec;
            dec = paillier_dec(NULL, pubKey, secKey, ctxt);
            gmp_printf("Decrypted ctable[0][c_list.h1]: %Zd\n", dec);

            paillier_freeciphertext(encryptedValue);
            paillier_freeciphertext(encryptedCnt);
            paillier_freeciphertext(encryptedSum);
            paillier_freeplaintext(dec);
            free(byteEncryptedSum);
        }

    }
    paillier_freepubkey(pubKey);
    paillier_freeprvkey(secKey);

    close(connect);
    close(sockfd);

    return 0;
}
