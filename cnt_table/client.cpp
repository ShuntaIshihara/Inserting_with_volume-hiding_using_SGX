#include <iostream> //標準入出力
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
#include <openssl/sha.h>
#include <cereal/cereal.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <gmp.h>
#include "paillier.h"
#include "structure.hpp"


std::string getPubKey(std::string filename);
std::string getSecKey(std::string filename);
std::vector<int> randomized_response(double p, int key, int key_max);
std::vector<int> select_0(double p, int key_max);
std::string sha256(SHA256_CTX sha_ctx, std::string m);


int main(){

	//ソケットの生成
	int sockfd = socket(AF_INET, SOCK_STREAM, 0); //アドレスドメイン, ソケットタイプ, プロトコル
	if(sockfd < 0){ //エラー処理

		std::cout << "Error socket:" << std::strerror(errno); //標準出力
		exit(1); //異常終了
	}

	//アドレスの生成
	struct sockaddr_in addr; //接続先の情報用の構造体(ipv4)
	std::memset(&addr, 0, sizeof(struct sockaddr_in)); //memsetで初期化
	addr.sin_family = AF_INET; //アドレスファミリ(ipv4)
	addr.sin_port = htons(8000); //ポート番号,htons()関数は16bitホストバイトオーダーをネットワークバイトオーダーに変換
//    addr.sin_addr.s_addr = inet_addr("40.65.118.71"); //IPアドレス,inet_addr()関数はアドレスの翻訳
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	//ソケット接続要求
	connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)); //ソケット, アドレスポインタ, アドレスサイズ

    //opnessl shaのコンテキスト初期化

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx); // コンテキストを初期化

    //pubkey, seckey読み込み
    std::string hexPubKey = getPubKey("pubkey.txt");
    std::string hexSecKey = getSecKey("seckey.txt");

    paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);
    paillier_prvkey_t* secKey = paillier_prvkey_from_hex(&hexSecKey[0], pubKey);

    //キー -> キー番号　リストの宣言と初期化
    std::unordered_map<std::string, int> n_list;

    //キー番号 -> キー　リストの宣言と初期化
    std::vector<std::string> key_list;

    //データの挿入操作
    std::string line;
    int cnt = 0;
    while(std::cin >> line) {
        
        //新しいキーであれば、キーリストに追加
        if (n_list.find(line) == n_list.end()) {
            n_list[line] = cnt;
            key_list.push_back(line);
            cnt++;
        }

        //randomized response
        std::vector<int> keys = randomized_response(0.5, n_list[line], n_list.size());

        //サーバーに送るキーのリスト
        std::vector<cnt_data> cnt_list;

        //byteEncryptedOneの生成
        paillier_plaintext_t* m1 = paillier_plaintext_from_ui(1);
        paillier_ciphertext_t* ctxt1;
        ctxt1 = paillier_enc(NULL, pubKey, m1, paillier_get_rand_devurandom);
        char* byteEncryptedOne = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ctxt1);

        for (int i = 0; i < (int)keys.size(); ++i) {
           //sha256ハッシュ値生成
           std::string h = sha256(sha_ctx, key_list[keys[i]]);
           // 確認
            std::cout << "ハッシュ値: ";
            std::cout << h << std::endl;


            cnt_data w;
            w.h = h;
            std::memcpy(w.byteEncryptedValue, byteEncryptedOne, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

            cnt_list.push_back(w);
        }

        paillier_freeplaintext(m1);
        paillier_freeciphertext(ctxt1);
        free(byteEncryptedOne);
        keys.clear();

        //0を送るキーを選ぶ
        std::vector<int> keys0 = select_0(0.5, n_list.size());

        //byteEncryptedZeroを生成
        paillier_plaintext_t* m0 = paillier_plaintext_from_ui(0);
        paillier_ciphertext_t* ctxt0;
        ctxt0 = paillier_enc(NULL, pubKey, m0, paillier_get_rand_devurandom);
        char* byteEncryptedZero = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ctxt0);

        for (int i = 0; i < (int)keys0.size(); ++i) {
            //sha256ハッシュ値生成
            std::string h = sha256(sha_ctx, key_list[keys0[i]]);
            // 確認
            std::cout << "ハッシュ値: ";
            std::cout << h << std::endl;

            cnt_data w;
            w.h = h;
            std::memcpy(w.byteEncryptedValue, byteEncryptedZero, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

            cnt_list.push_back(w);
        }

        paillier_freeplaintext(m0);
        paillier_freeciphertext(ctxt0);
        free(byteEncryptedZero);
        keys0.clear();

        //シリアライズ
        std::stringstream ss;
        {
            cereal::PortableBinaryOutputArchive o_archive(ss, cereal::PortableBinaryOutputArchive::Options::LittleEndian());
            o_archive(cnt_list);
        }
        std::cout << ss.str() << std::endl;

        char buffer[ss.str().size()];
        std::memcpy(buffer, ss.str().data(), ss.str().size());

        int size = ss.str().size();
        std::cout << size << std::endl;

        send(sockfd, &size, sizeof(int), 0);
        send(sockfd, buffer, size, 0);

        cnt_list.clear();

    }

    //ソケットクローズ
    close(sockfd);

    return 0;
}
