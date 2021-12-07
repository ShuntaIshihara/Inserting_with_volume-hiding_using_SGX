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
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <cereal/cereal.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <gmp.h>
#include "paillier.h"
#include "structure.hpp"


#include "define.h"

void client_err_print(int status);
int client_create_rsa_priv2_key(int mod_size, int exp_size, const unsigned char *p_rsa_key_e, const unsigned char *p_rsa_key_p, const unsigned char *p_rsa_key_q,
	const unsigned char *p_rsa_key_dmp1, const unsigned char *p_rsa_key_dmq1, const unsigned char *p_rsa_key_iqmp,
	void **new_pri_key2);
int client_create_rsa_pub1_key(int mod_size, int exp_size, const unsigned char *le_n, const unsigned char *le_e, void **new_pub_key1);
int client_rsa_encrypt_sha256(const void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len);
int client_rsa_decrypt_sha256(const void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len);

std::string getPubKey(std::string filename);
std::string getSecKey(std::string filename);
std::vector<int> randomized_response(double p, int key, int key_max);
std::vector<int> select_0(double p, int key_max);
std::string sha256(SHA256_CTX sha_ctx, std::string m);
std::vector<cnt_data> deserialize(char buffer[], int size);
void init(std::string filename, std::unordered_map<std::string, int>& id_list, std::vector<std::string>& key_list);

std::vector<struct keyvalue> stash;
std::vector<std::string> split(std::string& src, const char* delim)
{
    std::vector<std::string> vec;
    std::string::size_type len = src.length();

    for (std::string::size_type i = 0, n; i < len; i = n + 1) {
        n = src.find_first_of(delim, i);
        if (n == std::string::npos) {
            n = len;
        }
        vec.push_back(src.substr(i, n - i));
    }

    return vec;
}
int main(int argc, char *argv[]){
    if (argc != 3) {
        std::cerr << "Command line arguments are not enough." << std::endl;
        std::cerr << "$> ./app [time_result_file] [key_list_file] < [dataset_file]" << std::endl;
        return 1;
    }

    std::ofstream ofs((const char *)argv[1]);
    if (!ofs)
    {
        std::cout << "ファイルが開けませんでした。" << std::endl;
        return 1;
    }
    std::string klfile = argv[2];
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
//    addr.sin_addr.s_addr = inet_addr("40.65.118.71"); //IPアドレス,inet_addr()関数はアドレスの翻訳
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	//ソケット接続要求
	connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)); //ソケット, アドレスポインタ, アドレスサイズ

    //鍵の成分の生成
    int n_byte_size = 256;
    unsigned char n[256];
    unsigned char d[256];
    unsigned char p[256];
    unsigned char q[256];
    unsigned char dmp1[256];
    unsigned char dmq1[256];
    unsigned char iqmp[256];
    long e = 65537;
    void *pub_key = NULL;
    void *priv_key = NULL;

    //鍵のパーツを受信
    int count = 0;
    int bytes;
    do {
        bytes = recv(sockfd, n + count, 256 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv n error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, d + count, 256 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv d error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, p + count, 256 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv p error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, q + count, 256 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv q error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, dmp1 + count, 256 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv q error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, dmq1 + count, 256 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv dmq1 error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, iqmp + count, 256 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv iqmp error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, &e + count, 8 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv e error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 8);


    //公開鍵、秘密鍵の生成
    int status =  client_create_rsa_priv2_key(n_byte_size, sizeof(e), (const unsigned char *)&e,
            (const unsigned char *)p, (const unsigned char *)q, (const unsigned char *)dmp1,
            (const unsigned char *)dmq1, (const unsigned char *)iqmp, &priv_key);
    client_err_print(status);
    
    status = client_create_rsa_pub1_key(n_byte_size, sizeof(e),
            (const unsigned char *)n, (const unsigned char *)&e, &pub_key);
    client_err_print(status);


    //opnessl shaのコンテキスト初期化

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx); // コンテキストを初期化

    //pubkey, seckey読み込み
    std::string hexPubKey = getPubKey("pubkey.txt");
    std::string hexSecKey = getSecKey("seckey.txt");

    paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);
    paillier_prvkey_t* secKey = paillier_prvkey_from_hex(&hexSecKey[0], pubKey);

    //キー -> キー番号　リストの宣言と初期化
    std::unordered_map<std::string, int> id_list;

    //キー番号 -> キー　リストの宣言と初期化
    std::vector<std::string> key_list;

    init(klfile, id_list, key_list);


    //データの挿入操作
    std::string line;
    int cnt = 0;
    int loop_cnt = 0;
    int vc = 0;
    while(1) {
        int flag = 0;
        std::cout << "> ";
        std::vector<std::string> v;
        std::getline(std::cin, line);
        v = split(line, " ");
        std::string key;
        std::string val;
        if (v.size() == 1) {
            key = v[0];
            flag = 1;
        } else if (v.size() == 2) {
            key = v[0];
            val = v[1];
            flag = 2;
        } else {
            std::cerr << "Warning: The number of inputs is incorrect." << std::endl;
            std::cerr << "Usage:" << std::endl;
            std::cerr << "Searching > [key]" << std::endl;
            std::cerr << "Inserting > [key] [value]" << std::endl;
            continue;
        }
        if (key == "q" || key == "quit") {
            flag = 0;
        }
        send(sockfd, &flag, sizeof(int), 0);
        vc += (int)sizeof(int);
        if (flag == 0) break;

        if (flag == 2) {
            auto start = std::chrono::system_clock::now();

            //新しいキーであれば、キーリストに追加
            if (id_list.find(key) == id_list.end()) {
                id_list[key] = cnt;
                key_list.push_back(key);
                cnt++;
            }

            //hash値 -> キー　リストの宣言と初期化
            std::unordered_map<std::string, std::string> hash_list;


            auto start_c = std::chrono::system_clock::now();

            //randomized response
            std::vector<int> keys = randomized_response(0.5, id_list[key], id_list.size());

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

                hash_list[h] = key_list[keys[i]];

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
            std::vector<int> keys0 = select_0(0.5, id_list.size());

            //byteEncryptedZeroを生成
            paillier_plaintext_t* m0 = paillier_plaintext_from_ui(0);
            paillier_ciphertext_t* ctxt0;
            ctxt0 = paillier_enc(NULL, pubKey, m0, paillier_get_rand_devurandom);
            char* byteEncryptedZero = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ctxt0);

            for (int i = 0; i < (int)keys0.size(); ++i) {
                //sha256ハッシュ値生成
                std::string h = sha256(sha_ctx, key_list[keys0[i]]);

                hash_list[h] = key_list[keys0[i]];

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

            char buffer[ss.str().size()];
            std::memcpy(buffer, ss.str().data(), ss.str().size());

            int bf_size = ss.str().size();

            send(sockfd, &bf_size, sizeof(int), 0);
            vc += (int)sizeof(int);
            send(sockfd, buffer, bf_size, 0);
            vc += bf_size;
            cnt_list.clear();

            //結果を受け取る
            int count = 0;
            int bytes;
            int s;
            do {
                bytes = recv(sockfd, &s + count, sizeof(int) - count, 0);
                if (bytes < 0) {
                    std::cerr << "recv s error\n";
                    return 1;
                }
                count += bytes;
            }while(count < (int)sizeof(int));
            vc += count;

            count = 0;
            char bf[s];
            do {
                bytes = recv(sockfd, bf + count, s - count, 0);
                if (bytes < 0) {
                    std::cerr << "recv bf error" << std::endl;
                    return 1;
                }
                count += bytes;
            }while(count < s);
            vc += count;

            //デシリアライズ
            std::vector<cnt_data> recv_list = deserialize(bf, s);

            int index;

            for (int i = 0; i < (int)recv_list.size(); ++i) {
                if (key != hash_list[recv_list[i].h]) {
                    continue;
                }

                paillier_ciphertext_t* ctxt = paillier_ciphertext_from_bytes((void*)recv_list[i].byteEncryptedValue, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
                paillier_plaintext_t* dec;
                dec = paillier_dec(NULL, pubKey, secKey, ctxt);
                index = mpz_get_si((mpz_srcptr)dec);
                paillier_freeplaintext(dec);
                paillier_freeciphertext(ctxt);
            }
            auto end_c = std::chrono::system_clock::now();

            auto start_t = std::chrono::system_clock::now();
            struct keyvalue data;
            size_t enc_len = 256;
            size_t dec_len = 0;
            std::string key_idx = key + ":" + std::to_string(index);
            unsigned char *in_key = (unsigned char*)key_idx.c_str();
            int size = 256;

            status = client_rsa_encrypt_sha256((const void *)pub_key, data.key, (size_t *)&size, in_key, std::strlen((const char *)in_key)+1);
            client_err_print(status);        


            unsigned char *in_value = (unsigned char*)val.c_str();
            status = client_rsa_encrypt_sha256((const void *)pub_key, 
                    data.value, (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
            client_err_print(status);


            send(sockfd, &data, sizeof(struct keyvalue), 0); //送信
            vc += (int)sizeof(struct keyvalue);

            //stash受信
            struct keyvalue st[2];
            count = 0;
            do {
                bytes = recv(sockfd, &st[0], sizeof(struct keyvalue), 0);
                if (bytes < 0) {
                    std::cerr << "recv stash[0] error\n";
                    return 1;
                }
                count+=bytes;
            }while(count < (int)sizeof(struct keyvalue));
            vc += count;

            count = 0;
            do {
                bytes = recv(sockfd, &st[1], sizeof(struct keyvalue), 0);
                if (bytes < 0) {
                    std::cerr << "recv stash[1] error\n";
                    return 1;
                }
                count+=bytes;
            }while(count < (int)sizeof(struct keyvalue));
            vc += count;

            // stashに格納する

            status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                    (const unsigned char *)st[0].key, enc_len);
            if (status != SUCCESS) {
                std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
                client_err_print(status);
            }

            unsigned char key0[dec_len];
            status = client_rsa_decrypt_sha256(priv_key, key0, &dec_len,
                    (const unsigned char *)st[0].key, enc_len);
            if (status != SUCCESS) {
                std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
                client_err_print(status);
            }
            if (std::strncmp((char*)key0, "dummy_", 6) != 0) {
                stash.push_back(st[0]);
                std::cout << "key(" << key0 << ")" << std::endl;
            }

            status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                    (const unsigned char *)st[1].key, enc_len);
            if (status != SUCCESS) {
                std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
                client_err_print(status);
            }

            unsigned char key1[dec_len];
            status = client_rsa_decrypt_sha256(priv_key, key1, &dec_len,
                    (const unsigned char *)st[1].key, enc_len);
            if (status != SUCCESS) {
                std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
                client_err_print(status);
            }
            if (std::strncmp((char*)key1, "dummy_", 6) != 0) {
                stash.push_back(st[1]);
                std::cout << "key(" << key1 << ")" << std::endl;
            }
            auto end_t = std::chrono::system_clock::now(); 
            auto end = std::chrono::system_clock::now();
            //end_all = time(NULL);

            if (loop_cnt != 0) {
                sum += std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count();
                sum_c += std::chrono::duration_cast<std::chrono::milliseconds>(end_c-start_c).count();
                sum_t += std::chrono::duration_cast<std::chrono::milliseconds>(end_t-start_t).count();
            }

            loop_cnt++;
            std::cout << "insertion pass" << std::endl;
        }
    }
    std::cout << "end" << std::endl;

    double average_insertion = (double)sum_t / (loop_cnt-1);
    double average_volume = (double)sum_c / (loop_cnt-1);
    double average_all = (double)sum / (loop_cnt-1);
    double ave_vol = (double)vc / (loop_cnt);

    ofs << "ボリューム更新の平均処理時間(ms): ";
    ofs << std::to_string(average_volume) << std::endl;

    ofs << "挿入の平均処理時間(ms): ";
    ofs << std::to_string(average_insertion) << std::endl;

    ofs << "全体の平均処理時間(s): ";
    ofs << std::to_string(average_all) << std::endl;

    ofs << "全体の通信量(bytes): ";
    ofs << std::to_string(ave_vol) << std::endl;


    //ソケットクローズ
    close(sockfd);

    return 0;
}
