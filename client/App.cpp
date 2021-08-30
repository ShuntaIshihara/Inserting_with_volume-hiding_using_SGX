#include <iostream> //標準入出力
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include <string> //string型
#include <cstring>
#include <cstdlib>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "define.h"

void client_err_print(int status);
int client_create_rsa_priv2_key(int mod_size, int exp_size, const unsigned char *p_rsa_key_e, const unsigned char *p_rsa_key_p, const unsigned char *p_rsa_key_q,
	const unsigned char *p_rsa_key_dmp1, const unsigned char *p_rsa_key_dmq1, const unsigned char *p_rsa_key_iqmp,
	void **new_pri_key2);
int client_create_rsa_pub1_key(int mod_size, int exp_size, const unsigned char *le_n, const unsigned char *le_e, void **new_pub_key1);
int client_rsa_encrypt_sha256(const void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len);
int client_rsa_decrypt_sha256(const void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len);



int main(){

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
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv n error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, d + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv d error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, p + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv p error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, q + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv q error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, dmp1 + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv q error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, dmq1 + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv dmq1 error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, iqmp + count, 256 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv iqmp error\n";
            return 1;
        }
        count+=bytes;
    }while(count < 256);

    count = 0;
    do {
        bytes = recv(sockfd, &e + count, 8 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
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

/*
    //公開鍵、秘密鍵の受信
    unsigned char pub_key[8];
    unsigned char priv_key[8];

    int count = 0;
    int bytes;
    do {
        bytes = recv(sockfd, pub_key + count, 8 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv pub_key error\n";
            return 1;
        }
        count += bytes;
    }while(count < 8);

    count = 0;
    do {
        bytes = recv(sockfd, priv_key + count, 8 - count, 0);
        std::cout << "bytes = " << bytes << std::endl;
        if (bytes < 0) {
            std::cerr << "recv priv_key error\n";
            return 1;
        }
        count += bytes;
    }while(count < 8);
*/
    //データの挿入操作
    std::string line;
    int cnt = 0;
    while(std::cin >> line) {
        struct keyvalue data;
        size_t enc_len = 256;
        size_t dec_len = 0;
        unsigned char *in_key = (unsigned char*)line.c_str();
        int size = 256;
        status = client_rsa_encrypt_sha256((const void *)pub_key, data.key, (size_t *)&size, in_key, std::strlen((const char *)in_key)+1);
        client_err_print(status);

        status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                (const unsigned char *)data.key, enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }

        for (int i = 0; i < 10; ++i) {
            std::cin >> line;
            unsigned char *in_value = (unsigned char*)line.c_str();
            status = client_rsa_encrypt_sha256((const void *)pub_key, 
                    data.value[i], (size_t *)&size, in_value, std::strlen((const char *)in_value)+1);
            client_err_print(status);
        }

        /* 確認 */
        status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                (const unsigned char *)data.key, enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }

        unsigned char check_key[dec_len];
        status = client_rsa_decrypt_sha256(priv_key, check_key, &dec_len,
                (const unsigned char *)data.key, enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }
        std::cout << check_key << std::endl;

        /*  確認 */

        //count tableの更新
        //randomized response
        

        send(sockfd, &data, sizeof(struct keyvalue), 0); //送信

        //stash受信
        struct keyvalue stash[2];
        count = 0;
        do {
            bytes = recv(sockfd, &stash[0], sizeof(struct keyvalue), 0);
            std::cout << "bytes = " << bytes << std::endl;
            if (bytes < 0) {
                std::cerr << "recv stash[0] error\n";
                return 1;
            }
            count+=bytes;
        }while(count < 256);

        count = 0;
        do {
            bytes = recv(sockfd, &stash[1], sizeof(struct keyvalue), 0);
            std::cout << "bytes = " << bytes << std::endl;
            if (bytes < 0) {
                std::cerr << "recv stash[1] error\n";
                return 1;
            }
            count+=bytes;
        }while(count < 256);

        std::cout << "stash[0] = {";

        status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                (const unsigned char *)stash[0].key, enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }

        unsigned char key0[dec_len];
        status = client_rsa_decrypt_sha256(priv_key, key0, &dec_len,
                (const unsigned char *)stash[0].key, enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }
        std::cout << "key(" << key0 << "), value(";

        for (int i = 0; i < 9; ++i) {
            status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                    (const unsigned char *)stash[0].value[i], enc_len);
            if (status != SUCCESS) {
                std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
                client_err_print(status);
            }

            unsigned char value0[dec_len];
            status = client_rsa_decrypt_sha256(priv_key, value0, &dec_len,
                    (const unsigned char *)stash[0].value[i], enc_len);
            if (status != SUCCESS) {
                std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
                client_err_print(status);
            }
            std::cout << value0 << ", ";
        }
        status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                (const unsigned char *)stash[0].value[9], enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }

        unsigned char value1[dec_len];
        status = client_rsa_decrypt_sha256(priv_key, value1, &dec_len,
                (const unsigned char *)stash[0].value[9], enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }
        std::cout << value1 << ")}\n";

        std::cout << "stash[1] = {";

        status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                (const unsigned char *)stash[1].key, enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }

        unsigned char key1[dec_len];
        status = client_rsa_decrypt_sha256(priv_key, key1, &dec_len,
                (const unsigned char *)stash[1].key, enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }
        std::cout << "key(" << key1 << "), value(";

        for (int i = 0; i < 9; ++i) {
            status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                    (const unsigned char *)stash[1].value[i], enc_len);
            if (status != SUCCESS) {
                std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
                client_err_print(status);
            }

            unsigned char value2[dec_len];
            status = client_rsa_decrypt_sha256(priv_key, value2, &dec_len,
                    (const unsigned char *)stash[1].value[i], enc_len);
            if (status != SUCCESS) {
                std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
                client_err_print(status);
            }
            std::cout << value2 << ", ";
        }
        status = client_rsa_decrypt_sha256(priv_key, NULL, &dec_len,
                (const unsigned char *)stash[1].value[9], enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }

        unsigned char value3[dec_len];
        status = client_rsa_decrypt_sha256(priv_key, value3, &dec_len,
                (const unsigned char *)stash[1].value[9], enc_len);
        if (status != SUCCESS) {
            std::cerr << "Error at: sgx_rsa_priv_decrypt_sha256\n";
            client_err_print(status);
        }
        std::cout << value3 << ")}\n";
    }


    //ソケットクローズ
    close(sockfd);

    return 0;
}
