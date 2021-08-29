#include <assert.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <gmp.h>
#include "paillier.h"
#include <string>
#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用
#include <cstring>
#include <string.h>


int main (int argc, char *argv[])
{
    // Read public key from disk and initialize it
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

    // Read messages from disk
    std::fstream message1File("message1.txt", std::fstream::in);
    std::fstream message2File("message2.txt", std::fstream::in);

    assert(message1File.is_open());
    assert(message2File.is_open());

    std::string message1;
    std::string message2;
    std::getline(message1File, message1);
    std::getline(message2File, message2);

    message1File.close();
    message2File.close();

    std::cout << "message1: " << message1 << std::endl;
    std::cout << "message2: " << message2 << std::endl;

    // Encrypt messages
    paillier_plaintext_t* m1 = paillier_plaintext_from_ui(std::atoi(message1.c_str()));
    paillier_plaintext_t* m2 = paillier_plaintext_from_ui(std::atoi(message2.c_str()));

    paillier_ciphertext_t* ctxt1;
    paillier_ciphertext_t* ctxt2;    
    ctxt1 = paillier_enc(NULL, pubKey, m1, paillier_get_rand_devurandom);
    ctxt2 = paillier_enc(NULL, pubKey, m2, paillier_get_rand_devurandom);


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
//    addr.sin_addr.s_addr = inet_addr("40.65.118.71"); //IPアドレス,inet_addr()関数はアドレスの翻訳
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	//ソケット接続要求
	connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)); //ソケット, アドレスポインタ, アドレスサイズ


    // Write ciphertexts to disk
//    std::fstream ctxt1File("ciphertext1.txt", std::fstream::out|std::fstream::trunc|std::fstream::binary);
//    std::fstream ctxt2File("ciphertext2.txt", std::fstream::out|std::fstream::trunc|std::fstream::binary);

//    assert(ctxt1File.is_open());
//    assert(ctxt2File.is_open());

    // The length of the ciphertext is twice the length of the key
    char* byteCtxt1 = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ctxt1);
    char* byteCtxt2 = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, ctxt2);

    send(sockfd, byteCtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, 0);
    send(sockfd, byteCtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, 0);

//    ctxt1File.write(byteCtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
//    ctxt2File.write(byteCtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);    
    
//    ctxt1File.close();
//    ctxt2File.close();

    // Recieve encrypedSum from server
    char* byteEncryptedSum = (char*)malloc(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    int count = 0;
    int bytes;
    do {
        bytes = recv(sockfd, byteEncryptedSum, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, 0);
        if (bytes < 0){
            std::cerr << "recv data error!" << std::endl;
            return 1;
        }
        count += bytes;
    }while(count < PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

    paillier_ciphertext_t* encryptedSum = paillier_ciphertext_from_bytes((void*)byteEncryptedSum, 
            PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

    // Decrypt the ciphertext (sum)
    paillier_plaintext_t* dec;
    dec = paillier_dec(NULL, pubKey, secKey, encryptedSum);
    gmp_printf("Decrypted sum: %Zd\n", dec);



    // Cleaning up
    paillier_freepubkey(pubKey);
    paillier_freeprvkey(secKey);
    paillier_freeplaintext(m1);
    paillier_freeplaintext(m2);
    paillier_freeciphertext(ctxt1);
    paillier_freeciphertext(ctxt2);
    paillier_freeciphertext(encryptedSum);
    free(byteCtxt1);
    free(byteCtxt2);
    free(byteEncryptedSum);
    close(sockfd);

    
    return 0;
}

