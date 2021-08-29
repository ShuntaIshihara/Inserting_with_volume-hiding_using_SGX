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


    // Read public key from disk and initialize it
    std::fstream pubKeyFile("pubkey.txt", std::fstream::in);
//    std::fstream secKeyFile("seckey.txt", std::fstream::in);    
    
    assert(pubKeyFile.is_open());
//    assert(secKeyFile.is_open());    

    std::string hexPubKey;
//    std::string hexSecKey;    
    std::getline(pubKeyFile, hexPubKey);
//    std::getline(secKeyFile, hexSecKey);    

    pubKeyFile.close();
//    secKeyFile.close();    
    
    paillier_pubkey_t* pubKey = paillier_pubkey_from_hex(&hexPubKey[0]);
//    paillier_prvkey_t* secKey = paillier_prvkey_from_hex(&hexSecKey[0], pubKey);

    // Recieve ciphertexts from client
//    std::fstream ctxt1File("ciphertext1.txt", std::fstream::in|std::fstream::binary);
//    std::fstream ctxt2File("ciphertext2.txt", std::fstream::in|std::fstream::binary);

//    assert(ctxt1File.is_open());
//    assert(ctxt2File.is_open());
    int count = 0;
    int bytes;

    // The length of the ciphertext is twice the length of the key
    char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    char* byteCtxt2 = (char*)malloc(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

//    ctxt1File.read(byteCtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    do {
        bytes = recv(connect, byteCtxt1 + count, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv data error!" << std::endl;
            return 1;
        }
        count += bytes;
    }while(count < PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

//    ctxt2File.read(byteCtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);    
    count = 0;
    do {
        bytes = recv(connect, byteCtxt2 + count, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2 - count, 0);
        if (bytes < 0) {
            std::cerr << "recv data error!" << std::endl;
            return 1;
        }
        count += bytes;
    }while(count < PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

//    ctxt1File.close();
//    ctxt2File.close();

    paillier_ciphertext_t* ctxt1 = paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);
    paillier_ciphertext_t* ctxt2 = paillier_ciphertext_from_bytes((void*)byteCtxt2, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2);

    // Initialize the ciphertext that will hold the sum with an encryption of zero
    paillier_ciphertext_t* encryptedSum = paillier_create_enc_zero();

    // Sum the encrypted values by multiplying the ciphertexts
    paillier_mul(pubKey, encryptedSum, ctxt1, ctxt2);
    
    // Send byteEncryptedSum to client
    char* byteEncryptedSum = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, encryptedSum);
    send(connect, byteEncryptedSum, PAILLIER_BITS_TO_BYTES(pubKey->bits)*2, 0);
    // Decrypt the ciphertext (sum)
//    paillier_plaintext_t* dec;
//    dec = paillier_dec(NULL, pubKey, secKey, encryptedSum);
//    gmp_printf("Decrypted sum: %Zd\n", dec);
    
    // Cleaning up
    paillier_freepubkey(pubKey);
//    paillier_freeprvkey(secKey);
//    paillier_freeplaintext(dec);
    paillier_freeciphertext(ctxt1);
    paillier_freeciphertext(ctxt2);
    paillier_freeciphertext(encryptedSum);
    free(byteCtxt1);
    free(byteCtxt2);
    free(byteEncryptedSum);
    close(connect);
    close(sockfd);
    
    return 0;
}
