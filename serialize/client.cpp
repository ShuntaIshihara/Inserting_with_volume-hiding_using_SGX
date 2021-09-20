#include <iostream>
#include <sstream>
#include <string>
#include <cstring>

#include <cereal/cereal.hpp>
//#include <cereal/archives/json.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/memory.hpp>


#include <sys/socket.h> //アドレスドメイン
#include <sys/types.h> //ソケットタイプ
#include <arpa/inet.h> //バイトオーダの変換に利用
#include <unistd.h> //close()に利用

struct Pokemon {
    char name[256];
    int hp = 0;

    template<class Archive>
    void serialize(Archive & archive)
    {
        archive(name, hp);
    }
};

int main()
{
    std::vector<struct Pokemon> pokemon;
    Pokemon pikachu;
    std::strcpy(pikachu.name, "PIKACHU");
    pikachu.hp = 100;

    Pokemon hitokage;
    std::strcpy(hitokage.name, "HITOKAGE");
    hitokage.hp = 100;

    Pokemon zenigame;
    std::strcpy(zenigame.name, "ZENIGAME");
    zenigame.hp = 100;

    Pokemon fushigidane;
    std::strcpy(fushigidane.name, "FUSHIGIDANE");
    fushigidane.hp = 100;

    pokemon.push_back(pikachu);
    pokemon.push_back(hitokage);
    pokemon.push_back(zenigame);
    pokemon.push_back(fushigidane);

    std::stringstream ss;
    {
        cereal::PortableBinaryOutputArchive o_archive(ss, cereal::PortableBinaryOutputArchive::Options::LittleEndian());
        o_archive(pokemon);
    }
    std::cout << ss.str() << std::endl;

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

//    std::vector<char> buffer(ss.str().size());   // ストリームのサイズ分の領域を確保
    char buffer[ss.str().size()];
    std::memcpy(buffer, ss.str().data(), ss.str().size());    // バッファにコピー

    int size = ss.str().size();
    std::cout << size << std::endl;
    
//    std::cout << buffer << std::endl;
    send(sockfd, &size, sizeof(int), 0);
    send(sockfd, buffer, size, 0);

/*
    std::vector<struct Pokemon> pokemon_i;
    cereal::JSONInputArchive i_archive(ss);
    i_archive(pokemon_i);

    for (int i = 0; i < (int)pokemon_i.size(); ++i) {
    std::cout << pokemon_i[i].name << std::endl;
    std::cout << pokemon_i[i].hp << std::endl;
    }
*/
#ifdef _MSC_VER
    system("pause");
#endif
    return 0;
}
