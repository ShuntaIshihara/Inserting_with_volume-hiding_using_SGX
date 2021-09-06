#include <iostream>
#include <sstream>
#include <string>

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
    std::string name;
    int hp = 0;

    template<class Archive>
    void serialize(Archive & archive)
    {
        archive(CEREAL_NVP(name), CEREAL_NVP(hp));
    }
};

int main()
{
/*
    std::vector<struct Pokemon> pokemon;
    Pokemon pikachu;
    pikachu.name = "PIKACHU";
    pikachu.hp = 100;

    Pokemon hitokage;
    hitokage.name = "HITOKAGE";
    hitokage.hp = 100;

    Pokemon zenigame;
    zenigame.name = "ZENIGAME";
    zenigame.hp = 100;

    Pokemon fushigidane;
    fushigidane.name = "FUSHIGIDANE";
    fushigidane.hp = 100;

    pokemon.push_back(pikachu);
    pokemon.push_back(hitokage);
    pokemon.push_back(zenigame);
    pokemon.push_back(fushigidane);

    std::stringstream ss;
    {
        cereal::JSONOutputArchive o_archive(ss);
        o_archive(cereal::make_nvp("root", pokemon));
    }
    std::cout << ss.str() << std::endl;
*/
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

    int size = 0;
    int count = 0;
    int bytes;

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
    }while(count < size);


    std::stringstream ss;
    ss.write(buffer, size);
    
    std::vector<struct Pokemon> pokemon_i;
    cereal::PortableBinaryInputArchive i_archive(ss, cereal::PortableBinaryInputArchive::Options::LittleEndian());
    i_archive(pokemon_i);

    for (int i = 0; i < (int)pokemon_i.size(); ++i) {
    std::cout << pokemon_i[i].name << std::endl;
    std::cout << pokemon_i[i].hp << std::endl;
    }

#ifdef _MSC_VER
    system("pause");
#endif
    return 0;
}
