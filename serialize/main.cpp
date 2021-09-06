#include <iostream>
#include <sstream>
#include <string>

#include <cereal/cereal.hpp>
//#include <cereal/archives/json.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/memory.hpp>

struct Pokemon {
    std::string name;
    int hp = 0;

    template<class Archive>
    void serialize(Archive & archive)
    {
//        archive(CEREAL_NVP(name), CEREAL_NVP(hp));
        archive(name, hp);
    }
};

int main()
{
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

   std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);
    {
        cereal::PortableBinaryOutputArchive o_archive(ss, cereal::PortableBinaryOutputArchive::Options::LittleEndian());
        o_archive(pokemon);
    }
    std::cout << ss.str() << std::endl;

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
