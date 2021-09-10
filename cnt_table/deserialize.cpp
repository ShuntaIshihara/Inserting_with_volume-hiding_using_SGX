#include <sstream>
#include <vector>
#include <cereal/cereal.hpp>
//#include <cereal/archives/json.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/memory.hpp>
#include <gmp.h>
#include "paillier.h"
#include "structure.hpp"


std::vector<cnt_data> deserialize(char buffer[], int size)
{
    std::stringstream ss;
    ss.write(buffer, size);

    std::vector<cnt_data> cnt_list;
    cereal::PortableBinaryInputArchive i_archive(ss, cereal::PortableBinaryInputArchive::Options::LittleEndian());
    i_archive(cnt_list);

    return cnt_list;
}
