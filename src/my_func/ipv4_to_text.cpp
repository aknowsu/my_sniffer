#include "my_func/address.hpp"

namespace my {

std::string ipv4_to_text(std::uint32_t addr) {
    std::string out;
    for (int shift = 24; shift >= 0; shift -= 8) {
        if (shift != 24) {
            out.push_back('.');
        }
        out += std::to_string((addr >> shift) & 0xFFu);
    }
    return out;
}

}
