#include "my_func/byteorder.hpp"

namespace my {

std::uint16_t bswap16(std::uint16_t v) {
    return static_cast<std::uint16_t>((v >> 8) | (v << 8));
}

}
