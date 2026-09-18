#include "my_func/byteorder.hpp"

namespace my {

std::uint16_t bswap16(std::uint16_t value) {
    return static_cast<std::uint16_t>((value >> 8) | (value << 8));
}

}
