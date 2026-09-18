#include "my_func/byteorder.hpp"

namespace my {

std::uint32_t bswap32(std::uint32_t value) {
    return (value >> 24) |
           ((value >> 8) & 0x0000FF00u) |
           ((value << 8) & 0x00FF0000u) |
           (value << 24);
}

}
