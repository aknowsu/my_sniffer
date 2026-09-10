#include "my_func/byteorder.hpp"

namespace my {

std::uint32_t bswap32(std::uint32_t v) {
    return (v >> 24) |
           ((v >> 8) & 0x0000FF00u) |
           ((v << 8) & 0x00FF0000u) |
           (v << 24);
}

}
