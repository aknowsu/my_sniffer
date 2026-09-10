#include "my_func/byteorder.hpp"

#include <bit>

namespace my {

std::uint16_t hton16(std::uint16_t v) {
    if constexpr (std::endian::native == std::endian::big) {
        return v;
    } else {
        return bswap16(v);
    }
}

std::uint16_t ntoh16(std::uint16_t v) {
    return hton16(v);
}

}
