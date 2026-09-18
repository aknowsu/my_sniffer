#include "my_func/byteorder.hpp"

#include <bit>

namespace my {

std::uint16_t hton16(std::uint16_t value) {
    if constexpr (std::endian::native == std::endian::big) {
        return value;
    } else {
        return bswap16(value);
    }
}

std::uint16_t ntoh16(std::uint16_t value) {
    return hton16(value);
}

}
