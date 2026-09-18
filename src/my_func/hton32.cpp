#include "my_func/byteorder.hpp"

#include <bit>

namespace my {

std::uint32_t hton32(std::uint32_t value) {
    if constexpr (std::endian::native == std::endian::big) {
        return value;
    } else {
        return bswap32(value);
    }
}

std::uint32_t ntoh32(std::uint32_t value) {
    return hton32(value);
}

}
