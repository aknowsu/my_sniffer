#include "my_func.hpp"

#include <bit>

namespace my {

std::uint32_t hton32(std::uint32_t v) {
    if constexpr (std::endian::native == std::endian::big) {
        return v;
    } else {
        return bswap32(v);
    }
}

std::uint32_t ntoh32(std::uint32_t v) {
    return hton32(v);
}

} // namespace my
