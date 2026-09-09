#include "my_func.hpp"

namespace my {

std::uint32_t bswap32(std::uint32_t v) {
    return static_cast<std::uint32_t>
    (
          (v >> 24)
        | ((v >>  8) & 0x0000FF00u)
        | ((v <<  8) & 0x00FF0000u)
        | (v << 24)
    );
}

} // namespace my
