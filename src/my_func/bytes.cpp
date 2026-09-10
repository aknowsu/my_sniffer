#include "my_func/bytes.hpp"

namespace my {

std::uint8_t read_u8(const std::uint8_t *p) {
    return p[0];
}

std::uint16_t read_u16be(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

std::uint32_t read_u32be(const std::uint8_t *p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           (static_cast<std::uint32_t>(p[3]));
}

}
