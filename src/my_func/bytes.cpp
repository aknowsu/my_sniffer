#include "my_func/bytes.hpp"

namespace my {

std::uint8_t read_u8(const std::uint8_t *data) {
    return data[0];
}

std::uint16_t read_u16be(const std::uint8_t *data) {
    return static_cast<std::uint16_t>((data[0] << 8) | data[1]);
}

std::uint32_t read_u32be(const std::uint8_t *data) {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
           (static_cast<std::uint32_t>(data[3]));
}

}
