#include "my_func/checksum.hpp"

#include "my_func/bytes.hpp"

namespace my {

std::uint16_t checksum16(const std::uint8_t *data, std::size_t len) {
    std::uint32_t sum = 0;

    for (std::size_t i = 0; i + 1 < len; i += 2) {
        sum += read_u16be(data + i);
    }
    if (len & 1) {
        sum += static_cast<std::uint32_t>(data[len - 1]) << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

}
