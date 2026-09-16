#include "my_func/checksum.hpp"

#include "my_func/bytes.hpp"

namespace my {
namespace {

constexpr int word_bits = 16;
constexpr std::uint32_t low_word_mask = (1u << word_bits) - 1;

}

std::uint32_t checksum_accumulate(const std::uint8_t *data, std::size_t len, std::uint32_t seed) {
    std::uint32_t sum = seed;

    for (std::size_t i = 0; i + 1 < len; i += 2) {
        sum += read_u16be(data + i);
    }
    if (len & 1) {
        sum += static_cast<std::uint32_t>(data[len - 1]) << 8;
    }
    return sum;
}

std::uint16_t checksum_fold(std::uint32_t sum) {
    while (sum >> word_bits) {
        sum = (sum & low_word_mask) + (sum >> word_bits);
    }
    return static_cast<std::uint16_t>(~sum);
}

std::uint16_t checksum16(const std::uint8_t *data, std::size_t len) {
    return checksum_fold(checksum_accumulate(data, len));
}

}
