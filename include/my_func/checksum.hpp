#pragma once

#include <cstddef>
#include <cstdint>

namespace my {

std::uint32_t checksum_accumulate(const std::uint8_t *data, std::size_t len, std::uint32_t seed = 0);
std::uint16_t checksum_fold(std::uint32_t sum);

std::uint16_t checksum16(const std::uint8_t *data, std::size_t len);

}
