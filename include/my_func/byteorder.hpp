#pragma once

#include <cstdint>

namespace my {

std::uint16_t bswap16(std::uint16_t value);
std::uint32_t bswap32(std::uint32_t value);

std::uint16_t hton16(std::uint16_t value);
std::uint32_t hton32(std::uint32_t value);
std::uint16_t ntoh16(std::uint16_t value);
std::uint32_t ntoh32(std::uint32_t value);

}
