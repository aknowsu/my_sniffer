#pragma once

#include <cstdint>

namespace my {

std::uint8_t read_u8(const std::uint8_t *data);
std::uint16_t read_u16be(const std::uint8_t *data);
std::uint32_t read_u32be(const std::uint8_t *data);

}
