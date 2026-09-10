#pragma once

#include <cstddef>
#include <cstdint>

namespace my {

std::uint16_t checksum16(const std::uint8_t *data, std::size_t len);

}
