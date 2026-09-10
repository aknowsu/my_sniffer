#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace my {

std::string hexdump(const std::uint8_t *data, std::size_t len, std::size_t base = 0);

}
