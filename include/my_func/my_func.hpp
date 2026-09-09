#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace my {
    std::uint16_t bswap16(std::uint16_t v);
    std::uint32_t bswap32(std::uint32_t v);
} // namespace my
