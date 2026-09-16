#include "my_func/address.hpp"

namespace my {

std::optional<std::uint32_t> ipv4_from_text(std::string_view text) {
    std::uint32_t addr = 0;
    std::size_t   pos = 0;

    for (int octet = 0; octet < 4; ++octet) {
        if (octet != 0) {
            if (pos >= text.size() || text[pos] != '.') {
                return std::nullopt;
            }
            ++pos;
        }

        const std::size_t start = pos;
        std::uint32_t     value = 0;
        while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
            value = value * 10 + static_cast<std::uint32_t>(text[pos] - '0');
            if (value > 255) {
                return std::nullopt;
            }
            ++pos;
        }

        const std::size_t digits = pos - start;
        if (digits == 0 || digits > 3) {
            return std::nullopt;
        }
        if (digits > 1 && text[start] == '0') {
            return std::nullopt;
        }

        addr = (addr << 8) | value;
    }

    if (pos != text.size()) {
        return std::nullopt;
    }
    return addr;
}

}
