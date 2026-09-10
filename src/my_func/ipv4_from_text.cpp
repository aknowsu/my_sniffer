#include "my_func.hpp"

namespace my {

std::optional<std::uint32_t> ipv4_from_text(std::string_view text) {
    std::uint32_t addr = 0;
    std::size_t   pos  = 0;

    for (int octet = 0; octet < 4; ++octet) {
        // Dot separator between octets (not before the first).
        if (octet != 0) {
            if (pos >= text.size() || text[pos] != '.') {
                return std::nullopt;
            }
            ++pos;
        }

        // 1-3 decimal digits, value 0-255.
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
            return std::nullopt;   // reject leading zero ("01")
        }

        addr = (addr << 8) | value;
    }

    if (pos != text.size()) {
        return std::nullopt;   // trailing characters
    }
    return addr;
}

} // namespace my
