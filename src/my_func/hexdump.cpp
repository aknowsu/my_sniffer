#include "my_func.hpp"

namespace my {

std::string hexdump(const std::uint8_t *data, std::size_t len, std::size_t base) {
    static const char hex[] = "0123456789abcdef";
    std::string out;

    for (std::size_t off = 0; off < len; off += 16) {
        // Offset column: 8 hex digits.
        const std::size_t line_addr = base + off;
        for (int shift = 28; shift >= 0; shift -= 4) {
            out.push_back(hex[(line_addr >> shift) & 0xF]);
        }
        out += "  ";

        // 16 hex bytes, extra space after the 8th, spaces where the row is short.
        for (std::size_t i = 0; i < 16; ++i) {
            if (i == 8) {
                out.push_back(' ');
            }
            if (off + i < len) {
                const std::uint8_t b = data[off + i];
                out.push_back(hex[b >> 4]);
                out.push_back(hex[b & 0x0F]);
            } else {
                out += "  ";
            }
            out.push_back(' ');
        }

        // ASCII gutter: printable bytes, '.' otherwise.
        out.push_back('|');
        for (std::size_t i = 0; i < 16 && off + i < len; ++i) {
            const std::uint8_t b = data[off + i];
            out.push_back((b >= 0x20 && b <= 0x7e) ? static_cast<char>(b) : '.');
        }
        out += "|\n";
    }
    return out;
}

} // namespace my
