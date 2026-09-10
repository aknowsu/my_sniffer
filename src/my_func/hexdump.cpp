#include "my_func/hexdump.hpp"

#include <cstdio>

namespace my {

std::string hexdump(const std::uint8_t *data, std::size_t len, std::size_t base) {
    std::string out;
    std::string ascii;
    char        buf[24];

    for (std::size_t i = 0; i < (len + 15) / 16 * 16; ++i) {
        if (i % 16 == 0) {
            std::snprintf(buf, sizeof buf, "%08zx  ", base + i);
            out += buf;
            ascii.clear();
        }
        if (i < len) {
            std::snprintf(buf, sizeof buf, "%02x ", data[i]);
            out += buf;
            ascii += (data[i] >= 0x20 && data[i] <= 0x7e) ? static_cast<char>(data[i]) : '.';
        } else {
            out += "   ";
        }
        if (i % 16 == 7) {
            out += ' ';
        }
        if (i % 16 == 15) {
            out += "|" + ascii + "|\n";
        }
    }
    return out;
}

}
