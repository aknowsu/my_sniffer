#include "my_func/hexdump.hpp"

#include <cstdio>

namespace my {
namespace {

constexpr std::size_t kBytesPerRow  = 16;
constexpr std::size_t kGroupSize    = 8;
constexpr std::size_t kLineBufSize  = 24;

}

std::string hexdump(const std::uint8_t *data, std::size_t len, std::size_t base) {
    std::string out;
    char        buf[kLineBufSize];

    const std::size_t rows = (len + kBytesPerRow - 1) / kBytesPerRow * kBytesPerRow;
    for (std::size_t i = 0; i < rows; ++i) {
        const std::size_t col = i % kBytesPerRow;

        if (col == 0) {
            std::snprintf(buf, sizeof buf, "%08zx  ", base + i);
            out += buf;
        }
        if (i < len) {
            std::snprintf(buf, sizeof buf, "%02x ", data[i]);
            out += buf;
        } else {
            out += "   ";
        }
        if (col == kGroupSize - 1) {
            out += ' ';
        }
        if (col == kBytesPerRow - 1) {
            while (!out.empty() && out.back() == ' ') {
                out.pop_back();
            }
            out += '\n';
        }
    }
    return out;
}

}
