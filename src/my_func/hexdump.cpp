#include "my_func/hexdump.hpp"

#include <cstdio>

namespace my {
namespace {

constexpr std::size_t bytes_per_row  = 16;
constexpr std::size_t group_size    = 8;
constexpr std::size_t line_buf_size  = 24;

}

std::string hexdump(const std::uint8_t *data, std::size_t len, std::size_t base) {
    std::string out;
    char buf[line_buf_size];

    const std::size_t rows = (len + bytes_per_row - 1) / bytes_per_row * bytes_per_row;
    for (std::size_t i = 0; i < rows; ++i) {
        const std::size_t col = i % bytes_per_row;

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
        if (col == group_size - 1) {
            out += ' ';
        }
        if (col == bytes_per_row - 1) {
            while (!out.empty() && out.back() == ' ') {
                out.pop_back();
            }
            out += '\n';
        }
    }
    return out;
}

}
