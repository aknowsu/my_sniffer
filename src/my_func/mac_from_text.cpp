#include "my_func/address.hpp"

namespace my {
namespace {

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}

bool mac_from_text(std::string_view text, std::uint8_t out[6]) {
    if (text.size() != 17) {
        return false;
    }

    std::uint8_t tmp[6];
    for (int i = 0; i < 6; ++i) {
        const std::size_t p = static_cast<std::size_t>(i) * 3;
        if (i != 0 && text[p - 1] != ':') {
            return false;
        }
        const int hi = hex_digit(text[p]);
        const int lo = hex_digit(text[p + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        tmp[i] = static_cast<std::uint8_t>(hi * 16 + lo);
    }

    for (int i = 0; i < 6; ++i) {
        out[i] = tmp[i];
    }
    return true;
}

}
