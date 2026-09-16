#include "my_func/address.hpp"

namespace my {
namespace {

constexpr std::size_t mac_len   = 6;
constexpr std::size_t group_len = 3;
constexpr std::size_t text_len  = mac_len * group_len - 1;

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}

bool mac_from_text(std::string_view text, std::uint8_t out[6]) {
    if (text.size() != text_len) {
        return false;
    }

    std::uint8_t tmp[mac_len];
    for (std::size_t i = 0; i < mac_len; ++i) {
        const std::size_t p = i * group_len;
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

    for (std::size_t i = 0; i < mac_len; ++i) {
        out[i] = tmp[i];
    }
    return true;
}

}
