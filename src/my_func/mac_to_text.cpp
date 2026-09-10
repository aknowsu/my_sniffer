#include "my_func/address.hpp"

namespace my {

std::string mac_to_text(const std::uint8_t mac[6]) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 6; ++i) {
        if (i != 0) {
            out.push_back(':');
        }
        out.push_back(hex[mac[i] >> 4]);
        out.push_back(hex[mac[i] & 0x0F]);
    }
    return out;
}

}
