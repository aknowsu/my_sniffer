#include "my_func/address.hpp"

namespace my {

bool cidr_contains(std::uint32_t network, std::uint8_t prefix_len, std::uint32_t addr) {
    if (prefix_len == 0) return true;
    if (prefix_len >= 32) return addr == network;
    const std::uint32_t mask = ~std::uint32_t{0} << (32 - prefix_len);
    return (addr & mask) == (network & mask);
}

}
