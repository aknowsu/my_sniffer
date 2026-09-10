#pragma once

#include <cstdint>
#include <optional>

#include "parse/cursor.hpp"

namespace sniffer {

namespace ethertype {
inline constexpr std::uint16_t kIpv4 = 0x0800;
inline constexpr std::uint16_t kArp  = 0x0806;
inline constexpr std::uint16_t kIpv6 = 0x86DD;
inline constexpr std::uint16_t kVlan = 0x8100;
}

struct EthernetHeader {
    std::uint8_t  dst[6];
    std::uint8_t  src[6];
    std::uint16_t ethertype;
    std::uint16_t vlan_id;
};

std::optional<EthernetHeader> parse_ethernet(Cursor &c);

}
