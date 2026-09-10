#pragma once

#include <cstdint>
#include <optional>

#include "parse/cursor.hpp"

namespace sniffer {

namespace ethertype {
inline constexpr std::uint16_t kIpv4 = 0x0800;
inline constexpr std::uint16_t kArp  = 0x0806;
inline constexpr std::uint16_t kIpv6 = 0x86DD;
inline constexpr std::uint16_t kVlan = 0x8100;   // 802.1Q tag
}  // namespace ethertype

struct EthernetHeader {
    std::uint8_t  dst[6];
    std::uint8_t  src[6];
    std::uint16_t ethertype;   // inner type if a VLAN tag was present
    std::uint16_t vlan_id;     // 0 when the frame is untagged
};

// Consume the Ethernet II header (14 bytes, or 18 with one 802.1Q tag) from
// `c`, leaving it at the payload. std::nullopt if the frame is too short.
std::optional<EthernetHeader> parse_ethernet(Cursor &c);

// "IPv4" / "ARP" / "IPv6" / "VLAN" / "unknown" — never null.
const char *ethertype_name(std::uint16_t ethertype);

} // namespace sniffer
