#include "parse/ethernet.hpp"

namespace sniffer {

std::optional<EthernetHeader> parse_ethernet(Cursor &c) {
    EthernetHeader h{};

    c.copy(h.dst, 6);
    c.copy(h.src, 6);
    h.ethertype = c.u16();

    if (h.ethertype == ethertype::kVlan) {
        const std::uint16_t tci = c.u16();   // priority (3b) + DEI (1b) + VLAN id (12b)
        h.vlan_id   = tci & 0x0FFF;
        h.ethertype = c.u16();               // the real ethertype, after the tag
    }

    if (!c.ok()) {
        return std::nullopt;
    }
    return h;
}

const char *ethertype_name(std::uint16_t et) {
    switch (et) {
        case ethertype::kIpv4: return "IPv4";
        case ethertype::kArp:  return "ARP";
        case ethertype::kIpv6: return "IPv6";
        case ethertype::kVlan: return "VLAN";
        default:               return "unknown";
    }
}

} // namespace sniffer
