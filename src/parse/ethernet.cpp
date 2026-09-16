#include "parse/ethernet.hpp"

namespace sniffer {
namespace {

constexpr std::size_t   mac_len      = 6;
constexpr std::uint16_t vlan_id_mask = 0x0FFF;

}

std::optional<EthernetHeader> parse_ethernet(Cursor &c) {
    EthernetHeader h{};

    c.copy(h.dst, mac_len);
    c.copy(h.src, mac_len);
    h.ethertype = c.u16();

    if (h.ethertype == ethertype::Vlan) {
        h.vlan_id   = c.u16() & vlan_id_mask;
        h.ethertype = c.u16();
    }

    if (!c.ok()) {
        return std::nullopt;
    }
    return h;
}

}
