#include "parse/ethernet.hpp"

namespace sniffer {

std::optional<EthernetHeader> parse_ethernet(Cursor &c) {
    EthernetHeader h{};

    c.copy(h.dst, 6);
    c.copy(h.src, 6);
    h.ethertype = c.u16();

    if (h.ethertype == ethertype::kVlan) {
        h.vlan_id   = c.u16() & 0x0FFF;
        h.ethertype = c.u16();
    }

    if (!c.ok()) {
        return std::nullopt;
    }
    return h;
}

}
