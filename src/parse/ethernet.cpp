#include "parse/ethernet.hpp"

namespace sniffer {
namespace {

constexpr std::size_t mac_len = 6;
constexpr std::uint16_t vlan_id_mask = 0x0FFF;

}

std::optional<EthernetHeader> parse_ethernet(Cursor &cursor) {
    EthernetHeader header{};

    cursor.copy(header.dst, mac_len);
    cursor.copy(header.src, mac_len);
    header.ethertype = cursor.u16();

    if (header.ethertype == ethertype::Vlan) {
        header.vlan_id = cursor.u16() & vlan_id_mask;
        header.ethertype = cursor.u16();
    }

    if (!cursor.ok()) {
        return std::nullopt;
    }
    return header;
}

}
