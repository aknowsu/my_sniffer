#include "parse/ipv4.hpp"

#include "my_func/checksum.hpp"

namespace sniffer {

std::optional<Ipv4Header> parse_ipv4(Cursor &c) {
    const std::uint8_t *start = c.ptr();

    Ipv4Header h{};
    const std::uint8_t version_ihl = c.u8();
    h.ihl = version_ihl & 0x0F;
    h.tos = c.u8();
    h.total_length   = c.u16();
    h.identification = c.u16();

    const std::uint16_t flags_frag = c.u16();
    h.flag_df     = (flags_frag & 0x4000) != 0;
    h.flag_mf     = (flags_frag & 0x2000) != 0;
    h.frag_offset = flags_frag & 0x1FFF;

    h.ttl      = c.u8();
    h.protocol = c.u8();
    h.checksum = c.u16();
    h.src = c.u32();
    h.dst = c.u32();

    if (!c.ok() || (version_ihl >> 4) != 4 || h.ihl < 5) {
        return std::nullopt;
    }

    h.header_len = static_cast<std::size_t>(h.ihl) * 4;
    c.skip(h.header_len - 20);
    if (!c.ok()) {
        return std::nullopt;
    }

    h.checksum_ok = my::checksum16(start, h.header_len) == 0;

    const std::size_t declared =
        h.total_length >= h.header_len ? h.total_length - h.header_len : 0;
    h.payload_len = declared < c.remaining() ? declared : c.remaining();

    return h;
}

}
