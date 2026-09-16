#include "parse/ipv4.hpp"

#include "my_func/checksum.hpp"

namespace sniffer {
namespace {

constexpr std::uint8_t ipv4_version = 4;
constexpr std::uint8_t min_ihl = 5;
constexpr std::size_t bytes_per_word = 4;
constexpr std::uint16_t flag_df_mask = 0x4000;
constexpr std::uint16_t flag_mf_mask = 0x2000;
constexpr std::uint16_t frag_offset_mask = 0x1FFF;

}

std::optional<Ipv4Header> parse_ipv4(Cursor &c) {
    const std::uint8_t *start = c.ptr();

    Ipv4Header h{};
    const std::uint8_t version_ihl = c.u8();
    h.ihl = version_ihl & 0x0F;
    h.tos = c.u8();
    h.total_length = c.u16();
    h.identification = c.u16();

    const std::uint16_t flags_frag = c.u16();
    h.flag_df = (flags_frag & flag_df_mask) != 0;
    h.flag_mf = (flags_frag & flag_mf_mask) != 0;
    h.frag_offset = flags_frag & frag_offset_mask;

    h.ttl = c.u8();
    h.protocol = c.u8();
    h.checksum = c.u16();
    h.src = c.u32();
    h.dst = c.u32();

    if (!c.ok() || (version_ihl >> 4) != ipv4_version || h.ihl < min_ihl) {
        return std::nullopt;
    }

    h.header_len = static_cast<std::size_t>(h.ihl) * bytes_per_word;
    c.skip(h.header_len - min_ihl * bytes_per_word);
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
