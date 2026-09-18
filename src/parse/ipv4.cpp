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

std::optional<Ipv4Header> parse_ipv4(Cursor &cursor) {
    const std::uint8_t *start = cursor.ptr();

    Ipv4Header header{};
    const std::uint8_t version_ihl = cursor.u8();
    header.ihl = version_ihl & 0x0F;
    header.tos = cursor.u8();
    header.total_length = cursor.u16();
    header.identification = cursor.u16();

    const std::uint16_t flags_frag = cursor.u16();
    header.flag_df = (flags_frag & flag_df_mask) != 0;
    header.flag_mf = (flags_frag & flag_mf_mask) != 0;
    header.frag_offset = flags_frag & frag_offset_mask;

    header.ttl = cursor.u8();
    header.protocol = cursor.u8();
    header.checksum = cursor.u16();
    header.src = cursor.u32();
    header.dst = cursor.u32();

    if (!cursor.ok() || (version_ihl >> 4) != ipv4_version || header.ihl < min_ihl) {
        return std::nullopt;
    }

    header.header_len = static_cast<std::size_t>(header.ihl) * bytes_per_word;
    cursor.skip(header.header_len - min_ihl * bytes_per_word);
    if (!cursor.ok()) {
        return std::nullopt;
    }

    header.checksum_ok = my::checksum16(start, header.header_len) == 0;

    const std::size_t declared =
        header.total_length >= header.header_len ? header.total_length - header.header_len : 0;
    header.payload_len = declared < cursor.remaining() ? declared : cursor.remaining();

    return header;
}

}
