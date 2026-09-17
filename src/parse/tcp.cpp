#include "parse/tcp.hpp"

#include "my_func/checksum.hpp"
#include "parse/ipv4.hpp"

namespace sniffer {
namespace {

constexpr std::uint8_t min_data_offset = 5;
constexpr std::size_t bytes_per_word = 4;
constexpr std::size_t pseudo_header_len = 12;

bool tcp_checksum_ok(std::uint32_t src_ip, std::uint32_t dst_ip,
                     const std::uint8_t *segment, std::size_t len) {
    std::uint8_t pseudo[pseudo_header_len];
    pseudo[0] = static_cast<std::uint8_t>(src_ip >> 24);
    pseudo[1] = static_cast<std::uint8_t>(src_ip >> 16);
    pseudo[2] = static_cast<std::uint8_t>(src_ip >> 8);
    pseudo[3] = static_cast<std::uint8_t>(src_ip);
    pseudo[4] = static_cast<std::uint8_t>(dst_ip >> 24);
    pseudo[5] = static_cast<std::uint8_t>(dst_ip >> 16);
    pseudo[6] = static_cast<std::uint8_t>(dst_ip >> 8);
    pseudo[7] = static_cast<std::uint8_t>(dst_ip);
    pseudo[8] = 0;
    pseudo[9] = ip_proto::Tcp;
    pseudo[10] = static_cast<std::uint8_t>(len >> 8);
    pseudo[11] = static_cast<std::uint8_t>(len);

    std::uint32_t sum = my::checksum_accumulate(pseudo, sizeof pseudo);
    sum = my::checksum_accumulate(segment, len, sum);
    return my::checksum_fold(sum) == 0;
}

}

std::optional<TcpHeader> parse_tcp(Cursor &c, std::uint32_t src_ip, std::uint32_t dst_ip,
                                   std::size_t segment_len) {
    const std::uint8_t *start = c.ptr();
    if (segment_len > c.remaining()) {
        segment_len = c.remaining();
    }

    TcpHeader h{};
    h.src_port = c.u16();
    h.dst_port = c.u16();
    h.seq = c.u32();
    h.ack = c.u32();

    const std::uint8_t offset_reserved_ns = c.u8();
    h.data_offset = offset_reserved_ns >> 4;

    const std::uint8_t flag_bits = c.u8();
    h.flags.ns = (offset_reserved_ns & 0x01) != 0;
    h.flags.cwr = (flag_bits & 0x80) != 0;
    h.flags.ece = (flag_bits & 0x40) != 0;
    h.flags.urg = (flag_bits & 0x20) != 0;
    h.flags.ack = (flag_bits & 0x10) != 0;
    h.flags.psh = (flag_bits & 0x08) != 0;
    h.flags.rst = (flag_bits & 0x04) != 0;
    h.flags.syn = (flag_bits & 0x02) != 0;
    h.flags.fin = (flag_bits & 0x01) != 0;

    h.window = c.u16();
    h.checksum = c.u16();
    h.urgent_pointer = c.u16();

    if (!c.ok() || h.data_offset < min_data_offset) {
        return std::nullopt;
    }

    h.header_len = static_cast<std::size_t>(h.data_offset) * bytes_per_word;
    if (segment_len < h.header_len) {
        return std::nullopt;
    }

    c.skip(h.header_len - min_data_offset * bytes_per_word);
    if (!c.ok()) {
        return std::nullopt;
    }

    h.checksum_ok = tcp_checksum_ok(src_ip, dst_ip, start, segment_len);
    h.payload_len = segment_len - h.header_len;

    return h;
}

}
