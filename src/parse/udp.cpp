#include "parse/udp.hpp"

#include "my_func/checksum.hpp"
#include "parse/ipv4.hpp"

namespace sniffer {
namespace {

constexpr std::size_t fixed_header_len = 8;
constexpr std::size_t pseudo_header_len = 12;

bool udp_checksum_ok(std::uint32_t src_ip, std::uint32_t dst_ip,
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
    pseudo[9] = ip_proto::Udp;
    pseudo[10] = static_cast<std::uint8_t>(len >> 8);
    pseudo[11] = static_cast<std::uint8_t>(len);

    std::uint32_t sum = my::checksum_accumulate(pseudo, sizeof pseudo);
    sum = my::checksum_accumulate(segment, len, sum);
    return my::checksum_fold(sum) == 0;
}

}

std::optional<UdpHeader> parse_udp(Cursor &cursor, std::uint32_t src_ip, std::uint32_t dst_ip) {
    const std::uint8_t *start = cursor.ptr();

    UdpHeader header{};
    header.src_port = cursor.u16();
    header.dst_port = cursor.u16();
    header.length = cursor.u16();
    header.checksum = cursor.u16();

    if (!cursor.ok() || header.length < fixed_header_len) {
        return std::nullopt;
    }

    header.header_len = fixed_header_len;

    const std::size_t available = fixed_header_len + cursor.remaining();
    header.checksum_present = header.checksum != 0;
    header.checksum_ok = header.checksum_present && header.length <= available &&
                    udp_checksum_ok(src_ip, dst_ip, start, header.length);

    const std::size_t declared = header.length - fixed_header_len;
    header.payload_len = declared < cursor.remaining() ? declared : cursor.remaining();

    return header;
}

}
