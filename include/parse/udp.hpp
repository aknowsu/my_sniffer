#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "parse/cursor.hpp"

namespace sniffer {

struct UdpHeader {
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint16_t length;
    std::uint16_t checksum;
    bool          checksum_present;
    bool          checksum_ok;
    std::size_t   header_len;
    std::size_t   payload_len;
};

std::optional<UdpHeader> parse_udp(Cursor &cursor, std::uint32_t src_ip, std::uint32_t dst_ip);

}
