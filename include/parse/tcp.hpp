#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "parse/cursor.hpp"

namespace sniffer {

struct TcpFlags {
    bool ns;
    bool cwr;
    bool ece;
    bool urg;
    bool ack;
    bool psh;
    bool rst;
    bool syn;
    bool fin;
};

struct TcpHeader {
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint32_t seq;
    std::uint32_t ack;
    std::uint8_t data_offset;
    TcpFlags flags;
    std::uint16_t window;
    std::uint16_t checksum;
    bool checksum_ok;
    std::uint16_t urgent_pointer;
    std::size_t header_len;
    std::size_t payload_len;
};

// `segment_len` is the TCP segment length (header + data) as declared by the
// IPv4 layer (Ipv4Header::payload_len) — TCP has no length field of its own,
// so this is the only accurate way to know where the segment ends and
// trailing Ethernet padding begins. Needed for the checksum's pseudo-header.
std::optional<TcpHeader> parse_tcp(Cursor &cursor, std::uint32_t src_ip, std::uint32_t dst_ip,
                                   std::size_t segment_len);

}
