#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "parse/cursor.hpp"

namespace sniffer {

namespace ip_proto {
inline constexpr std::uint8_t Icmp = 1;
inline constexpr std::uint8_t Tcp = 6;
inline constexpr std::uint8_t Udp = 17;
inline constexpr std::uint8_t Icmpv6 = 58;
}

struct Ipv4Header {
    std::uint8_t ihl;
    std::uint8_t tos;
    std::uint16_t total_length;
    std::uint16_t identification;
    bool flag_df;
    bool flag_mf;
    std::uint16_t frag_offset;
    std::uint8_t ttl;
    std::uint8_t protocol;
    std::uint16_t checksum;
    bool checksum_ok;
    std::uint32_t src;
    std::uint32_t dst;
    std::size_t header_len;
    std::size_t payload_len;
};

std::optional<Ipv4Header> parse_ipv4(Cursor &cursor);

}
