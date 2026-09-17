#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "capture.hpp"
#include "parse/ethernet.hpp"
#include "parse/ipv4.hpp"
#include "parse/tcp.hpp"
#include "parse/udp.hpp"

namespace sniffer {

struct ParsedPacket {
    std::int64_t ts_us = 0;
    std::size_t frame_len = 0;

    std::optional<EthernetHeader> eth;
    std::optional<Ipv4Header> ipv4;
    std::optional<TcpHeader> tcp;
    std::optional<UdpHeader> udp;

    const std::uint8_t *payload = nullptr;
    std::size_t payload_len = 0;

    bool truncated = false;
};

ParsedPacket parse_packet(const Frame &frame, LinkType link_type);

}
