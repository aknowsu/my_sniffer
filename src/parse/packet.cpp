#include "parse/packet.hpp"

#include "parse/cursor.hpp"

namespace sniffer {

ParsedPacket parse_packet(const Frame &frame, LinkType link_type) {
    ParsedPacket packet;
    packet.ts_us = frame.ts_us;
    packet.frame_len = frame.len;

    Cursor cursor(frame.data, frame.len);
    std::uint16_t next_ethertype = ethertype::Ipv4;

    if (link_type == LinkType::Ethernet) {
        packet.eth = parse_ethernet(cursor);
        if (!packet.eth) {
            packet.truncated = true;
            return packet;
        }
        next_ethertype = packet.eth->ethertype;
    }

    if (next_ethertype == ethertype::Ipv4) {
        packet.ipv4 = parse_ipv4(cursor);
        if (!packet.ipv4) {
            packet.truncated = true;
            return packet;
        }

        if (packet.ipv4->protocol == ip_proto::Tcp) {
            packet.tcp = parse_tcp(cursor, packet.ipv4->src, packet.ipv4->dst, packet.ipv4->payload_len);
            if (!packet.tcp) {
                packet.truncated = true;
                return packet;
            }
        } else if (packet.ipv4->protocol == ip_proto::Udp) {
            packet.udp = parse_udp(cursor, packet.ipv4->src, packet.ipv4->dst);
            if (!packet.udp) {
                packet.truncated = true;
                return packet;
            }
        }
    }

    packet.payload = cursor.ptr();
    packet.payload_len = cursor.remaining();
    return packet;
}

}
