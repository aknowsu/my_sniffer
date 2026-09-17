#include "parse/packet.hpp"

#include "parse/cursor.hpp"

namespace sniffer {

ParsedPacket parse_packet(const Frame &frame, LinkType link_type) {
    ParsedPacket p;
    p.ts_us = frame.ts_us;
    p.frame_len = frame.len;

    Cursor c(frame.data, frame.len);
    std::uint16_t ethertype = ethertype::Ipv4;

    if (link_type == LinkType::Ethernet) {
        p.eth = parse_ethernet(c);
        if (!p.eth) {
            p.truncated = true;
            return p;
        }
        ethertype = p.eth->ethertype;
    }

    if (ethertype == ethertype::Ipv4) {
        p.ipv4 = parse_ipv4(c);
        if (!p.ipv4) {
            p.truncated = true;
            return p;
        }

        if (p.ipv4->protocol == ip_proto::Tcp) {
            p.tcp = parse_tcp(c, p.ipv4->src, p.ipv4->dst, p.ipv4->payload_len);
            if (!p.tcp) {
                p.truncated = true;
                return p;
            }
        } else if (p.ipv4->protocol == ip_proto::Udp) {
            p.udp = parse_udp(c, p.ipv4->src, p.ipv4->dst);
            if (!p.udp) {
                p.truncated = true;
                return p;
            }
        }
    }

    p.payload = c.ptr();
    p.payload_len = c.remaining();
    return p;
}

}
