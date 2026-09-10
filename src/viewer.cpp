#include "viewer.hpp"

#include "my_func/address.hpp"
#include "my_func/hexdump.hpp"

namespace sniffer {
namespace {

const char *ethertype_name(std::uint16_t et) {
    switch (et) {
        case ethertype::kIpv4: return "IPv4";
        case ethertype::kArp:  return "ARP";
        case ethertype::kIpv6: return "IPv6";
        case ethertype::kVlan: return "VLAN";
        default:               return "unknown";
    }
}

const char *ip_protocol_name(std::uint8_t proto) {
    switch (proto) {
        case ip_proto::kIcmp:   return "ICMP";
        case ip_proto::kTcp:    return "TCP";
        case ip_proto::kUdp:    return "UDP";
        case ip_proto::kIcmpv6: return "ICMPv6";
        default:                return "unknown";
    }
}

}

void print_packet(std::FILE *out, const Frame &frame, const ParsedPacket &pkt,
                  const ViewOptions &opts) {
    const char *suffix = pkt.truncated ? "  [truncated]" : "";

    if (pkt.ipv4) {
        std::fprintf(out, "%s > %s  %s  ttl=%u  %zu bytes%s\n",
                     my::ipv4_to_text(pkt.ipv4->src).c_str(),
                     my::ipv4_to_text(pkt.ipv4->dst).c_str(),
                     ip_protocol_name(pkt.ipv4->protocol),
                     pkt.ipv4->ttl, frame.len, suffix);
    } else if (pkt.eth) {
        std::fprintf(out, "%s > %s  %s (0x%04x)  %zu bytes%s\n",
                     my::mac_to_text(pkt.eth->src).c_str(),
                     my::mac_to_text(pkt.eth->dst).c_str(),
                     ethertype_name(pkt.eth->ethertype), pkt.eth->ethertype,
                     frame.len, suffix);
    } else {
        std::fprintf(out, "unparsed  %zu bytes\n", frame.len);
    }

    if (opts.verbose) {
        std::fputs(my::hexdump(frame.data, frame.len).c_str(), out);
    }
}

}
