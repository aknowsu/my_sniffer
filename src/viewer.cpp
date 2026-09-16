#include "viewer.hpp"

#include "my_func/address.hpp"
#include "my_func/hexdump.hpp"

#include <string>

namespace sniffer {
namespace {

const char *ethertype_name(std::uint16_t et) {
    switch (et) {
        case ethertype::Ipv4: return "IPv4";
        case ethertype::Arp:  return "ARP";
        case ethertype::Vlan: return "VLAN";
        default:              return "unknown";
    }
}

const char *ip_protocol_name(std::uint8_t proto) {
    switch (proto) {
        case ip_proto::Icmp:   return "ICMP";
        case ip_proto::Tcp:    return "TCP";
        case ip_proto::Udp:    return "UDP";
        case ip_proto::Icmpv6: return "ICMPv6";
        default:               return "unknown";
    }
}

std::string tcp_flags_text(const TcpFlags &f) {
    std::string s;
    auto add = [&](bool set, const char *name) {
        if (!set) return;
        if (!s.empty()) s += ',';
        s += name;
    };
    add(f.syn, "SYN");
    add(f.ack, "ACK");
    add(f.fin, "FIN");
    add(f.rst, "RST");
    add(f.psh, "PSH");
    add(f.urg, "URG");
    add(f.ece, "ECE");
    add(f.cwr, "CWR");
    add(f.ns, "NS");
    return s.empty() ? "-" : s;
}

std::string hex_u8(std::uint8_t v) {
    char buf[8];
    std::snprintf(buf, sizeof buf, "0x%02x", v);
    return buf;
}

std::string hex_u16(std::uint16_t v) {
    char buf[8];
    std::snprintf(buf, sizeof buf, "0x%04x", v);
    return buf;
}

void field(std::FILE *out, const char *name, const std::string &value) {
    std::fprintf(out, "    %-19s %s\n", name, value.c_str());
}

void print_ethernet_fields(std::FILE *out, const EthernetHeader &eth) {
    field(out, "ethernet.dst", my::mac_to_text(eth.dst));
    field(out, "ethernet.src", my::mac_to_text(eth.src));
    field(out, "ethernet.ethertype",
         hex_u16(eth.ethertype) + " (" + ethertype_name(eth.ethertype) + ")");
    if (eth.vlan_id != 0) {
        field(out, "ethernet.vlan_id", std::to_string(eth.vlan_id));
    }
}

void print_ipv4_fields(std::FILE *out, const Ipv4Header &ip) {
    field(out, "ipv4.version", "4");
    field(out, "ipv4.ihl", std::to_string(ip.ihl));
    field(out, "ipv4.header_len", std::to_string(ip.header_len) + " bytes");
    field(out, "ipv4.tos", hex_u8(ip.tos));
    field(out, "ipv4.total_length", std::to_string(ip.total_length));
    field(out, "ipv4.identification", hex_u16(ip.identification));

    std::string flags;
    if (ip.flag_df) flags += "DF ";
    if (ip.flag_mf) flags += "MF";
    if (!flags.empty() && flags.back() == ' ') flags.pop_back();
    field(out, "ipv4.flags", flags.empty() ? "-" : flags);

    field(out, "ipv4.frag_offset", std::to_string(ip.frag_offset));
    field(out, "ipv4.ttl", std::to_string(ip.ttl));
    field(out, "ipv4.protocol",
         std::to_string(ip.protocol) + " (" + ip_protocol_name(ip.protocol) + ")");
    field(out, "ipv4.checksum", hex_u16(ip.checksum) + (ip.checksum_ok ? " (valid)" : " (invalid)"));
    field(out, "ipv4.src", my::ipv4_to_text(ip.src));
    field(out, "ipv4.dst", my::ipv4_to_text(ip.dst));
}

void print_tcp_fields(std::FILE *out, const TcpHeader &tcp) {
    field(out, "tcp.src_port", std::to_string(tcp.src_port));
    field(out, "tcp.dst_port", std::to_string(tcp.dst_port));
    field(out, "tcp.seq", std::to_string(tcp.seq));
    field(out, "tcp.ack", std::to_string(tcp.ack));
    field(out, "tcp.data_offset",
         std::to_string(tcp.data_offset) + " (" + std::to_string(tcp.header_len) + " bytes)");
    field(out, "tcp.flags", tcp_flags_text(tcp.flags));
    field(out, "tcp.window", std::to_string(tcp.window));
    field(out, "tcp.checksum", hex_u16(tcp.checksum) + (tcp.checksum_ok ? " (valid)" : " (invalid)"));
    field(out, "tcp.urgent_pointer", std::to_string(tcp.urgent_pointer));
}

}

void print_packet(std::FILE *out, const Frame &frame, const ParsedPacket &pkt,
                  const ViewOptions &opts) {
    const char *suffix = pkt.truncated ? "  [truncated]" : "";

    if (pkt.tcp) {
        std::fprintf(out, "%s:%u > %s:%u  TCP [%s]  ttl=%u  %zu bytes%s\n",
                     my::ipv4_to_text(pkt.ipv4->src).c_str(), pkt.tcp->src_port,
                     my::ipv4_to_text(pkt.ipv4->dst).c_str(), pkt.tcp->dst_port,
                     tcp_flags_text(pkt.tcp->flags).c_str(),
                     pkt.ipv4->ttl, frame.len, suffix);
    } else if (pkt.ipv4) {
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
        if (pkt.eth) {
            print_ethernet_fields(out, *pkt.eth);
        }
        if (pkt.ipv4) {
            print_ipv4_fields(out, *pkt.ipv4);
        }
        if (pkt.tcp) {
            print_tcp_fields(out, *pkt.tcp);
        }
        std::fputs(my::hexdump(frame.data, frame.len).c_str(), out);
        std::fputc('\n', out);
    }
}

}
