#include "filter/filter.hpp"

namespace sniffer::filter {
namespace {

bool side_matches(Direction direction, bool src_matches, bool dst_matches) {
    return (direction != Direction::Dst && src_matches) ||
           (direction != Direction::Src && dst_matches);
}

bool compare_len(std::size_t len, Compare cmp, std::uint32_t value) {
    switch (cmp) {
        case Compare::Eq: return len == value;
        case Compare::Lt: return len < value;
        case Compare::Gt: return len > value;
    }
    return false;
}

bool flag_set(const TcpFlags &flags, TcpFlagName name) {
    switch (name) {
        case TcpFlagName::Syn: return flags.syn;
        case TcpFlagName::Ack: return flags.ack;
        case TcpFlagName::Fin: return flags.fin;
        case TcpFlagName::Rst: return flags.rst;
        case TcpFlagName::Psh: return flags.psh;
        case TcpFlagName::Urg: return flags.urg;
        case TcpFlagName::Ece: return flags.ece;
        case TcpFlagName::Cwr: return flags.cwr;
        case TcpFlagName::Ns: return flags.ns;
    }
    return false;
}

bool test_matches(const Item &item, const Frame &frame, const ParsedPacket &packet) {
    switch (item.test) {
        case TestKind::Tcp: return packet.tcp.has_value();
        case TestKind::Udp: return packet.udp.has_value();
        case TestKind::Icmp: return packet.ipv4 && packet.ipv4->protocol == ip_proto::Icmp;
        case TestKind::Arp: return packet.eth && packet.eth->ethertype == ethertype::Arp;
        case TestKind::Ip: return packet.ipv4.has_value();
        case TestKind::Port:
            return (packet.tcp && side_matches(item.direction, packet.tcp->src_port == item.port,
                                               packet.tcp->dst_port == item.port)) ||
                   (packet.udp && side_matches(item.direction, packet.udp->src_port == item.port,
                                               packet.udp->dst_port == item.port));
        case TestKind::Host:
            return packet.ipv4 && side_matches(item.direction, packet.ipv4->src == item.addr,
                                               packet.ipv4->dst == item.addr);
        case TestKind::Net:
            return packet.ipv4 &&
                   side_matches(item.direction, (packet.ipv4->src & item.mask) == (item.addr & item.mask),
                                (packet.ipv4->dst & item.mask) == (item.addr & item.mask));
        case TestKind::Len: return compare_len(frame.len, item.cmp, item.len_value);
        case TestKind::TcpFlag: return packet.tcp && flag_set(packet.tcp->flags, item.flag);
    }
    return false;
}

}

bool Filter::matches(const Frame &frame, const ParsedPacket &packet) const {
    std::vector<bool> stack;
    for (const Item &item : postfix_) {
        if (item.item == ItemKind::Test) {
            stack.push_back(test_matches(item, frame, packet));
            continue;
        }
        if (item.op == Op::Not) {
            stack.back() = !stack.back();
            continue;
        }
        const bool right = stack.back();
        stack.pop_back();
        const bool left = stack.back();
        stack.pop_back();
        stack.push_back(item.op == Op::And ? (left && right) : (left || right));
    }
    return stack.back();
}

}
