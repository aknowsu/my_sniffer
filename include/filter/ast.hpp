#pragma once

#include <cstdint>
#include <memory>

#include "parse/tcp.hpp"

namespace sniffer::filter {

enum class NodeKind {
    And, Or, Not,
    Tcp, Udp, Icmp, Arp, Ip,
    Port, SrcPort, DstPort,
    Host, SrcHost, DstHost,
    Net, SrcNet, DstNet,
    Len,
    TcpFlag,
};

enum class Compare { Eq, Lt, Gt };

struct Node;
using NodePtr = std::unique_ptr<Node>;

struct Node {
    NodeKind kind;
    NodePtr left;
    NodePtr right;
    std::uint32_t port = 0;
    std::uint32_t addr = 0;
    std::uint32_t mask = 0;
    std::uint32_t len_value = 0;
    Compare cmp = Compare::Eq;
    bool TcpFlags::*flag_member = nullptr;
};

}
