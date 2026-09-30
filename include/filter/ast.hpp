#pragma once

#include <cstdint>

namespace sniffer::filter {

enum class TestKind { Tcp, Udp, Icmp, Arp, Ip, Port, Host, Net, Len, TcpFlag };
enum class Op { And, Or, Not };
enum class Compare { Eq, Lt, Gt };
enum class Direction { Any, Src, Dst };
enum class TcpFlagName { Syn, Ack, Fin, Rst, Psh, Urg, Ece, Cwr, Ns };
enum class ItemKind { Test, Operator };

struct Item {
    ItemKind item;
    TestKind test = TestKind::Tcp;
    Op op = Op::And;
    Direction direction = Direction::Any;
    std::uint32_t port = 0;
    std::uint32_t addr = 0;
    std::uint32_t mask = 0;
    std::uint32_t len_value = 0;
    Compare cmp = Compare::Eq;
    TcpFlagName flag = TcpFlagName::Syn;
};

}
