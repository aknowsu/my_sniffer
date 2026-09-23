#include "filter/filter.hpp"

#include "filter/token.hpp"

#include <stdexcept>
#include <utility>

namespace sniffer::filter {
namespace {

struct SimplePredicate {
    std::string_view name;
    NodeKind kind;
};

constexpr SimplePredicate simple_predicates[] = {
    {"tcp", NodeKind::Tcp},
    {"udp", NodeKind::Udp},
    {"icmp", NodeKind::Icmp},
    {"arp", NodeKind::Arp},
    {"ip", NodeKind::Ip},
};

struct FlagEntry {
    std::string_view name;
    bool TcpFlags::*member;
};

constexpr FlagEntry flag_table[] = {
    {"syn", &TcpFlags::syn},
    {"ack", &TcpFlags::ack},
    {"fin", &TcpFlags::fin},
    {"rst", &TcpFlags::rst},
    {"psh", &TcpFlags::psh},
    {"urg", &TcpFlags::urg},
    {"ece", &TcpFlags::ece},
    {"cwr", &TcpFlags::cwr},
    {"ns", &TcpFlags::ns},
};

class Parser {
public:
    explicit Parser(std::vector<Token> tokens) : tokens_(std::move(tokens)) {}

    NodePtr parse() {
        NodePtr node = parse_or();
        expect(TokenKind::End, "end of expression");
        return node;
    }

private:
    const Token &peek() const { return tokens_[pos_]; }

    Token advance() { return tokens_[pos_++]; }

    bool at_identifier(std::string_view word) const {
        return peek().kind == TokenKind::Identifier && peek().text == word;
    }

    [[noreturn]] void fail(const std::string &message) const {
        throw std::runtime_error(message + " at position " + std::to_string(peek().position));
    }

    Token expect(TokenKind kind, const char *what) {
        if (peek().kind != kind) {
            fail(std::string("expected ") + what);
        }
        return advance();
    }

    void expect_word(std::string_view word) {
        if (!at_identifier(word)) {
            fail("expected '" + std::string(word) + "'");
        }
        advance();
    }

    static NodePtr leaf(NodeKind kind) {
        NodePtr node = std::make_unique<Node>();
        node->kind = kind;
        return node;
    }

    NodePtr parse_or() {
        NodePtr node = parse_and();
        while (at_identifier("or")) {
            advance();
            NodePtr result = leaf(NodeKind::Or);
            result->left = std::move(node);
            result->right = parse_and();
            node = std::move(result);
        }
        return node;
    }

    NodePtr parse_and() {
        NodePtr node = parse_not();
        while (at_identifier("and")) {
            advance();
            NodePtr result = leaf(NodeKind::And);
            result->left = std::move(node);
            result->right = parse_not();
            node = std::move(result);
        }
        return node;
    }

    NodePtr parse_not() {
        if (at_identifier("not")) {
            advance();
            NodePtr result = leaf(NodeKind::Not);
            result->left = parse_not();
            return result;
        }
        return parse_atom();
    }

    NodePtr parse_atom() {
        if (peek().kind == TokenKind::LParen) {
            advance();
            NodePtr node = parse_or();
            expect(TokenKind::RParen, "')'");
            return node;
        }
        return parse_predicate();
    }

    Compare parse_compare() {
        if (peek().kind == TokenKind::Gt) { advance(); return Compare::Gt; }
        if (peek().kind == TokenKind::Lt) { advance(); return Compare::Lt; }
        if (peek().kind == TokenKind::Eq) { advance(); return Compare::Eq; }
        fail("expected '>', '<' or '=='");
    }

    bool TcpFlags::*parse_flag_name() {
        const Token token = expect(TokenKind::Identifier, "a TCP flag name");
        for (const FlagEntry &entry : flag_table) {
            if (token.text == entry.name) {
                return entry.member;
            }
        }
        throw std::runtime_error("unknown TCP flag '" + token.text + "' at position " +
                                 std::to_string(token.position));
    }

    static std::uint32_t prefix_to_mask(std::uint8_t prefix_len) {
        if (prefix_len == 0) return 0;
        if (prefix_len >= 32) return 0xFFFFFFFFu;
        return ~std::uint32_t{0} << (32 - prefix_len);
    }

    NodePtr parse_predicate() {
        if (peek().kind != TokenKind::Identifier) {
            fail("expected a predicate");
        }
        const Token word = advance();

        if (word.text == "tcp.flags") {
            expect_word("has");
            NodePtr node = leaf(NodeKind::TcpFlag);
            node->flag_member = parse_flag_name();
            return node;
        }
        for (const SimplePredicate &entry : simple_predicates) {
            if (word.text == entry.name) {
                return leaf(entry.kind);
            }
        }

        if (word.text == "src" || word.text == "dst") {
            const bool is_src = word.text == "src";
            if (at_identifier("port")) {
                advance();
                const Token number = expect(TokenKind::Number, "a port number");
                NodePtr node = leaf(is_src ? NodeKind::SrcPort : NodeKind::DstPort);
                node->port = static_cast<std::uint32_t>(number.number);
                return node;
            }
            if (at_identifier("host")) {
                advance();
                const Token addr = expect(TokenKind::Ipv4, "an IPv4 address");
                NodePtr node = leaf(is_src ? NodeKind::SrcHost : NodeKind::DstHost);
                node->addr = addr.addr;
                return node;
            }
            if (at_identifier("net")) {
                advance();
                const Token cidr = expect(TokenKind::Cidr, "a CIDR network");
                NodePtr node = leaf(is_src ? NodeKind::SrcNet : NodeKind::DstNet);
                node->addr = cidr.addr;
                node->mask = prefix_to_mask(cidr.prefix_len);
                return node;
            }
            fail("expected 'port', 'host' or 'net' after '" + word.text + "'");
        }

        if (word.text == "port") {
            const Token number = expect(TokenKind::Number, "a port number");
            NodePtr node = leaf(NodeKind::Port);
            node->port = static_cast<std::uint32_t>(number.number);
            return node;
        }
        if (word.text == "host") {
            const Token addr = expect(TokenKind::Ipv4, "an IPv4 address");
            NodePtr node = leaf(NodeKind::Host);
            node->addr = addr.addr;
            return node;
        }
        if (word.text == "net") {
            const Token cidr = expect(TokenKind::Cidr, "a CIDR network");
            NodePtr node = leaf(NodeKind::Net);
            node->addr = cidr.addr;
            node->mask = prefix_to_mask(cidr.prefix_len);
            return node;
        }
        if (word.text == "len") {
            NodePtr node = leaf(NodeKind::Len);
            node->cmp = parse_compare();
            const Token number = expect(TokenKind::Number, "a length");
            node->len_value = static_cast<std::uint32_t>(number.number);
            return node;
        }

        throw std::runtime_error("unknown predicate '" + word.text + "' at position " +
                                 std::to_string(word.position));
    }

    std::vector<Token> tokens_;
    std::size_t pos_ = 0;
};

bool port_matches(const ParsedPacket &packet, std::uint32_t port, bool check_src, bool check_dst) {
    if (packet.tcp) {
        if (check_src && packet.tcp->src_port == port) return true;
        if (check_dst && packet.tcp->dst_port == port) return true;
    }
    if (packet.udp) {
        if (check_src && packet.udp->src_port == port) return true;
        if (check_dst && packet.udp->dst_port == port) return true;
    }
    return false;
}

bool cidr_matches(const ParsedPacket &packet, std::uint32_t network, std::uint32_t mask,
                  bool check_src, bool check_dst) {
    if (!packet.ipv4) return false;
    if (check_src && (packet.ipv4->src & mask) == (network & mask)) return true;
    if (check_dst && (packet.ipv4->dst & mask) == (network & mask)) return true;
    return false;
}

bool compare_len(std::size_t len, Compare cmp, std::uint32_t value) {
    switch (cmp) {
        case Compare::Eq: return len == value;
        case Compare::Lt: return len < value;
        case Compare::Gt: return len > value;
    }
    return false;
}

bool evaluate(const Node &node, const Frame &frame, const ParsedPacket &packet) {
    switch (node.kind) {
        case NodeKind::And: return evaluate(*node.left, frame, packet) && evaluate(*node.right, frame, packet);
        case NodeKind::Or: return evaluate(*node.left, frame, packet) || evaluate(*node.right, frame, packet);
        case NodeKind::Not: return !evaluate(*node.left, frame, packet);
        case NodeKind::Tcp: return packet.tcp.has_value();
        case NodeKind::Udp: return packet.udp.has_value();
        case NodeKind::Icmp: return packet.ipv4 && packet.ipv4->protocol == ip_proto::Icmp;
        case NodeKind::Arp: return packet.eth && packet.eth->ethertype == ethertype::Arp;
        case NodeKind::Ip: return packet.ipv4.has_value();
        case NodeKind::Port: return port_matches(packet, node.port, true, true);
        case NodeKind::SrcPort: return port_matches(packet, node.port, true, false);
        case NodeKind::DstPort: return port_matches(packet, node.port, false, true);
        case NodeKind::Host: return packet.ipv4 && (packet.ipv4->src == node.addr || packet.ipv4->dst == node.addr);
        case NodeKind::SrcHost: return packet.ipv4 && packet.ipv4->src == node.addr;
        case NodeKind::DstHost: return packet.ipv4 && packet.ipv4->dst == node.addr;
        case NodeKind::Net: return cidr_matches(packet, node.addr, node.mask, true, true);
        case NodeKind::SrcNet: return cidr_matches(packet, node.addr, node.mask, true, false);
        case NodeKind::DstNet: return cidr_matches(packet, node.addr, node.mask, false, true);
        case NodeKind::Len: return compare_len(frame.len, node.cmp, node.len_value);
        case NodeKind::TcpFlag: return packet.tcp && packet.tcp->flags.*node.flag_member;
    }
    return false;
}

}

bool Filter::matches(const Frame &frame, const ParsedPacket &packet) const {
    return evaluate(*root_, frame, packet);
}

std::optional<Filter> parse_filter(std::string_view expr, std::string &error) {
    try {
        Parser parser(tokenize(expr));
        return Filter(parser.parse());
    } catch (const std::exception &e) {
        error = e.what();
        return std::nullopt;
    }
}

}
