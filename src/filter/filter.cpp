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

struct CompareEntry {
    TokenKind token;
    Compare cmp;
};

constexpr CompareEntry compare_table[] = {
    {TokenKind::Gt, Compare::Gt},
    {TokenKind::Lt, Compare::Lt},
    {TokenKind::Eq, Compare::Eq},
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
    struct Keyword {
        std::string_view name;
        NodePtr (Parser::*parse)(Direction);
        bool directional;
    };

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

    static std::uint32_t prefix_to_mask(std::uint8_t prefix_len) {
        if (prefix_len == 0) return 0;
        if (prefix_len >= 32) return 0xFFFFFFFFu;
        return ~std::uint32_t{0} << (32 - prefix_len);
    }

    NodePtr parse_chain(std::string_view word, NodeKind kind, NodePtr (Parser::*operand)()) {
        NodePtr node = (this->*operand)();
        while (at_identifier(word)) {
            advance();
            NodePtr parent = leaf(kind);
            parent->left = std::move(node);
            parent->right = (this->*operand)();
            node = std::move(parent);
        }
        return node;
    }

    NodePtr parse_or() { return parse_chain("or", NodeKind::Or, &Parser::parse_and); }

    NodePtr parse_and() { return parse_chain("and", NodeKind::And, &Parser::parse_not); }

    NodePtr parse_not() {
        if (at_identifier("not")) {
            advance();
            NodePtr node = leaf(NodeKind::Not);
            node->left = parse_not();
            return node;
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

    NodePtr parse_predicate() {
        if (peek().kind != TokenKind::Identifier) {
            fail("expected a predicate");
        }
        const Token word = advance();

        for (const SimplePredicate &entry : simple_predicates) {
            if (word.text == entry.name) {
                return leaf(entry.kind);
            }
        }

        Direction direction = Direction::Any;
        std::string keyword = word.text;
        if (word.text == "src" || word.text == "dst") {
            direction = word.text == "src" ? Direction::Src : Direction::Dst;
            keyword = expect(TokenKind::Identifier, "'port', 'host' or 'net'").text;
        }

        static constexpr Keyword keywords[] = {
            {"port", &Parser::parse_port, true},
            {"host", &Parser::parse_host, true},
            {"net", &Parser::parse_net, true},
            {"len", &Parser::parse_len, false},
            {"tcp.flags", &Parser::parse_tcp_flags, false},
        };
        for (const Keyword &entry : keywords) {
            if (keyword == entry.name) {
                if (direction != Direction::Any && !entry.directional) {
                    throw std::runtime_error("'" + word.text + "' cannot be used before '" + keyword +
                                             "' at position " + std::to_string(word.position));
                }
                return (this->*entry.parse)(direction);
            }
        }
        throw std::runtime_error("unknown predicate '" + keyword + "' at position " +
                                 std::to_string(word.position));
    }

    NodePtr parse_port(Direction direction) {
        const Token number = expect(TokenKind::Number, "a port number");
        NodePtr node = leaf(NodeKind::Port);
        node->direction = direction;
        node->port = static_cast<std::uint32_t>(number.number);
        return node;
    }

    NodePtr parse_host(Direction direction) {
        const Token addr = expect(TokenKind::Ipv4, "an IPv4 address");
        NodePtr node = leaf(NodeKind::Host);
        node->direction = direction;
        node->addr = addr.addr;
        return node;
    }

    NodePtr parse_net(Direction direction) {
        const Token cidr = expect(TokenKind::Cidr, "a CIDR network");
        NodePtr node = leaf(NodeKind::Net);
        node->direction = direction;
        node->addr = cidr.addr;
        node->mask = prefix_to_mask(cidr.prefix_len);
        return node;
    }

    NodePtr parse_len(Direction) {
        NodePtr node = leaf(NodeKind::Len);
        node->cmp = parse_compare();
        const Token number = expect(TokenKind::Number, "a length");
        node->len_value = static_cast<std::uint32_t>(number.number);
        return node;
    }

    NodePtr parse_tcp_flags(Direction) {
        expect_word("has");
        const Token name = expect(TokenKind::Identifier, "a TCP flag name");
        for (const FlagEntry &entry : flag_table) {
            if (name.text == entry.name) {
                NodePtr node = leaf(NodeKind::TcpFlag);
                node->flag_member = entry.member;
                return node;
            }
        }
        throw std::runtime_error("unknown TCP flag '" + name.text + "' at position " +
                                 std::to_string(name.position));
    }

    Compare parse_compare() {
        for (const CompareEntry &entry : compare_table) {
            if (peek().kind == entry.token) {
                advance();
                return entry.cmp;
            }
        }
        fail("expected '>', '<' or '=='");
    }

    std::vector<Token> tokens_;
    std::size_t pos_ = 0;
};

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

bool evaluate(const Node &node, const Frame &frame, const ParsedPacket &packet) {
    const Direction dir = node.direction;
    switch (node.kind) {
        case NodeKind::And: return evaluate(*node.left, frame, packet) && evaluate(*node.right, frame, packet);
        case NodeKind::Or: return evaluate(*node.left, frame, packet) || evaluate(*node.right, frame, packet);
        case NodeKind::Not: return !evaluate(*node.left, frame, packet);
        case NodeKind::Tcp: return packet.tcp.has_value();
        case NodeKind::Udp: return packet.udp.has_value();
        case NodeKind::Icmp: return packet.ipv4 && packet.ipv4->protocol == ip_proto::Icmp;
        case NodeKind::Arp: return packet.eth && packet.eth->ethertype == ethertype::Arp;
        case NodeKind::Ip: return packet.ipv4.has_value();
        case NodeKind::Port:
            return (packet.tcp && side_matches(dir, packet.tcp->src_port == node.port,
                                               packet.tcp->dst_port == node.port)) ||
                   (packet.udp && side_matches(dir, packet.udp->src_port == node.port,
                                               packet.udp->dst_port == node.port));
        case NodeKind::Host:
            return packet.ipv4 && side_matches(dir, packet.ipv4->src == node.addr,
                                               packet.ipv4->dst == node.addr);
        case NodeKind::Net:
            return packet.ipv4 &&
                   side_matches(dir, (packet.ipv4->src & node.mask) == (node.addr & node.mask),
                                (packet.ipv4->dst & node.mask) == (node.addr & node.mask));
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
