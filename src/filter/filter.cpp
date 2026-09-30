#include "filter/filter.hpp"

#include "filter/token.hpp"

#include <stdexcept>
#include <utility>

namespace sniffer::filter {
namespace {

struct SimplePredicate {
    std::string_view name;
    TestKind kind;
};

constexpr SimplePredicate simple_predicates[] = {
    {"tcp", TestKind::Tcp},
    {"udp", TestKind::Udp},
    {"icmp", TestKind::Icmp},
    {"arp", TestKind::Arp},
    {"ip", TestKind::Ip},
};

struct FlagEntry {
    std::string_view name;
    TcpFlagName flag;
};

constexpr FlagEntry flag_table[] = {
    {"syn", TcpFlagName::Syn}, {"ack", TcpFlagName::Ack}, {"fin", TcpFlagName::Fin},
    {"rst", TcpFlagName::Rst}, {"psh", TcpFlagName::Psh}, {"urg", TcpFlagName::Urg},
    {"ece", TcpFlagName::Ece}, {"cwr", TcpFlagName::Cwr}, {"ns", TcpFlagName::Ns},
};

int precedence(std::string_view word) {
    if (word == "not") return 3;
    if (word == "and") return 2;
    return 1;
}

bool right_associative(std::string_view word) {
    return word == "not";
}

Op op_from_word(std::string_view word) {
    if (word == "and") return Op::And;
    if (word == "or") return Op::Or;
    return Op::Not;
}

Item test_item(TestKind kind) {
    Item item{};
    item.item = ItemKind::Test;
    item.test = kind;
    return item;
}

Item op_item(std::string_view word) {
    Item item{};
    item.item = ItemKind::Operator;
    item.op = op_from_word(word);
    return item;
}

std::uint32_t prefix_to_mask(std::uint8_t prefix_len) {
    if (prefix_len == 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFFu;
    return ~std::uint32_t{0} << (32 - prefix_len);
}

class Parser {
public:
    explicit Parser(std::vector<Token> tokens) : tokens_(std::move(tokens)) {}

    std::vector<Item> parse() {
        while (peek().kind != TokenKind::End) {
            if (peek().kind == TokenKind::LParen) {
                if (!expect_operand_) fail("expected an operator");
                op_stack_.push_back(advance());
            } else if (peek().kind == TokenKind::RParen) {
                if (expect_operand_) fail("expected a predicate");
                pop_until_paren();
            } else if (at_identifier("and") || at_identifier("or")) {
                if (expect_operand_) fail("expected a predicate");
                push_operator(advance());
                expect_operand_ = true;
            } else if (at_identifier("not")) {
                if (!expect_operand_) fail("expected an operator");
                push_operator(advance());
            } else {
                if (!expect_operand_) fail("expected an operator");
                output_.push_back(parse_predicate());
                expect_operand_ = false;
            }
        }
        if (expect_operand_) {
            fail("expected a predicate");
        }
        while (!op_stack_.empty()) {
            const Token top = op_stack_.back();
            op_stack_.pop_back();
            if (top.kind == TokenKind::LParen) {
                throw std::runtime_error("unmatched '(' at position " + std::to_string(top.position));
            }
            output_.push_back(op_item(top.text));
        }
        return std::move(output_);
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

    void push_operator(const Token &token) {
        while (!op_stack_.empty() && op_stack_.back().kind != TokenKind::LParen) {
            const int top_prec = precedence(op_stack_.back().text);
            const int new_prec = precedence(token.text);
            const bool pop_it = right_associative(token.text) ? top_prec > new_prec : top_prec >= new_prec;
            if (!pop_it) break;
            output_.push_back(op_item(op_stack_.back().text));
            op_stack_.pop_back();
        }
        op_stack_.push_back(token);
    }

    void pop_until_paren() {
        while (!op_stack_.empty() && op_stack_.back().kind != TokenKind::LParen) {
            output_.push_back(op_item(op_stack_.back().text));
            op_stack_.pop_back();
        }
        if (op_stack_.empty()) {
            fail("unmatched ')'");
        }
        op_stack_.pop_back();
        advance();
        expect_operand_ = false;
    }

    Compare parse_compare() {
        if (peek().kind == TokenKind::Gt) { advance(); return Compare::Gt; }
        if (peek().kind == TokenKind::Lt) { advance(); return Compare::Lt; }
        if (peek().kind == TokenKind::Eq) { advance(); return Compare::Eq; }
        fail("expected '>', '<' or '=='");
    }

    Item parse_predicate() {
        if (peek().kind != TokenKind::Identifier) {
            fail("expected a predicate");
        }
        const Token word = advance();

        for (const SimplePredicate &entry : simple_predicates) {
            if (word.text == entry.name) {
                return test_item(entry.kind);
            }
        }

        Direction direction = Direction::Any;
        Token keyword = word;
        if (word.text == "src" || word.text == "dst") {
            direction = word.text == "src" ? Direction::Src : Direction::Dst;
            keyword = expect(TokenKind::Identifier, "'port', 'host' or 'net'");
        }

        if (keyword.text == "port") {
            const Token number = expect(TokenKind::Number, "a port number");
            Item item = test_item(TestKind::Port);
            item.direction = direction;
            item.port = static_cast<std::uint32_t>(number.number);
            return item;
        }
        if (keyword.text == "host") {
            const Token addr = expect(TokenKind::Ipv4, "an IPv4 address");
            Item item = test_item(TestKind::Host);
            item.direction = direction;
            item.addr = addr.addr;
            return item;
        }
        if (keyword.text == "net") {
            const Token cidr = expect(TokenKind::Cidr, "a CIDR network");
            Item item = test_item(TestKind::Net);
            item.direction = direction;
            item.addr = cidr.addr;
            item.mask = prefix_to_mask(cidr.prefix_len);
            return item;
        }
        if (keyword.text == "len") {
            if (direction != Direction::Any) {
                fail("'" + word.text + "' cannot be used before 'len'");
            }
            Item item = test_item(TestKind::Len);
            item.cmp = parse_compare();
            const Token number = expect(TokenKind::Number, "a length");
            item.len_value = static_cast<std::uint32_t>(number.number);
            return item;
        }
        if (keyword.text == "tcp.flags") {
            if (direction != Direction::Any) {
                fail("'" + word.text + "' cannot be used before 'tcp.flags'");
            }
            expect_word("has");
            const Token name = expect(TokenKind::Identifier, "a TCP flag name");
            for (const FlagEntry &entry : flag_table) {
                if (name.text == entry.name) {
                    Item item = test_item(TestKind::TcpFlag);
                    item.flag = entry.flag;
                    return item;
                }
            }
            throw std::runtime_error("unknown TCP flag '" + name.text + "' at position " +
                                     std::to_string(name.position));
        }

        throw std::runtime_error("unknown predicate '" + keyword.text + "' at position " +
                                 std::to_string(keyword.position));
    }

    std::vector<Token> tokens_;
    std::size_t pos_ = 0;
    std::vector<Token> op_stack_;
    std::vector<Item> output_;
    bool expect_operand_ = true;
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
