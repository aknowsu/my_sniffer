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
