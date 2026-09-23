#include "filter/token.hpp"

#include "my_func/address.hpp"

#include <cctype>
#include <optional>

namespace sniffer::filter {
namespace {

bool is_ident_start(char ch) {
    return std::isalpha(static_cast<unsigned char>(ch)) || ch == '_';
}

bool is_ident_char(char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' || ch == '.';
}

Token classify_number(std::string_view text, std::size_t position) {
    const std::size_t slash = text.find('/');
    const std::string_view addr_text = text.substr(0, slash);

    if (addr_text.find('.') == std::string_view::npos) {
        std::uint64_t value = 0;
        for (const char ch : text) {
            value = value * 10 + static_cast<std::uint64_t>(ch - '0');
        }
        return Token{TokenKind::Number, std::string(text), value, 0, 0, position};
    }

    const std::optional<std::uint32_t> addr = my::ipv4_from_text(addr_text);
    if (!addr) {
        return Token{TokenKind::Identifier, std::string(text), 0, 0, 0, position};
    }
    if (slash == std::string_view::npos) {
        return Token{TokenKind::Ipv4, std::string(text), 0, *addr, 0, position};
    }

    const std::string_view prefix_text = text.substr(slash + 1);
    if (prefix_text.empty()) {
        return Token{TokenKind::Identifier, std::string(text), 0, 0, 0, position};
    }
    std::uint32_t prefix_len = 0;
    for (const char ch : prefix_text) {
        if (ch < '0' || ch > '9') {
            return Token{TokenKind::Identifier, std::string(text), 0, 0, 0, position};
        }
        prefix_len = prefix_len * 10 + static_cast<std::uint32_t>(ch - '0');
    }
    if (prefix_len > 32) {
        return Token{TokenKind::Identifier, std::string(text), 0, 0, 0, position};
    }

    return Token{TokenKind::Cidr, std::string(text), 0, *addr, static_cast<std::uint8_t>(prefix_len), position};
}

}

std::vector<Token> tokenize(std::string_view expr) {
    std::vector<Token> tokens;
    std::size_t pos = 0;

    while (pos < expr.size()) {
        const char ch = expr[pos];

        if (std::isspace(static_cast<unsigned char>(ch))) {
            ++pos;
            continue;
        }
        if (ch == '(') { tokens.push_back({TokenKind::LParen, "(", 0, 0, 0, pos}); ++pos; continue; }
        if (ch == ')') { tokens.push_back({TokenKind::RParen, ")", 0, 0, 0, pos}); ++pos; continue; }
        if (ch == '<') { tokens.push_back({TokenKind::Lt, "<", 0, 0, 0, pos}); ++pos; continue; }
        if (ch == '>') { tokens.push_back({TokenKind::Gt, ">", 0, 0, 0, pos}); ++pos; continue; }
        if (ch == '=') {
            const std::size_t start = pos;
            ++pos;
            if (pos < expr.size() && expr[pos] == '=') ++pos;
            tokens.push_back({TokenKind::Eq, "=", 0, 0, 0, start});
            continue;
        }

        if (std::isdigit(static_cast<unsigned char>(ch))) {
            const std::size_t start = pos;
            while (pos < expr.size() &&
                   (std::isdigit(static_cast<unsigned char>(expr[pos])) || expr[pos] == '.' || expr[pos] == '/')) {
                ++pos;
            }
            tokens.push_back(classify_number(expr.substr(start, pos - start), start));
            continue;
        }

        if (is_ident_start(ch)) {
            const std::size_t start = pos;
            while (pos < expr.size() && is_ident_char(expr[pos])) {
                ++pos;
            }
            tokens.push_back({TokenKind::Identifier, std::string(expr.substr(start, pos - start)), 0, 0, 0, start});
            continue;
        }

        tokens.push_back({TokenKind::Identifier, std::string(1, ch), 0, 0, 0, pos});
        ++pos;
    }

    tokens.push_back({TokenKind::End, "", 0, 0, 0, expr.size()});
    return tokens;
}

}
