#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sniffer::filter {

enum class TokenKind { End, LParen, RParen, Lt, Gt, Eq, Number, Ipv4, Cidr, Identifier };

struct Token {
    TokenKind kind;
    std::string text;
    std::uint64_t number = 0;
    std::uint32_t addr = 0;
    std::uint8_t prefix_len = 0;
    std::size_t position = 0;
};

std::vector<Token> tokenize(std::string_view expr);

}
