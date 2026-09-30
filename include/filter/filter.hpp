#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "capture.hpp"
#include "filter/ast.hpp"
#include "parse/packet.hpp"

namespace sniffer::filter {

class Filter {
public:
    explicit Filter(std::vector<Item> postfix) : postfix_(std::move(postfix)) {}

    bool matches(const Frame &frame, const ParsedPacket &packet) const;

private:
    std::vector<Item> postfix_;
};

std::optional<Filter> parse_filter(std::string_view expr, std::string &error);

}
