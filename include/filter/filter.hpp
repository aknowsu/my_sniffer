#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "capture.hpp"
#include "filter/ast.hpp"
#include "parse/packet.hpp"

namespace sniffer::filter {

class Filter {
public:
    explicit Filter(NodePtr root) : root_(std::move(root)) {}

    bool matches(const Frame &frame, const ParsedPacket &packet) const;

private:
    NodePtr root_;
};

std::optional<Filter> parse_filter(std::string_view expr, std::string &error);

}
