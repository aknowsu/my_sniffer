#pragma once

#include <optional>
#include <string>

namespace sniffer {

struct Options {
    std::string                interface;
    std::optional<std::string> filter;
    std::optional<std::string> write_path;
    std::optional<std::string> read_path;
    bool                       verbose = false;
    bool                       analyse = false;
};

struct ParseResult {
    enum class Action { Proceed, Exit } action = Action::Proceed;
    int     exit_code = 0;
    Options options;
};

ParseResult parse_args(int argc, char **argv);
void        print_usage(const char *argv0);
void        print_version();

}
