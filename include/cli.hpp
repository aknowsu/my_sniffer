#pragma once

#include <optional>
#include <string>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace sniffer {

struct Options {
    std::string           interface;          // -i / --interface, or positional
    std::optional<std::string> filter;        // -f / --filter
    std::optional<std::string> write_path;    // -w / --write
    std::optional<std::string> read_path;     // -r / --read
    bool                  verbose  = false;   // -v / --verbose
    bool                  analyse  = false;   //      --analyse
};
struct ParseResult {
    enum class Action { kProceed, kExit } action = Action::kProceed;
    int     exit_code = 0;
    Options options;
};
ParseResult parse_args(int argc, char **argv);
void print_usage(const char *argv0);
void print_version();
} // namespace sniffer
