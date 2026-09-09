#include "cli.hpp"

#include <cstdio>

int main(int argc, char **argv) {
    const sniffer::ParseResult parsed = sniffer::parse_args(argc, argv);
    if (parsed.action == sniffer::ParseResult::Action::kExit) {
        return parsed.exit_code;
    }
    const sniffer::Options &opt = parsed.options;

    std::printf("my_sniffer: capture not implemented yet\n");
    std::printf("  interface : %s\n",
                opt.interface.empty() ? "(default)" : opt.interface.c_str());
    std::printf("  filter    : %s\n", opt.filter ? opt.filter->c_str() : "(none)");
    std::printf("  write     : %s\n",
                opt.write_path ? opt.write_path->c_str() : "(none)");
    std::printf("  read      : %s\n",
                opt.read_path ? opt.read_path->c_str() : "(none)");
    std::printf("  verbose   : %s\n", opt.verbose ? "yes" : "no");
    std::printf("  analyse   : %s\n", opt.analyse ? "yes" : "no");
    return 0;
}
