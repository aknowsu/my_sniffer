#include "cli.hpp"

#include <cstdio>
#include <string_view>

#ifndef SNIFFER_NAME
#define SNIFFER_NAME "my_sniffer"
#endif
#ifndef SNIFFER_VERSION
#define SNIFFER_VERSION "0.0.0-dev"
#endif

namespace sniffer {
namespace {

enum class OptId { Filter, Write, Read, Whitelist, Verbose, Analyse, DecodedOnly, Help, Version };

struct OptSpec {
    OptId id;
    char short_name;
    std::string_view long_name;
    bool takes_value;
};

constexpr OptSpec option_table[] = {
    {OptId::Filter, 'f', "filter", true},
    {OptId::Write, 'w', "write", true},
    {OptId::Read, 'r', "read", true},
    {OptId::Whitelist, '\0', "whitelist", true},
    {OptId::Verbose, 'v', "verbose", false},
    {OptId::Analyse, 'a', "analyse", false},
    {OptId::DecodedOnly, 'd', "decoded-only", false},
    {OptId::Help, 'h', "help", false},
    {OptId::Version, 'V', "version", false},
};

const OptSpec *find_option(std::string_view name) {
    for (const OptSpec &spec : option_table) {
        const bool as_short = name.size() == 2 && name[0] == '-' &&
                              spec.short_name != '\0' && name[1] == spec.short_name;
        const bool as_long = name.size() > 2 && name.substr(0, 2) == "--" &&
                             name.substr(2) == spec.long_name;
        if (as_short || as_long) {
            return &spec;
        }
    }
    return nullptr;
}

}

void print_usage(const char *argv0) {
    const char *prog = (argv0 && *argv0) ? argv0 : SNIFFER_NAME;
    std::printf(
        "Usage: %s [options]\n"
        "\n"
        "A from-scratch network packet sniffer: raw capture, protocol parsing,\n"
        "filtering and behavioural analysis.\n"
        "\n"
        "Options:\n"
        "  -f, --filter <expr>      Only show packets matching <expr>.\n"
        "  -w, --write <file>       Log the displayed packets to <file>, same\n"
        "                           layout as the screen (-v included), each\n"
        "                           prefixed with its UTC time.\n"
        "  -r, --read <file>        Read packets back from a file written by -w.\n"
        "                           Only used together with --analyse.\n"
        "  -v, --verbose            Print a hexdump for every packet.\n"
        "      --analyse            Run the behavioural analysis engine over the\n"
        "                           capture given with -r (requires -r).\n"
        "      --whitelist <file>   One IP or CIDR per line: addresses allowed\n"
        "                           as destinations. Used with --analyse to flag\n"
        "                           connections to anything else. Optional.\n"
        "      --decoded-only       Only show packets whose protocol is\n"
        "                           decoded (hide the 'unknown' ones).\n"
        "  -h, --help               Show this help and exit.\n"
        "  -V, --version            Show version information and exit.\n"
        "\n"
        "Capturing live traffic needs elevated privileges (CAP_NET_RAW on\n"
        "Linux, Administrator on Windows). See the README for details.\n",
        prog);
}

void print_version() {
    std::printf("%s %s\n", SNIFFER_NAME, SNIFFER_VERSION);
}

ParseResult parse_args(int argc, char **argv) {
    ParseResult result;
    const char *prog = (argc > 0 && argv[0] && *argv[0]) ? argv[0] : SNIFFER_NAME;

    auto fail = [&](const char *msg, std::string_view arg) {
        std::fprintf(stderr, "%s: %s", SNIFFER_NAME, msg);
        if (!arg.empty()) {
            std::fprintf(stderr, ": %.*s", static_cast<int>(arg.size()), arg.data());
        }
        std::fprintf(stderr, "\nTry '%s --help' for more information.\n", prog);
        result.action = ParseResult::Action::Exit;
        result.exit_code = 2;
    };

    Options &opt = result.options;
    bool options_ended = false;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];

        if (!options_ended && arg == "--") {
            options_ended = true;
            continue;
        }

        if (options_ended || arg.size() < 2 || arg[0] != '-') {
            fail("unexpected extra argument", arg);
            return result;
        }

        std::string_view name = arg;
        std::string_view inline_value;
        bool has_inline = false;
        if (arg.rfind("--", 0) == 0) {
            if (const auto eq = arg.find('='); eq != std::string_view::npos) {
                name = arg.substr(0, eq);
                inline_value = arg.substr(eq + 1);
                has_inline = true;
            }
        }

        const OptSpec *spec = find_option(name);
        if (spec == nullptr) {
            fail("unknown option", arg);
            return result;
        }

        std::string_view value;
        if (spec->takes_value) {
            if (has_inline) {
                value = inline_value;
            } else if (i + 1 < argc) {
                value = argv[++i];
            } else {
                fail("option requires an argument", name);
                return result;
            }
        } else if (has_inline) {
            fail("option takes no argument", name);
            return result;
        }

        switch (spec->id) {
        case OptId::Help:
            print_usage(prog);
            result.action = ParseResult::Action::Exit;
            return result;
        case OptId::Version:
            print_version();
            result.action = ParseResult::Action::Exit;
            return result;
        case OptId::Verbose: opt.verbose = true; break;
        case OptId::Analyse: opt.analyse = true; break;
        case OptId::DecodedOnly: opt.decoded_only = true; break;
        case OptId::Filter: opt.filter = std::string(value); break;
        case OptId::Write: opt.write_path = std::string(value); break;
        case OptId::Read: opt.read_path = std::string(value); break;
        case OptId::Whitelist: opt.whitelist_path = std::string(value); break;
        }
    }

    if (opt.write_path && opt.read_path) {
        fail("--write and --read are mutually exclusive", {});
        return result;
    }
    if (opt.read_path && !opt.analyse) {
        fail("-r/--read requires --analyse", {});
        return result;
    }
    if (opt.analyse && !opt.read_path) {
        fail("--analyse requires -r/--read", {});
        return result;
    }
    if (opt.whitelist_path && !opt.analyse) {
        fail("--whitelist requires --analyse", {});
        return result;
    }

    return result;
}

}
