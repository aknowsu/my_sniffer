#include "capture.hpp"
#include "cli.hpp"
#include "my_func/my_func.hpp"

#include <csignal>
#include <cstdio>
#include <exception>

namespace {

sniffer::Capture *g_capture = nullptr;

void on_sigint(int) {
    if (g_capture != nullptr) {
        g_capture->stop();
    }
}

} // namespace

int main(int argc, char **argv) {
    const sniffer::ParseResult parsed = sniffer::parse_args(argc, argv);
    if (parsed.action == sniffer::ParseResult::Action::kExit) {
        return parsed.exit_code;
    }
    const sniffer::Options &opt = parsed.options;

    try {
        sniffer::Capture capture(opt.interface);
        g_capture = &capture;
        std::signal(SIGINT, on_sigint);

        capture.run([&](const sniffer::Frame &f) {
            std::printf("%zu bytes\n", f.len);
            if (opt.verbose) {
                std::fputs(my::hexdump(f.data, f.len).c_str(), stdout);
            }
        });
    } catch (const std::exception &e) {
        std::fprintf(stderr, "my_sniffer: %s\n", e.what());
        return 1;
    }
    return 0;
}
