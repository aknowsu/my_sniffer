#include "capture.hpp"
#include "cli.hpp"
#include "filter/filter.hpp"
#include "parse/packet.hpp"
#include "viewer.hpp"

#include <signal.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <optional>
#include <string>

namespace {

std::atomic<sniffer::Capture *> g_capture{nullptr};

void on_signal(int) {
    if (sniffer::Capture *capture = g_capture.load()) {
        capture->stop();
    }
}

void install_signal_handlers() {
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

}

int main(int argc, char **argv) {
    const sniffer::ParseResult parsed = sniffer::parse_args(argc, argv);
    if (parsed.action == sniffer::ParseResult::Action::Exit) {
        return parsed.exit_code;
    }
    const sniffer::Options &opt = parsed.options;
    const sniffer::ViewOptions view{opt.verbose, opt.decoded_only};

    std::optional<sniffer::filter::Filter> filter;
    if (opt.filter) {
        std::string error;
        filter = sniffer::filter::parse_filter(*opt.filter, error);
        if (!filter) {
            std::fprintf(stderr, "my_sniffer: invalid filter: %s\n", error.c_str());
            return 2;
        }
    }

    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;

    try {
        sniffer::Capture capture(opt.interface);
        g_capture.store(&capture);
        install_signal_handlers();

        const sniffer::LinkType link = capture.link_type();
        capture.run([&](const sniffer::Frame &frame) {
            const sniffer::ParsedPacket pkt = sniffer::parse_packet(frame, link);
            if (filter && !filter->matches(frame, pkt)) {
                return;
            }
            ++packets;
            bytes += frame.len;
            sniffer::print_packet(stdout, frame, pkt, view);
        });

        g_capture.store(nullptr);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "my_sniffer: %s\n", e.what());
        return 1;
    }

    std::printf("\n%llu packets, %llu bytes captured\n",
                static_cast<unsigned long long>(packets),
                static_cast<unsigned long long>(bytes));
    return 0;
}
