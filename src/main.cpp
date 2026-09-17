#include "capture.hpp"
#include "cli.hpp"
#include "parse/packet.hpp"
#include "viewer.hpp"

#include <signal.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <exception>

namespace {

std::atomic<sniffer::Capture *> g_capture{nullptr};

void on_signal(int) {
    if (sniffer::Capture *c = g_capture.load()) {
        c->stop();
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
    const sniffer::Options    &opt = parsed.options;
    const sniffer::ViewOptions view{opt.verbose, opt.decoded_only};

    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;

    try {
        sniffer::Capture capture(opt.interface);
        g_capture.store(&capture);
        install_signal_handlers();

        const sniffer::LinkType link = capture.link_type();
        capture.run([&](const sniffer::Frame &frame) {
            ++packets;
            bytes += frame.len;
            const sniffer::ParsedPacket pkt = sniffer::parse_packet(frame, link);
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
