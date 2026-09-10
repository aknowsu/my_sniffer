#include "capture.hpp"
#include "cli.hpp"
#include "my_func/my_func.hpp"
#include "parse/ethernet.hpp"

#include <signal.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <exception>

namespace {

std::atomic<sniffer::Capture *> g_capture{nullptr};

// Async-signal-safe: only touches an atomic. No printf here.
void on_signal(int) {
    if (sniffer::Capture *c = g_capture.load()) {
        c->stop();
    }
}

void install_signal_handlers() {
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   // no SA_RESTART -> poll()/recv() return EINTR, we stop now
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

void show(const sniffer::Frame &f, bool verbose) {
    sniffer::Cursor c(f.data, f.len);
    if (const auto eth = sniffer::parse_ethernet(c)) {
        std::printf("%s > %s  %s (0x%04x)  %zu bytes\n",
                    my::mac_to_text(eth->src).c_str(),
                    my::mac_to_text(eth->dst).c_str(),
                    sniffer::ethertype_name(eth->ethertype), eth->ethertype,
                    f.len);
    } else {
        std::printf("[unparsed / truncated]  %zu bytes\n", f.len);
    }
    if (verbose) {
        std::fputs(my::hexdump(f.data, f.len).c_str(), stdout);
    }
}

} // namespace

int main(int argc, char **argv) {
    const sniffer::ParseResult parsed = sniffer::parse_args(argc, argv);
    if (parsed.action == sniffer::ParseResult::Action::kExit) {
        return parsed.exit_code;
    }
    const sniffer::Options &opt = parsed.options;

    std::uint64_t packets = 0;
    std::uint64_t bytes   = 0;

    try {
        sniffer::Capture capture(opt.interface);
        g_capture.store(&capture);
        install_signal_handlers();

        capture.run([&](const sniffer::Frame &f) {
            ++packets;
            bytes += f.len;
            show(f, opt.verbose);
        });

        g_capture.store(nullptr);   // capture is about to be destroyed
    } catch (const std::exception &e) {
        std::fprintf(stderr, "my_sniffer: %s\n", e.what());
        return 1;
    }

    std::printf("\n%llu packets, %llu bytes captured\n",
                static_cast<unsigned long long>(packets),
                static_cast<unsigned long long>(bytes));
    return 0;
}
