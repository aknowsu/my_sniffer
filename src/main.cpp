#include "analyse/report.hpp"
#include "capture.hpp"
#include "cli.hpp"
#include "filter/filter.hpp"
#include "log.hpp"
#include "parse/packet.hpp"
#include "viewer.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <string>

namespace {

std::atomic<sniffer::Capture *> g_capture{nullptr};

struct FileCloser {
    void operator()(std::FILE *file) const { std::fclose(file); }
};

#ifdef _WIN32

BOOL WINAPI on_console_event(DWORD) {
    if (sniffer::Capture *capture = g_capture.load()) {
        capture->stop();
    }
    return TRUE;
}

void install_signal_handlers() {
    SetConsoleCtrlHandler(on_console_event, TRUE);
}

#else

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

#endif

}

int main(int argc, char **argv) {
    const sniffer::ParseResult parsed = sniffer::parse_args(argc, argv);
    if (parsed.action == sniffer::ParseResult::Action::Exit) {
        return parsed.exit_code;
    }
    const sniffer::Options &opt = parsed.options;
    const sniffer::ViewOptions view{opt.verbose, opt.decoded_only};

    if (opt.analyse) {
        std::vector<sniffer::LogEntry> entries;
        try {
            entries = sniffer::read_log(*opt.read_path);
        } catch (const std::exception &e) {
            std::fprintf(stderr, "my_sniffer: %s\n", e.what());
            return 1;
        }

        std::vector<sniffer::analyse::Alert> alerts;
        const auto append = [&](std::vector<sniffer::analyse::Alert> found) {
            alerts.insert(alerts.end(), found.begin(), found.end());
        };
        append(sniffer::analyse::detect_spikes(entries));
        append(sniffer::analyse::detect_beaconing(entries));
        append(sniffer::analyse::detect_unknown_protocol(entries));
        if (opt.whitelist_path) {
            sniffer::analyse::Whitelist whitelist;
            try {
                whitelist = sniffer::analyse::read_whitelist(*opt.whitelist_path);
            } catch (const std::exception &e) {
                std::fprintf(stderr, "my_sniffer: %s\n", e.what());
                return 1;
            }
            append(sniffer::analyse::detect_foreign_ip(entries, whitelist));
        }

        for (const sniffer::analyse::Alert &alert : alerts) {
            std::printf("[%s] %s\n", alert.kind.c_str(), alert.description.c_str());
        }
        std::printf("\n%zu entries analysed, %zu alerts\n", entries.size(), alerts.size());
        return 0;
    }

    std::optional<sniffer::filter::Filter> filter;
    if (opt.filter) {
        std::string error;
        filter = sniffer::filter::parse_filter(*opt.filter, error);
        if (!filter) {
            std::fprintf(stderr, "my_sniffer: invalid filter: %s\n", error.c_str());
            return 2;
        }
    }

    std::unique_ptr<std::FILE, FileCloser> log;
    if (opt.write_path) {
        log.reset(std::fopen(opt.write_path->c_str(), "w"));
        if (!log) {
            std::fprintf(stderr, "my_sniffer: cannot open %s: %s\n", opt.write_path->c_str(),
                         std::strerror(errno));
            return 1;
        }
    }
    sniffer::ViewOptions log_view = view;
    log_view.show_time = true;

    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;

    try {
        sniffer::Capture capture;
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
            if (log) {
                sniffer::print_packet(log.get(), frame, pkt, log_view);
                std::fflush(log.get());
            }
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
