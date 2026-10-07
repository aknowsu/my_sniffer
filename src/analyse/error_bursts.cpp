#include "analyse/report.hpp"

#include <algorithm>

namespace sniffer::analyse {
namespace {

constexpr std::int64_t window_us = 1'000'000;
constexpr std::size_t rst_threshold = 10;

}

std::vector<Alert> detect_error_bursts(const std::vector<LogEntry> &entries) {
    std::vector<Alert> alerts;

    std::vector<std::int64_t> rst_times;
    for (const LogEntry &entry : entries) {
        if (entry.flags.find("RST") != std::string::npos) {
            rst_times.push_back(entry.ts_us);
        }
    }
    std::sort(rst_times.begin(), rst_times.end());

    std::size_t window_start = 0;
    for (std::size_t i = 0; i < rst_times.size(); ++i) {
        while (rst_times[i] - rst_times[window_start] > window_us) {
            ++window_start;
        }
        const std::size_t count = i - window_start + 1;
        if (count == rst_threshold) {
            alerts.push_back({"error_burst", std::to_string(count) + " RST packets within 1 second"});
        }
    }
    return alerts;
}

}
