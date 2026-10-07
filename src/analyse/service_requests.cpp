#include "analyse/report.hpp"

#include "my_func/address.hpp"

#include <algorithm>
#include <map>
#include <utility>

namespace sniffer::analyse {
namespace {

constexpr std::int64_t window_us = 10'000'000;
constexpr std::size_t syn_threshold = 20;

bool is_connection_attempt(const LogEntry &entry) {
    return entry.flags.find("SYN") != std::string::npos && entry.flags.find("ACK") == std::string::npos;
}

}

std::vector<Alert> detect_service_requests(const std::vector<LogEntry> &entries) {
    std::vector<Alert> alerts;

    std::map<std::pair<std::uint32_t, std::uint16_t>, std::vector<std::int64_t>> attempts_by_service;
    for (const LogEntry &entry : entries) {
        if (entry.dst_ip == 0 || !is_connection_attempt(entry)) {
            continue;
        }
        attempts_by_service[{entry.dst_ip, entry.dst_port}].push_back(entry.ts_us);
    }

    for (auto &[service, times] : attempts_by_service) {
        std::sort(times.begin(), times.end());

        std::size_t window_start = 0;
        for (std::size_t i = 0; i < times.size(); ++i) {
            while (times[i] - times[window_start] > window_us) {
                ++window_start;
            }
            const std::size_t count = i - window_start + 1;
            if (count == syn_threshold) {
                alerts.push_back({"service_requests",
                                  std::to_string(count) + " connection attempts to " +
                                      my::ipv4_to_text(service.first) + ":" +
                                      std::to_string(service.second) + " within 10s"});
            }
        }
    }
    return alerts;
}

}
