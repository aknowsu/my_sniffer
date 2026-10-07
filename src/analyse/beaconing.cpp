#include "analyse/report.hpp"

#include "my_func/address.hpp"

#include <algorithm>
#include <cmath>
#include <map>

namespace sniffer::analyse {
namespace {

constexpr std::size_t min_connections_for_beaconing = 4;
constexpr double max_coefficient_of_variation = 0.1;
constexpr std::int64_t microseconds_per_second = 1'000'000;

bool is_connection_attempt(const LogEntry &entry) {
    return entry.flags.find("SYN") != std::string::npos && entry.flags.find("ACK") == std::string::npos;
}

}

std::vector<Alert> detect_beaconing(const std::vector<LogEntry> &entries) {
    std::vector<Alert> alerts;

    std::map<std::uint32_t, std::vector<std::int64_t>> times_by_dst;
    for (const LogEntry &entry : entries) {
        if (entry.dst_ip == 0 || !is_connection_attempt(entry)) {
            continue;
        }
        times_by_dst[entry.dst_ip].push_back(entry.ts_us);
    }

    for (auto &[ip, times] : times_by_dst) {
        if (times.size() < min_connections_for_beaconing) continue;
        std::sort(times.begin(), times.end());

        std::vector<std::int64_t> intervals;
        for (std::size_t i = 1; i < times.size(); ++i) {
            intervals.push_back(times[i] - times[i - 1]);
        }

        double sum = 0;
        for (std::int64_t interval : intervals) {
            sum += static_cast<double>(interval);
        }
        const double mean = sum / static_cast<double>(intervals.size());
        if (mean <= 0) continue;

        double variance_sum = 0;
        for (std::int64_t interval : intervals) {
            const double diff = static_cast<double>(interval) - mean;
            variance_sum += diff * diff;
        }
        const double stddev = std::sqrt(variance_sum / static_cast<double>(intervals.size()));
        const double coefficient_of_variation = stddev / mean;

        if (coefficient_of_variation < max_coefficient_of_variation) {
            alerts.push_back({"beaconing",
                              my::ipv4_to_text(ip) + " contacted every ~" +
                                  std::to_string(static_cast<std::int64_t>(mean / microseconds_per_second)) +
                                  "s, very regularly (possible beaconing)"});
        }
    }
    return alerts;
}

}
