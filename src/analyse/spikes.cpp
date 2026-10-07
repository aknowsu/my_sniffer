#include "analyse/report.hpp"

#include "my_func/address.hpp"

#include <cmath>
#include <map>

namespace sniffer::analyse {
namespace {

constexpr std::int64_t window_us = 1'000'000;
constexpr double spike_stddev_multiplier = 3.0;
constexpr std::size_t min_windows_for_stats = 4;

}

std::vector<Alert> detect_spikes(const std::vector<LogEntry> &entries) {
    std::vector<Alert> alerts;

    std::map<std::uint32_t, std::map<std::int64_t, std::size_t>> bytes_per_window_by_ip;
    for (const LogEntry &entry : entries) {
        if (entry.src_ip == 0) continue;
        const std::int64_t window = entry.ts_us / window_us;
        bytes_per_window_by_ip[entry.src_ip][window] += entry.bytes;
    }

    for (const auto &[ip, windows] : bytes_per_window_by_ip) {
        if (windows.size() < min_windows_for_stats) continue;

        double sum = 0;
        for (const auto &[window, bytes] : windows) {
            sum += static_cast<double>(bytes);
        }
        const double mean = sum / static_cast<double>(windows.size());

        double variance_sum = 0;
        for (const auto &[window, bytes] : windows) {
            const double diff = static_cast<double>(bytes) - mean;
            variance_sum += diff * diff;
        }
        const double stddev = std::sqrt(variance_sum / static_cast<double>(windows.size()));
        if (stddev <= 0) continue;

        const double threshold = mean + spike_stddev_multiplier * stddev;
        for (const auto &[window, bytes] : windows) {
            if (static_cast<double>(bytes) > threshold) {
                alerts.push_back({"traffic_spike",
                                  my::ipv4_to_text(ip) + " sent " + std::to_string(bytes) +
                                      " bytes in one second (usual ~" +
                                      std::to_string(static_cast<std::size_t>(mean)) + ")"});
            }
        }
    }
    return alerts;
}

}
