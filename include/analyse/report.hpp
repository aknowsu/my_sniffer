#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "log.hpp"

namespace sniffer::analyse {

struct Alert {
    std::string kind;
    std::string description;
};

struct Whitelist {
    std::vector<std::pair<std::uint32_t, std::uint8_t>> entries;
};

Whitelist read_whitelist(const std::string &path);

std::vector<Alert> detect_spikes(const std::vector<LogEntry> &entries);
std::vector<Alert> detect_service_requests(const std::vector<LogEntry> &entries);
std::vector<Alert> detect_error_bursts(const std::vector<LogEntry> &entries);
std::vector<Alert> detect_beaconing(const std::vector<LogEntry> &entries);
std::vector<Alert> detect_foreign_ip(const std::vector<LogEntry> &entries, const Whitelist &whitelist);

}
