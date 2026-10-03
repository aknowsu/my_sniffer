#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sniffer {

struct LogEntry {
    std::int64_t ts_us = 0;
    std::uint32_t src_ip = 0;
    std::uint16_t src_port = 0;
    std::uint32_t dst_ip = 0;
    std::uint16_t dst_port = 0;
    std::string protocol;
    std::string flags;
    std::uint8_t ttl = 0;
    std::size_t bytes = 0;
};

std::vector<LogEntry> read_log(const std::string &path);

}
