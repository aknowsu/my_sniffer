#include "analyse/report.hpp"

#include "my_func/address.hpp"

#include <cstdio>
#include <set>
#include <stdexcept>

namespace sniffer::analyse {

Whitelist read_whitelist(const std::string &path) {
    std::FILE *file = std::fopen(path.c_str(), "r");
    if (!file) {
        throw std::runtime_error("cannot open " + path);
    }

    Whitelist whitelist;
    char buf[256];
    while (std::fgets(buf, sizeof buf, file) != nullptr) {
        std::string line(buf);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' ')) {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }

        const std::size_t slash = line.find('/');
        const std::string address_text = line.substr(0, slash);
        const auto address = my::ipv4_from_text(address_text);
        if (!address) {
            std::fclose(file);
            throw std::runtime_error("invalid whitelist entry: " + line);
        }

        std::uint8_t prefix_len = 32;
        if (slash != std::string::npos) {
            prefix_len = static_cast<std::uint8_t>(std::stoi(line.substr(slash + 1)));
        }
        whitelist.entries.push_back({*address, prefix_len});
    }
    std::fclose(file);
    return whitelist;
}

std::vector<Alert> detect_foreign_ip(const std::vector<LogEntry> &entries, const Whitelist &whitelist) {
    std::vector<Alert> alerts;
    std::set<std::uint32_t> already_flagged;

    for (const LogEntry &entry : entries) {
        if (entry.dst_ip == 0 || already_flagged.count(entry.dst_ip) != 0) {
            continue;
        }

        bool allowed = false;
        for (const auto &[network, prefix_len] : whitelist.entries) {
            if (my::cidr_contains(network, prefix_len, entry.dst_ip)) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            alerts.push_back({"foreign_ip",
                              "connection to " + my::ipv4_to_text(entry.dst_ip) + " (not in whitelist)"});
            already_flagged.insert(entry.dst_ip);
        }
    }
    return alerts;
}

}
