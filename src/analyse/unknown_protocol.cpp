#include "analyse/report.hpp"

#include "my_func/address.hpp"

namespace sniffer::analyse {
namespace {

struct StandardPort {
    std::uint16_t port;
    const char *service;
    const char *expected_protocol;
};

constexpr StandardPort standard_ports[] = {
    {22, "SSH", "TCP"},
    {80, "HTTP", "TCP"},
    {8080, "HTTP", "TCP"},
};

const StandardPort *find_standard_port(std::uint16_t port) {
    for (const StandardPort &entry : standard_ports) {
        if (entry.port == port) return &entry;
    }
    return nullptr;
}

}

std::vector<Alert> detect_unknown_protocol(const std::vector<LogEntry> &entries) {
    std::vector<Alert> alerts;

    for (const LogEntry &entry : entries) {
        const StandardPort *standard = find_standard_port(entry.dst_port);
        if (standard == nullptr) continue;
        if (entry.protocol == standard->expected_protocol) continue;

        alerts.push_back({"unknown_protocol",
                          my::ipv4_to_text(entry.src_ip) + " -> " + my::ipv4_to_text(entry.dst_ip) +
                              ":" + std::to_string(entry.dst_port) + " is " + entry.protocol +
                              ", expected " + standard->expected_protocol + " (" + standard->service +
                              ")"});
    }
    return alerts;
}

}
