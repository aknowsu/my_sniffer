#include "log.hpp"

#include "my_func/address.hpp"

#include <cstdio>
#include <stdexcept>
#include <string_view>

namespace sniffer {
namespace {

constexpr std::int64_t microseconds_per_second = 1'000'000;
constexpr std::int64_t microseconds_per_millisecond = 1'000;
constexpr std::int64_t seconds_per_minute = 60;
constexpr std::int64_t seconds_per_hour = 3600;
constexpr std::int64_t seconds_per_day = 86400;
constexpr std::int64_t days_epoch_offset = 719468;
constexpr int days_per_era = 146097;
constexpr int years_per_era = 400;

std::int64_t days_from_civil(int year, int month, int day) {
    year -= month <= 2 ? 1 : 0;
    const int era = (year >= 0 ? year : year - 399) / years_per_era;
    const int year_of_era = year - era * years_per_era;
    const int day_of_year = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    const int day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return static_cast<std::int64_t>(era) * days_per_era + day_of_era - days_epoch_offset;
}

bool starts_with(std::string_view text, std::string_view prefix) {
    return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view text, std::string_view suffix) {
    return text.size() >= suffix.size() && text.substr(text.size() - suffix.size()) == suffix;
}

std::vector<std::string> split_on_double_space(std::string_view text) {
    std::vector<std::string> fields;
    std::size_t pos = 0;
    while (pos < text.size()) {
        const std::size_t next = text.find("  ", pos);
        if (next == std::string_view::npos) {
            fields.emplace_back(text.substr(pos));
            break;
        }
        fields.emplace_back(text.substr(pos, next - pos));
        pos = next + 2;
        while (pos < text.size() && text[pos] == ' ') {
            ++pos;
        }
    }
    return fields;
}

std::int64_t parse_timestamp(std::string_view text) {
    if (text.size() < 23) {
        throw std::runtime_error("malformed timestamp");
    }
    const int year = std::stoi(std::string(text.substr(0, 4)));
    const int month = std::stoi(std::string(text.substr(5, 2)));
    const int day = std::stoi(std::string(text.substr(8, 2)));
    const int hour = std::stoi(std::string(text.substr(11, 2)));
    const int minute = std::stoi(std::string(text.substr(14, 2)));
    const int second = std::stoi(std::string(text.substr(17, 2)));
    const int millis = std::stoi(std::string(text.substr(20, 3)));

    const std::int64_t days_since_epoch = days_from_civil(year, month, day);
    const std::int64_t seconds_since_epoch = days_since_epoch * seconds_per_day + hour * seconds_per_hour +
                                             minute * seconds_per_minute + second;
    return seconds_since_epoch * microseconds_per_second + millis * microseconds_per_millisecond;
}

void parse_address_part(const std::string &part, LogEntry &entry) {
    const std::size_t arrow = part.find(" > ");
    if (arrow == std::string::npos) {
        return;
    }
    const std::string left = part.substr(0, arrow);
    const std::string right = part.substr(arrow + 3);

    const std::size_t left_colon = left.find(':');
    const std::size_t right_colon = right.find(':');
    if (left_colon == std::string::npos || right_colon == std::string::npos) {
        return;
    }
    if (left.find(':', left_colon + 1) != std::string::npos) {
        return;
    }

    const auto src = my::ipv4_from_text(left.substr(0, left_colon));
    const auto dst = my::ipv4_from_text(right.substr(0, right_colon));
    if (!src || !dst) {
        return;
    }
    entry.src_ip = *src;
    entry.dst_ip = *dst;
    entry.src_port = static_cast<std::uint16_t>(std::stoi(left.substr(left_colon + 1)));
    entry.dst_port = static_cast<std::uint16_t>(std::stoi(right.substr(right_colon + 1)));
}

void parse_field(const std::string &field, LogEntry &entry) {
    if (starts_with(field, "ttl=")) {
        entry.ttl = static_cast<std::uint8_t>(std::stoi(field.substr(4)));
    } else if (ends_with(field, " bytes")) {
        entry.bytes = static_cast<std::size_t>(std::stoul(field.substr(0, field.size() - 6)));
    } else if (field == "[truncated]") {
        return;
    } else if (starts_with(field, "TCP [") && ends_with(field, "]")) {
        entry.protocol = "TCP";
        entry.flags = field.substr(5, field.size() - 6);
    } else if (!field.empty()) {
        entry.protocol = field;
    }
}

LogEntry parse_line(const std::string &line) {
    const std::size_t separator = line.find("  ");
    if (separator == std::string::npos) {
        throw std::runtime_error("malformed log line: " + line);
    }

    LogEntry entry;
    entry.ts_us = parse_timestamp(line.substr(0, separator));

    const std::vector<std::string> fields = split_on_double_space(line.substr(separator + 2));
    if (fields.empty()) {
        throw std::runtime_error("malformed log line: " + line);
    }

    parse_address_part(fields[0], entry);
    for (std::size_t i = 1; i < fields.size(); ++i) {
        parse_field(fields[i], entry);
    }
    return entry;
}

}

std::vector<LogEntry> read_log(const std::string &path) {
    std::FILE *file = std::fopen(path.c_str(), "r");
    if (!file) {
        throw std::runtime_error("cannot open " + path);
    }

    std::vector<LogEntry> entries;
    char buf[1024];
    while (std::fgets(buf, sizeof buf, file) != nullptr) {
        std::string line(buf);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (line.size() < 5 || line[0] == ' ' || line[4] != '-') {
            continue;
        }
        entries.push_back(parse_line(line));
    }
    std::fclose(file);
    return entries;
}

}
