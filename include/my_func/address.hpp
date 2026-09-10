#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace my {

std::string                  ipv4_to_text(std::uint32_t addr);
std::optional<std::uint32_t> ipv4_from_text(std::string_view text);

std::string mac_to_text(const std::uint8_t mac[6]);
bool        mac_from_text(std::string_view text, std::uint8_t out[6]);

}
