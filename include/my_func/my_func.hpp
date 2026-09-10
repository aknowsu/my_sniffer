#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace my {
    // --- byte order --------------------------------------------------------
    std::uint16_t bswap16(std::uint16_t v);
    std::uint32_t bswap32(std::uint32_t v);
    std::uint16_t hton16(std::uint16_t v);
    std::uint32_t hton32(std::uint32_t v);
    std::uint16_t ntoh16(std::uint16_t v);
    std::uint32_t ntoh32(std::uint32_t v);

    // --- address conversion ---------------------------------------------—--
    // IPv4 address as a host-order uint32: high byte = first dotted octet
    // (0xC0A80101 == "192.168.1.1").
    std::string ipv4_to_text(std::uint32_t addr);

    // Strict: exactly four 0-255 octets, no leading zeros, no extra chars.
    // std::nullopt otherwise.
    std::optional<std::uint32_t> ipv4_from_text(std::string_view text);

    // 6 raw bytes -> "aa:bb:cc:dd:ee:ff".
    std::string mac_to_text(const std::uint8_t mac[6]);

    // --- display -------------------------------------------------------—---
    // Canonical hexdump (offset, 16 bytes hex, ASCII gutter, '\n' per line).
    // Empty input -> "". `base` is added to the printed offset.
    std::string hexdump(const std::uint8_t *data, std::size_t len, std::size_t base = 0);
} // namespace my
