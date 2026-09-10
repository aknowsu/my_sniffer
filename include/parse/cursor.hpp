#pragma once

#include <cstddef>
#include <cstdint>

#include "my_func/my_func.hpp"

namespace sniffer {

// Bounds-checked forward cursor over a borrowed byte span. A parser reads its
// header fields from the cursor and leaves it positioned at the payload, ready
// for the next layer.
//
// It never throws and never reads out of range: an over-read marks the cursor
// "bad" (`ok()` becomes false) and returns 0. So a parser can read a whole
// header optimistically and check `ok()` once at the end — a truncated packet
// can't crash it.
class Cursor {
public:
    Cursor(const std::uint8_t *data, std::size_t len) noexcept
        : data_(data), len_(len) {}

    bool                ok() const noexcept { return !bad_; }
    std::size_t         remaining() const noexcept { return bad_ ? 0 : len_ - pos_; }
    const std::uint8_t *ptr() const noexcept { return data_ + pos_; }

    std::uint8_t u8() noexcept {
        if (!want(1)) return 0;
        const std::uint8_t v = my::read_u8(data_ + pos_);
        pos_ += 1;
        return v;
    }

    std::uint16_t u16() noexcept {
        if (!want(2)) return 0;
        const std::uint16_t v = my::read_u16be(data_ + pos_);
        pos_ += 2;
        return v;
    }

    std::uint32_t u32() noexcept {
        if (!want(4)) return 0;
        const std::uint32_t v = my::read_u32be(data_ + pos_);
        pos_ += 4;
        return v;
    }

    // Copy `n` raw bytes out (MAC addresses…) and advance.
    void copy(std::uint8_t *out, std::size_t n) noexcept {
        if (!want(n)) return;
        for (std::size_t i = 0; i < n; ++i) {
            out[i] = data_[pos_ + i];
        }
        pos_ += n;
    }

    void skip(std::size_t n) noexcept {
        if (want(n)) pos_ += n;
    }

private:
    bool want(std::size_t n) noexcept {
        if (bad_ || len_ - pos_ < n) {
            bad_ = true;
            return false;
        }
        return true;
    }

    const std::uint8_t *data_;
    std::size_t         len_;
    std::size_t         pos_ = 0;
    bool                bad_ = false;
};

} // namespace sniffer
