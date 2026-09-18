#pragma once

#include <cstddef>
#include <cstdint>

#include "my_func/bytes.hpp"

namespace sniffer {

class Cursor {
public:
    Cursor(const std::uint8_t *data, std::size_t len) noexcept
        : data_(data), len_(len) {}

    bool                ok() const noexcept { return !bad_; }
    std::size_t         remaining() const noexcept { return bad_ ? 0 : len_ - pos_; }
    const std::uint8_t *ptr() const noexcept { return data_ + pos_; }

    std::uint8_t u8() noexcept {
        if (!want(1)) return 0;
        const std::uint8_t value = my::read_u8(data_ + pos_);
        pos_ += 1;
        return value;
    }

    std::uint16_t u16() noexcept {
        if (!want(2)) return 0;
        const std::uint16_t value = my::read_u16be(data_ + pos_);
        pos_ += 2;
        return value;
    }

    std::uint32_t u32() noexcept {
        if (!want(4)) return 0;
        const std::uint32_t value = my::read_u32be(data_ + pos_);
        pos_ += 4;
        return value;
    }

    void copy(std::uint8_t *out, std::size_t count) noexcept {
        if (!want(count)) return;
        for (std::size_t i = 0; i < count; ++i) {
            out[i] = data_[pos_ + i];
        }
        pos_ += count;
    }

    void skip(std::size_t count) noexcept {
        if (want(count)) pos_ += count;
    }

private:
    bool want(std::size_t count) noexcept {
        if (bad_ || len_ - pos_ < count) {
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

}
