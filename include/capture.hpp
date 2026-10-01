#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace sniffer {

enum class LinkType {
    Ethernet,
    RawIPv4,
};

struct Frame {
    const std::uint8_t *data;
    std::size_t len;
    std::int64_t ts_us;
};

using FrameHandler = std::function<void(const Frame &)>;

class Capture {
public:
    Capture();
    ~Capture();

    Capture(const Capture &) = delete;
    Capture &operator=(const Capture &) = delete;

    LinkType link_type() const noexcept;
    void run(const FrameHandler &on_frame);
    void stop() noexcept;

private:
    struct Impl;
    Impl *impl_;
};

}
