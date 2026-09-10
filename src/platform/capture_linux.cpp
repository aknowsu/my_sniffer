#include "capture.hpp"
#include "my_func/my_func.hpp"

#include <sys/socket.h>   // socket, recv, setsockopt, AF_PACKET, SOCK_RAW, SO_RCVTIMEO
#include <sys/time.h>     // struct timeval, gettimeofday
#include <unistd.h>       // close

#include <atomic>
#include <cerrno>
#include <cstring>        // strerror
#include <stdexcept>

namespace sniffer {

namespace {
constexpr std::uint16_t kEthPAll = 0x0003;   // ETH_P_ALL: capture every protocol
}

struct Capture::Impl {
    int               fd = -1;
    std::atomic<bool> running{false};
};

Capture::Capture(std::string /*iface*/) : impl_(nullptr) {
    const int fd = ::socket(AF_PACKET, SOCK_RAW, my::hton16(kEthPAll));
    if (fd < 0) {
        throw std::runtime_error(std::string("socket(AF_PACKET): ") +
                                 std::strerror(errno));
    }

    // Time recv() out every 200 ms so stop() is noticed even with no traffic.
    const timeval tv{0, 200000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    impl_ = new Impl;
    impl_->fd = fd;
}

Capture::~Capture() {
    if (impl_->fd >= 0) {
        ::close(impl_->fd);
    }
    delete impl_;
}

LinkType Capture::link_type() const noexcept { return LinkType::Ethernet; }

void Capture::run(const FrameHandler &on_frame) {
    std::uint8_t buf[65536];

    for (impl_->running = true; impl_->running;) {
        const ssize_t n = ::recv(impl_->fd, buf, sizeof buf, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;   // signal, or the recv timeout -> re-check running
            }
            throw std::runtime_error(std::string("recv: ") + std::strerror(errno));
        }

        timeval now{};
        ::gettimeofday(&now, nullptr);
        const Frame frame{buf, static_cast<std::size_t>(n),
                          static_cast<std::int64_t>(now.tv_sec) * 1000000 +
                              now.tv_usec};
        on_frame(frame);
    }
}

void Capture::stop() noexcept { impl_->running = false; }

} // namespace sniffer
