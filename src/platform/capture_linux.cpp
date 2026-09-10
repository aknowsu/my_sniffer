#include "capture.hpp"
#include "my_func/my_func.hpp"

#include <sys/socket.h>   // socket, recv, AF_PACKET, SOCK_RAW
#include <poll.h>         // poll — generic fd wait (not networking)
#include <sys/time.h>     // gettimeofday, timeval
#include <unistd.h>       // close

#include <atomic>
#include <cerrno>
#include <cstring>        // strerror
#include <stdexcept>

namespace sniffer {

namespace {
constexpr std::uint16_t kEthPAll     = 0x0003;   // ETH_P_ALL: every protocol
constexpr int           kPollTimeout = 200;      // ms; safety net for stop()
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
    pollfd       pfd{};
    pfd.fd     = impl_->fd;
    pfd.events = POLLIN;

    for (impl_->running = true; impl_->running;) {
        // A signal interrupts poll() (EINTR); the timeout is just a safety
        // net for the tiny race where stop() lands right before this call.
        if (::poll(&pfd, 1, kPollTimeout) <= 0) {
            continue;   // timeout or EINTR -> re-check running
        }

        const ssize_t n = ::recv(impl_->fd, buf, sizeof buf, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
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
