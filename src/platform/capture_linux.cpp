#include "capture.hpp"
#include "my_func/my_func.hpp"

#include <sys/socket.h>   // socket, recv, AF_PACKET, SOCK_RAW
#include <poll.h>
#include <unistd.h>       // close
#include <ctime>          // clock_gettime
#include <atomic>
#include <cerrno>
#include <cstring>        // strerror
#include <stdexcept>

// Linux capture backend. Raw L2 capture by hand, no libpcap.
//   socket(AF_PACKET, SOCK_RAW) delivers the full Ethernet frame.
//   No bind() yet -> captures on every interface (the -i option comes later).

namespace sniffer {

namespace {
constexpr std::uint16_t kEthPAll     = 0x0003;   // ETH_P_ALL: every protocol
constexpr int           kPollTimeout = 200;      // ms; lets stop() be responsive
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
        if (::poll(&pfd, 1, kPollTimeout) <= 0) {
            continue;   // timeout or signal -> re-check running
        }

        const ssize_t n = ::recv(impl_->fd, buf, sizeof buf, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("recv: ") + std::strerror(errno));
        }

        timespec now{};
        ::clock_gettime(CLOCK_REALTIME, &now);
        const Frame frame{buf, static_cast<std::size_t>(n),
                          static_cast<std::int64_t>(now.tv_sec) * 1000000 +
                              now.tv_nsec / 1000};
        on_frame(frame);
    }
}

void Capture::stop() noexcept { impl_->running = false; }

} // namespace sniffer
