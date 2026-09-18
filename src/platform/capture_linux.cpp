#include "capture.hpp"

#include "my_func/byteorder.hpp"

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>

namespace sniffer {
namespace {

constexpr std::uint16_t eth_p_all = 0x0003;
constexpr int poll_timeout_ms = 200;
constexpr std::size_t capture_buffer_size = 65536;
constexpr std::int64_t microseconds_per_second = 1'000'000;

int resolve_ifindex(int fd, const std::string &iface) {
    if (iface.size() >= IFNAMSIZ) {
        throw std::runtime_error("interface name too long: " + iface);
    }
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        throw std::runtime_error("unknown interface '" + iface + "': " + std::strerror(errno));
    }
    return ifr.ifr_ifindex;
}

}

struct Capture::Impl {
    int               fd = -1;
    std::atomic<bool> running{false};
};

Capture::Capture(std::string iface) : impl_(nullptr) {
    const int fd = ::socket(AF_PACKET, SOCK_RAW, my::hton16(eth_p_all));
    if (fd < 0) {
        throw std::runtime_error(std::string("socket(AF_PACKET): ") +
                                 std::strerror(errno));
    }

    if (!iface.empty()) {
        try {
            sockaddr_ll addr{};
            addr.sll_family = AF_PACKET;
            addr.sll_protocol = my::hton16(eth_p_all);
            addr.sll_ifindex = resolve_ifindex(fd, iface);
            if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof addr) < 0) {
                throw std::runtime_error(std::string("bind: ") + std::strerror(errno));
            }
        } catch (...) {
            ::close(fd);
            throw;
        }
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

LinkType Capture::link_type() const noexcept {
    return LinkType::Ethernet;
}

void Capture::run(const FrameHandler &on_frame) {
    std::uint8_t buf[capture_buffer_size];
    pollfd       pfd{};
    pfd.fd = impl_->fd;
    pfd.events = POLLIN;

    for (impl_->running = true; impl_->running;) {
        if (::poll(&pfd, 1, poll_timeout_ms) <= 0) {
            continue;
        }

        const ssize_t received = ::recv(impl_->fd, buf, sizeof buf, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(std::string("recv: ") + std::strerror(errno));
        }

        timeval now{};
        ::gettimeofday(&now, nullptr);
        const Frame frame{buf, static_cast<std::size_t>(received),
                          static_cast<std::int64_t>(now.tv_sec) * microseconds_per_second +
                              now.tv_usec};
        on_frame(frame);
    }
}

void Capture::stop() noexcept {
    impl_->running = false;
}

}
