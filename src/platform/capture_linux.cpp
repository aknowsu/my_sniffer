#include "capture.hpp"

#include <stdexcept>

namespace sniffer {

struct Capture::Impl {};

Capture::Capture(std::string /*iface*/) : impl_(nullptr) {
    throw std::runtime_error("Linux capture backend not implemented yet");
}
Capture::~Capture() { delete impl_; }
LinkType Capture::link_type() const noexcept { return LinkType::Ethernet; }
void Capture::run(const FrameHandler & /*on_frame*/) {}
void Capture::stop() noexcept {}

} // namespace sniffer
