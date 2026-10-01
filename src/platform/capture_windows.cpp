#include "capture.hpp"

#include <stdexcept>

namespace sniffer {

struct Capture::Impl {};

Capture::Capture() : impl_(nullptr) {
    throw std::runtime_error("Windows capture backend not implemented yet");
}

Capture::~Capture() {
    delete impl_;
}

LinkType Capture::link_type() const noexcept {
    return LinkType::RawIPv4;
}

void Capture::run(const FrameHandler &) {}

void Capture::stop() noexcept {}

}
