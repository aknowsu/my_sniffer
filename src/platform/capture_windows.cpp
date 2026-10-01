#include "capture.hpp"

#include <windows.h>
#include <Packet32.h>

#include <atomic>
#include <cstring>
#include <stdexcept>
#include <string>

namespace sniffer {
namespace {

constexpr int read_timeout_ms = 200;
constexpr std::size_t capture_buffer_size = 65536;

std::string find_first_adapter() {
    char names[8192];
    ULONG size = sizeof names;
    if (!PacketGetAdapterNames(names, &size)) {
        throw std::runtime_error("PacketGetAdapterNames failed");
    }
    if (names[0] == '\0') {
        throw std::runtime_error("no capture adapter found");
    }
    return std::string(names);
}

}

struct Capture::Impl {
    LPADAPTER adapter = nullptr;
    LPPACKET packet = nullptr;
    std::uint8_t *buffer = nullptr;
    std::atomic<bool> running{false};
};

Capture::Capture() : impl_(nullptr) {
    const std::string adapter_name = find_first_adapter();

    LPADAPTER adapter = PacketOpenAdapter(const_cast<char *>(adapter_name.c_str()));
    if (adapter == nullptr || adapter->hFile == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("PacketOpenAdapter failed for " + adapter_name);
    }

    PacketSetReadTimeout(adapter, read_timeout_ms);
    PacketSetBuff(adapter, static_cast<int>(capture_buffer_size));

    LPPACKET packet = PacketAllocatePacket();
    if (packet == nullptr) {
        PacketCloseAdapter(adapter);
        throw std::runtime_error("PacketAllocatePacket failed");
    }

    std::uint8_t *buffer = new std::uint8_t[capture_buffer_size];
    PacketInitPacket(packet, buffer, static_cast<UINT>(capture_buffer_size));

    impl_ = new Impl;
    impl_->adapter = adapter;
    impl_->packet = packet;
    impl_->buffer = buffer;
}

Capture::~Capture() {
    PacketFreePacket(impl_->packet);
    PacketCloseAdapter(impl_->adapter);
    delete[] impl_->buffer;
    delete impl_;
}

LinkType Capture::link_type() const noexcept {
    return LinkType::Ethernet;
}

void Capture::run(const FrameHandler &on_frame) {
    for (impl_->running = true; impl_->running;) {
        if (!PacketReceivePacket(impl_->adapter, impl_->packet, TRUE)) {
            throw std::runtime_error("PacketReceivePacket failed");
        }

        const std::uint8_t *data = static_cast<const std::uint8_t *>(impl_->packet->Buffer);
        const std::size_t total = impl_->packet->ulBytesReceived;
        std::size_t offset = 0;

        while (offset + sizeof(bpf_hdr) <= total) {
            const bpf_hdr *header = reinterpret_cast<const bpf_hdr *>(data + offset);
            if (header->bh_caplen == 0) {
                break;
            }

            const std::uint8_t *frame_data = data + offset + header->bh_hdrlen;
            const std::int64_t ts_us = static_cast<std::int64_t>(header->bh_tstamp.tv_sec) * 1'000'000 +
                                       header->bh_tstamp.tv_usec;
            const Frame frame{frame_data, header->bh_caplen, ts_us};
            on_frame(frame);

            const std::size_t record_len = header->bh_hdrlen + header->bh_caplen;
            offset += (record_len + 3) & ~static_cast<std::size_t>(3);
        }
    }
}

void Capture::stop() noexcept {
    impl_->running = false;
}

}
