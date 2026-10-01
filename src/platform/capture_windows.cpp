#include "capture.hpp"

#include <Packet32.h>

#include <atomic>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace sniffer {
namespace {

constexpr std::size_t adapter_names_size = 8192;
constexpr char loopback_adapter_name[] = "\\Device\\NPF_Loopback";
constexpr int read_timeout_ms = 10;
constexpr int driver_buffer_size = 1024 * 1024;
constexpr std::size_t capture_buffer_size = 256 * 1024;
constexpr std::size_t bpf_alignment = 4;
constexpr std::int64_t microseconds_per_second = 1'000'000;

struct Adapter {
    LPADAPTER handle = nullptr;
    LPPACKET packet = nullptr;
    std::uint8_t *buffer = nullptr;
};

std::vector<std::string> list_adapter_names() {
    char names[adapter_names_size];
    ULONG size = sizeof names;
    if (!PacketGetAdapterNames(names, &size)) {
        throw std::runtime_error("PacketGetAdapterNames failed");
    }

    std::vector<std::string> list;
    for (const char *name = names; *name != '\0'; name += std::strlen(name) + 1) {
        list.emplace_back(name);
    }
    return list;
}

bool open_adapter(const std::string &name, Adapter &adapter) {
    adapter.handle = PacketOpenAdapter(name.c_str());
    if (adapter.handle == nullptr) {
        return false;
    }

    adapter.packet = PacketAllocatePacket();
    if (adapter.packet == nullptr) {
        PacketCloseAdapter(adapter.handle);
        return false;
    }

    PacketSetReadTimeout(adapter.handle, read_timeout_ms);
    PacketSetBuff(adapter.handle, driver_buffer_size);
    adapter.buffer = new std::uint8_t[capture_buffer_size];
    PacketInitPacket(adapter.packet, adapter.buffer, static_cast<UINT>(capture_buffer_size));
    return true;
}

void close_adapter(Adapter &adapter) {
    PacketFreePacket(adapter.packet);
    PacketCloseAdapter(adapter.handle);
    delete[] adapter.buffer;
}

void deliver_frames(const Adapter &adapter, const FrameHandler &on_frame) {
    const std::uint8_t *data = static_cast<const std::uint8_t *>(adapter.packet->Buffer);
    const std::size_t total = adapter.packet->ulBytesReceived;
    std::size_t offset = 0;

    while (offset + sizeof(bpf_hdr) <= total) {
        const bpf_hdr *header = reinterpret_cast<const bpf_hdr *>(data + offset);
        if (header->bh_caplen == 0) {
            break;
        }

        const std::int64_t ts_us = static_cast<std::int64_t>(header->bh_tstamp.tv_sec) * microseconds_per_second +
                                   header->bh_tstamp.tv_usec;
        const Frame frame{data + offset + header->bh_hdrlen, header->bh_caplen, ts_us};
        on_frame(frame);

        const std::size_t record_len = header->bh_hdrlen + header->bh_caplen;
        offset += (record_len + bpf_alignment - 1) & ~(bpf_alignment - 1);
    }
}

}

struct Capture::Impl {
    std::vector<Adapter> adapters;
    std::atomic<bool> running{false};
};

Capture::Capture() : impl_(nullptr) {
    std::vector<Adapter> adapters;
    for (const std::string &name : list_adapter_names()) {
        Adapter adapter;
        if (name != loopback_adapter_name && open_adapter(name, adapter)) {
            adapters.push_back(adapter);
        }
    }
    if (adapters.empty()) {
        throw std::runtime_error("no capture adapter could be opened");
    }

    impl_ = new Impl;
    impl_->adapters = adapters;
}

Capture::~Capture() {
    for (Adapter &adapter : impl_->adapters) {
        close_adapter(adapter);
    }
    delete impl_;
}

LinkType Capture::link_type() const noexcept {
    return LinkType::Ethernet;
}

void Capture::run(const FrameHandler &on_frame) {
    for (impl_->running = true; impl_->running;) {
        for (const Adapter &adapter : impl_->adapters) {
            if (!PacketReceivePacket(adapter.handle, adapter.packet, TRUE)) {
                throw std::runtime_error("PacketReceivePacket failed");
            }
            deliver_frames(adapter, on_frame);
        }
    }
}

void Capture::stop() noexcept {
    impl_->running = false;
}

}
