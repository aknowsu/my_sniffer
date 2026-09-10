#pragma once

#include <cstdio>

#include "capture.hpp"
#include "parse/packet.hpp"

namespace sniffer {

struct ViewOptions {
    bool verbose = false;
};

void print_packet(std::FILE *out, const Frame &frame, const ParsedPacket &pkt,
                  const ViewOptions &opts);

}
