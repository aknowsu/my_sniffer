#!/bin/sh
# Builds my_sniffer (Release) and grants it capture capability via setcap,
# so it can run without sudo. See README.md for the equivalent manual steps.
set -e

BUILD_DIR="${1:-build}"

cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR"

BINARY="$BUILD_DIR/my_sniffer"

if [ "$(id -u)" -eq 0 ]; then
    echo "Running as root: skipping setcap, run $BINARY directly."
else
    echo "Granting cap_net_raw,cap_net_admin to $BINARY (sudo needed once):"
    sudo setcap cap_net_raw,cap_net_admin+ep "$BINARY"
fi

echo "Build complete: $BINARY"
