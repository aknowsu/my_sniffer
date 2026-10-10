#!/bin/sh
# Installs build dependencies if missing, builds my_sniffer (Release), and
# grants it capture capability via setcap, so it can run without sudo.
# See README.md for the equivalent manual steps.
set -e

if ! command -v cmake >/dev/null 2>&1 || ! command -v make >/dev/null 2>&1 || \
   ! command -v setcap >/dev/null 2>&1 || \
   { ! command -v g++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1; }; then
    echo "Installing build dependencies (cmake, g++, make, setcap)..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y cmake g++ make libcap2-bin
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y cmake gcc-c++ make libcap
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --needed --noconfirm cmake gcc make libcap
    else
        echo "No known package manager found. Install cmake, make, a C++20 compiler, and libcap (for setcap) manually, then re-run this script." >&2
        exit 1
    fi
fi

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
