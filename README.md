# my_sniffer

A cross-platform network packet sniffer built from scratch: raw capture,
protocol parsing, filtering and behavioural analysis — no networking library.

> **Status: early development.** The build system and architecture are in
> place; capture and parsing are not implemented yet. See the
> [roadmap](#roadmap).

## Why "from scratch"

Every layer between the wire and an application is handled by this project
itself — raw socket capture, Ethernet/IP/transport parsing, filtering and
analysis. No `libpcap`, no packet-parsing or protocol-decoding library.
Libraries unrelated to networking (CLI parsing, logging, tests) may be used.

## Features

| Capability | Status |
| --- | --- |
| Raw capture — Linux (`PF_PACKET` / `SOCK_RAW`) | planned |
| Raw capture — Windows (raw socket + `SIO_RCVALL`) | planned |
| Parsing: Ethernet, IPv4, TCP, UDP | planned |
| Packet viewer (summary + hexdump) | planned |
| User-defined filter / search language | planned |
| Behavioural analysis (spikes, beaconing, anomalies) | planned |
| Capture logging & storage | planned |
| Bonus: ARP / ICMP / IPv6, DNS / HTTP, sniffer detection, TUI | planned |

## Supported platforms

- **Linux** — primary. `AF_PACKET` raw sockets, full Ethernet frames.
- **Windows** — second platform. `SOCK_RAW` + `WSAIoctl(SIO_RCVALL)`.

Because Npcap / WinPcap are networking libraries (forbidden), the Windows
backend uses plain raw sockets. That has consequences: **no Ethernet
header, no ARP, IPv4 only, requires Administrator**. On Windows the parser
therefore starts at the IPv4 layer (`LinkType::RawIPv4`). Whether this
satisfies the subject's "Ethernet" requirement on the second OS is to be
confirmed with the teaching team.

## Requirements

- A C++20 compiler (GCC ≥ 11 / Clang ≥ 14 on Linux, MSVC ≥ 19.3 on Windows)
- CMake ≥ 3.16
- Elevated privileges to capture (see [Running](#running))

## Build

```sh
cmake -S . -B build
cmake --build build
```

Debug builds (the default) enable AddressSanitizer / UBSan on GCC/Clang.
For a release build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

On Windows, generate for your toolchain, e.g.:

```pwsh
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

## Install

```sh
cmake --install build --prefix /usr/local
```

Installs the `my_sniffer` binary under `<prefix>/bin`.

## Running

Capturing raw traffic needs elevated privileges.

**Linux:**

```sh
# Option A — grant the capability once (recommended)
sudo setcap cap_net_raw,cap_net_admin+ep ./build/my_sniffer
./build/my_sniffer <interface>

# Option B — run as root
sudo ./build/my_sniffer <interface>
```

**Windows:** run from an **Administrator** terminal.

```pwsh
.\build\Release\my_sniffer.exe <interface-ip>
```

### Usage

```
my_sniffer [options] [interface]

  -i, --interface <name>   interface to capture on (default: first up)
  -f, --filter <expr>      filter expression (see docs/filter.md)
  -w, --write <file>       save captured packets to <file>
  -r, --read <file>        replay / analyse a saved capture
  -v, --verbose            per-packet hexdump
      --analyse            run the behavioural analysis engine
  -h, --help               show help and exit
  -V, --version            show version and exit
```

The command line is parsed today; capture and parsing are still stubbed
(`my_sniffer` prints the resolved options and exits).

## Project layout

```
my_sniffer/
├── CMakeLists.txt          build + install, per-OS capture backend
├── include/
│   ├── capture.hpp         common capture interface
│   └── cli.hpp             command-line options
├── src/
│   ├── main.cpp            entry point
│   ├── cli.cpp             option parsing / --help
│   └── platform/
│       ├── capture_linux.cpp     AF_PACKET / SOCK_RAW backend
│       └── capture_windows.cpp   raw socket + SIO_RCVALL backend
```

## Roadmap

Work is tracked as GitHub milestones, following the subject's steps:

| Milestone | Scope |
| --- | --- |
| M0 — Project setup | build system, repo hygiene |
| M1 — Step 0: function helpers | binary parsing / conversion helpers |
| M2 — Step 1: capture & viewer | raw capture + Ethernet/IPv4/TCP/UDP + display |
| M3 — Step 2: filter & search | user-defined filtering, live and post-capture |
| M4 — Step 3: analysis engine | anomaly & beaconing detection, logging |
| M5 — Step 4: packaging | install scripts, versioning, documentation |
| M6 — Bonus | extra protocols, app-layer, sniffer detection, TUI |

Detailed tasks: <https://github.com/aknowsu/my_sniffer/issues>