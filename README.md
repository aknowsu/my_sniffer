# my_sniffer

A cross-platform network packet sniffer built from scratch: raw capture,
protocol parsing, filtering and behavioural analysis — no networking library.

## Why "from scratch"

Every layer between the wire and an application is handled by this project
itself — raw socket capture, Ethernet/IP/transport parsing, filtering and
analysis. No `libpcap`, no packet-parsing or protocol-decoding library, no
`<arpa/inet.h>`-style address helpers. The only system headers used are the
minimal OS/kernel plumbing required to open a raw socket at all (`socket`,
`poll`) — never anything that parses or resolves for you.
Libraries unrelated to networking (CLI parsing, logging, tests) may be used.

## What it does

Raw capture off the wire, decoding of Ethernet (with VLAN tags), IPv4, TCP
and UDP with checksum verification, a packet viewer (summary line, per-field
detail, hexdump), a filter expression language (`-f`) to only display
matching packets (see [below](#filter-language)), a text log (`-w`), and a
behavioural analysis engine over a replayed log (`-r --analyse`, see
[below](#analysis)).

## Supported platforms

- **Linux** — capture backend implemented and tested (`AF_PACKET` / `SOCK_RAW`).
- **Windows** — capture backend implemented via Npcap's low-level driver API
  (`Packet32.h`), for raw capture only — all parsing stays our own code.
  Not yet verified on a real Windows machine.

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
./build/my_sniffer

# Option B — run as root
sudo ./build/my_sniffer
```

Capture always listens on every interface — there is no way to target a
single one.

**Windows:** run from an Administrator terminal. Requires
[Npcap](https://npcap.com/#download) installed on the machine, and its SDK
available at build time (see [Build](#build)).

### Usage

```
my_sniffer [options]

  -f, --filter <expr>      only show packets matching <expr> (see below)
  -w, --write <file>       log the displayed packets to <file> (see below)
  -r, --read <file>        read packets back from a file written by -w,
                            only used together with --analyse
  -v, --verbose            print every decoded field + a hexdump per packet
      --decoded-only       hide packets whose protocol wasn't decoded
      --analyse            run the behavioural analysis engine over the
                            capture given with -r (requires -r, see below)
      --whitelist <file>   one IP or CIDR per line: destinations allowed;
                            used with --analyse to flag anything else
  -h, --help               show help and exit
  -V, --version            show version and exit
```

## Logging

`-w <file>` writes every displayed packet to `<file>` (created or truncated),
in the same layout as the screen — one summary line per packet, or the full
per-field detail and hexdump with `-v` — each prefixed with its UTC time to
the millisecond:

```
2025-09-23 17:00:00.123  192.168.1.10:54321 > 93.184.216.34:443  TCP [SYN]  ttl=64  54 bytes
```

`-f` and `--decoded-only` apply to the log too: only packets that pass are
written. The log is flushed after each packet.

## Analysis

`-r <file> --analyse` reads back a file written by `-w` and runs a set of
behavioural detections over it — no live capture, no privileges needed:

```
my_sniffer -r capture.log --analyse
my_sniffer -r capture.log --analyse --whitelist allowed.txt
```

| Detection | Flags when |
| --- | --- |
| Traffic spikes | an IP's bytes/second jumps far above its own usual volume |
| Beaconing | a destination is contacted at suspiciously regular intervals |
| Unknown protocol on standard port | traffic on port 22/80/8080 isn't TCP |
| Foreign IP (needs `--whitelist`) | a destination isn't covered by any entry in the whitelist |

`--whitelist <file>` is optional — one IPv4 address or CIDR range per line.
Without it, the foreign-IP detection is simply skipped, not assumed.

## Filter language

`-f <expr>` only prints packets matching `<expr>`. Matching is done after
parsing, against the already-decoded fields (same ones `-v` shows) — an
invalid expression is rejected at startup with a message pointing at the
offending part, before any capture starts.

```
my_sniffer -f "tcp and port 443"
my_sniffer -f "udp or icmp"
my_sniffer -f "not (port 22 or port 3389)"
my_sniffer -f "net 192.168.0.0/16 and not port 22"
my_sniffer -f "len > 1400"
my_sniffer -f "tcp.flags has syn"
```

| Predicate | Matches |
| --- | --- |
| `tcp`, `udp`, `icmp`, `arp`, `ip` | the packet's protocol |
| `port N`, `src port N`, `dst port N` | a TCP/UDP port |
| `host A`, `src host A`, `dst host A` | an IPv4 address |
| `net A/M`, `src net A/M`, `dst net A/M` | an IPv4 CIDR range |
| `len (> \| < \| ==) N` | the captured frame length |
| `tcp.flags has <flag>` | a TCP flag (`syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr`, `ns`) |

Combine predicates with `and`, `or`, `not` and parentheses; `not` binds
tighter than `and`, which binds tighter than `or`.

## Project layout

```
my_sniffer/
├── CMakeLists.txt          build + install, per-OS capture backend
├── include/
│   ├── capture.hpp         common capture interface (PImpl)
│   ├── cli.hpp             command-line options
│   ├── viewer.hpp          packet display
│   ├── log.hpp             -w's text format read back into LogEntry records
│   ├── my_func/            byte-order, buffer reads, addresses, checksums, hexdump
│   ├── parse/              cursor + one header per protocol layer
│   ├── filter/             tokenizer, postfix AST, Filter
│   └── analyse/            behavioural detections over a replayed capture
└── src/
    ├── main.cpp            entry point — wires capture, filter, parsing, display
    ├── cli.cpp             option parsing / --help
    ├── viewer.cpp           packet display
    ├── log.cpp              parses -w's output back into LogEntry records
    ├── my_func/            one file per helper function
    ├── parse/               one file per protocol layer + the orchestrator
    ├── filter/               parse.cpp (reads the expression) / match.cpp (tests a packet)
    ├── analyse/              one file per detection
    └── platform/
        ├── capture_linux.cpp     AF_PACKET / SOCK_RAW backend
        └── capture_windows.cpp   Npcap (Packet32.h) backend
```
