#!/bin/sh
# Smoke test: builds my_sniffer, then exercises normal mode, -v, -w, -r and
# --analyse against real captured traffic. Needs capture privileges (see
# README.md's Running section) -- run as root, or setcap the binary first
# (scripts/install-linux.sh does that).
set -e

BUILD_DIR="${1:-build}"
BIN="$BUILD_DIR/my_sniffer"
DURATION=3
LOG="$(mktemp)"
SYNTHETIC_LOG="$(mktemp)"
WHITELIST="$(mktemp)"
trap 'rm -f "$LOG" "$SYNTHETIC_LOG" "$WHITELIST"' EXIT

echo "== building =="
cmake -S . -B "$BUILD_DIR" >/dev/null
cmake --build "$BUILD_DIR" -j"$(nproc)" >/dev/null
[ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ] && ! getcap "$BIN" 2>/dev/null | grep -q cap_net_raw; then
    echo "FAIL: $BIN has no capture privileges." >&2
    echo "Run as root, or first: ./scripts/install-linux.sh $BUILD_DIR" >&2
    exit 1
fi

# Background traffic so there is always something to capture.
( ping -c 10 1.1.1.1 >/dev/null 2>&1 & )
( curl -s -o /dev/null https://example.com 2>/dev/null & )

echo "== 1) normal mode =="
OUT="$(timeout "$DURATION" "$BIN" || true)"
echo "$OUT" | grep -q "packets," || { echo "FAIL: no summary line"; echo "$OUT"; exit 1; }
echo "OK"

echo "== 2) -v (verbose) =="
OUT="$(timeout "$DURATION" "$BIN" -v || true)"
echo "$OUT" | grep -q "packets," || { echo "FAIL: no summary line"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q "ttl=" || { echo "FAIL: no decoded field in -v output"; exit 1; }
echo "OK"

echo "== 3) -w (write log) =="
timeout "$DURATION" "$BIN" -w "$LOG" >/dev/null || true
[ -s "$LOG" ] || { echo "FAIL: $LOG is empty"; exit 1; }
grep -qE "^[0-9]{4}-[0-9]{2}-[0-9]{2} " "$LOG" || { echo "FAIL: $LOG has no timestamped line"; exit 1; }
echo "OK ($(wc -l < "$LOG") lines)"

echo "== 4) -r + --analyse =="
OUT="$("$BIN" -r "$LOG" --analyse)"
echo "$OUT" | grep -q "entries analysed" || { echo "FAIL: no analysis summary"; echo "$OUT"; exit 1; }
echo "OK"
echo "$OUT"

echo "== 5) --analyse detections (synthetic cases) =="
{
    # traffic_spike: 20 quiet seconds then one huge one, same source
    for s in $(seq 0 19); do
        printf '2025-09-23 17:00:%02d.000  10.0.0.9:51000 > 8.8.8.8:443  TCP [ACK]  ttl=64  100 bytes\n' "$s"
    done
    printf '2025-09-23 17:00:20.000  10.0.0.9:51000 > 8.8.8.8:443  TCP [ACK]  ttl=64  1000000 bytes\n'

    # beaconing: 5 connection attempts to the same destination, 10s apart
    for s in 0 10 20 30 40; do
        printf '2025-09-23 17:01:%02d.000  10.0.0.9:52000 > 203.0.113.50:9999  TCP [SYN]  ttl=64  60 bytes\n' "$s"
    done

    # unknown_protocol: UDP on port 80, which should be TCP (HTTP)
    printf '2025-09-23 17:02:00.000  10.0.0.9:53000 > 93.184.216.2:80  UDP  ttl=64  60 bytes\n'
} > "$SYNTHETIC_LOG"
# foreign_ip: none of the destinations above are in this whitelist
echo "192.168.0.0/16" > "$WHITELIST"

OUT="$("$BIN" -r "$SYNTHETIC_LOG" --analyse --whitelist "$WHITELIST")"
for kind in traffic_spike beaconing unknown_protocol foreign_ip; do
    echo "$OUT" | grep -q "\[$kind\]" || { echo "FAIL: [$kind] was not detected"; echo "$OUT"; exit 1; }
done
echo "OK (all 4 detections fired on crafted input)"

echo "== ALL TESTS PASSED =="
