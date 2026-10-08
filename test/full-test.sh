#!/bin/sh
# Smoke test: builds my_sniffer, then exercises normal mode, -v, -f, -w, -r
# and --analyse against real captured traffic. Needs capture privileges (see
# README.md's Running section) -- run as root, or setcap the binary first
# (scripts/setup-linux.sh does that).
set -e
cd "$(dirname "$0")/.."

BUILD_DIR="${1:-build}"
BIN="$BUILD_DIR/my_sniffer"
DURATION=3
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
SYNTHETIC_LOG="test/analyse-sample.log"
WHITELIST="test/whitelist.txt"

echo "== building =="
cmake -S . -B "$BUILD_DIR" >/dev/null
cmake --build "$BUILD_DIR" -j"$(nproc)" >/dev/null
[ -x "$BIN" ] || { echo "FAIL: build did not produce $BIN" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ] && ! getcap "$BIN" 2>/dev/null | grep -q cap_net_raw; then
    echo "FAIL: $BIN has no capture privileges." >&2
    echo "Run as root, or first: ./scripts/setup-linux.sh $BUILD_DIR" >&2
    exit 1
fi

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

echo "== 3) -f (filter) =="
OUT="$(timeout "$DURATION" "$BIN" -f "tcp or udp or icmp" || true)"
echo "$OUT" | grep -q "packets," || { echo "FAIL: no summary line"; echo "$OUT"; exit 1; }
echo "OK"

echo "== 4) -w (write log) =="
timeout "$DURATION" "$BIN" -w "$LOG" >/dev/null || true
[ -s "$LOG" ] || { echo "FAIL: $LOG is empty"; exit 1; }
grep -qE "^[0-9]{4}-[0-9]{2}-[0-9]{2} " "$LOG" || { echo "FAIL: $LOG has no timestamped line"; exit 1; }
echo "OK ($(wc -l < "$LOG") lines)"

echo "== 5) -r + --analyse =="
OUT="$("$BIN" -r "$LOG" --analyse)"
echo "$OUT" | grep -q "entries analysed" || { echo "FAIL: no analysis summary"; echo "$OUT"; exit 1; }
echo "OK"
echo "$OUT"

echo "== 6) --analyse detections (synthetic cases) =="
# test/analyse-sample.log is a crafted log, hand-built to trigger all 4
# detections regardless of what real traffic looks like (see its content:
# a traffic spike, a beaconing destination, UDP on port 80, and IPs outside
# test/whitelist.txt).
OUT="$("$BIN" -r "$SYNTHETIC_LOG" --analyse --whitelist "$WHITELIST")"
for kind in traffic_spike beaconing unknown_protocol foreign_ip; do
    echo "$OUT" | grep -q "\[$kind\]" || { echo "FAIL: [$kind] was not detected"; echo "$OUT"; exit 1; }
done
echo "OK (all 4 detections fired on crafted input)"

echo "== ALL TESTS PASSED =="
