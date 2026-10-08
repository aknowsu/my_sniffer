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
trap 'rm -f "$LOG"' EXIT

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

echo "== ALL TESTS PASSED =="
