#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTRL_BIN="$ROOT_DIR/wemo_ctrl/wemo_ctrl"
HOST="127.0.0.1"
PORT="49153"
LOG_FILE="/tmp/wemo_ipc_negative.log"

pkill -x wemo_ctrl 2>/dev/null || true
sleep 0.2

if [[ ! -x "$CTRL_BIN" ]]; then
  echo "missing binary: $CTRL_BIN" >&2
  exit 1
fi

cleanup() {
  if [[ -n "${CTRL_PID:-}" ]]; then
    kill "$CTRL_PID" 2>/dev/null || true
    wait "$CTRL_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

WEMO_LOG_MODE=quiet "$CTRL_BIN" >"$LOG_FILE" 2>&1 &
CTRL_PID=$!

for _ in $(seq 1 80); do
  if python3 - <<'PY'
import socket
try:
    s = socket.create_connection(("127.0.0.1", 49153), timeout=0.2)
    s.close()
    raise SystemExit(0)
except Exception:
    raise SystemExit(1)
PY
  then
    break
  fi
  sleep 0.1
done

if ! kill -0 "$CTRL_PID" 2>/dev/null; then
  echo "wemo_ctrl failed to start" >&2
  tail -n 40 "$LOG_FILE" >&2 || true
  exit 1
fi

python3 - <<'PY'
import socket
import struct
import time

HOST = "127.0.0.1"
PORT = 49153
CMD_PROTO = 1000

# Linux/x86_64 in this project; native int framing for ipc header.
HDR_FMT = "<iii"
PROTO_FMT = "<IHHIIiiiI"

def send_fragments(parts, pause=0.02):
    s = socket.create_connection((HOST, PORT), timeout=1.0)
    for p in parts:
        if p:
            s.sendall(p)
            time.sleep(pause)
    s.close()

# 1) partial header only
send_fragments([b"\x01\x02\x03"])

# 2) invalid oversized payload length
hdr = struct.pack(HDR_FMT, 1, 5, 999999)
send_fragments([hdr])

# 3) invalid proto magic/version
proto = struct.pack(PROTO_FMT, 0x12345678, 999, 1, 0x11111111, 1, 5, 7, 0, 0)
hdr = struct.pack(HDR_FMT, 7, CMD_PROTO, len(proto))
send_fragments([hdr + proto])

# 4) truncated payload body
hdr = struct.pack(HDR_FMT, 7, CMD_PROTO, 64)
send_fragments([hdr, b"\x00" * 8])

# 5) valid but unsupported legacy command frame
hdr = struct.pack(HDR_FMT, 1, 9999, 0)
send_fragments([hdr])
PY

sleep 0.5
if ! kill -0 "$CTRL_PID" 2>/dev/null; then
  echo "FAIL: wemo_ctrl crashed under malformed IPC frames" >&2
  tail -n 80 "$LOG_FILE" >&2 || true
  exit 1
fi

echo "PASS: IPC negative tests completed; daemon remained alive"
