#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTRL_BIN="$ROOT_DIR/wemo_ctrl/wemo_ctrl"
CLIENT_BIN="$ROOT_DIR/wemo_client/wemo_client"
LOG_FILE="/tmp/wemo_fault_injection.log"

cleanup() {
  if [[ -n "${CTRL_PID:-}" ]]; then
    kill "$CTRL_PID" 2>/dev/null || true
    wait "$CTRL_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ ! -x "$CTRL_BIN" || ! -x "$CLIENT_BIN" ]]; then
  echo "missing binaries; build first" >&2
  exit 1
fi

pkill -x wemo_ctrl 2>/dev/null || true
sleep 0.2
for _ in $(seq 1 20); do
  if python3 - <<'PY'
import socket
try:
    s=socket.create_connection(("127.0.0.1",49153),timeout=0.1)
    s.close()
    raise SystemExit(1)
except Exception:
    raise SystemExit(0)
PY
  then
    break
  fi
  pkill -x wemo_ctrl 2>/dev/null || true
  sleep 0.1
done

for attempt in 1 2 3; do
  WEMO_LOG_MODE=quiet "$CTRL_BIN" >"$LOG_FILE" 2>&1 &
  CTRL_PID=$!
  sleep 2
  if kill -0 "$CTRL_PID" 2>/dev/null; then
    break
  fi
  kill "$CTRL_PID" 2>/dev/null || true
  wait "$CTRL_PID" 2>/dev/null || true
  unset CTRL_PID
  pkill -x wemo_ctrl 2>/dev/null || true
  sleep 0.5
done

if [[ -z "${CTRL_PID:-}" ]] || ! kill -0 "$CTRL_PID" 2>/dev/null; then
  echo "wemo_ctrl failed to start" >&2
  tail -n 80 "$LOG_FILE" >&2 || true
  exit 1
fi

echo "fault-test: malformed proto frame"
python3 - <<'PY'
import socket, struct
s=socket.create_connection(("127.0.0.1",49153),timeout=2)
hdr=struct.pack("iii",1,1000,24)  # we_ipc_hdr: wemo_id, CMD_PROTO, size
payload=b"\x00"*24                # invalid proto header content
s.sendall(hdr+payload)
s.close()
PY

sleep 0.2
kill -0 "$CTRL_PID" 2>/dev/null

echo "fault-test: socket drop mid-frame"
python3 - <<'PY'
import socket, struct
s=socket.create_connection(("127.0.0.1",49153),timeout=2)
hdr=struct.pack("iii",1,1000,128)  # claim 128 bytes; do not send them
s.sendall(hdr[:8])
s.close()
PY

sleep 0.2
kill -0 "$CTRL_PID" 2>/dev/null

echo "fault-test: delayed/timeout path (short confirm timeout)"
set +e
printf 'poweron 12\nexit\n' | \
  WEMO_CLIENT_SERIAL_CONFIRM=1 WEMO_CLIENT_CONFIRM_TIMEOUT_MS=100 \
  "$CLIENT_BIN" >/tmp/wemo_fault_client.log 2>&1
set -e

kill -0 "$CTRL_PID" 2>/dev/null
echo "PASS: fault injection tests completed; daemon remained alive"
