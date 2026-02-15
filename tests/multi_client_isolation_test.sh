#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTRL_BIN="$ROOT_DIR/wemo_ctrl/wemo_ctrl"
CLIENT_BIN="$ROOT_DIR/wemo_client/wemo_client"
LOG_CTRL="/tmp/wemo_multi_ctrl.log"
OUT_A="/tmp/wemo_client_a.out"
OUT_B="/tmp/wemo_client_b.out"
ID_A="${1:-7}"
ID_B="${2:-8}"

pkill -x wemo_ctrl 2>/dev/null || true
sleep 0.2

cleanup() {
  if [[ -n "${CTRL_PID:-}" ]]; then
    kill "$CTRL_PID" 2>/dev/null || true
    wait "$CTRL_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

WEMO_LOG_MODE=quiet "$CTRL_BIN" >"$LOG_CTRL" 2>&1 &
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
  tail -n 40 "$LOG_CTRL" >&2 || true
  exit 1
fi

(
  printf "getstate %s\nexit\n" "$ID_A" |
    WEMO_CLIENT_QUIET=1 WEMO_CLIENT_SERIAL_CONFIRM=1 "$CLIENT_BIN"
) >"$OUT_A" 2>&1 &
PID_A=$!

(
  printf "getstate %s\nexit\n" "$ID_B" |
    WEMO_CLIENT_QUIET=1 WEMO_CLIENT_SERIAL_CONFIRM=1 "$CLIENT_BIN"
) >"$OUT_B" 2>&1 &
PID_B=$!

wait "$PID_A"
wait "$PID_B"

if ! grep -q "cmd_response:.*wemo_id=$ID_A" "$OUT_A"; then
  echo "client A missing response for wemo_id=$ID_A" >&2
  cat "$OUT_A" >&2
  exit 1
fi
if ! grep -q "cmd_response:.*wemo_id=$ID_B" "$OUT_B"; then
  echo "client B missing response for wemo_id=$ID_B" >&2
  cat "$OUT_B" >&2
  exit 1
fi

if grep -q "cmd_response:.*wemo_id=$ID_B" "$OUT_A" || grep -q "cmd_event:.*wemo_id=$ID_B" "$OUT_A"; then
  echo "cross-delivery detected in client A output" >&2
  cat "$OUT_A" >&2
  exit 1
fi
if grep -q "cmd_response:.*wemo_id=$ID_A" "$OUT_B" || grep -q "cmd_event:.*wemo_id=$ID_A" "$OUT_B"; then
  echo "cross-delivery detected in client B output" >&2
  cat "$OUT_B" >&2
  exit 1
fi

echo "PASS: multi-client isolation validated for wemo_id=$ID_A and wemo_id=$ID_B"
