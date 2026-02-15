#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTRL_BIN="$ROOT_DIR/wemo_ctrl/wemo_ctrl"
CLIENT_BIN="$ROOT_DIR/wemo_client/wemo_client"
LOG_DIR="${LOG_DIR:-/tmp/wemo_soak}"
DURATION_SEC="${DURATION_SEC:-300}"
CYCLE_SLEEP_SEC="${CYCLE_SLEEP_SEC:-1}"
IDS="${IDS:-}"
CONFIRM_TIMEOUT_MS="${CONFIRM_TIMEOUT_MS:-12000}"
MAX_TIMEOUTS="${MAX_TIMEOUTS:-2}"
MAX_TIMEOUT_RATE_BP="${MAX_TIMEOUT_RATE_BP:-500}"

mkdir -p "$LOG_DIR"
CTRL_LOG="$LOG_DIR/wemo_ctrl.log"
CLIENT_LOG="$LOG_DIR/wemo_client.log"
CMD_FILE="$LOG_DIR/cmd.txt"

cleanup() {
  if [[ -n "${CTRL_PID:-}" ]]; then
    kill "$CTRL_PID" 2>/dev/null || true
    wait "$CTRL_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ ! -x "$CTRL_BIN" || ! -x "$CLIENT_BIN" ]]; then
  echo "missing binaries under $ROOT_DIR" >&2
  exit 1
fi

pkill -x wemo_ctrl 2>/dev/null || true
sleep 0.2

WEMO_LOG_MODE=quiet "$CTRL_BIN" >"$CTRL_LOG" 2>&1 &
CTRL_PID=$!

for _ in $(seq 1 100); do
  if python3 - <<'PY'
import socket
try:
    s=socket.create_connection(("127.0.0.1",49153),timeout=0.2)
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
  tail -n 50 "$CTRL_LOG" >&2 || true
  exit 1
fi

if [[ -z "$IDS" ]]; then
  IDS="$($CLIENT_BIN <<'EOF2' | awk '/wemo devices in DB: wemo_id =/{print $NF}' | tr '\n' ' '
listdev
exit
EOF2
)"
fi
IDS="$(echo "$IDS" | xargs)"
if [[ -z "$IDS" ]]; then
  echo "no devices found" >&2
  exit 1
fi

echo "soak start: duration=${DURATION_SEC}s ids=[$IDS] confirm_timeout_ms=$CONFIRM_TIMEOUT_MS"

start_ts=$(date +%s)
cycle=0
: > "$CLIENT_LOG"

while true; do
  now_ts=$(date +%s)
  elapsed=$((now_ts - start_ts))
  if (( elapsed >= DURATION_SEC )); then
    break
  fi

  : > "$CMD_FILE"
  for id in $IDS; do
    echo "poweron $id" >> "$CMD_FILE"
    echo "getstate $id" >> "$CMD_FILE"
    echo "poweroff $id" >> "$CMD_FILE"
    echo "getstate $id" >> "$CMD_FILE"
  done
  echo "exit" >> "$CMD_FILE"

  if ! WEMO_CLIENT_QUIET=1 WEMO_CLIENT_SERIAL_CONFIRM=1 WEMO_CLIENT_CONFIRM_TIMEOUT_MS="$CONFIRM_TIMEOUT_MS" \
      "$CLIENT_BIN" < "$CMD_FILE" >> "$CLIENT_LOG" 2>&1; then
    echo "client command loop failed at cycle=$cycle" >&2
    break
  fi

  cycle=$((cycle + 1))
  sleep "$CYCLE_SLEEP_SEC"
done

timeouts=$(grep -c 'outcome=timeout(-10)' "$CLIENT_LOG" || true)
rejected=$(grep -c 'outcome=rejected(-12)' "$CLIENT_LOG" || true)
sendfail=$(grep -c 'outcome=send_failed(-13)' "$CLIENT_LOG" || true)
applied=$(grep -c 'outcome=applied(1)' "$CLIENT_LOG" || true)
responses=$(grep -c '^>> cmd_response:' "$CLIENT_LOG" || true)
power_txns=$(grep -c 'cmd_txn: cmd=power' "$CLIENT_LOG" || true)

if [[ "$power_txns" -gt 0 ]]; then
  timeout_rate_bp=$((timeouts * 10000 / power_txns))
else
  timeout_rate_bp=0
fi

timeout_by_device="$(awk '
/cmd_txn: cmd=power(on|off)\(4\).*outcome=timeout\(-10\)/ {
  for (i=1; i<=NF; ++i) {
    if ($i ~ /^wemo_id=/) {
      split($i, a, "=");
      cnt[a[2]]++;
    }
  }
}
END {
  for (id in cnt) {
    printf "%s:%d ", id, cnt[id];
  }
}
' "$CLIENT_LOG" | xargs || true)"
if [[ -z "$timeout_by_device" ]]; then
  timeout_by_device="none"
fi

status="PASS"
if [[ "$rejected" != "0" || "$sendfail" != "0" ]]; then
  status="WARN"
fi
if [[ "$timeouts" -gt "$MAX_TIMEOUTS" || "$timeout_rate_bp" -gt "$MAX_TIMEOUT_RATE_BP" ]]; then
  status="WARN"
fi

echo "soak summary: status=$status cycles=$cycle applied=$applied responses=$responses power_txns=$power_txns timeout=$timeouts timeout_rate_bp=$timeout_rate_bp rejected=$rejected send_failed=$sendfail thresholds(max_timeouts=$MAX_TIMEOUTS max_timeout_rate_bp=$MAX_TIMEOUT_RATE_BP)"
echo "soak timeout_by_device: $timeout_by_device"
echo "logs: ctrl=$CTRL_LOG client=$CLIENT_LOG"

if [[ "$status" != "PASS" ]]; then
  exit 2
fi
