# OpenWeMo Bridge Core

`OpenWeMo Bridge Core` is the public-facing name for this project.

This repository provides a local LAN control layer for WeMo devices and is designed to be used by a Matter bridge.

Matter bridge integration (Google Home / Home app bridge flow) is planned for a future release of this project.

## What Is Included

- `wemo_ctrl/`: daemon for discovery, SOAP control, subscriptions, and IPC
- `wemo_engine/`: shared/static library used by clients and bridge processes
- `wemo_client/`: interactive CLI for discovery/control/testing
- `tests/`: reliability and IPC stress scripts

## Prerequisites

Ubuntu/Debian packages:

```bash
sudo apt-get update
sudo apt-get install -y build-essential sqlite3 libsqlite3-dev libssl-dev
```

You also need `libupnp` + `ixml` headers/libs available either:

- from a local source tree at `../../libupnp-1.14.0` (default in current Makefiles), or
- installed under standard system paths (`/usr/local/include`, `/usr/local/lib`).

Hardware target note:

- You can run this project on Raspberry Pi devices, including Raspberry Pi Zero models, as long as toolchain and dependency requirements are met.
- For Pi Zero class hardware, expect slower build/test times and prefer lightweight runtime settings.

## Build

From repo root:

```bash
make
```

Outputs:

- `wemo_ctrl/wemo_ctrl`
- `wemo_client/wemo_client`
- `wemo_engine/libwemoengine.so`
- `wemo_engine/libwemoengine.a`

If your `libupnp` source tree is in a different location:

```bash
make -C wemo_ctrl UPNP_BASE=/path/to/libupnp-1.14.0
make -C wemo_client UPNP_BASE=/path/to/libupnp-1.14.0
```

## Runtime Data and Config

- `wemo_ctrl` reads `/etc/wemo_ctrl.conf` if present.
- If config is missing, defaults are used.
- Device/state sqlite DBs are stored under local state directories based on user/root context.

Optional config example (`/etc/wemo_ctrl.conf`):

```ini
wemo_device_db=/var/lib/wemo-matter/wemo_device.db
wemo_state_db=/var/lib/wemo-matter/wemo_state.db
ifname=eth0
ipc_host=127.0.0.1
ipc_port=49153
```

## Quick Start

Start controller daemon in one terminal:

```bash
cd wemo_ctrl
./wemo_ctrl
```

Use CLI in second terminal:

```bash
cd wemo_client
./wemo_client
```

Inside `wemo_client`:

```text
listdev
discover
poweron <devnum>
poweroff <devnum>
setlevel <devnum> <0-100>
setdimmer <devnum> <0/1> <0-100>
getstate <devnum>
```

## Recommended Validation Flow

1. Start `wemo_ctrl`.
2. In `wemo_client`, run `discover` and `listdev`.
3. Test state transitions:
   - `poweron <id>`
   - `getstate <id>`
   - `poweroff <id>`
   - `getstate <id>`
4. For dimmer devices:
   - `setdimmer <id> 1 40`
   - `setlevel <id> 80`
5. Confirm callback/event output in `wemo_client` and logs in `wemo_ctrl`.

For serialized command confirmation:

```bash
WEMO_CLIENT_SERIAL_CONFIRM=1 ./wemo_client
```

Useful tuning:

- `WEMO_CLIENT_CONFIRM_TIMEOUT_MS` (default 12000)
- `WEMO_CLIENT_QUIET=1`
- `WEMO_CLIENT_QUIET_ALL=1`

## Test Scripts

From repo root:

```bash
./tests/ipc_negative_test.sh
./tests/multi_client_isolation_test.sh
./tests/fault_injection_test.sh
./tests/bridge_soak_test.sh
```

These scripts expect local build artifacts and typically start/stop `wemo_ctrl` internally.

## Matter Bridge Integration Notes

- Full Matter bridge packaging/integration is planned for a future release.
- Keep `wemo_ctrl` running continuously.
- Have bridge process link to `wemo_engine` or talk to IPC endpoint.
- Use WeMo `UDN` as stable identity key and persist endpoint mapping on the bridge side.
- Ensure LAN supports multicast/SSDP and host firewall allows required UDP traffic.

## Troubleshooting

- `wemo_ctrl` starts but no devices:
  - verify interface selection (`ifname` or auto-detected interface)
  - verify same L2 network and multicast visibility
- IPC connection failures from client:
  - confirm `wemo_ctrl` is running
  - confirm `ipc_host`/`ipc_port` match on both sides
- Build link errors with `upnp`/`ixml`:
  - verify `UPNP_BASE` path or `/usr/local/lib` installation

## Notes

- Repository name is `openwemo-bridge-core`.
