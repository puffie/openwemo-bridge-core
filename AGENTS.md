# AGENTS.md — wemo-upnp (WeMo LAN control layer)

## What this directory contains
This is a LAN control stack for Belkin WeMo devices using UPnP/SOAP:

- `wemo_ctrl/`  : discovery + control daemon (SSDP + SOAP) storing devices in sqlite DB
- `wemo_engine/`: shared library exposing APIs used by clients (and by the Matter bridge)
- `wemo_client/`: **interactive CLI** tool that talks to `wemo_engine` (often via IPC) to list/control devices

This layer is reused by the Matter bridge as the “WeMo adapter”.

## External dependencies (host-installed)
Assumed available on the Ubuntu host:

- `libupnp` + `libixml` (already installed under `/usr/local/lib`)
- `sqlite3` / `libsqlite3`
- OpenSSL (`libssl`/`libcrypto`)
- Standard build tools (`gcc`, `make`, etc.)

Typical Ubuntu packages:
```sh
sudo apt-get update
sudo apt-get install -y build-essential sqlite3 libsqlite3-dev libssl-dev
```

## Build
From `wemo-upnp/`:
```sh
make
```

Expected artifacts:
- `wemo_ctrl/wemo_ctrl`
- `wemo_engine/libwemoengine.so` (and possibly `libwemoengine.a`)
- `wemo_client/wemo_client`

## Runtime configuration
`wemo_client` (and sometimes `wemo_ctrl`) can read `/etc/wemo_ctrl.conf`.
If missing, defaults are used and it will print:
`/etc/wemo_ctrl.conf not found using default DB paths`

Useful env vars for quieter output:
- `WEMO_CLIENT_QUIET=1` (less verbose)
- `WEMO_CLIENT_QUIET_ALL=1` (very quiet)

The client auto-selects a preferred network interface if one is not configured.

## Run / smoke tests

### 1) Start the control daemon (recommended)
In terminal A:
```sh
cd wemo_ctrl
./wemo_ctrl
```

### 2) Start the interactive client
In terminal B:
```sh
cd wemo_client
./wemo_client
```

You will enter a command loop. Type `help` to see the supported commands.

### 3) Common interactive commands (from `wemo_client` help)
Discovery / inventory:
- `discover`
- `listdev`
- `printdev <devnum>`
- `getstate <devnum>`
- `getnetstate <devnum>`
- `getinformation <devnum>`

Power / dimming:
- `poweron <devnum>`
- `poweroff <devnum>`
- `setlevel <devnum> <level>`            (typically 0–100)
- `setdimmer <devnum> <0/1> <level>`     (on/off + level)

Maintenance:
- `changename <devnum> '<new name>'`
- `deletedev <devnum>`
- `reset <devnum> <type>`  (1 soft, 2 full, 3 remote, 4 insight, 5 wifi)
- `closesetup <devnum>`
- `exit`

Wi‑Fi setup (only if you still use onboarding flows):
- `setup <devnum> <ssid> <passphrase> <auth> <encrypt> <channel>`

⚠️ Notes:
- `<devnum>` is the device index as shown by `listdev`.
- Prefer using the **UDN** internally as the stable identity; `devnum` may change after rediscovery.

## Integration guidance for the Matter bridge
Preferred integration pattern:
- Run `wemo_ctrl` as a daemon (handles discovery + event subscriptions).
- The Matter bridge links to and calls `wemo_engine` APIs to:
  - enumerate devices (or query sqlite DB)
  - read current state/level
  - set state/level
  - register callbacks for state changes (push into Matter attribute reports)

Identity:
- Use WeMo **UDN** as the canonical key.
- Persist `UDN → Matter endpointId` mapping on the bridge host.

Threading:
- Do not block inside WeMo event callbacks; forward work to the Matter event loop / queue.

## Coding conventions
- Keep edits small and reviewable.
- Add explicit bounds checks for SOAP/event payload parsing.
- Avoid network operations on callback threads unless already designed for it.
