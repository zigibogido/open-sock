# open-sock

Reverse-engineering the eufy Baby Smart Sock (T8340) and its base (T8351) so the
device can be used without the official app — read telemetry, understand
settings, and (in progress) send commands directly.

**Status: full app-independent read AND write access is working end-to-end** —
a standalone client reads live sock telemetry and successfully changes base
settings, with the official app completely closed throughout.

## TL;DR

- The sock talks BLE to the base only. The phone app never talks to the sock
  directly, and the sock's BLE link to the base is still an unknown, separately
  encrypted channel.
- Everything useful — live telemetry, settings, alert thresholds, firmware
  info — actually flows over a **UDP P2P protocol (PPCS)** between the phone
  and the base on the LAN, **not BLE**. That's the protocol this project
  reverse-engineers.
- The encryption key is a static value the app itself leaks in cleartext via
  Android's `logcat` (a real bug in the vendor's app, not something we had to
  break). It's AES-128-ECB, used directly as the 16 raw ASCII bytes — no KDF.
- The base only answers a device it already trusts by **IP address** (set up
  during original pairing). There's no extra cloud-side authorization check,
  no app-session binding — any process running on the paired device's IP can
  open its own independent session with the base. We've proven this: a
  from-scratch Python client (no app involved at all) completes the full
  handshake and receives live data pushes from the base.

## What works right now

- Full session handshake from scratch (discovery → announce → echo → ping/pong)
- Correct acking so the base doesn't get stuck retransmitting
- Decoding live telemetry: heart rate, SpO2, wear status, battery, sleep
  session, movement, charging state
- Decoding settings pushes: HR/SpO2 alert thresholds, movement sensitivity,
  base LED brightness
- A full device-parameter dump (firmware versions, 77 config parameters)
- **Writing** a setting back to the base and having it take effect — verified
  by reading the changed value back afterward, not just by getting an ack

- **A small self-hosted HTTP API + web UI** (`scripts/server.py` +
  `scripts/web/`) for controlling the sock from a browser, with no app or
  cloud involved — see "Self-hosted web UI" below.

## Project goals

**Done:** full app/cloud-independent read + write over the local LAN protocol
(telemetry, brightness, movement threshold, HR/SpO2 thresholds, working
mode), a self-hosted HTTP API + web UI with history charts, and confirmation
(via a real isolated-network experiment) that day-to-day LAN control doesn't
need the base to reach the internet at all.

**Next priorities, in rough order, each with where a future session should
start:**

1. **Pair a base without ever touching Eufy's cloud.** The blocker isn't the
   BLE Wi-Fi provisioning step (already understood, see the BLE pairing
   capture below) — it's that the base won't commit its Wi-Fi credentials to
   flash until cloud account-binding (real TLS to `care-app.eufylife.com`,
   cert the device trusts + Eufy's real backend) completes. Confirmed by a
   real isolated-network pairing attempt (`docs/findings.md`, "Deepnest
   pairing experiment") — see that entry for the full story, including a
   **new, not-yet-explored lead**: a separate plaintext UDP check-in
   (`3.141.175.104:8006`, the base's serial sent every 10s pre-pairing) that's
   a much more tractable target than the TLS layer. **Start there**: capture
   that channel's *reply* during a real (internet-connected) pairing — if the
   base's "am I registered" state is satisfied by something on this channel
   rather than requiring the full TLS flow to also succeed, that's a far
   smaller thing to replicate than faking Eufy's real cloud. If that's a dead
   end, the next escalation is the base's own UART pads (TXD/RXD/3V3/GND near
   the SPI flash, still never used) — firmware-level access to see the actual
   pairing state machine, rather than guessing from the network side.
2. **Unlock the voice-prompt setting locally** (the one cloud-only setting
   that's actually device-bound, not just app-UI state — see `docs/findings.md`
   for why the others in that original group are believed to be phone-local
   only). This runs into the same ECIES wall as the unfinished cloud-API
   track: the scheme itself is fully reverse-engineered, only the account's
   EC private key is missing, wrapped at rest in `shared_preference_security.xml`.
   **Start with the cheap thing, not resuming the Frida fight**: a fresh
   `adb logcat -d | grep -iE 'ecdh|private|eccDecrypt|GetPrivateKey'` on a
   *plain unrooted* phone while the app does a cloud-settings action —
   directly inspired by this project's repeated pattern of the vendor's app
   leaking exactly this kind of material to `logcat` for free (this is
   literally how the local AES key and, separately, this project's biggest
   local-protocol wins were found). If that's empty, the next step is static,
   not dynamic: the app's DEX has already been recovered once (via a
   `dalvik-DEX` memory dump, see `docs/findings.md`) — search it for the
   `ecdh-key<email>` unwrap routine to determine whether it's software
   (crackable) or Android-Keystore/hardware-backed (isn't), before spending
   more time on live-device work either way.
3. **Local alerting matching the official app's notifications** (HR/SpO2 out
   of range, sock not worn, battery low) — lower priority, no new reverse
   engineering needed, just code: every notification type maps onto fields
   already fully decoded and already flowing through `history.py`. See
   "Future: local alerting" below for the exact condition each one needs.

### Future: local alerting (not yet built)

Nothing in this project has found evidence the base sends discrete alert
*events* — it only streams continuous raw telemetry. Every notification the
official app shows appears to be computed downstream (app-side when open,
cloud-side for push when it's closed) from fields this project already fully
decodes. Conditions for a future `history.py` addition, by confidence level:

**HR out of range** (solid):
```
telemetry.hr > 0                                    # 0 = "no reading," not a real value
  AND (hr >= thresholds.hr_warning_up OR hr <= thresholds.hr_warning_down)  → warning
  AND (hr >= thresholds.hr_dangerous_up OR hr <= thresholds.hr_dangerous_down) → danger
# thresholds from param_type 3519's packed string (already parsed by the web UI);
# gate on hr_advance_enable, same as the app's own toggle.
```

**SpO2 out of range** (solid, same source):
```
telemetry.oxy > 0
  AND oxy <= thresholds.o2_warning_down    → warning
  AND oxy <= thresholds.o2_dangerous_down  → danger
# gated on oxy_advance_enable.
```

**Sock not worn correctly** (medium confidence): the raw `wear`/`wear_val`/
`wear_threshold` fields clearly carry more detail (values `1`, `16`, `18`
seen in different states, exact bitmask not decoded), but across every
sample logged so far, `hr == 0 AND oxy == 0` reliably means "not worn well
enough for a reading" — the same signal the history charts already use to
treat `0` as missing rather than a real zero. That's the trustworthy
condition; don't build this on `wear` directly without a dedicated capture
correlating specific values to known worn/unworn states first.

**Battery low / shutting down** (real gap): no decoded threshold parameter
exists anywhere in the command catalog for this. `telemetry.battery_vol <=
20` (or whatever number) would be an arbitrary pick, not something sourced
from the device — the app's own actual cutoff isn't known.

**Sock disconnected** (not implementable yet): no confirmed signal at all.
The only lead is the still-undecoded `rssi_list` message (BLE signal
strength base↔sock, both directions) — needs a dedicated capture (toggle the
sock off/on the base, watch what changes) before this has a real condition.

## What's still in progress

- Write commands `3515` (brightness), `3516` (movement threshold), `3519`
  (HR/SpO2 thresholds), and `3546` (working mode) are all exercised
  end-to-end, including by the web UI.
- Pairing a brand-new base from scratch, bypassing the official app/phone
  setup flow entirely (or building a minimal web-based pairing flow) — not
  yet investigated.
- A separate class of settings (voice prompts, notifications, device name,
  time/timezone, volume) never touches this protocol at all — they're
  cloud-account-stored and go over `care-app.eufylife.com`'s still-unbroken
  ECIES scheme. Out of scope for this repo; see `docs/findings.md`.

## Requirements

- A Eufy Smart Sock (T8340) and its base (T8351), already paired with the
  official app at least once.
- A computer or Android device on the same LAN as the base.
- Python 3 (standard library only — no `pip install` needed) to run
  `scripts/standalone_client.py`.
- **No root needed, even to extract the AES key** — confirmed with a plain
  `adb logcat -d` on an unrooted phone after a factory reset + fresh pairing
  (root was used in earlier sessions for unrelated Frida work and the key
  extraction was mistakenly assumed to need it too). See
  `docs/protocol-findings.md` for the exact command.

## Self-hosted web UI

`scripts/server.py` is a small HTTP API (Python stdlib only, no `pip
install`) built directly on the same protocol as `standalone_client.py`,
plus a static web UI (`scripts/web/index.html`) for day-to-day control from
a browser — the point being to replace the official app/cloud for this
device entirely, not just to script it.

```
cd scripts
python3 server.py --host 127.0.0.1 --port 8420
```

It must run on something that's on the same LAN as the base (e.g. your home
server), **and a firewall rule allowing inbound UDP from the base's IP is
required** if that host runs a default-deny firewall — the base replies from
a different ephemeral port than the one you send to, which defeats normal
connection tracking:

```
sudo ufw allow from <base's LAN IP> comment 'eufy base PPCS replies'
```

Expose it to yourself remotely via your own reverse proxy / subdomain with
auth in front — this process only speaks plain HTTP and expects a proxy (or
`EUFY_API_TOKEN` + `Authorization: Bearer <token>`, as a fallback) in front
of it for anything beyond localhost/LAN access.

Each API call is a fresh ~1-6s session (discovery → handshake → action →
listen briefly → close), not a persistent connection — simple, and matches
how the protocol was already proven to work.

Endpoints: `GET /api/telemetry`, `GET /api/params`, `GET
/api/history?minutes=N`, `POST /api/settings/{brightness,movement,alerts}`.
See `scripts/eufy_client.py` for the request bodies (same field names as the
command catalog).

### History (stats over time, like the official app's dashboard)

`scripts/history.py` runs a background sampler (every `EUFY_HISTORY_INTERVAL`
seconds, default 90) that takes one telemetry reading and logs it to a local
SQLite file (`scripts/eufy_history.sqlite3`, gitignored — it's runtime data,
not source). The web UI charts HR, SpO2, movement, and battery over 1h/6h/24h/7d
as separate single-metric line charts (never one combined dual-axis chart),
with hover detail and a table-view fallback. A reading of `0` for HR/SpO2 is
treated as "not currently being worn," not a real zero, and leaves a gap in
the line rather than plotting a false zero.

### Does the base need the internet at all?

Evidence from this project says no, for everything this UI does: the base's
local-protocol trust gating is by source IP, not by any active cloud
session, and LAN control (telemetry + settings writes) kept working in
every test here even while the base's own internet path was cut off. Firmly
block it at your router if you want to; just don't assume that's been
stress-tested over days, only minutes, and note OTA updates and the
cloud-only settings above would stop working too.

## Running in Docker

A prebuilt image is published to `ghcr.io/zigibogido/open-sock` whenever a version tag is pushed. Minimal `docker-compose.yml`:

```yaml
services:
  open-sock:
    image: ghcr.io/zigibogido/open-sock:0.1.0
    container_name: open-sock
    network_mode: host
    restart: unless-stopped
    env_file: .env
    volumes:
      - open-sock-data:/data

volumes:
  open-sock-data:
```

Copy `.env.example` to `.env` and fill it in, or build the image yourself with `docker build -t open-sock .`.

| Variable | Default | Purpose |
|---|---|---|
| `EUFY_AES_KEY` | required | 16-character device key |
| `EUFY_ACCOUNT_ID` | required | account ID used in command packets |
| `EUFY_BASE_IP` | `10.10.10.10` | IP address of the base on your network |
| `EUFY_BIND_HOST` | `127.0.0.1` | address the web UI and API listen on |
| `EUFY_PORT` | `8420` | port for the web UI and API |
| `EUFY_LOCAL_PORT` | `32109` | fixed local UDP port for the base protocol |
| `EUFY_HISTORY_INTERVAL` | `90` | seconds between history samples |
| `EUFY_API_TOKEN` | empty | optional bearer token for the API |

The key and account ID belong to your own base and app account and are not part of this repository. `docs/findings.md` describes how they were found on one device.

Use host networking. The base replies from a different UDP source port than the one the client sends to, so a stateful firewall drops the replies unless it allows UDP from the base to `EUFY_LOCAL_PORT`.

The server listens on localhost by default and has no authentication unless `EUFY_API_TOKEN` is set. Put it behind an authenticating reverse proxy instead of exposing it directly.

## Repo layout

- `docs/protocol-findings.md` — the detailed, narrative reverse-engineering
  log for the local LAN protocol covered by this README: hardware IDs, BLE
  pairing capture, the PPCS/UDP packet format, the handshake sequence, how
  the AES key was found, and the full command catalog. Read this if you want
  the "how do we know that" story, not just the result.
- `docs/findings.md` — a much larger, rawer, continuously-updated working
  log kept during the investigation, including a separate, not-yet-finished
  side investigation into the app's cloud account API (a different,
  much harder problem — reverse-engineering a vendor's HTTPS backend rather
  than a LAN device you own — tracked independently of this repo's main,
  finished local-protocol result above). Mentioned here for completeness;
  `docs/protocol-findings.md` is the one to read for the actual, working
  local protocol this README describes.
- `scripts/standalone_client.py` — a working, dependency-free (pure Python,
  no pip packages) standalone client. Runs on the paired phone itself (e.g.
  via Termux) and independently discovers the base, completes the handshake,
  and decodes live data pushes — without the official app running at all.
- `scripts/pure_aes.py` — a small pure-Python AES-128 implementation used by
  the client, since neither `openssl` nor a crypto pip package were worth
  installing on-device for this.
- `work/` — gitignored scratch space (decompiled app code, packet captures,
  device backups). Not part of this repo; mentioned so it doesn't come as a
  surprise if you're working from a clone of the working directory rather
  than the GitHub repo itself.

## Sending commands directly (without the official app)

`scripts/standalone_client.py` can both *read* live telemetry/settings and
*write* settings back to the base, over the same local UDP PPCS protocol the
official app uses — just without the app running.

### Quick start

Reading is the default mode — just run the script with no arguments and it
discovers the base, completes the handshake, and prints decoded telemetry and
settings pushes as they arrive:

```sh
python3 scripts/standalone_client.py
```

To send a **write** command, put the command as JSON in a file and pass its
path as the one argument:

```sh
echo '{"cmd":3515,"payload":{"brightness":9,"brightness_auto":0}}' > cmd.json
python3 scripts/standalone_client.py cmd.json
```

`account_id`, `mChannel`, and `mValue3` are filled in automatically if you
omit them (see `ACCOUNT_ID`/`TEST_CMD_OBJ` near the top of the script) — you
normally only need to supply `cmd` and `payload`.

### How a command packet is built

Every command — read or write — is a UDP packet with this wire layout:

```
f1 d0 <total_len:u16be> d1 00 <msgid:u16be> 58 5a 59 48 <12-byte subtype> <AES-128-ECB ciphertext>
```

- The 24 bytes before the ciphertext are a fixed header; `XZYH` (`58 5a 59
  48`) is a constant tag.
- The **12-byte "subtype"** right after `XZYH` is **specific to each `cmd`
  number**, not a universal constant — reusing one command's subtype for a
  different command gets the packet silently dropped (no ack, looks
  identical to "the base rejected the value"). `COMMAND_SUBTYPES` in the
  script holds the subtypes extracted from real captured packets for each
  command verified so far; extracting a new command's subtype from a real
  capture is required before testing it.
- The ciphertext is the command's JSON, with keys in this exact order
  (`account_id`, `cmd`, `mChannel`, `mValue3`, `payload`), zero-padded to a
  16-byte boundary, encrypted with AES-128-ECB using the key documented in
  `docs/findings.md` (not repeated here to avoid a second place to keep in
  sync — see the script for the literal key and account ID already in use).

### Known commands

| `cmd` | Direction | Status | Payload shape | Notes |
|---|---|---|---|---|
| 3503 | base → phone | read (periodic) | `{"sn","rssi","wear","hr","oxy","move","move_val","wear_val","wear_threshold","charge","battery_vol","signal_quality","cur_sleep_start/end/duration","time"}` | Live sock telemetry, pushed frequently while worn. |
| 3515 | phone → base | **write verified** | `{"brightness":0-11,"brightness_auto":0\|1}` | Base status LED. `brightness_auto:1` = auto mode (ignores explicit `brightness`). |
| 3516 | phone → base | **write verified** | `{"move_threshold":N,"tones_pushes":N}` | Movement alert threshold; also sent periodically as a heartbeat with just `tones_pushes` incrementing. |
| 3519 | phone → base | **write verified** | `{"hr_advance_enable","hr_dangerous_down/up","hr_warning_down/up","hr_warning_down_real/up_real","o2_dangerous_down","o2_warning_down","o2_warning_down_real","oxy_advance_enable"}` | HR/SpO2 safety-alert thresholds. UI range for warning thresholds is roughly 40-250 bpm. Test with a small tweak, not by disabling (`*_advance_enable:0`). |
| 3546 | phone → base | **write verified** | `{"mode":0\|1}` | Working Mode: `0` = Standard, `1` = Mute. |
| 3509 | phone → base | read only so far | `{"bindStatus","birthdate","child_id","gender","height","name","race","weight"}` | Child/baby profile (the "Me → Child profile" screen). Contains personal info by design. |
| 1201 | phone → base | read only, purpose unclear | `{"time_out":N,"user_name":"..."}` | Seen fired automatically, not tied to a specific UI action; may be account/session-related rather than a device setting. |
| — (bulk params dump) | base → phone | read only | `{"params":[{"dev_type","param_type","param_value"}, ...],"main_sw_version","sec_sw_version"}` | Fragmented across multiple ~1032-byte packets + a short terminator. 77 params observed. `param_type 3519` is the packed form of the `cmd 3519` thresholds; `param_type 1176` is the base's LAN IP; `param_type 1296` is the region code. Use this to verify a write actually took effect — read the relevant `param_type` back rather than trusting the ack alone. |

A command's JSON field name doesn't necessarily match the closest-looking
`param_type` number in the bulk dump — confirm any new mapping by diffing the
params dump before/after a write, the same way each command above was
verified.

See `docs/findings.md` for the full handshake sequence, the AES key and how
it was found, and the complete, continuously-updated investigation log this
table is drawn from.

## Safety / scope note

This only works against a base that already trusts your device's IP from
normal pairing. It's not a remote exploit — it requires LAN access to a base
you've already paired with the official app at least once.
