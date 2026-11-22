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

## What's still in progress

- Write commands `3515` (brightness), `3516` (movement threshold), and `3519`
  (HR/SpO2 thresholds) are exercised end-to-end, including by the web UI.
  `3546` (working mode) has a *confirmed mapping* but no captured subtype yet
  — writing it is deliberately left unimplemented rather than guessed; see
  `docs/protocol-findings.md`'s command catalog.
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
| 3546 | phone → base | mapping confirmed, write not yet tested | `{"mode":0\|1}` | Working Mode: `0` = Standard, `1` = Mute. |
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
