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

## What's still in progress

- Only one write command type (`cmd 3515`, base LED brightness) has been
  exercised end-to-end so far. The same encoder generalizes directly to the
  other known command types (movement threshold, HR/SpO2 alert thresholds) —
  just needs doing.
- Pairing a brand-new base from scratch, bypassing the official app/phone
  setup flow entirely (or building a minimal web-based pairing flow) — not
  yet investigated.

## Repo layout

- `docs/findings.md` — the detailed, continuously-updated reverse-engineering
  log: hardware IDs, protocol byte layouts, the exact handshake sequence, the
  AES key and how it was found, the full command catalog, and setup notes for
  reproducing the rooted-device toolchain (Magisk, Termux, frida-server
  version quirks, etc.)
- `scripts/standalone_client.py` — a working, dependency-free (pure Python,
  no pip packages) standalone client. Runs on the paired phone itself (e.g.
  via Termux) and independently discovers the base, completes the handshake,
  and decodes live data pushes — without the official app running at all.
- `scripts/pure_aes.py` — a small pure-Python AES-128 implementation used by
  the client, since neither `openssl` nor a crypto pip package were worth
  installing on-device for this.

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
