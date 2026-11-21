# Eufy Smart Sock + Base — Local Protocol Findings

This is the detailed reverse-engineering log behind the client in
`scripts/standalone_client.py`: how the local (non-cloud) protocol between the
phone app, the Eufy Sock base station (T8351), and the sock itself (T8340) was
discovered, byte by byte. It's scoped deliberately — this project is about
interoperating with hardware the user owns over the LAN, not about the app's
separate cloud account/API layer (a distinct, harder, and not-yet-finished
piece of work tracked separately and not duplicated here).

If you just want to *use* the result, read the README instead — this document
is the "how we know that" narrative for anyone who wants to verify, extend, or
re-derive the protocol themselves.

## Hardware

- **Base** T8351 (FCC ID 2AOKB-T8351, board T8351-MB-V0.3): MediaTek MT7628NN
  (MIPS24KEc, 2.4GHz Wi-Fi), Nanya 128MB DDR2, Winbond 25Q256JVEQ 32MB SPI
  NOR flash, Nordic nRF52820 (BLE-only, acts as the Wi-Fi SoC's BLE
  controller). TXD/RXD/3V3/GND pads near the flash chip look like a UART
  console header. The charging dock has a 5V+GND-only pogo-pin connector (no
  data lines).
- **Sock** T8340 (FCC ID 2AOKB-T8340, board S91-V1.2): Nordic nRF52840 (BLE
  5). Has some unlabeled pads, possibly SWD, unconfirmed.
- Both radios operate in the standard 2402-2480 MHz BLE band; the base's
  Wi-Fi radio is 2.4GHz-only.

## Topology

`sock --BLE--> base --Wi-Fi--> Eufy cloud --> phone app` is the vendor's
intended path. In practice:

- The sock **never appears as its own BLE peer to the phone**, in either a
  pairing capture or a ~90-minute idle-use capture. The phone's app only ever
  opens a BLE GATT connection to the base; the base relays to/from the sock
  over its own separate link (BLE central role on the base's second Nordic
  chip, or something else — not confirmed, would need base-side hardware
  access to settle).
- Live data, settings reads, and settings writes all flow over a **UDP P2P
  protocol between the phone and the base on the LAN** — not through BLE and
  not through the cloud, for anything that needs to take effect on the
  physical device. This is the protocol this document is about.
- A separate subset of settings (voice prompts, notification toggles, device
  name, time format, timezone, audio volume) turned out to be **cloud-stored
  instead of locally applied** — see "Settings sweep: most toggles don't
  touch the local protocol at all" below. Those aren't covered by this
  protocol or by `scripts/standalone_client.py`.

## BLE pairing capture

Captured via Android's built-in HCI snoop log during a factory-reset pairing.

- Only BLE device seen was the base advertising as `eufy_XXXX`; the sock was
  never visible by name.
- Custom GATT service `2520567c-05cf-6eb4-c541-02030080858c`, with a write
  characteristic (handle `0x000d`) and a notify characteristic (handle
  `0x000f`, CCCD at `0x0010`).
- Frame format: `ff 09 | len:u16le (whole frame) | 01 00 (phone→base) / 01 30
  (base→phone) | msg_id | c0 | payload`.
- Payloads are high-entropy (encrypted) over this channel; same-kind messages
  share a short byte prefix. This BLE-level encryption was never cracked —
  it didn't need to be, since the useful data is all reachable over the LAN
  UDP protocol below instead.
- Provisioning (sending the home Wi-Fi SSID/password to the base) happens
  entirely over this same BLE channel, as an encrypted write — there's no
  temporary Wi-Fi access point involved, unlike some other Eufy product
  lines.

## The LAN protocol: PPCS over UDP

This is the actual useful channel — a vendor SDK called **PPCS** (matching
the `libNDT_API_PPCS.so` library bundled in the app), carried over UDP
between the phone and the base, independent of BLE and independent of the
cloud for anything that needs to reach the physical device.

### Packet framing

Every PPCS packet starts with magic byte `0xf1`:

| Bytes | Meaning |
|---|---|
| `f1 00 00 00` | discovery request (to a relay candidate) |
| `f1 30 00 00` | discovery request (direct to a known base IP, or LAN broadcast) |
| `f1 41 ...` / `f1 42 ...` | base's discovery announce |
| `f1 e0 00 00` | ping (phone→base) |
| `f1 e1 00 00` | pong (base→phone) |
| `f1 d0 <len:u16le> ...` | data packet (encrypted payload follows) |
| `f1 d1 ...` | ack |

A `f1 d0` packet's header is 24 bytes on the **first** fragment of a message
(includes a fixed `58 5a 59 48` / `"XZYH"` tag at offset 8) but only 8 bytes
on **continuation** fragments of the same message (no tag) — using a fixed
24-byte skip for every packet corrupts continuation fragments, a real early
bug. Decrypted plaintext for a data packet is JSON; a short trailer after the
closing `}` is a block-count/length field, not meaningful payload.

Acks echo the exact channel byte (header offset 5) from the packet being
acknowledged, plus the msgid — `f1 d1 <len> d1 00 00 01 <msgid>`. The base
tracks a per-channel msgid counter and silently drops anything too far out of
sequence (no ack at all) rather than rejecting it visibly.

Messages over ~1000 bytes arrive as **multiple UDP fragments** that must be
concatenated in order per-channel before decrypting/parsing as one logical
message; channels 0 and 2 are independent parallel streams and must be
buffered separately (interleaving them corrupts JSON boundaries).

### Discovery and handshake (what a standalone client needs to do)

From a cold-start capture of the real app connecting fresh:

1. The phone tries two discovery paths in parallel: a cloud-relay lookup
   (`f1 00 00 00` to a few AWS-hosted relay candidates on port 32100) and a
   direct LAN attempt (`f1 30 00 00`, historically to broadcast, though a
   **direct unicast to the base's known IP works identically and is
   simpler** — confirmed by testing unicast-only from a from-scratch script).
2. The base replies from a freshly chosen ephemeral UDP port with
   `f1 41 <20-byte announce>` (repeated as `f1 42 ...`). **This is how a
   client learns the base's current port** — no pre-shared port is needed.
3. The client must **echo the exact `f1 41` bytes back to the base 3-4
   times** before the base will proceed — missing this step was the reason
   several early standalone-client attempts got silence after the announce.
4. Normal ping/pong keepalive (`f1 e0`/`f1 e1`) starts on the learned
   (phone_port, base_port) pair.
5. First encrypted exchange: a fixed capability/hello flag
   (`ff 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00` once decrypted), not
   JSON — a session-ready signal, not data.
6. From here on, traffic is ordinary `cmd`-numbered JSON messages (below).

**Access control is by source IP only.** Sending the exact same discovery
packet from an unrelated host gets no reply; from the already-paired phone's
IP, the base replies instantly. There's no additional cloud-side
authorization, app-session binding, or time-limited "arming window" —
confirmed directly: a from-scratch client completes the entire handshake
using only the paired device's IP and the documented packet formats, with the
official app fully closed the whole time. The base does additionally bind an
established session to the exact (IP, port) pair from its handshake, so an
unrelated process can't blindly inject a packet into someone else's existing
session — it has to complete its own handshake and get its own session, which
is exactly what a standalone client does.

### Encryption

AES-128-ECB, no IV, used directly on raw bytes with no KDF:

- **Key**: a fixed, per-base string that the vendor's own app logs in
  cleartext to the Android system log (`logcat`) as part of its normal P2P
  setup — not something that had to be extracted from obfuscated code. Format
  observed: `<last 7 chars of the base's serial number>-<6 digits>-M`, e.g.
  `REDACTED-AES-KEY` for base serial `REDACTED-SERIAL`. The full 16-ASCII-byte
  string is used as-is as the AES-128-ECB key (no truncation, no hashing).
  This value is stable across app relaunches (deterministic per base, not
  session-random).
- One quirk found while building a standalone client: in at least one test
  session, the base sent some larger (channel 2) content **unencrypted** on
  the wire, apparently as a compatibility fallback when it doesn't recognize
  a client's hello/capability negotiation (a fixed captured hello was being
  replayed rather than a full negotiation being implemented). A client should
  try both "parse as JSON directly" and "AES-decrypt then parse as JSON" on
  every received buffer — decrypting something that wasn't actually
  ciphertext just produces unparseable garbage that's harmlessly discarded.

## Command catalog

All of these are `{"account_id","cmd","mChannel","mValue3","payload"}` JSON
objects (in that exact key order for outgoing/write packets), AES-128-ECB
encrypted, wrapped in the `f1 d0` framing above. Writes additionally need a
**12-byte "subtype"** value placed right after the `XZYH` tag in the header —
this is specific to each `cmd` number, not a shared constant; reusing one
command's subtype for a different command gets the packet silently dropped
(looks identical to "value rejected", but isn't — it's "packet shape not
recognized"). Extract the correct subtype from a real captured packet for
each new command before testing it; known-good values are in
`COMMAND_SUBTYPES` in `scripts/standalone_client.py`.

| `cmd` | Direction | Status | Payload | Notes |
|---|---|---|---|---|
| 3503 | base→phone | read (periodic) | `sn, rssi, wear, wear_val, wear_threshold, hr, oxy, move, move_val, charge, battery_vol, signal_quality, cur_sleep_start/end/duration, time` | Live sock telemetry, the sock's own serial (`T8340...`) appears here for the first time — otherwise invisible to the phone. |
| 3515 | phone→base | **write verified** | `brightness:0-11, brightness_auto:0\|1` | Base status LED. |
| 3516 | phone→base | **write verified** | `move_threshold, tones_pushes` | Movement alert threshold; `tones_pushes` doubles as a periodic heartbeat/notification counter. Wire identity of the threshold value is actually `param_type 3520` in the bulk dump below — `param_type 3516` is `tones_pushes` instead; don't assume a command's JSON field name matches the closest-looking `param_type`. |
| 3519 | phone→base | **write verified** | `hr_advance_enable, hr_dangerous_down/up, hr_warning_down/up(+_real), o2_dangerous_down, o2_warning_down(+_real), oxy_advance_enable` | HR/SpO2 safety-alert thresholds. UI range for warning thresholds is roughly 40-250 bpm. |
| 3546 | phone→base | mapping confirmed | `mode:0\|1` | Working Mode: `0`=Standard, `1`=Mute. |
| 3509 | phone→base | read only | `bindStatus, birthdate, child_id, gender, height, name, race, weight` | Child/baby profile screen. Contains personal info by design, not a bug. |
| 1201 | phone→base | read only, purpose unclear | `time_out, user_name` | Fires automatically, not tied to one specific UI action; may be account/session-related rather than a device setting. |
| — (bulk params dump) | base→phone | read only | `params:[{dev_type,param_type,param_value}, ...], main_sw_version, sec_sw_version` | Fragmented across multiple ~1032-byte packets + a short terminator. 77 params observed. Use this to verify a write actually took effect by reading the value back, rather than trusting the ack alone — the base acks the *packet*, not necessarily the applied value. |

A separate, undecoded `rssi_list` message (no `cmd` wrapper) reports BLE
signal strength between the base and sock in both directions and confirms
both devices' serial numbers.

## Settings sweep: most toggles don't touch the local protocol at all

A systematic sweep (toggling voice prompts, notifications, audio volume,
device name, time format, timezone one at a time) produced **no new local
UDP traffic** for any of them. A simultaneous unfiltered capture during a
device-name change showed the actual traffic went over HTTPS to Eufy's cloud
API instead. Conclusion: only settings that need to take effect on the
physical device immediately and independent of connectivity (brightness,
movement threshold, HR/SpO2 thresholds, working mode) go over this local
protocol — general metadata/preferences are cloud-stored instead. That puts
them out of scope for this document and for `scripts/standalone_client.py`;
reaching full settings parity with the app would mean separately reverse
engineering the cloud API, which is a different protocol, a different
authentication/encryption scheme, and not something this document covers.

## Reproducing this from scratch

1. Root the phone (Magisk) so you can read `logcat` and run a UDP capture.
2. Open the Eufy app once with `logcat` running and grep for a line
   containing the base's serial and a `-M`-suffixed value (search for
   `keyvalue=` or `key=`) — that string is the AES-128-ECB key for that base.
3. Capture UDP traffic between the phone and the base's LAN IP (no port
   filter needed — ports are chosen per-session, not fixed) with the app
   open, to see the handshake and confirm the key/framing against your own
   base.
4. Use `scripts/standalone_client.py` (pure Python, no root required once you
   have the key, works over plain Wi-Fi) to read telemetry/settings or send a
   write, with the official app closed the entire time.

## Safety / scope note

This only works against a base that already trusts your device's IP from
normal pairing — it's not a remote exploit, it requires LAN access to a base
you've already paired with the official app at least once.
