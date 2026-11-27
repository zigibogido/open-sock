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
  session-random) — and, confirmed since, across a full factory reset and
  fresh re-pair of the same physical base too (identical key extracted
  before and after). That rules out the `<6 digits>-M` part being
  per-pairing-session random, but **doesn't yet distinguish "deterministic
  function of this device's identity" from "a constant shared by every base
  of this model"** — settling that needs the same extraction done against a
  second, different physical base.
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
bytes 2-3 are the ciphertext length, little-endian (inferred, fits six data
points), so commands with the same padded length share a subtype (3516 and
3527 both pad to 160 bytes). Bytes 0-1 (`46 05`), and 4-11 are not understood.
Safer for a new length: `subtype[2:4] = len(ciphertext).to_bytes(2, 'little')`
(untested with a length change). A wrong subtype gets the packet silently
dropped (looks like "value rejected", but is "packet shape not recognized").
Extract the subtype from a real captured packet for each new command; known-good values are in
`COMMAND_SUBTYPES` in `scripts/standalone_client.py`.

| `cmd` | Direction | Status | Payload | Notes |
|---|---|---|---|---|
| 3503 | base→phone | read (periodic) | `sn, rssi, wear, wear_val, wear_threshold, hr, oxy, move, move_val, charge, battery_vol, signal_quality, cur_sleep_start/end/duration, time` | Live sock telemetry, the sock's own serial (`T8340...`) appears here for the first time — otherwise invisible to the phone. |
| 3515 | phone→base | **write verified** | `brightness:1-11, brightness_auto:0\|1` | Base status LED. **`0` is not a valid value** — confirmed by repeated testing (4/4) that it's silently remapped by the base's firmware to a built-in default (`9`), not applied as "off" and not rejected outright either. The packet is still acked; only the readback reveals the remap. Use `1` for "lowest", not `0`. |
| 3516 | phone→base | **write verified** | `move_threshold, tones_pushes` | Movement alert threshold; `tones_pushes` is a bitmask of voice prompt toggles, not a counter (see below). Always send both fields; read the current `tones_pushes` first. Wire identity of the threshold value is actually `param_type 3520` in the bulk dump below — `param_type 3516` is `tones_pushes` instead; don't assume a command's JSON field name matches the closest-looking `param_type`. |
| 3519 | phone→base | **write verified** | `hr_advance_enable, hr_dangerous_down/up, hr_warning_down/up(+_real), o2_dangerous_down, o2_warning_down(+_real), oxy_advance_enable` | HR/SpO2 safety-alert thresholds. **Only `hr_warning_down/up` is confirmed to correspond to a real app control** (2026-11-22: the app's own UI turns out to expose exactly one "Heart rate alert" setting, range 40-100 low / 120-250 high — matches `hr_warning_down=100`/`hr_warning_up=250` from the one real sample on record, not `hr_dangerous_down=80`). The app has **no visible control at all** for `hr_dangerous_*`, either `o2_*` field, or either `*_enable` flag — current theory is the app always sends fixed values for these alongside the one real control, not that they're independently settable; unconfirmed. To settle it: capture the app's HR alert control at several different values and diff all 8 decoded fields — if only `hr_warning_down/up` ever change, that confirms the theory. **Correction (2026-11-22): the packed `param_type 3519` string's first two positions are `hr_dangerous_up-hr_warning_up-...`, not `hr_warning_up-hr_dangerous_up-...` as originally written below and in `docs/findings.md`'s original discovery entry** — confirmed by isolating each field with a distinct test value (e.g. `hr_warning_up=199`, `hr_dangerous_up=230` → packed string read back `230-199-...`) and diffing the readback across several writes, not by inference. The remaining positions (`hr_warning_down-hr_dangerous_down,o2_warning_down-o2_dangerous_down,hr_advance_enable-oxy_advance_enable`) are correct as documented. |
| 3527 | phone→base | decoded, replayed; effect on a live alert unproven | `alarm_on:0, hr_alarm:0, oxy_alarm:0, stop:1` | Alarm stop. Subtype same as 3516. Base acks on ch0 (~250 ms) and pushes `{"cmd":3527,"payload":{sn,alarm_on,test,hr_alarm,oxy_alarm}}` on ch2 (~0.95 s, no account_id wrapper). Param 3527 reads 0 when idle; meaning unclear, `alarm_on:1` never observed. Needs a capture while the app shows the Stop button. |
| 3546 | phone→base | **write verified** | `mode:0\|1` | Working Mode: `0`=Standard, `1`=Mute. Subtype `46058000000001002c010000`, extracted from a real captured `mode:1` write (PCAPdroid, unrooted phone, LAN). Both directions tested and confirmed via readback. |
| 3509 | phone→base | read only | `bindStatus, birthdate, child_id, gender, height, name, race, weight` | Child/baby profile screen. Contains personal info by design, not a bug. |
| 1201 | phone→base | read only, purpose unclear | `time_out, user_name` | Fires automatically, not tied to one specific UI action; may be account/session-related rather than a device setting. |
| — (bulk params dump) | base→phone | read only | `params:[{dev_type,param_type,param_value}, ...], main_sw_version, sec_sw_version` | Fragmented across multiple ~1032-byte packets + a short terminator. 77 params observed. Use this to verify a write actually took effect by reading the value back, rather than trusting the ack alone — the base acks the *packet*, not necessarily the applied value. |

A separate, undecoded `rssi_list` message (no `cmd` wrapper) reports BLE
signal strength between the base and sock in both directions and confirms
both devices' serial numbers.

### `tones_pushes` voice prompt bitmask (cmd 3516, param 3516)

Set bit = prompt on. Current `move_threshold` is param 3520.

| Mask | Prompt | Status |
|---|---|---|
| 0x03 | Heart rate out of range (bits 0 and 1 change together, reason unknown) | verified live, both directions |
| 0x04 | Sock not worn correctly | verified live |
| 0x10 | Sock low battery | verified live |
| 0x20 | Sock disconnected | verified live |
| 0x1400 | Always set, never changed; preserve | unknown |
| 0x08, bits 6-9, 11 | Never changed | unknown |

All off = 5120 (0x1400); all four on = 5175. Sending `tones_pushes: 0`
turns every prompt off and clears the constant bits.

Other findings: param 1235 is the base speaker volume (1-26), readable
locally, no local write observed (probably BLE; treat as read-only). Writes
may land even when the verifying read fails, so never retry a write without
reading back first. The bulk dump is sometimes partial (about 5 in 40
reads), so validate it has 77 entries and retry.

## Settings sweep: most toggles don't touch the local protocol at all

A systematic sweep (toggling voice prompts, notifications, audio volume,
device name, time format, timezone one at a time) produced no new local
UDP traffic for most of them (exception: four voice prompts, see the
bitmask section above; other prompts and volume were not seen locally). A simultaneous unfiltered capture during a
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

1. **No root needed.** Confirmed on an unrooted phone: `adb logcat -d |
   grep -iE 'keyvalue=|aes test password='` after opening the app once
   (post-pairing) finds the key directly. (Root was used in this project's
   earlier sessions for unrelated Frida/anti-tamper work, and it was
   wrongly assumed to be a requirement for this specific step too — it
   isn't; the `shell` user's default `READ_LOGS` access is enough.)
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
