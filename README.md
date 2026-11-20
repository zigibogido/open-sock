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

## Safety / scope note

This only works against a base that already trusts your device's IP from
normal pairing. It's not a remote exploit — it requires LAN access to a base
you've already paired with the official app at least once.
