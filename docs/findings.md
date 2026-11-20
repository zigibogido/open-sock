# Findings

Short bullets only: hardware IDs, BLE UUIDs, endpoints, command formats.

## Hardware (from fccid.io)
- Base T8351 (FCC 2AOKB-T8351, board T8351-MB-V0.3)
  - MediaTek MT7628NN (MIPS24KEc + 2.4GHz Wi-Fi): application CPU, OpenWrt-class
  - Nanya 128MB DDR2, Winbond 25Q256JVEQ 32MB SPI NOR (firmware)
  - Nordic nRF52820 (BLE only) -> likely BLE controller for the MT7628
  - Pads labeled TXD/RXD/3V3/GND near flash: probable UART console
  - Pogo-pin board: 5V + GND only (charge dock)
- Sock T8340 (FCC 2AOKB-T8340, board S91-V1.2)
  - Nordic nRF52840 (BLE 5). Unlabeled pads, maybe SWD (unconfirmed)
- BLE 2402-2480 MHz; base Wi-Fi 2.4GHz only

## Topology (inferred, unverified)
- sock --BLE--> base --Wi-Fi--> Eufy cloud --> app
- Unknown: does the app talk to the sock/base directly after pairing?

## Environment
- User runs Localkit (Petkit) with Pi-hole DNS redirects; same pattern may apply to the base

## Base network (192.168.7.3, MAC 00:00:00:00:00:00)
- TCP open (tcpwrapped): 32290, 32292, 32293, 32295, 32392. TCP 80 filtered. UDP top-50: nothing
- DNS: care-app.eufylife.com, pushproxy-usa5/usa11.eufylife.com, security-traefik-us-prod-*.us-east-2.elb.amazonaws.com, time4.google.com, icanhazip.com
- Pairing timeline (phone clock 2026-11-20): 15:32:00 QR, 15:32:25 beep, 15:32:41 wifi, 15:33:03 setup ok, 15:33:20 sock on base, 15:33:32 sock added
- WARNING: HCI snoop likely contains Wi-Fi credentials; keep out of git

## BLE (HCI snoop, pairing capture 2026-11-20)
- Only Eufy device seen: eufy_XXXX @ 00:00:00:00:00:00 (likely base in setup mode). Sock never advertised by name to the phone
- Custom GATT service 2520567c-05cf-6eb4-c541-02030080858c (tshark byte order, may be reversed)
  - chars ...0180858c, ...0280858c (probably write + notify, unconfirmed)
- 7 ATT writes in the session (Wi-Fi provisioning likely; payloads not yet inspected)
- bugreport path of log: FS/data/log/bt/btsnoop_hci.log

## TODO
- [x] Base IP, nmap ports
- [x] Base DNS hostnames
- [x] HCI snoop extracted (pairing capture)
- [ ] Inspect ATT write/notify headers + handle->UUID map
- [ ] Idle-use capture (does phone talk to base/sock after pairing?)
- [ ] TLS probe of 32290 (openssl s_client)
- [ ] Decompile APK (user to supply)
