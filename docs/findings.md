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

## TODO
- [x] Base IP, nmap ports
- [x] Base DNS hostnames
- [ ] HCI snoop: extract from bugreport, then idle-use capture
- [ ] TLS probe of 32290 (openssl s_client)
- [ ] Decompile APK (user to supply)
