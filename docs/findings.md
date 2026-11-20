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

## TODO
- [ ] Base IP, nmap ports (work/base-tcp.txt)
- [ ] Base DNS hostnames (Pi-hole)
- [ ] HCI snoop: pairing capture + idle-use capture
- [ ] Decompile APK (user to supply)
