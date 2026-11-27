# Base params table (the 77-entry bulk dump)

Generated 2026-11-27 from the live dump plus 11 historical dumps decoded from
work/magisk/*.pcap and work/loose/*.pcap (same decoder as scripts/eufy_client.py).
ID is param_type/dev_type. The dump has 78 unique id/dev pairs across all snapshots; 1141/255 appeared once.
dev_type is 44 for sock-scoped values and 255 for base-wide ones (inferred from which ids line up with 3503 telemetry); 0 appears for 1164/1201 only.
Confidence: High = verified by a write or an exact match with telemetry. Medium = correlates with telemetry.
Low = guess from value range. Unknown = no evidence yet, most are constant, so only a deliberate app action or a firmware change will move them.

| id/dev | now | seen across snapshots | meaning | conf | evidence |
|---|---|---|---|---|---|
| 1043/255 | 0 | 0 / 6 | Unknown | - | varies, no match found |
| 1101/44 | 100 | 100 / 96 / 98 | Sock battery % | High | equals telemetry battery_vol in all 5 captures that have both |
| 1102/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1131/44 | 1 | 1 | Unknown | - | constant in all snapshots |
| 1133/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1134/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1135/255 | 4 | 4 | Unknown | - | constant in all snapshots |
| 1137/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1141/255 | -17 | - / -17 | Unknown | - | varies, no match found |
| 1141/44 | -17 | -44 / -16 / -17 / -49 | Link signal strength (dBm-like) | Low | varies -16 to -49; no matching telemetry field |
| 1147/255 | 1795762786 | changes every poll | Base clock, unix seconds | High | rises ~10 s per 10 s poll |
| 1148/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1149/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1150/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1151/255 | 1 | 1 | Unknown | - | constant in all snapshots |
| 1154/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1162/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1164/0 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1165/255 |  |  | Unknown | - | constant in all snapshots |
| 1166/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1167/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1168/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1169/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1170/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1171/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1172/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1173/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1174/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1175/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1176/255 | (IP, omitted) | (IP, omitted) | Base LAN IP (string) | High | value is the base address |
| 1177/44 | 9 | 9 | Unknown | - | constant in all snapshots |
| 1200/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1201/0 | 0 | 0 | Account/session record (cmd 1201: time_out, user_name) | Low | same id as cmd 1201; value 0 in dump |
| 1224/255 | 1 | 1 | Unknown | - | constant in all snapshots |
| 1225/44 | 9 | 9 | Unknown | - | constant in all snapshots |
| 1235/255 | 1 | 16 / 26 / 19 / 15 | Speaker volume 1-26 | High | read verified; write path unknown (see findings) |
| 1239/44 | 9 | 9 | Unknown | - | constant in all snapshots |
| 1257/255 | 63 | 63 | Unknown | - | constant in all snapshots |
| 1265/255 | 2 | 2 | Unknown | - | constant in all snapshots |
| 1266/255 | -36 | -36 / -37 / -33 / -40 | Base Wi-Fi RSSI (dBm) | Low | varies -33 to -40; plausible but not matched to a field |
| 1279/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1280/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1281/255 | 1 | 1 | Unknown | - | constant in all snapshots |
| 1282/255 | 1 | 1 | Unknown | - | constant in all snapshots |
| 1283/255 | 1 | 1 | Unknown | - | constant in all snapshots |
| 1284/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1285/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 1296/255 | EU | EU | Region code | High | value is "EU" |
| 1660/255 | -1 | -1 | Unknown | - | constant in all snapshots |
| 1664/255 | 1 | 1 | Unknown | - | constant in all snapshots |
| 1670/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 2111/44 | 1 | 2 / 1 | Unknown | - | varies, no match found |
| 3511/44 | 1 | 1 / 0 / 16 | Sock wear state mirror | Medium | 1/0 track telemetry wear; 16 when wear was 18 (two captures) |
| 3512/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3513/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3514/44 | 0 | 0 / 98 | Unknown | - | varies, no match found |
| 3515/255 | 11 | 8 / 11 / 9 | LED brightness 1-11 | High | write verified via cmd 3515 |
| 3516/44 | 5123 | 8995 / 5140 / 5143 / 13312 | tones_pushes bitmask (voice prompts) | High | write verified via cmd 3516; see tones_pushes section |
| 3519/44 | 250-250-40-40,90-9 | 230-230-100-80,9 / 250-250-100-80,9 / 220-220-80-80,90 / 220-210-90-80,90 | HR/SpO2 alert thresholds, packed string | High | write verified via cmd 3519; first two HR fields swapped vs older notes |
| 3520/44 | 30 | 30 | Movement alert threshold | High | cur_map[3520] is move_threshold in eufy_client.py; constant 30 |
| 3521/44 | 210 | 210 / 0 | Unknown | - | varies, no match found |
| 3522/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3523/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3524/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3525/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3526/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3527/255 | 0 | 0 | Alarm stop state | Medium | cmd 3527 stop; effect on a live alert unproven |
| 3528/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3529/255 | 0 | 0 / 1 | Unknown | - | varies, no match found |
| 3537/44 | 5 | 5 | Unknown | - | constant in all snapshots |
| 3539/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3540/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3541/44 | 0 | 0 / 1 | Unknown | - | varies, no match found |
| 3543/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3545/44 | 3 | 3 | Unknown | - | constant in all snapshots |
| 3546/255 | 0 | 0 | Working mode 0=Standard, 1=Mute | High | write verified via cmd 3546 |
| 3547/44 | 20 | 20 | Unknown | - | constant in all snapshots |
| 3548/44 | 0 | 0 | Unknown | - | constant in all snapshots |

## How to resolve the Unknown rows
- Run scripts/poll_volume.py --all-changes (read-only) while changing one app setting at a time; a changed id is that setting's param.
- Most Unknown ids never changed in 12 snapshots, so they are probably features the app exposes rarely (sleep, child profile, firmware, hardware flags) or are reserved.
- Candidates that did vary and still need a trigger: 3514/44 (98 once), 3521/44 (0 vs 210), 2111/44 (1 vs 2), 3541/44, 3529/255, 1141/44.
