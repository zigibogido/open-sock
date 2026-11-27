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
| 1141/44 | -17 | -16 to -49 | Link signal strength, noisy | Medium | flips between -16 and -18 every few polls with no setting changed |
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
| 1235/255 | 26 | 16 / 26 / 19 / 15 | Speaker volume 1-26 | High | app change 1 -> 26 reached the base within one 10 s poll on 2026-11-27 (path still unknown) |
| 1239/44 | 9 | 9 | Unknown | - | constant in all snapshots |
| 1257/255 | 63 | 63 | Unknown | - | constant in all snapshots |
| 1265/255 | 2 | 2 | Unknown | - | constant in all snapshots |
| 1266/255 | -35 | -31 to -40 | Base Wi-Fi RSSI, noisy | Medium | jitters -31 to -36 over a minute with no setting changed |
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
| 3515/255 | 1 | 8 / 11 / 9 | LED brightness 1-11 | High | write verified; app change 11 -> 1 seen 2026-11-27. The two auto-brightness toggles produced no change here |
| 3516/44 | 8963 | many | tones_pushes bitmask. Low bits 0x03/0x04/0x10/0x20 = voice prompts (documented). Upper bits 0x100+0x200, 0x400, 0x1000, 0x2000 = the app's "base notifications" (4 toggles, 2026-11-27 poll, mapped by toggle order, direction of each toggle unknown) | Medium | one change per toggle; low bits did not move |
| 3519/44 | 250-240-100-40,90-90,1-1 | many | HR/SpO2 thresholds, packed string | High | app range 40-250 -> 100-240 changed fields 2 and 3 only: 250-250-40-40 -> 250-240-100-40 |
| 3520/44 | 30 | 30 | Movement alert threshold | High | cur_map[3520] is move_threshold in eufy_client.py; constant 30 |
| 3521/44 | 210 | 210 / 0 | Unknown | - | varies, no match found |
| 3522/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3523/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3524/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3525/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3526/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3527/255 | 0 | 0 | Alarm stop state | Medium | cmd 3527 stop; effect on a live alert unproven |
| 3528/255 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3529/255 | 0 | 0 / 1 | Unknown, transient flag | - | pulsed 1 for about 20 s right after the base volume change and brightness-auto toggles on 2026-11-27; also 1 in two old snapshots |
| 3537/44 | 5 | 5 | Unknown | - | constant in all snapshots |
| 3539/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3540/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3541/44 | 0 | 0 / 1 | Unknown | - | varies, no match found |
| 3543/44 | 0 | 0 | Unknown | - | constant in all snapshots |
| 3545/44 | 3 | 3 | Unknown | - | constant in all snapshots |
| 3546/255 | 0 | 0 | Working mode 0=Standard, 1=Mute | High | write verified via cmd 3546 |
| 3547/44 | 35 | 20 (12 old snapshots) | Unknown, volatile | - | was 20 in every old snapshot; moved 20 -> 23 -> 55 -> 51 -> 35 between 20:33:43 and 20:34:45 on 2026-11-27, starting 21 s after the mute toggle, and stayed at 35 |
| 3548/44 | 0 | 0 | Unknown | - | constant in all snapshots |

## How to resolve the Unknown rows
- Run scripts/poll_volume.py --all-changes (read-only) while changing one app setting at a time; a changed id is that setting's param.
- Most Unknown ids never changed in 12 snapshots, so they are probably features the app exposes rarely (sleep, child profile, firmware, hardware flags) or are reserved.
- Candidates that did vary and still need a trigger: 3514/44 (98 once), 3521/44 (0 vs 210), 2111/44 (1 vs 2), 3541/44, 3529/255, 1141/44.

## Settings poll, 2026-11-27 (poll_volume.py --all-changes, one app change at a time)
- Moved a param: standard<->mute (3546, both ways), the 4 "base notifications" toggles (3516 upper bits, one change each), heart-rate range (3519), base volume (1235), brightness level (3515).
- Did not move any param: sock name, base name, the 4 "app notifications" toggles, 12h/24h, timezone, and the two auto-brightness toggles. Name, time and timezone were presumably cloud/phone only; the app-notification toggles are phone-local or cloud. The poll ended at 20:39:31, so confirm the time and timezone changes had been made by then.
- Noise to ignore: 1147 (clock), 1141 and 1266 (signal strength).
