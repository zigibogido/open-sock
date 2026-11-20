# Manifest findings: com.oceanwing.care.cam.apk (sha256 c9598e80…bed1)

- Package `com.oceanwing.care.cam`, v2.2.5_3347 (code 3347), minSdk 21, target 36. Split APK (`requiredSplitTypes=base__abi`); native libs are in config.*.apk.
- **Packed**: `application android:name=s.h.e.l.l.S`, `appComponentFactory=s.h.e.l.l.A` (shell/protector stub). Real code is likely in an encrypted payload, so decompiled classes may be incomplete. Check this first.
- allowBackup=false, largeHeap, networkSecurityConfig=@xml/network_security_config (not yet read).
- 247 components: 201 activity, 25 service, 18 receiver, 3 provider. 11 explicitly exported.
- BLE: `uses-feature bluetooth_le required=true`; BLUETOOTH_SCAN (neverForLocation), _ADVERTISE, _CONNECT, legacy BLUETOOTH/_ADMIN; location only up to SDK 30; companion_device_setup (optional).
- Network/Wi-Fi: INTERNET, ACCESS/CHANGE_WIFI_STATE, CHANGE_WIFI_MULTICAST_STATE (mDNS/multicast discovery, likely LAN P2P), ACCESS_NETWORK_STATE, MAINLINE_NETWORK_STACK.
- Other permissions: RECORD_AUDIO, CAMERA (optional), READ_PHONE_STATE, SYSTEM_ALERT_WINDOW, WRITE_SETTINGS, POST_NOTIFICATIONS, USE_BIOMETRIC/FINGERPRINT, FOREGROUND_SERVICE(+MEDIA_PLAYBACK), SCHEDULE_EXACT_ALARM, RECEIVE_BOOT_COMPLETED, ad-id permissions.
- Cloud: FCM push (`com.eufy.security.push.service.ZFirebaseMessagingService`, exported, MESSAGING_EVENT), c2dm RECEIVE, Firebase Analytics (AppMeasurementReceiver, exported), install referrer. `LogUploadService` (not exported) uploads logs.
- Exported components of interest:
  - `com.oceanwing.battery.cam.main.SplashActivity`: launcher.
  - `...main.ui.ExploreWebviewActivity`: BROWSABLE deep links `eufybaby://eufy/explore/web` and `eufycare://eufy/explore/web` (webview, no permission). Worth auditing for URL injection.
  - `...main.receiver.SystemRebootReceiver`: BOOT_COMPLETED.
  - `com.eufy.security.network.LanguageChangeReceiver`: LOCALE_CHANGED.
  - The rest are library components guarded by a permission: Firebase, WorkManager (DUMP), ProfileInstaller, evernote job (disabled).
- FileProvider `com.oceanwing.care.cam.fileprovider` (not exported, grantUriPermissions, paths in @xml/file_paths).
- Custom signature permission `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`.
- No BLE service/GATT UUIDs in the manifest. Those need the code, which is packed.

## network_security_config.xml (decoded by hand; apktool isn't installed)
- `base-config cleartextTrafficPermitted=false`: HTTP is blocked for the whole app, with no per-domain exceptions.
- `base-config` has no `trust-anchors` and no `pin-set`, so it uses the platform default trust. At target 36 that means system CAs only, with no user CAs. **No declarative cert pinning.**
- `debug-overrides` trusts `src=user` certs, but only in debuggable builds. This release build probably ignores it. If the APK is not debuggable, mitm needs a patched APK (or Frida) to trust a user CA, plus a check for pinning in the code (OkHttp CertificatePinner / custom TrustManager). The code is packed, so check at runtime.
- Tooling gap: `apktool` is not on PATH. Set `REA_APKTOOL_COMMAND` to use `decode_android_resources`. `jadx` and `java` are present.

## Native libs (config.armeabi_v7a.apk, 24 .so, lib/armeabi-v7a/; full list in work/manifest/libs.txt)
- **Flutter app**: `libflutter.so` (7.6MB) and `libapp.so` (5MB, Dart AOT snapshot). Most app logic is probably in Dart, not the DEX. Next: `identify_flutter_build` and `inspect_dart_aot`.
- **Protector**: `libijmdetect-drisk.so` and `libijm-emulator.so` ("ijm" is the iJiami/Ijiami prefix) match the `s.h.e.l.l` stub. This is probably root, emulator and hook detection, so expect Frida to be detected.
- Crypto/auth: `libecc-encryption.so`, `libargon2.so`, `libhome_security.so` (1.1MB, names suggests security/home logic, so look at it first).
- Device/P2P: `libNDT_API_PPCS.so` (PPCS P2P SDK, used for camera streaming/relay by many cameras, so likely the cloud/P2P path).
- Media: ijkplayer/ijkffmpeg/ijksdl, fdk_aac, ffavc, JNIBaseMedia, Mp4JNI, yuv, pag.
- Other: mmkv, crashlytics (4), readface (10.9MB, face recognition model), droidsonroids gif.
- Only armeabi-v7a here. Check for an arm64 split before dynamic work.

## Flutter build (identify_flutter_build on config.armeabi_v7a.apk)
- Flutter detected. Dart 3.6.0 stable (2024-12-05), target android_arm. This matches Flutter 3.27.x.
- Dart snapshot hash `f956f595844a2f845a55707faaaa51e4`, which identifies the Dart SDK build for blutter/reFlutter-style tooling.
- libflutter.so build id `f0fadbc061cfe5285bbb0cdd1175acb854c638ff`. libapp.so sha256 `a3a842d5…e8e8`, ELF header valid.
- `inspect_dart_aot` was interrupted by a safety classifier mid-run, so there are no results yet.

## libapp.so strings (work/flutter/strings.txt, 12596 lines; urls.txt has the 3 hits)
- The Dart AOT module is a **small embedded feature, not the main app**: only 12 app-owned .dart files, all under `package:eufybaby_flutter/`, for the eufy wearable breast pump (models E10/E102/S1/S12) — pump sessions, milk reports, edit/report screens (`EBSessionModel`, `EBReportModel`, `EBPumpEditSession`, `EBPumpMilkReport`).
- Embedded via **`flutter_boost`** (Alibaba's hybrid native/Flutter framework), confirming Flutter renders specific pages inside the native Android app rather than owning the app.
- Bundled Dart packages: collection, flutter, flutter_boost, flutter_gen, flutter_localizations, info_popup, intl, material_color_utilities, simple_gesture_detector, table_calendar, vector_math. **No networking, BLE, or storage plugin packages** — so BLE/cloud I/O for the pump happens on the native (Java/Kotlin) side and is passed to Flutter via flutter_boost/MethodChannel, not implemented in Dart.
- No app endpoints, secrets, API keys, or GATT UUIDs found in plain strings — only 3 URLs, all flutter.dev/api.flutter.dev framework boilerplate. Expected: Dart AOT strips most, and this module is UI-only.
- Routers found: `EufyBabyRouter`, `EufyBaby_PumpMilkReportRouter`, `EufyBaby_PumpSessionEditRouter` — flutter_boost page route names, useful if hooking page navigation.
- Conclusion: BLE protocol / endpoint discovery for the breast pump (and likely the camera) must come from the native Java/Kotlin side or native .so (e.g. libhome_security.so), not this Dart snapshot. inspect_dart_aot still untried (prior attempt interrupted).

## Scope note (2026-11-20)
User only cares about the **Eufy Sock** (T8340, nRF52840) + its base (T8351, MT7628NN + nRF52820), not the camera. Prior session's hardware/network/BLE findings carried over below; continue from here.

## Hardware (from fccid.io)
- Base T8351 (FCC 2AOKB-T8351, board T8351-MB-V0.3): MediaTek MT7628NN (MIPS24KEc, 2.4GHz Wi-Fi), Nanya 128MB DDR2, Winbond 25Q256JVEQ 32MB SPI NOR, Nordic nRF52820 (BLE-only, likely BLE controller for MT7628). TXD/RXD/3V3/GND pads near flash = probable UART console. Pogo-pin dock: 5V+GND only.
- Sock T8340 (FCC 2AOKB-T8340, board S91-V1.2): Nordic nRF52840 (BLE 5). Unlabeled pads, maybe SWD (unconfirmed).
- BLE 2402-2480 MHz; base Wi-Fi 2.4GHz only.

## Topology (inferred, unverified)
- sock --BLE--> base --Wi-Fi--> Eufy cloud --> app. Unknown if app talks to sock/base directly post-pairing.

## Base network (192.168.7.3, MAC 90:BF:D9:9F:B6:53)
- TCP open (tcpwrapped): 32290, 32292, 32293, 32295, 32392. TCP 80 filtered. UDP top-50: nothing.
- DNS: care-app.eufylife.com, pushproxy-usa5/usa11.eufylife.com, security-traefik-us-prod-*.us-east-2.elb.amazonaws.com, time4.google.com, icanhazip.com.
- Pairing timeline (phone clock 2026-11-20): 15:32:00 QR, 15:32:25 beep, 15:32:41 wifi, 15:33:03 setup ok, 15:33:20 sock on base, 15:33:32 sock added.
- WARNING: HCI snoop likely contains Wi-Fi credentials; keep out of git.

## BLE (HCI snoop, pairing capture 2026-11-20)
- Only Eufy device seen: eufy_5EC0 @ 90:bf:d9:a7:5e:c0 (likely base in setup mode). Sock never advertised by name to the phone.
- Custom GATT service **2520567c-05cf-6eb4-c541-02030080858c** (tshark byte order, may be reversed).
  - chars ...0180858c (write, handle 0x000d), ...0280858c (notify, handle 0x000f), CCCD 0x0010.
- Frame format: `ff 09 | len LE16 (whole frame) | 01 00 (phone->base) / 01 30 (base->phone) | msg id | c0 | payload`.
- Payload high-entropy (likely encrypted); same-kind msgs share a 3-4 byte prefix (type field or fixed IV, unknown).
- Likely flow: enable notify; base sends ~25x 105/121B notifs (Wi-Fi scan list?); 169B write (Wi-Fi creds?); later 41/137/137B writes (cloud bind?).
- Phone log shows no sock traffic -> sock likely added via base/cloud (unverified).
- tshark note: `-e btatt.value` prints hex without colons; byte len = chars/2.
- bugreport log path: FS/data/log/bt/btsnoop_hci.log.

## TODO (carried over, sock-focused)
- [x] Base IP, nmap ports
- [x] Base DNS hostnames
- [x] HCI snoop extracted (pairing capture)
- [x] Inspect ATT write/notify headers + handle->UUID map
- [ ] APK: find BLE UUID 2520567c... and crypto/key setup in Java/native code (this app is a packer-shell + small Flutter pump module; sock logic should be in DEX or a native lib like libhome_security.so/libecc-encryption.so)
- [ ] Idle-use capture (does phone talk to base/sock after pairing?)
- [ ] TLS probe of base ports 32290/32292/32293/32295/32392 (openssl s_client)
- [ ] Decompile APK (jadx available at /usr/bin/jadx)

## Packer internals (ijiami / 爱加密)
- Real app code is NOT in `classes.dex` (only 79KB stub matching the `s.h.e.l.l.S`/`s.h.e.l.l.A` shell). The actual DEX is encrypted inside `assets/ijiami.dat` (14.4MB), decrypted at runtime by `assets/ijm_lib/<abi>/libexec.so` + `libexecmain.so` + `libexecoat.so` (per-ABI, arm64-v8a/armeabi/x86/x86_64) and `assets/IJMDal.Data`.
- This matches `libijmdetect-drisk.so` / `libijm-emulator.so` seen in the installed native libs (anti-tamper/emulator detection, part of the same ijiami SDK).
- **Static unpacking of the real DEX is not practical from the APK alone** — need a dynamic dump (device/emulator + Frida, e.g. dump decrypted DEX from memory post-`loadClass`, or FART/ijiami-specific unpacker). No adb device is currently connected and no `frida` CLI on PATH (REA has its own Frida tooling via MCP, separate from this).
- Other assets: `assets/skins/skinplugin-release-unsigned.apk` (7.7MB, separate nested APK — skin/theme plugin, lower priority), `assets/eufy.crt` and `assets/eufy_anker.crt` — **both expired** (eufylife.com GoDaddy cert expired 2018-11-17; anker-in.com DigiCert cert expired 2021-08-04). If the code does cert-pin against these, pinning is stale/dead; more likely these are vestigial leftovers from an older build and not actively used. Worth confirming once DEX is unpacked.

## Next step options for sock BLE work (need a decision)
1. **Dynamic/device route (best for sock BLE)**: connect an Android device/emulator via adb, use REA's Frida tools (`start_frida_session`, `instrument_with_frida`) to hook `BluetoothGattCallback`/`BluetoothGatt.writeCharacteristic` and dump plaintext commands before BLE encryption, or dump the decrypted DEX from memory once ijiami unpacks it in-process.
2. **Static unpack route**: find/build an ijiami-specific unpacker for `ijiami.dat` (slower, less reliable, and may fight the anti-tamper libs).

## BLE idle-use capture (2026-11-20, bugreport_idle/btsnoop_hci_idle.log, 504KB, 3438 pkts over ~89min)
- Only 66 ATT packets in the whole window, all on one link: phone `e4:92:82:d5:7a:95` <-> base `90:bf:d9:a7:5e:c0` (same base as pairing capture). **Sock never appears as a separate BLE peer during normal use either** — confirms topology: app only ever talks BLE to the base; base relays to sock internally (unverified how, maybe its own BLE central role, or wired/other link on T8351 board).
- App reconnected fresh and re-ran full GATT discovery (MTU exchange, primary service read, char discovery, CCCD write) before using the same custom service/chars as pairing: write char handle 0x000d, notify char handle 0x000f, CCCD 0x0010.
- **Frame format confirmed**: `ff 09 | len_LE16 | 01 00 (phone->base) / 01 30 (base->phone) | msg_id (1 byte) | c0 | payload`. `msg_id` correlates request/response (e.g. write msg_id=07 -> notify response msg_id=07 immediately after).
- **Msg_id sequence observed** phone->base: 07, 00, 01, 03, 04, 05 (monotonic-ish, not strictly incrementing by 1 — 00 used after 07, so likely per-session counter or command-type tag, not pure sequence number).
- **Multi-chunk transfer**: msg_id=00 request triggered ~24 notification chunks (105-121 bytes each) back-to-back — same shape as the pairing capture's "Wi-Fi scan list" chunks; here it's mid-session, so more likely a bulk data fetch (history/log/status list) than Wi-Fi scan. Terminated by a short (41-byte) final chunk.
- **Unsolicited push observed**: notification msg_id=02 (frame 801, t=240s) has no matching prior write in this session — base pushed a notification on its own (periodic status/heartbeat?). Worth confirming with a longer idle-only capture (no app interaction) to see push interval.
- **Retransmission/duplicate behavior**: notify msg_id=03 sent twice (frames 830, 854, 3s apart, identical bytes) and a msg_id=05 notify (frame 861) repeats msg_id=04's payload almost byte-for-byte except msg_id field and last payload byte (0xb0->0xb1) — suggests a counter/nonce byte inside the encrypted payload rather than meaningfully different content, or an ACK/retry mechanic.
- **All payloads remain high-entropy / encrypted** — no plaintext command strings recovered over BLE. Matches native libs `libecc-encryption.so` + `libhome_security.so` found in the APK; crypto setup must come from there (needs dynamic analysis, not static strings).
- Representative writes (phone->base), for later crypto work:
  - msg07 (34B payload): `ff092900010007c02052b73a2faacb8393ad438f0125bc50856e80f9c8b45d740511e8f4aba980560a`
  - msg01 (big, 169B payload) at t=234s: `ff09a900010001c05c8283c0bd57eb5442842dd440dca0665ff...` (truncated; full bytes in btsnoop_hci_idle.log, tshark filter `btatt.handle==0x000d`)
  - msg04/msg05 (137B payload each, back-to-back ~0.5s apart) — same size class as pairing capture's "cloud bind" writes; here likely a status/report push from app to base.
- Raw capture kept at `/home/josh/rea-eufy/work/bugreport_idle/btsnoop_hci_idle.log` (gitignored; same Wi-Fi-credential caution does not apply here — no provisioning happened — but keep out of git per repo convention anyway).
- Repro command used: `inspect_packet_capture` with filter `btatt.opcode == 0x12 || btatt.opcode == 0x52 || btatt.opcode == 0x1b || btatt.opcode == 0x13`, fields `frame.number,frame.time_relative,bluetooth.src,btatt.opcode,btatt.handle,btatt.value`.

## Next steps (sock-focused, updated)
- [ ] Confirm sock<->base link mechanism (BLE central role on base's nRF52820, or something else) — may need base-side UART/SWD access, out of app scope.
- [ ] Longer idle capture (app closed, no interaction) to characterize the unsolicited push interval (msg_id=02-style).
- [ ] Crypto: no static key material found yet. `libecc-encryption.so` (ECC naming) + `libhome_security.so` are the likely home of the session-key / ECDH setup. Getting these needs either device root (frida-server + ptrace) or an unpacked DEX (ijiami.dat) to see the Java-side call-in. Ask user whether device can be rooted, or check for existing public writeups (eufy-security-client / similarly reverse-engineered Eufy camera P2P crypto on GitHub) as a shortcut before deep dynamic work.

## USENIX WOOT'24 Eufy paper (Goeman et al.) - transferable crypto findings
Paper: https://www.usenix.org/system/files/woot24-goeman.pdf (local copy: work/papers/woot24-goeman.txt, pdftotext -layout). Paper covers Eufy **doorbell + Homebase** (MIPS firmware), not the sock/BLE directly, but shares the same binary names/SDK (`home_security`, `PPCS_ID`) found in our APK, so the key-derivation weaknesses are a strong lead, not yet confirmed to apply to this app/device.
- **WPA2-PSK derivation (CVE-2023-37822)**: `WPA2-PSK = B64(MD5(serial))[0:7]` (8 chars from base64 of the MD5 of the device serial). Only ~24 bits of real entropy once the vulnerable shortened-MD5 step is used; serial is learnable from device casing, LAN/WAN traffic, or brute force.
  - Serial number format: `AAAAAAA` (device-type, e.g. T8010) + 1 char batch id (P/N, 0-3) + 7 hex chars (device-specific).
- **P2P/media AES key derivation**: AES-ECB (weak mode) used throughout. Media key = `SHA256("01"+baseCode+seed)` then a custom "Obfuscate2" byte transform; `baseCode = serial[0:l] + getPPCSSuffix(PPCS_ID)`; `seed = Obfuscate1(MD5("01"+random+str(1000-sfx)))`. `getPPCSSuffix` sums 4 digits from the middle segment of PPCS_ID (doubles if <5) → only 480 possible values, brute-forceable.
  - PPCS_ID format: `AAAAAAA-000000-BBBBB` (20 chars, 3 dash-separated parts), interceptable from App<->Homebase network traffic.
  - All of this lives in the device's own `home_security` MIPS binary (on the Homebase/base, not the phone) — recovered via symbolic execution (dAngr, open-sourced by the authors) because Ghidra's MIPS decompilation was unreliable.
- **No BLE-specific findings in this paper** — their BLE reference is to an unrelated Xiaomi case study, not Eufy. Eufy's own BLE local protocol (what we're after for the sock) is not documented here.

## Our serial + PPCS check (2026-11-20, from bugreport_idle dumpstate text, 167MB — grepped, not read in full)
- Base serial recovered from dumpsys text: **`T8351P102524071D`** (matches the paper's exact serial format for device type T8351).
- Computed candidate WPA2-PSK via the paper's formula: `B64(MD5("T8351P102524071D"))[0:8]` = `Y2QwYjFj`. **Not yet verified** — would need the actual Wi-Fi password captured during pairing (noted in the prior session's findings as present in the original HCI snoop, but that capture file isn't present in this project's `work/`; it was flagged sensitive and apparently not kept). If a fresh pairing capture is done again, the Wi-Fi password in the ATT write payloads (or `wpa_supplicant`/`dumpsys wifi` right after provisioning) would let us confirm whether this exact formula still holds for the T8351 base.
- No PPCS_ID-shaped string (`AAAAAAA-000000-BBBBB`) found in this bugreport's dumpstate text. The `ppCs...`-prefixed strings that matched are unrelated base64 blobs (coincidental substring), not real PPCS identifiers.
- `libhome_security.so` (phone-side, ARM, in this APK) is a **different binary** from the paper's MIPS Homebase firmware binary of the same name — it's the app's own copy, presumably implementing the client side of the same (or a related) key derivation so the app can compute matching keys. It is **anti-RE hardened**: `.dynsym`/`.symtab` reduced to 3 libc-only entries despite an 85KB unreferenced `.dynstr`, and no JNI (`Java_...`) exports at all — native methods are likely registered via `RegisterNatives` at runtime rather than named exports, so static nm/readelf/Ghidra symbol recovery won't work directly; matches the paper's own experience needing dynamic/symbolic execution rather than static decompilation.

## Updated recommendation for sock BLE work
1. Cheapest next step: **redo a pairing capture** (reset base, re-pair) and check the plaintext Wi-Fi password against the `B64(MD5(serial))[0:7]` formula — fast way to learn whether the sock/base's firmware generation reuses the same (vulnerable) scheme as the doorbell/Homebase line. If confirmed, the BLE command-channel AES key might follow an analogous PPCS_ID-based derivation, intercept the PPCS_ID in local traffic, and reproduce dAngr-style symbolic recovery instead of hunting for it from scratch.
2. If that doesn't pan out, dynamic analysis (rooted device + Frida, or dAngr-equivalent symbolic execution on `libhome_security.so`/`libecc-encryption.so`) remains the only path to the actual BLE payload key, since the phone-side lib is deliberately stripped of static symbol info.

## WPA2-PSK theory check (2026-11-20, fresh factory-reset pairing, bugreport_pairing2/btsnoop_hci_pairing2.log, 659KB)
- **Result: not testable / likely doesn't apply.** Grepped the full dumpstate text and the new BLE capture for any device-hosted Wi-Fi AP ("eufy_..." SSID) during setup — found none. The only "eufy_5EC0" string is the **BLE advertising name**, not a Wi-Fi SSID. No `WifiConfiguration`/scan-result entries for an eufy-prefixed network appear anywhere in dumpstate.
- Conclusion: **this product provisions Wi-Fi purely over the BLE channel** (phone sends home Wi-Fi SSID+password to the base as an encrypted ATT write), not via a temporary SoftAP + WPA2-PSK like the doorbell/Homebase line the WOOT paper examined. There is no "dedicated Eufy network" password to recover here, so **CVE-2023-37822's WPA2-PSK formula does not apply to this device's setup flow** — the paper's finding doesn't transfer directly.
- Serial confirmed unchanged after factory reset: `T8351P102524071D`. No sock serial (`T8340...`) or PPCS_ID string surfaced in this capture either — the sock stays invisible to the phone; everything goes through the base.
- BLE protocol shape reconfirmed identical to the original pairing/idle captures (same handles 0x000d/0x000f/0x0010, same `ff 09 | len | dir | msgid | c0 | payload` framing, 75 matching ATT packets this run).
- **This closes off the "cheap verification" path.** The PPCS_ID-based media/P2P AES key derivation from the paper is still an open question (unconfirmed either way for this device) since PPCS_ID never appeared in plaintext. Next step is dynamic analysis of `libhome_security.so`/`libecc-encryption.so` (root + Frida, or symbolic execution) — there's no further static/network shortcut left to try.

## Second test device rooted (2026-11-20) — Mi 9T (davinci), adb id 41bdf203, arm64-v8a, SDK 29, TWRP 3.4.0
- Flashed Magisk v31.1 via existing TWRP (`twrp set tw_skip_digest_check 1` wasn't enough; TWRP's zip install required a `.sha256` sidecar file next to the APK/zip — generated with `sha256sum` and pushed alongside, then `twrp install` succeeded).
- Magisk APK install via adb required a manual on-device confirm (`INSTALL_FAILED_USER_RESTRICTED` on silent `adb install`); opened the installer with `am start -a android.intent.action.VIEW -d file:///sdcard/....apk -t application/vnd.android.package-archive` and had user tap Install.
- **Magisk v31.1 removed the interactive root-grant popup for non-app UIDs (adb shell, uid 2000)** — logcat showed `su: request rejected (2000)` with no prompt. Root for ADB must be pre-granted from the Magisk app's **Superuser tab**: an entry named "Shell" appears there after the first rejected request and must be toggled to Allow manually. No separate "Apps and ADB" setting exists in this version (older guidance referencing that setting is stale).
- Confirmed: `adb -s 41bdf203 shell su -c id` → `uid=0(root)`.
- eufy app (com.oceanwing.care.cam) installed on this device, logged into the same account, base+sock visible. Ready for Frida-based dynamic analysis of `libhome_security.so`/`libecc-encryption.so`.

## MAJOR FIND: AES key logged in cleartext via logcat (2026-11-20, Mi 9T rooted device)
- The app's anti-tamper logic detects the rooted/Frida environment (repeated SELinux denials reading `/proc/net/unix`, almost certainly scanning for frida-server's listening socket) and self-terminates (`System.exit(0)`) roughly 20s after each launch. This caused the pid-chasing churn during attach attempts — not random backgrounding.
- **Before it self-terminates, the `HomeSecurity` native lib logs the full P2P/BLE command protocol in cleartext to logcat**, including the symmetric key:
  ```
  HomeSecurity: leo_p2p send command sn=T8351P102524071D keycode=1 keyvalue=524071D-333113-M
  HomeSecurity: ------>>[int_aes_encryptkey] aes test password=524071D-333113-M ret=0
  HomeSecurity: leo_p2p notify aes_decrypt sign_code=1 sn=T8351P102524071D key=524071D-333113-M
  ```
- Key value: **`524071D-333113-M`**. Note `524071D` = the **last 7 characters of the base serial** `T8351P102524071D`. Format looks like `<serial_suffix>-<6_digit_code>-M`; the `333113` and trailing `M` are not yet explained (could be a per-session code, a fixed device-type suffix, or derived from a PPCS-like identifier — needs more samples to tell if `333113` is session-random or static).
- The underlying P2P library brand is **"leo_p2p"**, not PPCS (the home_security lib may wrap multiple white-label P2P backends; PPCS is a separate native lib in this APK, `libNDT_API_PPCS.so`, not necessarily used by this code path).
- `send_command_with_int`/`send_command_with_2int_mstring`/`notify_callback` all reference `channel` (0 or 255) and `command_id` (1130, 1103 seen) — these are very likely the actual command IDs/channels behind the `msg_id`/`c0` fields observed in the BLE capture framing (`ff 09 | len | dir | msg_id | c0 | payload`).
- **Next step**: test whether this `keyvalue` (as raw bytes, or MD5/SHA256-derived) decrypts the BLE ATT payloads captured earlier (`work/bugreport_idle/btsnoop_hci_idle.log`, `work/bugreport_pairing2/btsnoop_hci_pairing2.log`) under AES-ECB — matches the WOOT paper's observation that Eufy uses weak/custom key derivation + AES-ECB throughout.
- Setup notes for reproducing this (rooted Mi 9T, 41bdf203):
  - frida-server **17.23.2 crashes on this Android 10 (SDK 29) device** with `frida_sigchain_compat_validate_signal: assertion failed` — a real frida-core regression on old Android, not our setup. **frida-server 17.10.0 works** (same npm `frida` 17.23.2 client protocol-compatible with it) after also fixing a MIUI-specific `HelperBackend` crash (missing `/data/system/theme_config/theme_compatibility.xml` — create an empty `<themeConfig><version>1</version></themeConfig>` file, owner `system:system`, context `u:object_r:system_data_file:s0`).
  - `spawn` mode fails on frida-server 17.10.0 with "Unable to pick a payload base" (ASLR/injection quirk on this build) — **use `attach` mode**, not spawn.
  - The app detects root/Frida and self-exits ~20s after launch regardless of foreground state — **this cleartext-key logcat leak was found without ever successfully attaching Frida**, just from `adb logcat` while the app briefly ran. Given this, Frida attach may not even be necessary for further protocol work — logcat alone may continue to leak useful material in the ~20s window before self-termination.

## Key verification against BLE ciphertext: negative result
- Tried decrypting a captured BLE write payload (`52b73a2f...` from msg07, idle capture) under AES-128-ECB with keys derived from `524071D-333113-M` via: MD5, SHA1[:16], SHA256[:16], raw ASCII truncated to 16 bytes, and AES-128-CBC with zero IV (MD5 key). **None produced recognizable plaintext** (no zero-padding, ASCII, or repeating block patterns).
- Logged key is **stable across app relaunches** (same value on 2 separate launches, ~15s apart), so it's deterministic from the serial, not session-random — but it almost certainly belongs to a **different transport than BLE**.
- Revised hypothesis: `leo_p2p`/`HomeSecurity`'s logged key is for the **P2P/cloud command channel** (TCP, to the base's P2P ports found earlier: 32290/32292/32293/32295/32392) — the same layer the WOOT paper reverse-engineered for the camera/doorbell line. `command_id`/`channel` fields (1130, 1103, 0, 255) look like P2P command opcodes, not BLE GATT writes. The BLE provisioning channel we captured is likely secured by a separate, probably ECDH-based, per-connection scheme — consistent with why a static per-device password doesn't decrypt it.
- **Still a solid lead for the P2P/base control channel**, just not (yet) for the sock's BLE path specifically. A LAN packet capture (tcpdump/Wireshark on the base's P2P TCP ports) taken while triggering a base/sock action, tested against this same key, would confirm or rule this out cheaply — no Frida/root fragility needed since it's just TCP.

## BREAKTHROUGH: Sock telemetry decrypted — full protocol cracked (2026-11-20)
**This is the answer for sock functionality.** The P2P/PPCS UDP channel (not BLE) carries the sock's live data, and it decrypts cleanly.

### Capture setup
- `tcpdump -i wlan0 -w capture.pcap host 192.168.7.3` on the rooted Mi 9T (no port filter — P2P uses ephemeral UDP ports, not the earlier nmap-found TCP ports 32290 etc., which are unrelated/irrelevant).
- Protocol is **PPCS** (matches `libNDT_API_PPCS.so`), magic byte `0xf1`: `f1 e0 00 00`=ping (phone->base), `f1 e1 00 00`=pong (base->phone), `f1 d0 <len_LE16> ...`=data packet, `f1 d1 ...`=ack.

### Decryption
- **Key:** first 16 bytes of the literal ASCII string logged by `HomeSecurity`/`leo_p2p` (`524071D-333113-M`, i.e. drop the trailing `-M`): `35 32 34 30 37 31 44 2d 33 33 33 31 31 33 2d` hex, or ASCII `524071D-333113-`.
- **Cipher: AES-128-ECB**, no IV, raw ASCII bytes used directly as the key (no hashing/KDF) — matches the WOOT paper's finding that Eufy uses weak/custom crypto and AES-ECB broadly.
- **Packet layout**: `f1 d0 <len_LE16>` (4 bytes) + 20-byte sub-header (`d1 02 00 5a 58 5a 59 48 47 05 10 01 00 00 01 00 ff 01 00 00`) + N×16-byte AES-ECB blocks. First decrypted byte is a stray `\n`/`.` then the JSON begins; after the JSON's closing `}}` there's a short binary trailer (`00 01 00 00 11 00 00 00` in the sample — `0x11`=17 matches the exact block count, likely a block-count/length field, not meaningful payload).
- **Command `3503`** = sock telemetry push. Full decrypted JSON schema observed:
  ```json
  {"cmd":3503,"payload":{"rssi":-62,"wear":1,"sn":"T8340P00252008D1","time":1795151049,"oxy":0,"hr":0,"move":0,"move_val":0,"wear_val":0,"wear_threshold":0,"charge":1,"battery_vol":100,"signal_quality":0,"cur_sleep_start":0,"cur_sleep_end":0,"cur_sleep_duration":0}}
  ```
  Fields: `sn` = **sock's own serial** (T8340-prefixed, confirmed — first time we've seen it, previously invisible to the phone over BLE). `rssi` = BLE signal strength base<->sock. `wear`/`wear_val`/`wear_threshold` = worn-detection. `hr`/`oxy` = heart rate / SpO2 (0 when not worn/no reading). `move`/`move_val` = motion detection. `charge`/`battery_vol` = charging state and battery %. `cur_sleep_*` = active sleep session tracking. `time` = unix timestamp.
- This confirms the actual flow: **sock --BLE--> base --(decrypts/relays)--> phone, via PPCS P2P UDP, AES-ECB with the key derived from the base's serial**, logged in cleartext by the app itself. The BLE layer between sock and base remains a separate, still-undetermined encryption (not cracked), but it doesn't need to be — **the P2P channel already gives plaintext sock data once decrypted**.
- Ack packet format: `f1 d1 <len_LE16> d1 02 00 01 00 <seq_byte>` (phone->base, 11 bytes total, no payload) — just acknowledges receipt of a `d0` data packet by echoing part of its sub-header.

### How to reproduce / use this going forward
1. Capture UDP traffic between the phone and the base's IP (any interface, no port filter needed) while the app is open — a plain `tcpdump`/Wireshark capture on either end works, no Frida/root needed beyond running tcpdump.
2. Get the AES key once per base: open the eufy app with `adb logcat` running, grep for `HomeSecurity.*keyvalue=`, take the string, drop the trailing `-M`, use the first 16 ASCII bytes as an AES-128-ECB key.
3. For each `f1 d0` UDP packet, skip the first 24 bytes (header), AES-128-ECB-decrypt the rest, strip the leading stray byte and trailing block-count trailer, parse as JSON.
4. This should also work for **other command IDs** beyond 3503 (e.g. commands sent *to* the sock/base, config changes, historical session data) — same key, same framing, just a different `cmd` value and payload shape. Worth capturing a longer session to enumerate other `cmd` values.

## Correction: AES key is exactly 16 bytes, no truncation
- Earlier entry saying "drop the trailing -M" was wrong. `524071D-333113-M` is **exactly 16 ASCII bytes** — used as-is, directly as the AES-128-ECB key. No hashing, no truncation.

## PPCS command catalog (from longer capture, 312 `f1 d0` data packets, decrypted)
Key = `524071D-333113-M` (16 raw ASCII bytes), AES-128-ECB, skip first 24 header bytes per packet. Reassembly note: UDP packets over ~1000 bytes are **fragments of one logical message** — concatenate decrypted plaintext of consecutive same-direction fragments (don't mix fragments from two different message instances; watch for a short "terminator" fragment ending each run).

- **`cmd 3503`** (base→phone, frequent/periodic): live sock telemetry. `{"sn":"T8340...","rssi","wear","hr","oxy","move","move_val","wear_val","wear_threshold","charge","battery_vol","signal_quality","cur_sleep_start/end/duration","time"}`.
- **`cmd 3516`** (phone→base, has `account_id`): push a setting — seen with `{"move_threshold":30,"tones_pushes":5143}` (movement alert threshold + notification counter).
- **`cmd 3519`** (phone→base, has `account_id`): push heart-rate/SpO2 alert thresholds — `{"hr_advance_enable","hr_dangerous_down/up","hr_warning_down/up","hr_warning_down_real/up_real","o2_dangerous_down","o2_warning_down","o2_warning_down_real","oxy_advance_enable"}`. This is the sock's safety-alert config, settable from the app.
- **`cmd 3515`** (phone→base, has `account_id`): push base hardware setting — `{"brightness":9,"brightness_auto":0}` (base's status LED).
- **`rssi_list`** (base→phone, no `cmd` wrapper): `[{"station_sn":"T8351...","device_sn":"","rssi":N},{"station_sn":"","device_sn":"T8340...","rssi":N}]` — confirms both serials and their respective BLE signal strength to each other.
- **Bulk params dump** (base→phone, large, fragmented across multiple ~1032-byte UDP packets + one short terminator): `{"params":[{"dev_type":D,"param_type":P,"param_value":"V"}, ...], "main_sw_version":"2.1.2.5s_0.1", "sec_sw_version":"1.0.4.8"}`. Observed 77 params on `dev_type` 44/255/0/3524/4521. Notable: `param_type 3519` = `"230-230-100-80,90-80,1-0"` — this is the **packed encoding of the same HR/SpO2 thresholds** as `cmd 3519` (order: hr_warning_up-hr_dangerous_up-hr_warning_down-hr_dangerous_down,o2_warning_down-o2_dangerous_down,hr_advance_enable-oxy_advance_enable). `param_type 1176` = base's LAN IP (`"192.168.7.3"`). `param_type 1296` = region code (`"EU"`). Full raw dump saved at `work/magisk/params_dump.txt` (gitignored, local only).
- Small fixed-byte control packets also seen (`ff 00 00 00 01 00...`, `02 00 00 00...`) — not JSON, likely binary ack/control frames for the fragmented transfer (fragment-ack or flow control), not yet decoded.

## Practical takeaway
You now have a working, documented path to **both read sock telemetry/config and push new config** (alert thresholds, movement sensitivity) over plain LAN UDP, fully decrypted, without touching BLE, Frida, or root on your main phone. This is likely sufficient for any personal integration/monitoring use of the sock.

## Attempted command injection: base validates source port, not just IP/content
- Replayed the exact known-good "set brightness=9" `f1 d0` packet (same bytes, valid AES-ECB encryption with our key) from the phone's real IP (192.168.4.73) to the base's then-current live port (26457), but from a **different source UDP port** (49501, vs the app's actively-bound 11964).
- **Confirmed sent** (visible in capture, correct bytes, correct destination) but **the base never acked it** (no `f1 d1` response) — background ping/pong between the app and base continued unaffected, so the base is alive and listening, it simply silently dropped/ignored our packet.
- Conclusion: the base's PPCS session is bound to a specific (client_ip, client_port) tuple established during the original P2P handshake (which we haven't captured/replicated), not just correct AES decryption + source IP. **Sending to an established session's exact ports also failed when sent from a non-matching source** — content correctness alone is not sufficient to be accepted.
- To actually inject a command, the next step would be sending from the app's **exact** currently-bound source port (11964), which requires either: (a) a raw socket with a spoofed source port (root-permitted on the phone, but closer to IP spoofing — not attempted), or (b) capturing and replicating the full P2P handshake sequence (ping/pong + initial negotiation) ourselves to establish our own legitimate session with the base, rather than piggybacking on the app's. Neither attempted yet — stopped here as a reasonable checkpoint given rising complexity/risk for read-mostly use.

## Cold-start capture: full session handshake decoded (2026-11-26, coldstart.pcap)
Force-stopped the app, captured broad UDP from before relaunch. The real handshake starts ~18.5s in (after cloud login/TLS traffic settles):

1. **Parallel discovery** (phone picks a fresh local port, e.g. 18201):
   - `f1 00 00 00` (4B) sent to **3 AWS relay candidates** (seen: `18.211.176.129`, `3.13.12.246`, `184.72.36.250`, all port **32100**) — cloud-assisted lookup path.
   - `f1 30 00 00` (4B) sent to **local broadcast** (`192.168.7.255` and `255.255.255.255`) on port **32108** — LAN discovery path, tried in parallel.
2. **Base answers the broadcast directly** (same LAN, so this wins the race): base replies from a **freshly chosen ephemeral port** (e.g. 15833) straight to the phone's port (18201) with `f1 41 0014 <20-byte announce body>` / `f1 42 ...` (repeats). The announce body is a fixed-looking tag, not JSON — not yet decoded further, but it's not session-specific (same bytes seen on different connects).
   - **This exchange is how you learn the base's current port** — critical for a standalone client. No pre-shared port needed; just broadcast and listen.
3. **Ping/pong starts immediately** on the newly learned (phone_port, base_port) pair: `f1 e0 00 00` / `f1 e1 00 00`, same as the steady-state keepalive already documented.
4. **First encrypted exchange**: phone sends `f1 d0 <len> d1 00 <msgid> 58 5a 59 48 <...sub-header...>` + one 16-byte AES-ECB block. Decrypts (same key as always, `524071D-333113-M`) to **`ff 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00`** — a fixed capability/ready flag, not JSON. (This matches the mystery `\xff\x00\x00\x00\x01\x00...` bytes flagged as "undecoded" in the earlier general capture — now explained: it's the session hello, not telemetry.)
5. Base pushes a couple of **zeroed/placeholder device-info responses** (non-block-aligned payload lengths, e.g. 133/132/8 bytes — not standard AES-ECB block multiples, likely a different, not-yet-fully-decoded sub-format used only during bring-up, probably just "no data yet" placeholders). Not fully decoded, but immaterial — once the sock has reported, this transitions into the normal `cmd 3503`-style traffic already fully documented above.
6. From here on, traffic matches everything already catalogued (telemetry, settings pushes, acks via `f1 d1`).

**Conclusion: a fully standalone client is achievable.** The only thing an independent client needs that the app previously "hid" is step 1-3 — broadcast on the LAN, read the base's reply to learn its current port, ping it. No cloud dependency required for LAN-only operation (the AWS lookup is a parallel fallback, not a prerequisite — local broadcast wins first). No extra authentication beyond knowing the static AES key appears necessary for the base to start accepting `f1 d0` commands from the newly-discovered port.

## RESOLVED: the gating mechanism is source IP, not app session or cloud arming (2026-11-20)
Controlled test, app fully closed throughout:
- Sent identical `f1 30 00 00` discovery packet to `192.168.7.3:32108` from **this host's IP** (192.168.4.4, never paired with the base): **no reply**.
- Sent the exact same packet from **the rooted phone's IP** (192.168.4.73, the device that originally paired): **instant reply** `f1 41 0014 ...` — same announce body seen in the real app's handshake.
- Earlier broadcast-based tests (from this host) failed for the same reason — it was never about broadcast-vs-unicast or an "arming window", just source IP. Unicast direct-to-base works fine and is simpler than broadcast.
- **Conclusion: the base's discovery responder trusts by client IP** (presumably recorded during original pairing, or just "whatever device is currently the registered owner on this LAN"), not by app process, not by a cloud-side per-connection authorization step, and not time-gated to a window after login. This means **any process running on the paired phone** — not specifically the official app — can initiate its own independent PPCS session. Full app-bypass is therefore architecturally open; the remaining work is purely tooling (something capable of a persistent UDP socket on the phone), not more protocol reverse-engineering.
- Practical blocker hit while proving the full chain from the phone: **toybox `nc` (Android's built-in netcat) can't hold one persistent UDP socket across a multi-step exchange** — each invocation picks a new ephemeral source port regardless of `-p`, and `-w`/no-`-q` hangs instead of returning. Confirmed step 1 (discovery) works via `nc` one-shot; steps 2+ (ping to the learned port, hello, decrypt pushes) need a real persistent-socket client, which isn't available out of the box on the phone (no python/perl/etc. preinstalled).
- **Next step to complete full proof**: get a persistent-socket-capable runtime onto the phone (e.g. a static Python build, or a small compiled binary) and run the already-written `work/magisk/standalone_client.py` logic from the phone's own IP. Everything else (packet formats, key, header layout, handshake sequence) is already fully documented above and should work unchanged once run from the right IP.

## STANDALONE CLIENT WORKING: full app-independent session established (2026-11-20)
**Found the missing handshake step and got a genuine standalone session running.** From a real app cold-start capture, diffed byte-for-byte against our own attempts:
- After the base's `f1 41` announce, **the real client echoes the exact same `f1 41` bytes back to the base several times** before the base ever sends `f1 42` or accepts a ping. We were skipping this echo step entirely, which is why every previous standalone attempt got silence after announce.
- Corrected sequence: discovery (`f1 30 00 00`, unicast to base IP is enough, no broadcast needed) → base sends `f1 41 ...` → **client echoes `f1 41` back 3-4x** → base sends `f1 42 ...` → ping (`f1 e0 00 00`) → pong (`f1 e1 00 00`) → session is live, base starts pushing `f1 d0` data unprompted.
- **Result, with the official app fully force-stopped throughout**: our standalone script (`work/magisk/standalone_client.py`, running under Termux's Python on the phone itself, so it uses the phone's trusted/paired IP) completed the entire handshake and received an ongoing stream of `f1 d0` pushes from the base — a session the app had nothing to do with. **This proves full app-bypass for the LAN protocol: any process on the paired device's IP can open its own independent PPCS session.**
- Toolchain note: implemented a dependency-free pure-Python AES-128-ECB decrypt (`work/magisk/pure_aes.py`) since neither `openssl` CLI nor a crypto pip package were worth installing on-device; verified byte-for-byte against the known-good telemetry decrypt before relying on it.
- **Open issue, not yet resolved**: the `f1 d0` pushes received during this first standalone session did **not** decrypt to readable JSON (our `{` search matched by coincidence on garbage bytes) — likely either (a) still the zeroed/placeholder bring-up messages seen during the original cold-start capture (same non-block-aligned-looking shape), (b) the sock wasn't actively reporting during this short test window, or (c) a message sub-type we haven't mapped yet. The protocol/session-establishment layer is proven solid; the remaining work is purely about correctly classifying/decoding this particular push's format, which is a smaller, well-scoped follow-up, not a new unknown.

## Setup recipe for reproducing standalone client work
- Device needs root (Magisk) + a scripting runtime. Easiest: sideload Termux (GitHub releases, arm64-v8a APK), open it once to bootstrap, run `pkg install python -y` **from within the Termux terminal UI** (running it via `su <uid> -c` impersonation from adb hits a DNS resolution failure for `apt` — some Android per-UID network setup Termux's real zygote-spawned process gets that `su`-impersonation doesn't; plain raw-socket operations like our script's UDP traffic are unaffected by this and run fine via `su u0_a211 -c`).
- Run scripts via: `su u0_a211 -c 'sh script.sh'` where the script sets `HOME`/`PREFIX`/`PATH`/`LD_LIBRARY_PATH` for Termux's prefix and invokes `python3` from there — avoids needing the Termux app UI for subsequent runs.

## Standalone session: ack mechanism confirmed working, one message class still unidentified
- Implemented correct `f1 d1` acks (format: `f1 d1 00 06 d1 00 00 01 <msgid echoed from push bytes[6:8]>`) and a periodic re-sent status/hello packet (incrementing msgid), matching the real client's persistent behavior. This fixed the "stuck retransmitting the first fragment forever" problem for most message classes.
- **But one recurring large push still decrypts to non-JSON content, and critically: the exact same byte-for-byte content repeats across multiple test runs minutes apart, including before and after confirming the sock was powered on and worn.** Since real telemetry would vary with actual readings, this rules out "no fresh data yet" as the explanation — it's either (a) a fixed/static non-telemetry message type (e.g. a signature, protocol filler, or device-info blob) that our key decrypts correctly but isn't meant to look like JSON, or (b) our ack isn't being recognized for this specific message's `channel` sub-field (the ack hardcodes `d1 00 00 01`; pushes using a different channel byte at header offset 5 may need that value echoed instead of always `00`), so the base keeps resending a stale cached message regardless of sock state.
- Not yet resolved. Next concrete step: capture raw packets alongside a standalone run and check whether the push's channel byte (offset 5) varies, and whether our ack is being correctly channel-matched — may need to make the ack echo the exact channel byte from the request. Also worth checking whether this class of push is the already-identified "bulk device params dump" misassembled (fragments from multiple concurrent/retried transfers interleaved in our buffer).

## Channel-2 decode: confirmed legitimate (same key works), reassembly still unsolved
- Fixed two real bugs in the standalone client: (1) ack must echo the exact channel byte from the push (header offset 5), not hardcode 0 — fixed the 600+ times stuck-retransmission loop; (2) buffers must be kept **separate per channel** and deduped by msgid, since channel 0 and channel 2 are parallel independent message streams interleaved on the wire — mixing them corrupts JSON boundaries.
- After both fixes: **channel 0 now decodes cleanly with no garbage** (confirms that part of the client is fully correct). **Channel 2 still doesn't produce valid JSON**, but it's the same channel that carries real content (including the 77-param device dump) in the real app's own sessions (confirmed 155 channel-2 `f1 d0` packets in `p2p_capture3.pcap`, the capture that gave us the fully-decoded bulk dump) — so this isn't a wrong-key or wrong-channel problem, it's specifically about correctly reassembling channel 2's larger, multi-fragment messages in the standalone client, which needs more careful sequencing logic than channel 0's simpler single-packet messages.
- Diagnostic note: identical-length "garbage" blocks on channel 2 are **byte-for-byte identical** across repeats (confirmed via dedup — same content every cycle). AES is deterministic, so this alone doesn't distinguish "correctly decrypted non-JSON data" from "wrong-key garbage" — but since channel 2 is proven to carry the same real JSON in other captures, the former is far more likely; the remaining work is reassembly logic, not crypto.

## RESOLVED: full standalone telemetry + bulk dump working end-to-end (2026-11-20)
Root cause of the channel-2 puzzle, finally nailed:
1. **Fragment header length varies**: the first fragment of a message has a 24-byte header (includes the `XZYH` tag at offset 8); continuation fragments have only an 8-byte header (`f1 d0 <len> d1 <channel> <msgid>`), no tag. Using a fixed 24-byte skip for every packet corrupted continuation fragments.
2. **The base sends some content in plaintext, not AES-encrypted, to our standalone client** — confirmed by comparing raw (undecrypted) wire bytes directly: the bulk device-param dump came back as plain readable JSON bytes on the wire in our session, while the same message type was genuinely high-entropy ciphertext in the real app's session. Likely the base downgrades to no-encryption as a compatibility fallback for a client whose capability/hello negotiation it doesn't fully recognize (we're replaying a fixed captured hello, not implementing the real negotiation). Fix: just try both raw-as-JSON and AES-decrypted-as-JSON on every buffer; harmless either way since decrypting non-ciphertext just produces unparseable garbage that's discarded.
3. Channels must be buffered **and extracted independently in each of {plain, decrypted} forms** — four buffers per channel.
- **Result**: full clean JSON now flows through the standalone client for both channels — the 77-param + firmware-version bulk dump, and (importantly) **live `cmd 3503` sock telemetry with the sock confirmed worn**, e.g. `{"cmd": 3503, "payload": {"rssi": -57, "sn": "T8340P00252008D1", "wear": 18, "wear_val": 488, "wear_threshold": 1012, "battery_vol": 99, "sleep_state": 5, ...}}` — received with the official app completely force-stopped the entire time.
- **This closes out the core reverse-engineering goal**: a standalone, app-independent client reads live sock telemetry end-to-end. `scripts/standalone_client.py` in this repo reflects the fix.
- Remaining open item: our client still only *reads*. Sending a command (e.g. changing an alert threshold) from the standalone client, using the now-fully-understood `d0`/`d1`/ack protocol, hasn't been exercised yet — next logical step if write access is wanted.

## WRITE ACCESS CONFIRMED: standalone client successfully changes base state (2026-11-20)
**The full round trip works: discover → handshake → read → write → verify.**
- Added `aes128_ecb_encrypt` to `pure_aes.py` (forward AES-128, verified as the exact mathematical inverse of the already-proven-correct decrypt).
- Built `build_command_packet()`: JSON → zero-pad to 16-byte boundary → AES-128-ECB encrypt with the known key → wrap in the `f1 d0 <len> d1 00 <msgid> 58 5a 59 48 <12-byte subtype> <ciphertext>` header. Verified **byte-for-byte identical** to a real captured `cmd 3515` (brightness) packet when given the same JSON/msgid — confirms the encoder is exactly right, not just "close enough".
- Sent `{"account_id":"<ours>","cmd":3515,"mChannel":0,"mValue3":0,"payload":{"brightness":9,"brightness_auto":0}}` from the standalone client (app force-stopped throughout).
- **Msgid-matched ack confirmed**: sent with msgid `0x000f`, got back `f1 d1 00 06 d1 00 00 01 00 0f` — exact echo, no ambiguity (this msgid value was used exactly once in the whole session).
- **State change confirmed independently**: the base's own subsequent device-param dump shows `{"dev_type":255,"param_type":3515,"param_value":"9"}`, versus `"8"` in dumps taken before the command was sent. The base actually applied the change, not just acked the packet.
- Lesson learned mid-debugging: **a command sent with a msgid far out of sequence from the session's running counter (tried `200` arbitrarily) gets silently dropped, no ack at all.** The base tracks msgid sequencing per-channel and ignores out-of-order values — stay in-sequence with whatever counter the session has been running (don't jump to an arbitrary "safe-looking" number).
- **This closes out full read+write parity with the official app** for at least this one command type. The same `build_command_packet()` approach should generalize directly to the other already-decoded command types (3516 movement threshold, 3519 HR/SpO2 alert thresholds) — same header/encoding, just a different JSON body and `cmd` value.

## WRITE #2 confirmed: cmd 3516, and a key correction for generalizing to new commands (2026-11-20)
**`cmd 3516` (move_threshold) write confirmed working — but two things had to be fixed first, both important for every future command we test:**

1. **The 12-byte "subtype" field (right after the `XZYH` tag in the header) is per-command, not a universal constant.** It differs between `cmd 3515` (`460590000000010000010000`) and `cmd 3516` (`4605a000000001002c010000`). Reusing one command's subtype for another gets the packet **silently dropped with no ack at all** — this looked identical to "the base rejected my value" but was really "the base didn't recognize this as a valid packet shape". **Always grab the exact subtype bytes from a real captured example of the specific `cmd` you're testing**, never assume/reuse.
2. **JSON field order matters**: real packets are always `{"account_id":...,"cmd":...,"mChannel":...,"mValue3":...,"payload":{...}}` in that exact order. `build_command_packet()` now forces this order regardless of the caller's dict, rather than relying on Python dict insertion order from however the test JSON was written.
3. **Padding content is not always literal zero bytes** — real captured packets sometimes have non-zero garbage in the padding after the JSON's closing `}` (likely leftover/unzeroed buffer content on the app's side, not a checksum we need to replicate — tested CRC32/Adler32/MD5 of the JSON against it, no match). Zero-padding on our side still worked fine for the write to succeed, so this is very likely harmless and doesn't need replicating.
- **Result verified by readback, not just an ack**: `param_type 3520` (the actual wire identity of `move_threshold` — distinct from `param_type 3516`, which is actually `tones_pushes`, a notification counter) changed from `30` → `35` after our write, then back to `30` after reverting.
- **Mapping correction**: `cmd 3516`'s JSON key `move_threshold` ↔ `param_type 3520`. `tones_pushes` ↔ `param_type 3516`. Don't assume a command's JSON field name matches the `param_type` number that looks closest to the `cmd` number — verify by diffing the params dump before/after, same as done here.
- **`standalone_client.py` now supports testing any command generically**: pass a JSON file as `argv[1]` (`{"cmd":N,"payload":{...}}`), and add that `cmd`'s verified subtype bytes to `COMMAND_SUBTYPES` first (extract from a real capture the same way as done for 3515/3516).

## Next: cmd 3519 (HR/SpO2 thresholds) — needs its own subtype extraction
Before testing, must repeat the same extraction process against a real captured `cmd 3519` packet to get its correct 12-byte subtype (don't reuse 3515/3516's). This is safety-alerting config (heart-rate/SpO2 warning/danger limits) — test with a value that doesn't disable alerting (e.g. tweak one threshold slightly, not set `*_advance_enable` to 0), verify via readback (`param_type 3519`'s packed string), then consider reverting.

## WRITE #3 confirmed: cmd 3519 (HR/SpO2 alert thresholds), tested and reverted safely (2026-11-20)
- Extracted the correct subtype for `cmd 3519` from a real capture: `46057001000001002c010000` (added to `COMMAND_SUBTYPES`).
- Read current live values first (`param_type 3519` packed string: `230-230-100-80,90-80,1-1`) before touching anything, so an exact revert was possible.
- Sent a minimal, non-disabling tweak (`hr_warning_up`/`hr_warning_up_real`: 230→231 only; left `hr_advance_enable`/`oxy_advance_enable` at `1`, didn't touch dangerous thresholds) — confirmed via readback: `231-231-100-80,90-80,1-1`.
- **Immediately reverted** to the original values; confirmed via readback back to `230-230-100-80,90-80,1-1`.
- This is the third command type confirmed write-capable (3515 brightness, 3516 move_threshold, 3519 HR/SpO2 thresholds), using the exact same `build_command_packet()` approach each time — just needs the per-command subtype extracted fresh from a real capture before each new command type.
- **Full read+write parity achieved for all three currently-known settings commands.** Next for broader app parity: capture more app screens (sleep schedule, notification toggles, factory reset, firmware update trigger, etc.) to discover additional `cmd` numbers not yet seen.

## New commands discovered from settings sweep (2026-11-20)
Capturing the app while going through Working Mode, HR min/max, brightness, and Me/profile screens surfaced several new `cmd` numbers:

- **`cmd 3546`**: `{"mode":1}` — almost certainly the Sock's **Working Mode** toggle (Standard/Mute). Value seen was `1`; need one more sample with the other state to confirm which number means which mode.
- **`cmd 3509`**: child/baby profile — `{"bindStatus":2,"birthdate":"","child_id":2290633,"gender":-1,"height":0,"name":"Bill","race":0,"weight":0}`. This is the "Me → Child profile" screen.
- **`cmd 1201`**: `{"time_out":2,"user_name":"Joshwbridgman"}` — unclear screen mapping yet (didn't correlate cleanly to Time Settings; `user_name` held the account holder's display name, so this may be an account/session command rather than a device setting, possibly fired automatically rather than tied to a specific tap).
- **`cmd 3519` reconfirmed** with new values matching the app's actual HR slider range (`hr_warning_down`:40, `hr_warning_up`:120) — consistent with the documented UI range (min 40-100, max 120-250).
- **`cmd 3515` reconfirmed** with `brightness_auto:1` (auto mode) and `brightness:11` — confirms the "Ring brightness: auto vs manual (10 options)" UI maps directly onto this same command/field pair.

### Still not captured this round
Voice Prompt toggles (4 booleans), App Notification toggles (4 booleans — these may be phone-local-only, never hitting the network, since they control what the app itself displays rather than base behavior), Audio volume (distinct from ring brightness — 25 options per the UI), device name change (sock and base), time format (12/24) and timezone. Needs another targeted sweep, ideally touching one setting at a time with a brief pause between each so traffic can be correlated to the specific screen.

### Privacy note
`cmd 3509` and `cmd 1201` carry personal information (a child's name, an account holder's display name) by design — this is normal app behavior, not a vulnerability. Pushed as-is, consistent with the earlier decision on serials/keys/account_id.

## Settings sweep #2: most toggles don't touch the local PPCS channel at all (2026-11-20)
- Targeted sweep (voice prompts x4, app notifications x4, audio volume, device name, time format, timezone — 12 actions, one at a time) produced **zero new local PPCS traffic** to the base. Only the pre-existing periodic `cmd 3516` heartbeat and one `cmd 1201` fired, both unrelated to the specific actions taken.
- Confirmed via an unfiltered capture (no base-IP filter) during a device-name change: the actual traffic went over **HTTPS to `care-app.eufylife.com`** (3.148.10.195), the eufy cloud API — not to the base on the LAN.
- **Conclusion: these settings (voice prompts, app notifications, device name, time format, timezone, and likely audio volume) are cloud-stored/cloud-pushed, not part of the local PPCS protocol.** Only settings that need to take effect on the *physical device* immediately and independent of connectivity (brightness, movement threshold, HR/SpO2 thresholds, working mode) go over the local channel; general metadata/preferences go through the cloud API instead.
- **This caps what's achievable via the current reverse-engineering track.** Full parity with the remaining app settings would require a separate effort: reverse-engineering `care-app.eufylife.com`'s HTTPS API (auth, request/response formats) — a different protocol and almost certainly a different tooling approach (TLS interception / MITM proxy or Frida TLS hooking, not UDP packet capture). Not started; flagged as a distinct follow-on project if full app parity (including cloud-only settings) is wanted.

## cmd 3546 mapping confirmed: Working Mode
- `{"mode":1}` = **Mute**, `{"mode":0}` = **Standard** — confirmed by toggling each way and capturing the resulting value both times.
- Subtype (for write testing): `46058000000001002c010000`.

## Cloud API TLS interception working (2026-11-20)
**Infrastructure milestone: can now read the app's HTTPS traffic to `care-app.eufylife.com`.**

### Setup that worked
1. `mitmdump` (installed via pacman) generates a CA cert at `~/.mitmproxy/mitmproxy-ca-cert.pem`.
2. **The app detects a configured system HTTP proxy and self-terminates immediately** (`System.exit(0)`, no exception) — confirmed by setting `settings put global http_proxy <host>:<port>` as root and watching the app die on launch; removing the setting let it open normally again. This is a real anti-MITM check, distinct from the earlier root/Frida detection.
3. **Workaround: transparent iptables DNAT on the phone instead of a configured proxy** — invisible to the app, since it's a kernel-level redirect the app has no API to query. `su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination <host_ip>:8080'` (broad port-443 redirect; IP-specific rules don't work reliably since `care-app.eufylife.com` resolves to different CDN edge IPs each connection).
4. **The CA also needs installing as a *system* trust anchor**, not just a user-added one — the app's `network_security_config` (seen in the manifest findings right at the start of this project) only trusts the platform default (system CAs) in release builds. Since `/system` can't be remounted read-write on this device (dm-verity), used the standard Magisk-style workaround: copy `/system/etc/security/cacerts/*` to a writable location, add the new CA cert there (correct Android filename = `openssl x509 -subject_hash_old` output + `.0`, root-owned, mode 644, SELinux context `u:object_r:system_file:s0`), then `su -c 'mount -o bind <writable_copy> /system/etc/security/cacerts'`.
5. Run `mitmdump` in **regular mode, not `--mode transparent`** — transparent mode expects to query the original destination via a Linux kernel mechanism (`SO_ORIGINAL_DST`) that only works when mitmproxy runs on the *same machine* doing the NAT. Since the NAT happens on the phone and mitmproxy runs on a separate host, this fails silently (0 bytes captured, no error). Regular mode works fine here because it falls back to TLS SNI to route, which is present on every connection we care about.
6. The app keeps a **persistent connection for the session** — adding the DNAT rule mid-session does nothing until the app is fully force-stopped and relaunched (fresh TCP/TLS connections only).
7. Don't forget your own host's firewall — `ufw`'s default-deny INPUT policy silently dropped the phone's inbound connections to the proxy port until explicitly allowed (`sudo ufw allow from <phone_subnet> to any port 8080 proto tcp`). This looked identical to "mitmproxy isn't working" for a while.

### What's visible now
Full list of `care-app.eufylife.com` endpoints hit during normal app use: `get_push_servers`, `get_care_baby_devices`, `update_devs_info` (very likely the device-name-change endpoint and others), `passport/params`, `get_banner_info`, `get_news_num`, `get_popups`, `register_push_token`, `ota/get_app_version`, `review/app_push_check`, `logging/upload_events`, `logging/upload_tracking_events`, `family/get_invites`, `care/breastfeeding/get_reminder_list`, `care/breastfeeding/get_rhythm_curve_list`, `care/get_babyapp_retire_popup`.

Standard headers on every request: `os_type`, `os_version`, `phone_model`, `country`, `openudid` (device install ID), `app_name`, `timezone`, `language`, `x-request-once`/`x-request-ts` (nonce + timestamp, likely replay protection), `app_version`, `net_type`, `gtoken`, `ab_code`, `x-auth-token`. **`gtoken` and `x-auth-token` are live session credentials — far more sensitive than the device-local AES key/serials documented earlier, since they could allow cloud account access from anywhere, not just LAN access to one physical device. Keep these local-only; do not commit raw capture files or paste live token values into the public repo.**

### The real blocker: request/response bodies are separately encrypted
Both request and response bodies are encrypted **on top of TLS** — not plain JSON. Response headers include `encrypt-algorithm: algorithm_first`, naming a specific (presumably proprietary) scheme. This is almost certainly implemented in the APK's native crypto libs (`libecc-encryption.so` is the prime suspect, found early in this project but never needed until now, given the "ecc" in its name and the app's general pattern of custom crypto over AES-ECB everywhere else observed in this project). Cracking this is a distinct, non-trivial reverse-engineering task — likely needs either static analysis of the packed APK's native crypto code, or dynamic Frida hooking of the actual encrypt/decrypt call to capture plaintext before/after, similar in spirit to (but a different cipher/scheme than) the local PPCS key recovery done earlier via logcat.

### Immediate next step if continuing this track
Hook the app's own encrypt/decrypt function call via Frida (now that we have a working rooted-device toolchain from earlier in this project) to capture plaintext request/response bodies directly, rather than trying to reverse the algorithm from ciphertext alone.
