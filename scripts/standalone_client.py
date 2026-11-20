#!/usr/bin/env python3
"""Minimal standalone PPCS client for the eufy base, bypassing the app entirely.
For personal use against the user's own device. Read-only test: discover, handshake,
listen for telemetry pushes.
"""
import json
import socket
import sys
import time
from binascii import unhexlify

import pure_aes

# optional: pass a path to a JSON file on argv[1] to test a write, e.g.
#   echo '{"cmd":3516,"payload":{"move_threshold":35,"tones_pushes":5143}}' > cmd.json
#   python3 standalone_client.py cmd.json
# account_id/mChannel/mValue3 are filled in automatically if omitted.
TEST_CMD_OBJ = None
if len(sys.argv) > 1:
    with open(sys.argv[1]) as f:
        TEST_CMD_OBJ = json.load(f)

KEY = b'REDACTED-AES-KEY'
BROADCAST_PORT = 32108
LOCAL_SUBNET_BROADCAST = '192.168.7.255'
GLOBAL_BROADCAST = '255.255.255.255'
BASE_IP = '192.168.7.3'


ACCOUNT_ID = 'REDACTED-ACCOUNT-ID'
if TEST_CMD_OBJ is not None:
    TEST_CMD_OBJ.setdefault('account_id', ACCOUNT_ID)
    TEST_CMD_OBJ.setdefault('mChannel', 0)
    TEST_CMD_OBJ.setdefault('mValue3', 0)

# the 12-byte "subtype" after the XZYH tag is command-specific, not a
# universal constant -- verified against real captured packets per cmd.
# header overall is f1 d0 <len> d1 00 <msgid> 58 5a 59 48 <subtype> <ciphertext>
# (24-byte header total before ciphertext).
COMMAND_SUBTYPES = {
    3515: bytes.fromhex('460590000000010000010000'),  # brightness -- verified write
    3516: bytes.fromhex('4605a000000001002c010000'),  # move_threshold/tones_pushes
}
DEFAULT_SUBTYPE = COMMAND_SUBTYPES[3515]


def aes_ecb_decrypt(ct: bytes) -> bytes:
    if len(ct) == 0:
        return b''
    return pure_aes.aes128_ecb_decrypt(ct, KEY)


def aes_ecb_encrypt(pt: bytes) -> bytes:
    return pure_aes.aes128_ecb_encrypt(pt, KEY)


def build_command_packet(cmd_obj: dict, msgid: int) -> bytes:
    """Build a channel-0 f1 d0 command packet carrying cmd_obj as JSON,
    AES-128-ECB encrypted with the known key, zero-padded to a block
    boundary. Verified byte-for-byte identical to a real captured
    cmd 3515 (brightness) packet when given the same inputs.

    Field order is forced to match the real wire format exactly
    (account_id, cmd, mChannel, mValue3, payload) -- the base may do
    byte-level validation, not just semantic JSON parsing, so don't
    rely on the caller's dict insertion order."""
    import json
    ordered = {
        'account_id': cmd_obj.get('account_id', ACCOUNT_ID),
        'cmd': cmd_obj['cmd'],
        'mChannel': cmd_obj.get('mChannel', 0),
        'mValue3': cmd_obj.get('mValue3', 0),
        'payload': cmd_obj['payload'],
    }
    j = json.dumps(ordered, separators=(',', ':')).encode()
    pad = (-len(j)) % 16
    plain = j + b'\x00' * pad
    ct = aes_ecb_encrypt(plain)
    subtype = COMMAND_SUBTYPES.get(cmd_obj['cmd'], DEFAULT_SUBTYPE)
    sub = bytes.fromhex('585a5948') + subtype
    body = bytes.fromhex('d100') + msgid.to_bytes(2, 'big') + sub + ct
    total_len = len(body)
    header = bytes.fromhex('f1d0') + total_len.to_bytes(2, 'big')
    return header + body


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    local_port = s.getsockname()[1]
    print(f'[*] bound local port {local_port}')

    discovery_pkt = bytes.fromhex('f1300000')
    s.settimeout(1)
    base_addr = None
    announce_body = None
    for attempt in range(6):
        s.sendto(discovery_pkt, (BASE_IP, BROADCAST_PORT))
        print(f'[*] sent discovery attempt {attempt+1}')
        try:
            data, addr = s.recvfrom(2048)
            print(f'[<] from {addr}: {data.hex()}')
            if data[:2] == b'\xf1\x41':
                base_addr = addr
                announce_body = data
                break
        except socket.timeout:
            pass
    if base_addr is None:
        print('[!] no announce (f1 41) received')
        return
    print(f'[*] base announced itself at {base_addr}')

    # the real client echoes the exact f1 41 announce back to the base several
    # times before the base will send f1 42 and start accepting pings
    for _ in range(4):
        s.sendto(announce_body, base_addr)
    print('[>] echoed announce back 4x, waiting for f1 42...')

    s.settimeout(2)
    got_42 = False
    for _ in range(10):
        try:
            data, addr = s.recvfrom(2048)
            print(f'[<] from {addr}: {data.hex()}')
            if data[:2] == b'\xf1\x42':
                got_42 = True
                break
        except socket.timeout:
            pass
    if not got_42:
        print('[!] no f1 42 received, continuing anyway')

    # ping/pong -- real client sends several before the first pong arrives
    s.settimeout(0.3)
    got_pong = False
    for attempt in range(10):
        s.sendto(bytes.fromhex('f1e00000'), base_addr)
        try:
            data, addr = s.recvfrom(2048)
            print(f'[<] ping reply from {addr}: {data.hex()}')
            if data[:2] == b'\xf1\xe1':
                got_pong = True
                break
        except socket.timeout:
            print(f'[!] no reply to ping attempt {attempt+1}')
    if not got_pong:
        print('[!] giving up on pong')
        return

    # step 1: initial version/capability exchange -- plain bytes, no AES payload.
    # the real client sends this FIRST and the base won't progress past a zeroed
    # placeholder state until it does.
    version_hello = bytes.fromhex('f1d00014d1000000585a59487304000000000100ff000000')
    s.settimeout(0.5)
    for i in range(4):
        s.sendto(version_hello, base_addr)
        try:
            data, addr = s.recvfrom(2048)
            print(f'[<] version exchange reply: {data.hex()[:80]}')
        except socket.timeout:
            pass
    print('[>] sent version/capability hello (f1 d0 ... 7304)')

    # step 2: periodic AES-encrypted status packet (the one we previously sent
    # alone and got stuck). Real client increments the msgid byte each time.
    status_header = bytes.fromhex('f1d00024d1000000585a59484f0410000000010000010000')
    status_block = bytes.fromhex('cdb666c3839198050621f9da7eceb80e')
    for msgid in range(5):
        pkt = bytearray(status_header)
        pkt[7] = msgid  # msgid byte
        pkt += status_block
        s.sendto(bytes(pkt), base_addr)
        try:
            data, addr = s.recvfrom(2048)
            print(f'[<] status reply msgid={msgid}: {data.hex()[:80]}')
        except socket.timeout:
            print(f'[!] no reply to status msgid={msgid}')
        time.sleep(0.3)

    print('[*] listening for telemetry pushes (30s)...')
    s.settimeout(0.3)
    end = time.time() + 30
    bufs = {}       # channel_byte -> (raw_buf, dec_buf), kept separate per channel
    seen = {}       # channel_byte -> set of msgid bytes already appended (dedupe retransmits)
    next_status = time.time()
    status_msgid = 5
    command_sent = False
    command_send_at = time.time() + 3  # give the session a few seconds to warm up first

    def try_extract(buf):
        """Try to pull one complete {...} JSON object off the front of buf.
        Returns (json_bytes_or_None, remaining_buf)."""
        start = buf.find(b'{')
        if start == -1:
            return None, buf
        depth = 0
        for i in range(start, len(buf)):
            if buf[i:i+1] == b'{':
                depth += 1
            elif buf[i:i+1] == b'}':
                depth -= 1
                if depth == 0:
                    return bytes(buf[start:i+1]), buf[i+1:]
        return None, buf  # incomplete, wait for more data

    try:
        while time.time() < end:
            if time.time() >= next_status:
                pkt = bytearray(status_header)
                pkt[7] = status_msgid % 256
                pkt += status_block
                s.sendto(bytes(pkt), base_addr)
                status_msgid += 1
                next_status = time.time() + 0.3
            if not command_sent and TEST_CMD_OBJ is not None and time.time() >= command_send_at:
                cmd_msgid = status_msgid  # stay in-sequence with the running status counter
                cmd_pkt = build_command_packet(TEST_CMD_OBJ, cmd_msgid)
                s.sendto(cmd_pkt, base_addr)
                print(f'[>] sent WRITE command (cmd {TEST_CMD_OBJ.get("cmd")}) msgid={cmd_msgid} (0x{cmd_msgid:04x}): {json.dumps(TEST_CMD_OBJ)}')
                status_msgid += 1
                command_sent = True
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            if data[:2] != b'\xf1\xd0':
                print(f'[<] non-d0 from {addr}: {data.hex()[:60]}')
                continue
            # ack every d0 push, or the base just retransmits the same
            # fragment forever instead of advancing to the next one.
            # format: f1 d1 00 06 d1 <channel echoed from data[5]> 00 01 <msgid bytes echoed from data[6:8]>
            if len(data) >= 8:
                ack = bytes.fromhex('f1d10006d1') + data[5:6] + bytes.fromhex('0001') + data[6:8]
                s.sendto(ack, addr)
            # the first fragment of a message has a 24-byte header starting
            # with the "XZYH" tag at offset 8; continuation fragments have
            # no tag and only an 8-byte header (f1 d0 <len> d1 <ch> <msgid>).
            # The base also sometimes sends this content in plaintext (no
            # AES at all) rather than encrypted -- seen on our own standalone
            # sessions but not on the real app's -- so try both.
            has_tag = data[8:12] == b'XZYH'
            hdr_len = 24 if has_tag else 8
            payload = data[hdr_len:]
            channel = data[5]
            msgid_key = bytes(data[6:8])
            channel_seen = seen.setdefault(channel, set())
            if msgid_key in channel_seen:
                continue  # retransmit of something we already buffered -- skip, don't duplicate
            channel_seen.add(msgid_key)

            raw_buf, dec_buf = bufs.setdefault(channel, (bytearray(), bytearray()))
            raw_buf += payload
            if len(payload) % 16 == 0 and len(payload) > 0:
                dec_buf += aes_ecb_decrypt(payload)
            for label, buf in (('plain', raw_buf), ('decrypted', dec_buf)):
                if len(buf) > 8192:
                    print(f'[!] buffer overflow on channel {channel} ({label}), resetting')
                    buf[:] = b''
                    continue
                while True:
                    obj_bytes, rest = try_extract(buf)
                    if obj_bytes is None:
                        break
                    buf[:] = rest
                    try:
                        import json
                        obj = json.loads(obj_bytes)
                        print(f'[<] JSON from {addr} (channel {channel}, {label}): {json.dumps(obj)}')
                    except Exception:
                        print(f'[<] channel {channel} {label}: braces matched but not valid JSON ({len(obj_bytes)}B): {obj_bytes[:120]}')
    except socket.timeout:
        pass
    print('[*] done listening')


if __name__ == '__main__':
    main()
