"""Reusable eufy base client, factored out of standalone_client.py so the
same proven protocol logic can be driven from a short HTTP API (server.py)
instead of only as a one-shot CLI script. Same key, same handshake, same
framing -- nothing new reverse-engineered here, just repackaged.

Each call opens a fresh session (discovery -> handshake -> action ->
listen briefly -> close) rather than keeping a long-lived connection open.
That matches how the one-shot script already worked, avoids needing a
background keepalive thread, and costs ~1-3s per API call, which is fine
for a settings/telemetry UI.
"""
import json
import socket
import time

import pure_aes

KEY = b'REDACTED-AES-KEY'
BROADCAST_PORT = 32108
BASE_IP = '192.168.7.3'
ACCOUNT_ID = 'REDACTED-ACCOUNT-ID'

# 12-byte "subtype" placed right after the XZYH tag -- specific to each cmd,
# extracted from real captured packets. See docs/protocol-findings.md's
# "Command catalog". cmd 3546 (working mode) is NOT here yet: its mapping is
# confirmed but no real write packet has been captured to pull a subtype
# from, so writing it would mean guessing a 12-byte value the base will
# likely silently drop (or worse, misapply) -- deliberately left
# unimplemented until that capture is done.
COMMAND_SUBTYPES = {
    3515: bytes.fromhex('460590000000010000010000'),  # brightness
    3516: bytes.fromhex('4605a000000001002c010000'),  # move_threshold / tones_pushes
    3519: bytes.fromhex('46057001000001002c010000'),  # HR/SpO2 alert thresholds
}

SUPPORTED_WRITE_COMMANDS = set(COMMAND_SUBTYPES)


class EufyBaseError(Exception):
    pass


def aes_ecb_decrypt(ct: bytes) -> bytes:
    if not ct:
        return b''
    return pure_aes.aes128_ecb_decrypt(ct, KEY)


def aes_ecb_encrypt(pt: bytes) -> bytes:
    return pure_aes.aes128_ecb_encrypt(pt, KEY)


def build_command_packet(cmd_obj: dict, msgid: int) -> bytes:
    """Build a channel-0 f1 d0 write packet. Field order is forced to match
    the real wire format exactly (account_id, cmd, mChannel, mValue3,
    payload) -- verified byte-for-byte against real captures."""
    cmd = cmd_obj['cmd']
    if cmd not in SUPPORTED_WRITE_COMMANDS:
        raise EufyBaseError(
            f'cmd {cmd} has no known subtype -- would be a guess, refusing to send'
        )
    ordered = {
        'account_id': cmd_obj.get('account_id', ACCOUNT_ID),
        'cmd': cmd,
        'mChannel': cmd_obj.get('mChannel', 0),
        'mValue3': cmd_obj.get('mValue3', 0),
        'payload': cmd_obj['payload'],
    }
    j = json.dumps(ordered, separators=(',', ':')).encode()
    pad = (-len(j)) % 16
    plain = j + b'\x00' * pad
    ct = aes_ecb_encrypt(plain)
    subtype = COMMAND_SUBTYPES[cmd]
    sub = bytes.fromhex('585a5948') + subtype
    body = bytes.fromhex('d100') + msgid.to_bytes(2, 'big') + sub + ct
    header = bytes.fromhex('f1d0') + len(body).to_bytes(2, 'big')
    return header + body


def _try_extract_json(buf: bytearray):
    start = buf.find(b'{')
    if start == -1:
        return None, buf
    depth = 0
    for i in range(start, len(buf)):
        if buf[i:i + 1] == b'{':
            depth += 1
        elif buf[i:i + 1] == b'}':
            depth -= 1
            if depth == 0:
                return bytes(buf[start:i + 1]), buf[i + 1:]
    return None, buf  # incomplete


class EufyBaseSession:
    """One handshake + a short listen/write window, then close. Use as a
    context manager: `with EufyBaseSession() as sess: sess.collect(...)`."""

    def __init__(self, base_ip: str = BASE_IP):
        self.base_ip = base_ip
        self.sock = None
        self.base_addr = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('', 0))
        self.sock = s

        discovery_pkt = bytes.fromhex('f1300000')
        s.settimeout(1)
        base_addr = None
        announce_body = None
        for _ in range(6):
            s.sendto(discovery_pkt, (self.base_ip, BROADCAST_PORT))
            try:
                data, addr = s.recvfrom(2048)
                if data[:2] == b'\xf1\x41':
                    base_addr = addr
                    announce_body = data
                    break
            except socket.timeout:
                pass
        if base_addr is None:
            self.close()
            raise EufyBaseError('no announce (f1 41) received -- base unreachable?')
        self.base_addr = base_addr

        for _ in range(4):
            s.sendto(announce_body, base_addr)

        s.settimeout(2)
        for _ in range(10):
            try:
                data, _ = s.recvfrom(2048)
                if data[:2] == b'\xf1\x42':
                    break
            except socket.timeout:
                pass

        s.settimeout(0.3)
        got_pong = False
        for _ in range(10):
            s.sendto(bytes.fromhex('f1e00000'), base_addr)
            try:
                data, _ = s.recvfrom(2048)
                if data[:2] == b'\xf1\xe1':
                    got_pong = True
                    break
            except socket.timeout:
                pass
        if not got_pong:
            self.close()
            raise EufyBaseError('no pong -- base did not respond to ping')

        version_hello = bytes.fromhex('f1d00014d1000000585a59487304000000000100ff000000')
        s.settimeout(0.5)
        for _ in range(4):
            s.sendto(version_hello, base_addr)
            try:
                s.recvfrom(2048)
            except socket.timeout:
                pass

    def collect(self, duration: float = 5.0, write_cmd: dict = None, write_after: float = 1.0):
        """Run the keepalive loop for `duration` seconds. If write_cmd is
        given, send it `write_after` seconds in (lets the session warm up
        first, matching the proven script's timing). Returns a dict with
        whatever JSON objects were decoded: {'telemetry': {...} or None,
        'params': {...} or None, 'all': [ {...}, ... ]}."""
        s = self.sock
        base_addr = self.base_addr
        status_header = bytes.fromhex('f1d00024d1000000585a59484f0410000000010000010000')
        status_block = bytes.fromhex('cdb666c3839198050621f9da7eceb80e')

        s.settimeout(0.3)
        end = time.time() + duration
        next_status = time.time()
        status_msgid = 0
        # The write is plain UDP with no per-packet ack/retry of its own
        # (unlike every other step in the handshake -- announce echoed 4x,
        # ping sent up to 10x, version hello sent 4x) -- a fire-and-forget
        # single send is indistinguishable from "silently dropped on a
        # lossy Wi-Fi link" from the caller's side. Resend it a few times
        # on the SAME msgid (the base's dedup is per msgid, so repeats are
        # safe/idempotent, not re-applied N times) to match that pattern.
        cmd_pkt = None
        cmd_msgid = None
        write_resends_left = 4
        write_at = time.time() + write_after

        bufs = {}
        seen = {}
        results = {'telemetry': None, 'params': None, 'all': []}

        while time.time() < end:
            if time.time() >= next_status:
                pkt = bytearray(status_header)
                pkt[7] = status_msgid % 256
                pkt += status_block
                s.sendto(bytes(pkt), base_addr)
                status_msgid += 1
                next_status = time.time() + 0.3
            if write_cmd is not None and write_resends_left > 0 and time.time() >= write_at:
                if cmd_pkt is None:
                    cmd_msgid = status_msgid % 65536
                    cmd_pkt = build_command_packet(write_cmd, cmd_msgid)
                    status_msgid += 1
                s.sendto(cmd_pkt, base_addr)
                write_resends_left -= 1
                write_at = time.time() + 0.4

            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            if data[:2] != b'\xf1\xd0':
                continue
            if len(data) >= 8:
                ack = bytes.fromhex('f1d10006d1') + data[5:6] + bytes.fromhex('0001') + data[6:8]
                s.sendto(ack, addr)

            has_tag = data[8:12] == b'XZYH'
            hdr_len = 24 if has_tag else 8
            payload = data[hdr_len:]
            channel = data[5]
            msgid_key = bytes(data[6:8])
            channel_seen = seen.setdefault(channel, set())
            if msgid_key in channel_seen:
                continue
            channel_seen.add(msgid_key)

            raw_buf, dec_buf = bufs.setdefault(channel, (bytearray(), bytearray()))
            raw_buf += payload
            if payload and len(payload) % 16 == 0:
                dec_buf += aes_ecb_decrypt(payload)

            for buf in (raw_buf, dec_buf):
                if len(buf) > 8192:
                    buf[:] = b''
                    continue
                while True:
                    obj_bytes, rest = _try_extract_json(buf)
                    if obj_bytes is None:
                        break
                    buf[:] = rest
                    try:
                        obj = json.loads(obj_bytes)
                    except Exception:
                        continue
                    results['all'].append(obj)
                    if isinstance(obj, dict) and obj.get('cmd') == 3503:
                        results['telemetry'] = obj.get('payload', obj)
                    elif isinstance(obj, dict) and 'params' in obj:
                        results['params'] = obj

        return results


def read_telemetry(duration: float = 6.0) -> dict:
    with EufyBaseSession() as sess:
        res = sess.collect(duration=duration)
    if res['telemetry'] is None:
        raise EufyBaseError('no telemetry (cmd 3503) seen in the window -- try again')
    return res['telemetry']


def read_params(duration: float = 10.0) -> dict:
    with EufyBaseSession() as sess:
        res = sess.collect(duration=duration)
    if res['params'] is None:
        raise EufyBaseError('no params dump seen in the window -- try again')
    return res['params']


def write_setting(cmd: int, payload: dict, duration: float = 8.0) -> dict:
    """Send a write command and listen for a bit afterward so the caller
    can read back the new state (bulk dump / telemetry) to confirm it
    actually took effect, per the project's own stated best practice:
    the base acks the packet, not necessarily the applied value. Returns
    a trimmed summary, not the raw capture window (which repeats the same
    few objects many times as the base keeps re-pushing)."""
    with EufyBaseSession() as sess:
        res = sess.collect(duration=duration, write_cmd={'cmd': cmd, 'payload': payload})
    return {
        'sent': {'cmd': cmd, 'payload': payload},
        'telemetry': res['telemetry'],
        'params': res['params']['params'] if res['params'] else None,
    }
