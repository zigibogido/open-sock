#!/usr/bin/env python3
"""Tiny self-hosted HTTP API + web UI for the eufy base, built entirely on
scripts/eufy_client.py (same proven LAN protocol as standalone_client.py,
no cloud/app involved). Meant to sit on your home server, on the same LAN
as the base, with a reverse proxy in front of it for remote/TLS access --
this process itself speaks plain HTTP on localhost/LAN only.

Run:
    python3 server.py [--host 0.0.0.0] [--port 8420]

Optional shared-secret auth (defense in depth if you expose this directly
instead of behind an authenticating reverse proxy): set EUFY_API_TOKEN in
the environment, then send it as `Authorization: Bearer <token>` on every
request. If EUFY_API_TOKEN is unset, no auth is enforced (expected to be
behind your own proxy's auth instead).
"""
import argparse
import json
import os
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import eufy_client
import history

WEB_DIR = Path(__file__).parent / 'web'
API_TOKEN = os.environ.get('EUFY_API_TOKEN')
HISTORY_INTERVAL_SECONDS = float(os.environ.get('EUFY_HISTORY_INTERVAL', 90))

# serialize all base access -- the protocol is a single stateful UDP
# session; two API calls racing each other would both try to discover/
# handshake against the same base at once and likely confuse each other.
_lock = threading.Lock()

# very small in-memory cache so the UI can show "last known" telemetry
# without forcing a fresh ~6s round trip on every page load.
_cache = {'telemetry': None, 'params': None, 'at': 0}


class Handler(BaseHTTPRequestHandler):
    server_version = 'eufy-selfhost/1'

    def _authed(self) -> bool:
        if not API_TOKEN:
            return True
        return self.headers.get('Authorization') == f'Bearer {API_TOKEN}'

    def _send_json(self, status: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, content_type: str):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write(f'[{time.strftime("%H:%M:%S")}] {fmt % args}\n')

    # ---- static UI ----
    def _serve_static(self):
        rel = self.path.lstrip('/') or 'index.html'
        if rel == '':
            rel = 'index.html'
        target = (WEB_DIR / rel).resolve()
        if WEB_DIR.resolve() not in target.parents and target != WEB_DIR.resolve():
            self.send_error(404)
            return
        if not target.is_file():
            target = WEB_DIR / 'index.html'
        content_type = 'text/html'
        if target.suffix == '.js':
            content_type = 'application/javascript'
        elif target.suffix == '.css':
            content_type = 'text/css'
        self._send_file(target, content_type)

    # ---- API ----
    def do_GET(self):
        if self.path.startswith('/api/'):
            if not self._authed():
                return self._send_json(401, {'ok': False, 'error': 'unauthorized'})
            return self._handle_api_get()
        return self._serve_static()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.end_headers()

    def do_POST(self):
        if not self.path.startswith('/api/'):
            return self.send_error(404)
        if not self._authed():
            return self._send_json(401, {'ok': False, 'error': 'unauthorized'})
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length else b'{}'
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            return self._send_json(400, {'ok': False, 'error': 'invalid JSON body'})
        return self._handle_api_post(body)

    def _handle_api_get(self):
        if self.path == '/api/telemetry':
            return self._run(lambda: eufy_client.read_telemetry(), cache_key='telemetry')
        if self.path == '/api/params':
            return self._run(lambda: eufy_client.read_params(), cache_key='params')
        if self.path == '/api/volume':
            return self._run(lambda: {'volume': eufy_client.read_volume(), 'min': 1, 'max': 26})
        if self.path == '/api/status':
            return self._send_json(200, {'ok': True, 'cache': _cache})
        if self.path.startswith('/api/history'):
            from urllib.parse import urlsplit, parse_qs
            qs = parse_qs(urlsplit(self.path).query)
            try:
                minutes = float(qs.get('minutes', ['360'])[0])
            except ValueError:
                return self._send_json(400, {'ok': False, 'error': 'minutes must be a number'})
            minutes = max(1.0, min(minutes, 60 * 24 * 30))  # cap at 30 days
            samples = history.query_history(minutes)
            return self._send_json(200, {'ok': True, 'data': {'minutes': minutes, 'samples': samples}})
        return self._send_json(404, {'ok': False, 'error': 'unknown endpoint'})

    def _handle_api_post(self, body: dict):
        try:
            if self.path == '/api/settings/brightness':
                payload = {
                    'brightness': int(body['brightness']),
                    'brightness_auto': int(body.get('brightness_auto', 0)),
                }
                return self._run(lambda: eufy_client.write_setting(3515, payload))
            if self.path == '/api/settings/movement':
                thr = int(body['move_threshold'])
                if 'tones_pushes' in body:
                    tones = int(body['tones_pushes'])
                    return self._run(lambda: eufy_client.write_setting(
                        3516, {'move_threshold': thr, 'tones_pushes': tones}))

                def _write_keep_prompts():
                    # tones_pushes is the voice-prompt bitmask: preserve current value
                    cur = int(eufy_client._param_map(eufy_client.read_params())[3516])
                    return eufy_client.write_setting(
                        3516, {'move_threshold': thr, 'tones_pushes': cur})
                return self._run(_write_keep_prompts)
            if self.path == '/api/settings/prompts':
                name = body.get('prompt')
                if name not in eufy_client.PROMPT_MASKS:
                    return self._send_json(400, {'ok': False, 'error': f'prompt must be one of {sorted(eufy_client.PROMPT_MASKS)}'})
                if not isinstance(body.get('on'), bool):
                    return self._send_json(400, {'ok': False, 'error': 'on must be true or false'})
                on = body['on']
                return self._run(lambda: eufy_client.set_prompt(name, on))
            if self.path == '/api/alarm/stop':
                return self._run(lambda: eufy_client.stop_alarm())
            if self.path == '/api/settings/alerts':
                required = [
                    'hr_advance_enable', 'hr_dangerous_down', 'hr_dangerous_up',
                    'hr_warning_down', 'hr_warning_up', 'o2_dangerous_down',
                    'o2_warning_down', 'oxy_advance_enable',
                ]
                missing = [k for k in required if k not in body]
                if missing:
                    return self._send_json(400, {'ok': False, 'error': f'missing fields: {missing}'})
                return self._run(lambda: eufy_client.write_setting(3519, body))
            if self.path == '/api/settings/mode':
                payload = {'mode': int(body['mode'])}
                return self._run(lambda: eufy_client.write_setting(3546, payload))
            return self._send_json(404, {'ok': False, 'error': 'unknown endpoint'})
        except (KeyError, ValueError) as e:
            return self._send_json(400, {'ok': False, 'error': f'bad request body: {e}'})

    def _run(self, fn, cache_key: str = None):
        with _lock:
            try:
                data = fn()
            except eufy_client.EufyBaseError as e:
                return self._send_json(502, {'ok': False, 'error': str(e)})
            except Exception:
                traceback.print_exc()
                return self._send_json(500, {'ok': False, 'error': 'internal error'})
        if cache_key:
            _cache[cache_key] = data
            _cache['at'] = time.time()
        return self._send_json(200, {'ok': True, 'data': data})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default=os.environ.get('EUFY_BIND_HOST', '127.0.0.1'))
    ap.add_argument('--port', type=int, default=int(os.environ.get('EUFY_PORT', '8420')))
    args = ap.parse_args()

    if not API_TOKEN:
        print('[!] EUFY_API_TOKEN not set -- no auth enforced. '
              'Fine behind an authenticating reverse proxy, not fine exposed directly.',
              file=sys.stderr)

    history.start_sampler(HISTORY_INTERVAL_SECONDS, _lock)
    print(f'[*] history sampler running every {HISTORY_INTERVAL_SECONDS:.0f}s -> {history.DB_PATH}')

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f'[*] listening on http://{args.host}:{args.port}')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
