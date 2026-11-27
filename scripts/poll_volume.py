#!/usr/bin/env python3
"""Poll the base over the LAN and log when the speaker volume (param 1235)
or any other watched param changes. Read-only: nothing is written.

Use it for the cloud-vs-local test: block the base's internet access, change
the volume in the app on the same LAN, and see whether (and how fast) the
value changes here. Repeat with a voice-prompt toggle as a control.

    env $(cat work/secrets/env) EUFY_BASE_IP=<ip> python3 scripts/poll_volume.py
    ... --also 3527 --all-changes --log work/volume_poll.log

Each poll opens a short session and reads a full params dump (~10 s).
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eufy_client  # noqa: E402

VOLUME = 1235
NOISY = {1147}  # device clock, changes every poll


def snapshot(duration):
    d = eufy_client.read_params(duration=duration, attempts=2)
    return {int(p['param_type']): str(p['param_value']) for p in d['params']}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--interval', type=float, default=2.0, help='pause between polls (s)')
    ap.add_argument('--window', type=float, default=8.0, help='listen time per poll (s)')
    ap.add_argument('--also', type=int, nargs='*', default=[], help='extra param ids to watch')
    ap.add_argument('--all-changes', action='store_true',
                    help='report every param that changes, not only watched ones')
    ap.add_argument('--log', help='append lines to this file as well as stdout')
    ap.add_argument('--heartbeat', type=int, default=10,
                    help='print an "unchanged" line every N polls (0 = never)')
    args = ap.parse_args()

    watch = {VOLUME, *args.also}
    logf = open(args.log, 'a', buffering=1) if args.log else None

    def out(msg):
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        print(line, flush=True)
        if logf:
            logf.write(line + '\n')

    prev, polls, fails = None, 0, 0
    out(f"watching params {sorted(watch)}{' (+all changes)' if args.all_changes else ''}; Ctrl+C to stop")
    try:
        while True:
            t0 = time.time()
            try:
                cur = snapshot(args.window)
                fails = 0
            except eufy_client.EufyBaseError as e:
                fails += 1
                out(f"poll failed ({fails}): {e}")
                time.sleep(args.interval)
                continue
            polls += 1
            # time between the end of the previous poll window and this one bounds
            # when the change could have happened
            if prev is None:
                out('start: ' + ' '.join(f'{k}={cur.get(k)}' for k in sorted(watch)))
            else:
                ids = sorted(k for k in set(cur) | set(prev)
                             if prev.get(k) != cur.get(k)
                             and k not in NOISY
                             and (args.all_changes or k in watch))
                for k in ids:
                    out(f"CHANGE param {k}: {prev.get(k)} -> {cur.get(k)} "
                        f"(seen after {time.time() - t0:.1f}s poll)")
                if not ids and args.heartbeat and polls % args.heartbeat == 0:
                    out('unchanged: ' + ' '.join(f'{k}={cur.get(k)}' for k in sorted(watch)))
            prev = cur
            time.sleep(args.interval)
    except KeyboardInterrupt:
        out('stopped')


if __name__ == '__main__':
    main()
