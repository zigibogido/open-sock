"""Background telemetry sampler + SQLite history store, so the web UI can
show stats over time like the official app's dashboard -- without any
cloud involved, just periodic local reads via eufy_client.

Kept deliberately simple (stdlib sqlite3, one table, no migrations) since
this is a single-user personal tool, not a product with a schema that
needs to evolve under load.
"""
import sqlite3
import sys
import threading
import time
from pathlib import Path

import eufy_client

DB_PATH = Path(__file__).parent / 'eufy_history.sqlite3'

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts REAL NOT NULL,
    hr INTEGER,
    oxy INTEGER,
    move INTEGER,
    move_val INTEGER,
    wear INTEGER,
    battery_vol INTEGER,
    rssi INTEGER
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
"""


def _connect():
    con = sqlite3.connect(DB_PATH)
    con.execute('PRAGMA journal_mode=WAL')
    con.executescript(_SCHEMA)
    return con


def record_sample(telemetry: dict):
    con = _connect()
    try:
        con.execute(
            'INSERT INTO samples (ts, hr, oxy, move, move_val, wear, battery_vol, rssi) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (
                time.time(),
                telemetry.get('hr'),
                telemetry.get('oxy'),
                telemetry.get('move'),
                telemetry.get('move_val'),
                telemetry.get('wear'),
                telemetry.get('battery_vol'),
                telemetry.get('rssi'),
            ),
        )
        con.commit()
    finally:
        con.close()


def query_history(minutes: float) -> list:
    """Returns samples from the last `minutes`, oldest first."""
    con = _connect()
    try:
        cutoff = time.time() - minutes * 60
        rows = con.execute(
            'SELECT ts, hr, oxy, move, move_val, wear, battery_vol, rssi '
            'FROM samples WHERE ts >= ? ORDER BY ts ASC',
            (cutoff,),
        ).fetchall()
    finally:
        con.close()
    return [
        {
            'ts': r[0], 'hr': r[1], 'oxy': r[2], 'move': r[3],
            'move_val': r[4], 'wear': r[5], 'battery_vol': r[6], 'rssi': r[7],
        }
        for r in rows
    ]


def prune_older_than(days: float = 30):
    con = _connect()
    try:
        cutoff = time.time() - days * 86400
        con.execute('DELETE FROM samples WHERE ts < ?', (cutoff,))
        con.commit()
    finally:
        con.close()


def start_sampler(interval_seconds: float, lock: threading.Lock, stop_event: threading.Event = None):
    """Runs forever in a background thread: every `interval_seconds`, take
    one telemetry reading and store it. Uses the same lock the HTTP API
    uses, so this never races a user-triggered API call against the base
    -- it just waits its turn, same as any other caller would."""

    def _loop():
        last_prune = 0
        while not (stop_event and stop_event.is_set()):
            try:
                with lock:
                    telemetry = eufy_client.read_telemetry()  # default duration, same as the API endpoint uses
                record_sample(telemetry)
            except eufy_client.EufyBaseError as e:
                sys.stderr.write(f'[history] sample failed: {e}\n')
            except Exception as e:
                sys.stderr.write(f'[history] unexpected error: {e}\n')
            if time.time() - last_prune > 86400:
                prune_older_than()
                last_prune = time.time()
            time.sleep(interval_seconds)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t
