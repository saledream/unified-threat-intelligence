"""Persistent rolling quota for personal VirusTotal Public API access.
Only a SHA256 key fingerprint and request times are stored, never the key or IOC.
"""
import hashlib
import os
import sqlite3
import time
from pathlib import Path


def reserve_public_request(key: str) -> dict | None:
    path = Path(os.getenv('VIRUSTOTAL_QUOTA_DB', 'data/virustotal-personal-quota.sqlite3'))
    digest = hashlib.sha256(key.encode()).hexdigest()
    now = time.time()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path, timeout=5) as db:
            db.execute('CREATE TABLE IF NOT EXISTS requests (key_digest TEXT NOT NULL, requested_at REAL NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS quota_key_time ON requests(key_digest, requested_at)')
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM requests WHERE requested_at <= ?', (now - 86400,))
            times = [r[0] for r in db.execute('SELECT requested_at FROM requests WHERE key_digest = ? ORDER BY requested_at', (digest,))]
            minute = [t for t in times if t > now - 60]
            retry = 0
            if len(times) >= 500:
                retry = max(retry, times[0] + 86400 - now)
            if len(minute) >= 4:
                retry = max(retry, minute[0] + 60 - now)
            if retry:
                return {'status': 'rate_limited', 'retry_after': max(1, int(retry) + 1),
                        'reason': 'Personal VirusTotal quota: 4 requests/minute, 500/rolling 24 hours'}
            db.execute('INSERT INTO requests VALUES (?, ?)', (digest, now))
        return None
    except (OSError, sqlite3.Error):
        return {'status': 'blocked', 'error': 'Personal VirusTotal quota store unavailable; no request sent'}
