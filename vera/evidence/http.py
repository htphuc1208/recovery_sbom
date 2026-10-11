"""Cached HTTP GET (sqlite). Every external evidence lookup goes through here so
experiments are reproducible offline (VERA_OFFLINE=1) and tool-call counts are measurable."""
from __future__ import annotations
import json
import sqlite3
import threading
import time
import httpx
from .. import config

_lock = threading.Lock()
_conn = sqlite3.connect(config.CACHE_DB, check_same_thread=False, timeout=120)
_conn.execute("CREATE TABLE IF NOT EXISTS http (url TEXT PRIMARY KEY, status INT, body BLOB, ts REAL)")
_conn.commit()
_client = httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "vera-sbom-research/0.1"})

STATS = {"network": 0, "cache": 0}


def get(url: str, *, as_json: bool = True, max_age: float | None = None, retries: int = 3, headers=None):
    """Return parsed JSON (or text) or None for 404/errors."""
    with _lock:
        row = _conn.execute("SELECT status, body, ts FROM http WHERE url=?", (url,)).fetchone()
    if row and (max_age is None or time.time() - row[2] < max_age):
        STATS["cache"] += 1
        status, body = row[0], row[1]
    else:
        if config.OFFLINE:
            return None
        status, body = None, b""
        for i in range(retries):
            try:
                r = _client.get(url, headers=headers)
                status, body = r.status_code, r.content
                if status == 429 or status >= 500:
                    time.sleep(2 ** i * 2)
                    continue
                break
            except httpx.HTTPError:
                time.sleep(2 ** i)
        STATS["network"] += 1
        if status is None:
            return None
        if status in (200, 404, 410):
            with _lock:
                _conn.execute("INSERT OR REPLACE INTO http VALUES (?,?,?,?)", (url, status, body, time.time()))
                _conn.commit()
    if status != 200:
        return None
    if not as_json:
        return body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else body
    try:
        return json.loads(body)
    except Exception:
        return None
