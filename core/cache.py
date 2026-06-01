"""
core/cache.py
SQLite-backed IOC enrichment cache.
Avoids repeat API calls for IOCs already enriched within the TTL window.
"""

import hashlib
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_CACHE_PATH = Path.home() / ".cache" / "soc-ioc-enricher" / "cache.db"
DEFAULT_TTL        = 86_400 * 7   # 7 days


class EnrichmentCache:
    def __init__(self, db_path: Path = DEFAULT_CACHE_PATH, ttl: int = DEFAULT_TTL):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ttl  = ttl
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._init_db()

    def _init_db(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS enrichments (
                cache_key  TEXT PRIMARY KEY,
                payload    TEXT NOT NULL,
                cached_at  INTEGER NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cached_at ON enrichments(cached_at)
        """)
        self._conn.commit()

    @staticmethod
    def _key(ioc_value: str, source: str) -> str:
        raw = f"{source}:{ioc_value.lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, ioc_value: str, source: str) -> dict[str, Any] | None:
        key      = self._key(ioc_value, source)
        cutoff   = int(time.time()) - self._ttl
        row      = self._conn.execute(
            "SELECT payload FROM enrichments WHERE cache_key = ? AND cached_at > ?",
            (key, cutoff),
        ).fetchone()
        if row:
            log.debug("Cache hit: %s / %s", source, ioc_value)
            return json.loads(row[0])
        return None

    def set(self, ioc_value: str, source: str, data: dict[str, Any]) -> None:
        key = self._key(ioc_value, source)
        self._conn.execute(
            "INSERT OR REPLACE INTO enrichments (cache_key, payload, cached_at) VALUES (?, ?, ?)",
            (key, json.dumps(data), int(time.time())),
        )
        self._conn.commit()

    def purge_expired(self) -> int:
        cutoff = int(time.time()) - self._ttl
        cursor = self._conn.execute(
            "DELETE FROM enrichments WHERE cached_at <= ?", (cutoff,)
        )
        self._conn.commit()
        return cursor.rowcount

    def stats(self) -> dict[str, int]:
        total   = self._conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
        expired = self._conn.execute(
            "SELECT COUNT(*) FROM enrichments WHERE cached_at <= ?",
            (int(time.time()) - self._ttl,)
        ).fetchone()[0]
        return {"total": total, "expired": expired, "live": total - expired}
