"""enrichers/abuseipdb.py - AbuseIPDB enrichment for IP IOCs."""

import logging
import time
from typing import Any

import requests

from models.ioc import IOC

log = logging.getLogger(__name__)

_ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBEnricher:
    def __init__(self, api_key: str | None, retries: int = 2, backoff: float = 1.5):
        self._key     = api_key
        self._retries = retries
        self._backoff = backoff

    def enrich(self, ioc: IOC) -> dict[str, Any]:
        if not self._key:
            return {"status": "skipped", "reason": "ABUSEIPDB_API_KEY not configured"}

        params  = {"ipAddress": ioc.value, "maxAgeInDays": 90, "verbose": True}
        headers = {"Key": self._key, "Accept": "application/json"}

        for attempt in range(1, self._retries + 1):
            try:
                resp = requests.get(_ABUSE_URL, headers=headers,
                                    params=params, timeout=10)
            except requests.RequestException as exc:
                log.warning("AbuseIPDB error (attempt %d): %s", attempt, exc)
                time.sleep(self._backoff ** attempt)
                continue

            if resp.status_code == 429:
                time.sleep(self._backoff ** attempt)
                continue

            if not resp.ok:
                return {"status": "error", "http_status": resp.status_code}

            return self._parse(resp.json())

        return {"status": "error", "reason": "max retries exceeded"}

    @staticmethod
    def _parse(data: dict) -> dict[str, Any]:
        d = data.get("data", {})
        return {
            "status":             "ok",
            "abuse_confidence":   d.get("abuseConfidenceScore"),
            "total_reports":      d.get("totalReports"),
            "country_code":       d.get("countryCode"),
            "isp":                d.get("isp"),
            "domain":             d.get("domain"),
            "is_tor":             d.get("isTor"),
            "is_public":          d.get("isPublic"),
            "last_reported_at":   d.get("lastReportedAt"),
        }
