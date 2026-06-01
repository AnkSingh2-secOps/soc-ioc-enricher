"""enrichers/virustotal.py – VirusTotal v3 enrichment."""

import logging
import time
from typing import Any

import requests

from models.ioc import IOC, IOCType

log = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"

_TYPE_ENDPOINT: dict[IOCType, str] = {
    IOCType.IP:          "ip_addresses",
    IOCType.DOMAIN:      "domains",
    IOCType.URL:         "urls",
    IOCType.HASH_MD5:    "files",
    IOCType.HASH_SHA1:   "files",
    IOCType.HASH_SHA256: "files",
}


class VirusTotalEnricher:
    def __init__(self, api_key: str | None, retries: int = 3, backoff: float = 1.5):
        self._key     = api_key
        self._retries = retries
        self._backoff = backoff

    def enrich(self, ioc: IOC) -> dict[str, Any]:
        if not self._key:
            return {"status": "skipped", "reason": "VT_API_KEY not configured"}

        endpoint = _TYPE_ENDPOINT.get(ioc.type)
        if not endpoint:
            return {"status": "skipped", "reason": f"Unsupported IOC type: {ioc.type}"}

        resource = ioc.value
        if ioc.type == IOCType.URL:
            import base64
            resource = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")

        url     = f"{_VT_BASE}/{endpoint}/{resource}"
        headers = {"x-apikey": self._key}

        for attempt in range(1, self._retries + 1):
            try:
                resp = requests.get(url, headers=headers, timeout=10)
            except requests.RequestException as exc:
                log.warning("VT request error (attempt %d): %s", attempt, exc)
                time.sleep(self._backoff ** attempt)
                continue

            if resp.status_code == 429:
                wait = self._backoff ** attempt
                log.warning("VT rate-limited. Waiting %.1fs before retry.", wait)
                time.sleep(wait)
                continue

            if resp.status_code == 404:
                return {"status": "not_found"}

            if not resp.ok:
                return {"status": "error", "http_status": resp.status_code}

            return self._parse(resp.json())

        return {"status": "error", "reason": "max retries exceeded"}

    @staticmethod
    def _parse(data: dict) -> dict[str, Any]:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "status":        "ok",
            "malicious":     stats.get("malicious", 0),
            "suspicious":    stats.get("suspicious", 0),
            "undetected":    stats.get("undetected", 0),
            "harmless":      stats.get("harmless", 0),
            "total_engines": sum(stats.values()),
            "reputation":    attrs.get("reputation"),
            "tags":          attrs.get("tags", []),
            "country":       attrs.get("country"),
            "as_owner":      attrs.get("as_owner"),
        }
