"""enrichers/greynoise.py – GreyNoise IP context enrichment."""

import logging
import time
from typing import Any

import requests

from models.ioc import IOC

log = logging.getLogger(__name__)

_GN_URL = "https://api.greynoise.io/v3/community/{ip}"


class GreyNoiseEnricher:
    """
    Uses the GreyNoise Community API (free tier) for IP context.
    Classifies IPs as benign internet scanners, malicious, or unknown.
    """

    def __init__(self, api_key: str | None = None, retries: int = 2, backoff: float = 1.5):
        self._key     = api_key
        self._retries = retries
        self._backoff = backoff

    def enrich(self, ioc: IOC) -> dict[str, Any]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._key:
            headers["key"] = self._key

        url = _GN_URL.format(ip=ioc.value)

        for attempt in range(1, self._retries + 1):
            try:
                resp = requests.get(url, headers=headers, timeout=10)
            except requests.RequestException as exc:
                log.warning("GreyNoise error (attempt %d): %s", attempt, exc)
                time.sleep(self._backoff ** attempt)
                continue

            if resp.status_code == 404:
                return {"status": "not_found", "noise": False, "riot": False}

            if resp.status_code == 429:
                time.sleep(self._backoff ** attempt)
                continue

            if not resp.ok:
                return {"status": "error", "http_status": resp.status_code}

            return self._parse(resp.json())

        return {"status": "error", "reason": "max retries exceeded"}

    @staticmethod
    def _parse(data: dict) -> dict[str, Any]:
        classification = data.get("classification", "unknown")
        return {
            "status":         "ok",
            "noise":          data.get("noise", False),
            "riot":           data.get("riot", False),
            "classification": classification,
            "name":           data.get("name"),
            "link":           data.get("link"),
            "last_seen":      data.get("last_seen"),
            "message":        data.get("message"),
            # riot = known benign (Google, Cloudflare etc.)
            # noise = mass internet scanner
            # classification = malicious / benign / unknown
            "verdict_label":  _verdict(data),
        }


def _verdict(data: dict) -> str:
    if data.get("riot"):
        return "Benign (RIOT - known safe internet service)"
    cls = data.get("classification", "unknown")
    if cls == "malicious":
        return "Malicious (GreyNoise)"
    if cls == "benign":
        return "Benign scanner"
    if data.get("noise"):
        return "Mass internet scanner (unknown intent)"
    return "Not seen by GreyNoise"
