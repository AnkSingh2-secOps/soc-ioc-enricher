"""enrichers/whois_lookup.py - WHOIS enrichment for domain/URL IOCs."""

import logging
from typing import Any

from models.ioc import IOC, IOCType

log = logging.getLogger(__name__)


class WhoisEnricher:
    def enrich(self, ioc: IOC) -> dict[str, Any]:
        try:
            import whois
        except ImportError:
            return {"status": "skipped", "reason": "python-whois not installed (pip install python-whois)"}

        target = ioc.value
        if ioc.type == IOCType.URL:
            from urllib.parse import urlparse
            target = urlparse(ioc.value).netloc or ioc.value

        try:
            data = whois.whois(target)
        except Exception as exc:
            log.warning("WHOIS lookup failed for %s: %s", target, exc)
            return {"status": "error", "reason": str(exc)}

        def _scalar(v):
            if isinstance(v, list):
                return v[0] if v else None
            return v

        return {
            "status":       "ok",
            "registrar":    _scalar(data.get("registrar")),
            "creation_date":str(_scalar(data.get("creation_date"))),
            "expiration_date": str(_scalar(data.get("expiration_date"))),
            "name_servers": data.get("name_servers"),
            "org":          _scalar(data.get("org")),
            "country":      _scalar(data.get("country")),
        }
