"""
soc-ioc-enricher · enrich.py
CLI entry point.

Usage:
    python enrich.py --ioc 8.8.8.8
    python enrich.py --ioc evil-domain.com --format json
    python enrich.py --file iocs.txt --format markdown --output report.md
    python enrich.py --ioc 44d88612fea8a8f36de82e1278abb02f  # MD5 hash
"""

import argparse
import json
import os
import sys
from pathlib import Path

from models.ioc import IOC, IOCType
from enrichers.virustotal import VirusTotalEnricher
from enrichers.abuseipdb     import AbuseIPDBEnricher
from enrichers.greynoise     import GreyNoiseEnricher
from enrichers.malwarebazaar import MalwareBazaarEnricher
from enrichers.whois_lookup  import WhoisEnricher
from core.cache  import EnrichmentCache
from core.scorer import score_ioc
from reporter import build_markdown_report


def detect_type(value: str) -> IOCType:
    import re
    value = value.strip()
    # MD5 / SHA1 / SHA256
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return IOCType.HASH_MD5
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return IOCType.HASH_SHA1
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return IOCType.HASH_SHA256
    # IPv4
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
        return IOCType.IP
    # URL (has scheme)
    if re.match(r"https?://", value):
        return IOCType.URL
    # domain fallback
    return IOCType.DOMAIN


def enrich_ioc(
    ioc: IOC,
    vt_key: str | None,
    abuse_key: str | None,
    gn_key: str | None = None,
    cache: EnrichmentCache | None = None,
) -> dict:
    result: dict = {"ioc": ioc.value, "type": ioc.type.value, "enrichments": {}}

    def _cached(source: str, fn):
        if cache:
            hit = cache.get(ioc.value, source)
            if hit is not None:
                return hit
        data = fn()
        if cache:
            cache.set(ioc.value, source, data)
        return data

    result["enrichments"]["virustotal"] = _cached(
        "virustotal", lambda: VirusTotalEnricher(api_key=vt_key).enrich(ioc)
    )

    if ioc.type == IOCType.IP:
        result["enrichments"]["abuseipdb"] = _cached(
            "abuseipdb", lambda: AbuseIPDBEnricher(api_key=abuse_key).enrich(ioc)
        )
        result["enrichments"]["greynoise"] = _cached(
            "greynoise", lambda: GreyNoiseEnricher(api_key=gn_key).enrich(ioc)
        )

    if ioc.type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
        result["enrichments"]["malwarebazaar"] = _cached(
            "malwarebazaar", lambda: MalwareBazaarEnricher().enrich(ioc)
        )

    if ioc.type in (IOCType.DOMAIN, IOCType.URL):
        result["enrichments"]["whois"] = _cached(
            "whois", lambda: WhoisEnricher().enrich(ioc)
        )

    result["risk"] = score_ioc(result["enrichments"])
    return result


def load_iocs_from_file(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def main():
    parser = argparse.ArgumentParser(
        description="Multi-source IOC enrichment CLI for SOC analysts."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ioc", help="Single IOC value (IP, domain, hash, or URL).")
    group.add_argument("--file", help="Path to a file with one IOC per line.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown",
        help="Output format (default: markdown)."
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Write output to this file instead of stdout."
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Bypass the local SQLite enrichment cache."
    )
    args = parser.parse_args()

    vt_key    = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    gn_key    = os.getenv("GREYNOISE_API_KEY")

    cache = None if args.no_cache else EnrichmentCache()
    if cache:
        stats = cache.stats()
        print(f"[*] Cache: {stats['live']} live entries, {stats['expired']} expired.",
              file=sys.stderr)

    if not vt_key:
        print("[WARN] VT_API_KEY not set – VirusTotal enrichment will be limited.",
              file=sys.stderr)

    raw_iocs = [args.ioc] if args.ioc else load_iocs_from_file(Path(args.file))
    iocs     = [IOC(value=v, type=detect_type(v)) for v in raw_iocs]

    print(f"[*] Enriching {len(iocs)} IOC(s)...", file=sys.stderr)
    all_results = [enrich_ioc(ioc, vt_key, abuse_key, gn_key, cache) for ioc in iocs]

    if args.format == "json":
        output = json.dumps(all_results, indent=2)
    else:
        output = build_markdown_report(all_results)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"[+] Report written to: {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
