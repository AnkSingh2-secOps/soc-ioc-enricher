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
from enrichers.abuseipdb import AbuseIPDBEnricher
from enrichers.whois_lookup import WhoisEnricher
from reporter import build_markdown_report, build_json_report


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


def enrich_ioc(ioc: IOC, vt_key: str | None, abuse_key: str | None) -> dict:
    results: dict = {"ioc": ioc.value, "type": ioc.type.value, "enrichments": {}}

    vt = VirusTotalEnricher(api_key=vt_key)
    results["enrichments"]["virustotal"] = vt.enrich(ioc)

    if ioc.type == IOCType.IP:
        abuse = AbuseIPDBEnricher(api_key=abuse_key)
        results["enrichments"]["abuseipdb"] = abuse.enrich(ioc)

    if ioc.type in (IOCType.DOMAIN, IOCType.URL):
        whois = WhoisEnricher()
        results["enrichments"]["whois"] = whois.enrich(ioc)

    return results


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
    args = parser.parse_args()

    vt_key    = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")

    if not vt_key:
        print("[WARN] VT_API_KEY not set – VirusTotal enrichment will use public lookups only.",
              file=sys.stderr)

    raw_iocs = [args.ioc] if args.ioc else load_iocs_from_file(Path(args.file))
    iocs     = [IOC(value=v, type=detect_type(v)) for v in raw_iocs]

    print(f"[*] Enriching {len(iocs)} IOC(s)...", file=sys.stderr)
    all_results = [enrich_ioc(ioc, vt_key, abuse_key) for ioc in iocs]

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
