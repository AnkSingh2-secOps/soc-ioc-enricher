# SOC IOC Enricher

Multi-source IOC enrichment CLI for SOC analysts. Takes IPs, domains, file hashes, and URLs and queries VirusTotal, AbuseIPDB, GreyNoise, MalwareBazaar, and WHOIS in parallel. Synthesises results into a unified risk score (LOW/MEDIUM/HIGH/CRITICAL) with per-signal rationale.

Results are cached locally in SQLite to avoid re-querying APIs for the same IOCs. Outputs Markdown reports or JSON for SOAR/SIEM ingestion.

## Usage

```bash
pip install -r requirements.txt

# Single IOC
python enrich.py --ioc 8.8.8.8
python enrich.py --ioc evil-domain.com --format json
python enrich.py --ioc 44d88612fea8a8f36de82e1278abb02f

# Bulk enrichment from file (one IOC per line)
python enrich.py --file iocs.txt --format markdown --output report.md

# Skip the local cache
python enrich.py --file iocs.txt --no-cache
```

## Configuration

Set API keys as environment variables:

```bash
export VT_API_KEY=your_virustotal_key
export ABUSEIPDB_API_KEY=your_abuseipdb_key
export GREYNOISE_API_KEY=your_greynoise_key  # optional, community API also works without
```

If keys are not set the tool degrades gracefully. MalwareBazaar requires no API key.

## Supported IOC types

IOC type is detected automatically from the value format:

- IPv4 address (e.g. 8.8.8.8)
- Domain (e.g. evil-domain.com)
- URL with http/https scheme
- MD5 hash (32-character hex)
- SHA1 hash (40-character hex)
- SHA256 hash (64-character hex)

## Enrichment sources

| Source | IOC types | API key required |
|--------|-----------|-----------------|
| VirusTotal v3 | IP, Domain, Hash, URL | Yes (VT_API_KEY) |
| AbuseIPDB | IP | Yes (ABUSEIPDB_API_KEY) |
| GreyNoise | IP | Optional (GREYNOISE_API_KEY) |
| MalwareBazaar | Hash | No |
| WHOIS | Domain, URL | No |

## Risk scoring

After enrichment, a unified risk score from 0-100 is calculated across all sources. Bands: LOW (0-24), MEDIUM (25-49), HIGH (50-74), CRITICAL (75-100). Each contributing signal is listed in the report so analysts can see exactly what drove the score up.

## Caching

Enrichment results are cached per IOC and source in a local SQLite database at `~/.cache/soc-ioc-enricher/cache.db` with a 7-day TTL. Use `--no-cache` to force a fresh lookup.

## Requirements

- Python 3.10+
- requests
- python-whois
