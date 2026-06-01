# SOC IOC Enricher

Multi-source IOC enrichment CLI for SOC analysts. Takes IPs, domains, file hashes, and URLs and aggregates reputation data from VirusTotal v3, AbuseIPDB, and WHOIS into structured triage reports.

Designed to drop into SOAR pipelines via stdin/stdout or run standalone during triage.

---

## Usage

```bash
pip install -r requirements.txt

# Single IOC
python enrich.py --ioc 8.8.8.8
python enrich.py --ioc evil-domain.com --format json
python enrich.py --ioc 44d88612fea8a8f36de82e1278abb02f   # MD5 hash

# Bulk enrichment from file (one IOC per line)
python enrich.py --file iocs.txt --format markdown --output report.md
```

---

## Configuration

Set API keys as environment variables:

```bash
export VT_API_KEY=your_virustotal_key
export ABUSEIPDB_API_KEY=your_abuseipdb_key
```

If keys are not set, the tool degrades gracefully — VirusTotal falls back to limited public lookups, AbuseIPDB is skipped.

---

## Supported IOC types

| Type | Auto-detected by |
|------|-----------------|
| IPv4 address | Regex pattern |
| Domain | Default if no other pattern matches |
| URL | Presence of `http://` or `https://` scheme |
| MD5 hash | 32-character hex string |
| SHA1 hash | 40-character hex string |
| SHA256 hash | 64-character hex string |

---

## Output example

```markdown
## `185.220.101.5`  `[IP]`

### VirusTotal
- Verdict: **MALICIOUS**
- Malicious detections: `14` / `89` engines
- Suspicious: `3`
- Country: `DE`
- AS Owner: `Tor Project`

### AbuseIPDB
- Abuse Confidence: `97%`  (HIGH RISK)
- Total Reports: `482`
- ISP: `Frantech Solutions`
- Tor Exit Node: `True`
- Last Reported: `2026-05-31T18:42:00+00:00`
```

---

## Enrichment sources

| Source | IOC types | Requires API key |
|--------|-----------|-----------------|
| VirusTotal v3 | IP, Domain, Hash, URL | Yes (`VT_API_KEY`) |
| AbuseIPDB | IP | Yes (`ABUSEIPDB_API_KEY`) |
| WHOIS | Domain, URL | No |

---

## Project structure

```
soc-ioc-enricher/
├── enrich.py               # CLI entry point
├── enrichers/
│   ├── virustotal.py       # VirusTotal v3 enricher
│   ├── abuseipdb.py        # AbuseIPDB enricher
│   └── whois_lookup.py     # WHOIS enricher
├── models/
│   └── ioc.py              # IOC data model
├── reporter.py             # Markdown / JSON report builder
└── requirements.txt
```

---

## Requirements

- Python 3.10+
- `requests`
- `python-whois` (optional, for WHOIS enrichment)
