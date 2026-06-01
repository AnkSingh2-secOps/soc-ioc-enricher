"""
core/scorer.py
Synthesises enrichment results from multiple sources into a unified
risk score and verdict for each IOC.

Score bands:
  0-24   -> LOW
  25-49  -> MEDIUM
  50-74  -> HIGH
  75-100 -> CRITICAL
"""

from typing import Any


_BAND = [(75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW")]


def score_ioc(enrichments: dict[str, Any]) -> dict[str, Any]:
    """
    Returns {"score": int, "band": str, "signals": list[str]}
    score is 0-100, higher = more malicious.
    """
    score   = 0
    signals = []

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt = enrichments.get("virustotal", {})
    if vt.get("status") == "ok":
        mal   = vt.get("malicious", 0)
        total = vt.get("total_engines", 1) or 1
        vt_pct = int(mal / total * 100)
        if vt_pct >= 30:
            score += 40
            signals.append(f"VT: {mal}/{total} engines flag as malicious ({vt_pct}%)")
        elif vt_pct >= 5:
            score += 20
            signals.append(f"VT: {mal}/{total} engines flag as malicious ({vt_pct}%)")
        elif mal > 0:
            score += 10
            signals.append(f"VT: {mal} engine(s) flag as malicious")
        if vt.get("reputation", 0) is not None and (vt.get("reputation") or 0) < -20:
            score += 10
            signals.append(f"VT reputation: {vt['reputation']}")

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    ab = enrichments.get("abuseipdb", {})
    if ab.get("status") == "ok":
        conf = ab.get("abuse_confidence", 0) or 0
        if conf >= 75:
            score += 30
            signals.append(f"AbuseIPDB confidence: {conf}%")
        elif conf >= 25:
            score += 15
            signals.append(f"AbuseIPDB confidence: {conf}%")
        if ab.get("is_tor"):
            score += 10
            signals.append("Tor exit node")

    # ── GreyNoise ─────────────────────────────────────────────────────────────
    gn = enrichments.get("greynoise", {})
    if gn.get("status") == "ok":
        if gn.get("riot"):
            # Known safe service (Google, Cloudflare etc.) - reduce score
            score = max(score - 15, 0)
            signals.append("GreyNoise RIOT: known benign internet service")
        elif gn.get("classification") == "malicious":
            score += 25
            signals.append("GreyNoise: classified as malicious")
        elif gn.get("noise"):
            # Mass scanner - slightly elevate
            score += 5
            signals.append(f"GreyNoise: mass internet scanner ({gn.get('name', 'unknown')})")

    # ── MalwareBazaar ─────────────────────────────────────────────────────────
    mb = enrichments.get("malwarebazaar", {})
    if mb.get("status") == "ok" and mb.get("verdict") == "MALICIOUS":
        score += 50
        sig = mb.get("signature") or "unknown malware"
        signals.append(f"MalwareBazaar: {sig}")

    score = min(score, 100)

    band = "LOW"
    for threshold, label in _BAND:
        if score >= threshold:
            band = label
            break

    return {"score": score, "band": band, "signals": signals}
