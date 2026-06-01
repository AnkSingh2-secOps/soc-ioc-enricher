"""reporter.py – Formats enrichment results as Markdown or JSON."""

from typing import Any


def build_markdown_report(results: list[dict[str, Any]]) -> str:
    lines = ["# SOC IOC Enrichment Report", ""]

    for r in results:
        ioc_val  = r.get("ioc", "N/A")
        ioc_type = r.get("type", "unknown").upper()
        risk     = r.get("risk", {})
        band     = risk.get("band", "N/A")
        score    = risk.get("score", "N/A")
        lines += [f"## `{ioc_val}`  `[{ioc_type}]`  Risk: **{band}** ({score}/100)", ""]
        if risk.get("signals"):
            lines.append("**Risk signals:**")
            for sig in risk["signals"]:
                lines.append(f"- {sig}")
            lines.append("")

        enrichments = r.get("enrichments", {})

        # VirusTotal
        vt = enrichments.get("virustotal", {})
        lines.append("### VirusTotal")
        if vt.get("status") == "ok":
            mal   = vt.get("malicious", 0)
            total = vt.get("total_engines", 0)
            verdict = "**MALICIOUS**" if mal > 0 else "Clean"
            lines += [
                f"- Verdict: {verdict}",
                f"- Malicious detections: `{mal}` / `{total}` engines",
                f"- Suspicious: `{vt.get('suspicious', 0)}`",
                f"- Reputation score: `{vt.get('reputation', 'N/A')}`",
                f"- Country: `{vt.get('country', 'N/A')}`",
                f"- AS Owner: `{vt.get('as_owner', 'N/A')}`",
                f"- Tags: {', '.join(vt.get('tags', [])) or 'none'}",
            ]
        elif vt.get("status") == "not_found":
            lines.append("- No data found in VirusTotal.")
        else:
            lines.append(f"- Status: `{vt.get('status')}` – {vt.get('reason', '')}")

        lines.append("")

        # AbuseIPDB
        if "abuseipdb" in enrichments:
            ab = enrichments["abuseipdb"]
            lines.append("### AbuseIPDB")
            if ab.get("status") == "ok":
                conf = ab.get("abuse_confidence", 0)
                verdict = "**HIGH RISK**" if conf >= 75 else ("Moderate" if conf >= 25 else "Low Risk")
                lines += [
                    f"- Abuse Confidence: `{conf}%`  ({verdict})",
                    f"- Total Reports: `{ab.get('total_reports', 0)}`",
                    f"- ISP: `{ab.get('isp', 'N/A')}`",
                    f"- Country: `{ab.get('country_code', 'N/A')}`",
                    f"- Tor Exit Node: `{ab.get('is_tor', False)}`",
                    f"- Last Reported: `{ab.get('last_reported_at', 'N/A')}`",
                ]
            else:
                lines.append(f"- Status: `{ab.get('status')}` – {ab.get('reason', '')}")
            lines.append("")

        # GreyNoise
        if "greynoise" in enrichments:
            gn = enrichments["greynoise"]
            lines.append("### GreyNoise")
            if gn.get("status") == "ok":
                lines += [
                    f"- Classification: `{gn.get('classification', 'N/A')}`",
                    f"- Noise (mass scanner): `{gn.get('noise', False)}`",
                    f"- RIOT (known safe service): `{gn.get('riot', False)}`",
                    f"- Name: `{gn.get('name', 'N/A')}`",
                    f"- Last Seen: `{gn.get('last_seen', 'N/A')}`",
                    f"- Verdict: {gn.get('verdict_label', 'N/A')}",
                ]
            elif gn.get("status") == "not_found":
                lines.append("- Not seen by GreyNoise.")
            else:
                lines.append(f"- Status: `{gn.get('status')}` – {gn.get('reason', '')}")
            lines.append("")

        # MalwareBazaar
        if "malwarebazaar" in enrichments:
            mb = enrichments["malwarebazaar"]
            lines.append("### MalwareBazaar")
            if mb.get("status") == "ok":
                lines += [
                    f"- Verdict: **{mb.get('verdict', 'N/A')}**",
                    f"- File Name: `{mb.get('file_name', 'N/A')}`",
                    f"- File Type: `{mb.get('file_type', 'N/A')}`",
                    f"- Signature: `{mb.get('signature', 'N/A')}`",
                    f"- First Seen: `{mb.get('first_seen', 'N/A')}`",
                    f"- Tags: {', '.join(mb.get('tags', [])) or 'none'}",
                    f"- Intel: {mb.get('intelligence_url', '')}",
                ]
            elif mb.get("status") == "not_found":
                lines.append("- Hash not found in MalwareBazaar.")
            else:
                lines.append(f"- Status: `{mb.get('status')}` – {mb.get('reason', '')}")
            lines.append("")

        # WHOIS
        if "whois" in enrichments:
            wh = enrichments["whois"]
            lines.append("### WHOIS")
            if wh.get("status") == "ok":
                lines += [
                    f"- Registrar: `{wh.get('registrar', 'N/A')}`",
                    f"- Created: `{wh.get('creation_date', 'N/A')}`",
                    f"- Expires: `{wh.get('expiration_date', 'N/A')}`",
                    f"- Org: `{wh.get('org', 'N/A')}`",
                    f"- Country: `{wh.get('country', 'N/A')}`",
                ]
            else:
                lines.append(f"- Status: `{wh.get('status')}` – {wh.get('reason', '')}")
            lines.append("")

        lines += ["---", ""]

    # Add risk score block per IOC
    # (re-render summary table if multiple IOCs)
    if len(results) > 1:
        lines.insert(2, "")
        lines.insert(2, "| IOC | Type | Risk | Score | Top Signal |")
        lines.insert(2, "|-----|------|------|-------|------------|")
        for r in results:
            risk = r.get("risk", {})
            band  = risk.get("band", "N/A")
            score = risk.get("score", "N/A")
            sigs  = risk.get("signals", [])
            top   = sigs[0] if sigs else "none"
            lines.insert(3 + results.index(r),
                         f"| `{r['ioc']}` | {r['type'].upper()} | **{band}** | {score} | {top} |")
        lines.insert(2, "## Risk Summary")

    lines.append("_Generated by [soc-ioc-enricher](https://github.com/AnkSingh2-secOps/soc-ioc-enricher)_")
    return "\n".join(lines)
