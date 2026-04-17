#!/usr/bin/env python3
"""
============================================================
IOC Enrichment Script — BFSI Threat Intelligence
Author: Anvesh Raju Vishwaraju
Description: Automated IOC enrichment using OTX AlienVault
             and VirusTotal APIs
============================================================
"""

import argparse
import json
import requests
import sys
from datetime import datetime

# ── API Keys (set as environment variables) ──────────────
import os
OTX_API_KEY = os.getenv("OTX_API_KEY", "YOUR_OTX_API_KEY")
VT_API_KEY  = os.getenv("VT_API_KEY",  "YOUR_VT_API_KEY")

OTX_BASE = "https://otx.alienvault.com/api/v1"
VT_BASE  = "https://www.virustotal.com/api/v3"


# ── OTX AlienVault Lookup ────────────────────────────────

def otx_lookup_ip(ip: str) -> dict:
    """Lookup IP reputation on OTX AlienVault."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(
            f"{OTX_BASE}/indicators/IPv4/{ip}/general",
            headers=headers, timeout=10
        )
        data = r.json()
        return {
            "source": "OTX AlienVault",
            "ioc": ip,
            "type": "IP",
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "reputation": data.get("reputation", "unknown"),
            "country": data.get("country_name", "unknown"),
            "asn": data.get("asn", "unknown"),
            "malware_families": [
                p.get("name") for p in
                data.get("pulse_info", {}).get("pulses", [])[:3]
            ],
            "first_seen": data.get("first_seen", "unknown"),
        }
    except Exception as e:
        return {"source": "OTX", "error": str(e)}


def otx_lookup_domain(domain: str) -> dict:
    """Lookup domain reputation on OTX AlienVault."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(
            f"{OTX_BASE}/indicators/domain/{domain}/general",
            headers=headers, timeout=10
        )
        data = r.json()
        return {
            "source": "OTX AlienVault",
            "ioc": domain,
            "type": "Domain",
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "alexa_rank": data.get("alexa", "unknown"),
            "whois": data.get("whois", "unknown")[:200],
            "malware_families": [
                p.get("name") for p in
                data.get("pulse_info", {}).get("pulses", [])[:3]
            ],
        }
    except Exception as e:
        return {"source": "OTX", "error": str(e)}


def otx_lookup_hash(file_hash: str) -> dict:
    """Lookup file hash reputation on OTX AlienVault."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(
            f"{OTX_BASE}/indicators/file/{file_hash}/general",
            headers=headers, timeout=10
        )
        data = r.json()
        return {
            "source": "OTX AlienVault",
            "ioc": file_hash,
            "type": "File Hash",
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "malware_families": [
                p.get("name") for p in
                data.get("pulse_info", {}).get("pulses", [])[:3]
            ],
        }
    except Exception as e:
        return {"source": "OTX", "error": str(e)}


# ── VirusTotal Lookup ────────────────────────────────────

def vt_lookup_ip(ip: str) -> dict:
    """Lookup IP on VirusTotal."""
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(
            f"{VT_BASE}/ip_addresses/{ip}",
            headers=headers, timeout=10
        )
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "source": "VirusTotal",
            "ioc": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": data.get("country", "unknown"),
            "as_owner": data.get("as_owner", "unknown"),
            "reputation": data.get("reputation", 0),
        }
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def vt_lookup_domain(domain: str) -> dict:
    """Lookup domain on VirusTotal."""
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers=headers, timeout=10
        )
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "source": "VirusTotal",
            "ioc": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "categories": data.get("categories", {}),
            "reputation": data.get("reputation", 0),
        }
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def vt_lookup_hash(file_hash: str) -> dict:
    """Lookup file hash on VirusTotal."""
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(
            f"{VT_BASE}/files/{file_hash}",
            headers=headers, timeout=10
        )
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "source": "VirusTotal",
            "ioc": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "type_description": data.get("type_description", "unknown"),
            "meaningful_name": data.get("meaningful_name", "unknown"),
            "popular_threat_name": data.get(
                "popular_threat_classification", {}
            ).get("suggested_threat_label", "unknown"),
        }
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


# ── Risk Scoring ─────────────────────────────────────────

def calculate_risk(results: list) -> str:
    """Calculate overall risk score from enrichment results."""
    total_malicious = 0
    pulse_count = 0

    for r in results:
        total_malicious += r.get("malicious", 0)
        pulse_count += r.get("pulse_count", 0)

    if total_malicious >= 10 or pulse_count >= 5:
        return "🔴 HIGH RISK — Block immediately"
    elif total_malicious >= 3 or pulse_count >= 2:
        return "🟠 MEDIUM RISK — Investigate further"
    elif total_malicious >= 1 or pulse_count >= 1:
        return "🟡 LOW RISK — Monitor"
    else:
        return "🟢 CLEAN — No threats detected"


# ── Main ─────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IOC Enrichment Tool — BFSI Threat Intelligence"
    )
    parser.add_argument("--ioc",  required=True, help="IOC value to investigate")
    parser.add_argument("--type", required=True,
                        choices=["ip", "domain", "hash"],
                        help="IOC type: ip / domain / hash")
    parser.add_argument("--output", default="json",
                        choices=["json", "text"],
                        help="Output format")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  IOC ENRICHMENT REPORT")
    print(f"  Analyst: Anvesh Raju Vishwaraju")
    print(f"  Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  IOC:     {args.ioc}")
    print(f"  Type:    {args.type.upper()}")
    print(f"{'='*60}\n")

    results = []

    if args.type == "ip":
        results.append(otx_lookup_ip(args.ioc))
        results.append(vt_lookup_ip(args.ioc))
    elif args.type == "domain":
        results.append(otx_lookup_domain(args.ioc))
        results.append(vt_lookup_domain(args.ioc))
    elif args.type == "hash":
        results.append(otx_lookup_hash(args.ioc))
        results.append(vt_lookup_hash(args.ioc))

    risk = calculate_risk(results)

    report = {
        "timestamp": datetime.now().isoformat(),
        "analyst": "Anvesh Raju Vishwaraju",
        "ioc": args.ioc,
        "type": args.type,
        "risk_assessment": risk,
        "enrichment_results": results,
        "recommended_action": (
            "Block at firewall and email gateway. Add to SIEM watchlist."
            if "HIGH" in risk or "MEDIUM" in risk
            else "Continue monitoring."
        )
    }

    if args.output == "json":
        print(json.dumps(report, indent=2))
    else:
        print(f"Risk Assessment: {risk}")
        for r in results:
            print(f"\n[{r.get('source')}]")
            for k, v in r.items():
                if k != "source":
                    print(f"  {k}: {v}")

    # Save report
    filename = f"report_{args.ioc.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n✅ Report saved to: {filename}")


if __name__ == "__main__":
    main()
