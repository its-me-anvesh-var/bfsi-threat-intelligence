# IOC Enrichment Workflow & Pivot Methodology

> This document describes the structured process used to enrich raw Indicators of Compromise (IOCs) and pivot to related infrastructure using open-source tools. All examples use **publicly documented, historical IOCs** from published threat reports.

---

## What Is IOC Enrichment?

A raw IOC — an IP address, domain, file hash, or URL — tells you *what* was involved in an attack. Enrichment tells you:

- **Who** is behind it (actor attribution)
- **What else** they control (infrastructure mapping)
- **How active** it is (current vs. historical)
- **What other victims** may be affected (community intelligence)

Enrichment converts a single data point into actionable intelligence.

---

## The Enrichment Pipeline

```
Step 1: Collect Raw IOC
        (from alert, email header, threat report, dark web monitoring)
        │
        ▼
Step 2: Validate & Deduplicate
        (Is this a known false positive? CDN? Legitimate service?)
        │
        ▼
Step 3: VirusTotal Analysis
        (Detection ratio, first/last seen, relations, community comments)
        │
        ▼
Step 4: Shodan / Censys (for IPs/domains)
        (Open ports, running services, SSL cert, hosting provider)
        │
        ▼
Step 5: OTX AlienVault
        (Community pulses, MITRE tags, related IOCs, subscriber reports)
        │
        ▼
Step 6: PassiveDNS / WHOIS
        (Historical DNS resolutions, domain registration details)
        │
        ▼
Step 7: Pivot to Related IOCs
        (SSL cert shared across domains? Same registrant email? Same ASN?)
        │
        ▼
Step 8: Confidence Scoring & Documentation
        (How confident are we in this attribution? What's missing?)
```

---

## Tool Reference

### VirusTotal
**What it tells you:**
- Vendor detection ratio (e.g., 47/72 vendors flag this hash as malicious)
- File behavior in sandbox (process creation, network connections, registry changes)
- Relations tab — other files that communicated with same C2, same file dropped by different dropper
- Community tab — analyst notes on the sample

**Key fields to check:**
```
For file hashes:
- Detection ratio
- First submission date (how long has this been in the wild?)
- Behaviour > Network communications (what does it call home to?)
- Relations > Contacted IPs / Contacted Domains
- Relations > Similar files (same family?)

For IPs/Domains:
- Detection ratio
- Passive DNS (what domains resolved to this IP historically?)
- Referrer files (what malware samples used this C2?)
- Relations > Communicating files
```

---

### Shodan
**What it tells you:**
- What services are exposed on an IP (ports 80, 443, 22, 3389, etc.)
- SSL certificate details — **certificate sharing across domains is a powerful pivot**
- HTTP response headers — sometimes reveals C2 panel fingerprints
- Historical data — when was this service first seen?
- Geographic location and hosting provider (ASN)

**Useful Shodan queries:**
```
# Find other servers with same SSL certificate
ssl:"<certificate_hash>"

# Find servers running same C2 panel (by HTTP title)
http.title:"Cobalt Strike Beacon"

# Find servers on same ASN with same open ports
asn:AS12345 port:4444

# Find domains resolving to same IP
hostname:<ip_address>
```

---

### OTX AlienVault
**What it tells you:**
- Community-submitted "pulses" tagging this IOC to specific campaigns or actors
- MITRE ATT&CK tags associated with the IOC
- Related IOCs within the same pulse (actor's other infrastructure)
- Subscriber count — how many security teams are tracking this?

**Pivot tip:** If an IOC appears in a pulse tagged "APT38" or "Lazarus" — check all other IOCs in that pulse. That's the actor's extended infrastructure.

---

### PassiveDNS / WHOIS
**What it tells you:**
- What IP addresses a domain has historically resolved to
- When the domain was registered and by whom
- Registrar information — some actors reuse registrars or registrant email patterns

**Free tools:**
- SecurityTrails (limited free tier)
- ViewDNS.info
- RiskIQ Community (now Microsoft Defender Threat Intelligence — limited free)
- Hurricane Electric BGP Toolkit (ASN/IP lookups)

---

## Sample Pivot Walkthrough — APT38 Infrastructure

> Using publicly documented IOCs from US-CERT Alert AA19-168A (HOPLIGHT malware)

### Step 1 — Starting IOC

```
Type: C2 Domain (publicly documented, historical)
IOC:  hxxp://onedrive-en[.]com
Source: US-CERT AA19-168A
```

### Step 2 — VirusTotal Analysis

Query: `onedrive-en[.]com` on VirusTotal

**Findings:**
- Detection: 8/88 vendors flagged as malicious
- Category tags: malware, c2
- Passive DNS: resolved to IP `185.xxx.xxx.xxx` (Eastern European hosting)
- Referrer files: 3 samples identified that communicated with this domain
  - One sample matched HOPLIGHT malware family signature

### Step 3 — IP Pivot via Shodan

Query the resolved IP on Shodan:

**Findings:**
- Open ports: 80, 443, 8080
- SSL certificate on port 443: issued to generic name, self-signed
- SSL certificate hash: `sha256:abcd1234...`
- HTTP title on port 8080: blank (typical of C2 panels that hide their identity)

**Pivot:** Search Shodan for other servers sharing the same SSL certificate hash

```
ssl:"abcd1234..."
```

**Result:** 3 additional IPs found sharing the same certificate — likely same actor infrastructure

### Step 4 — OTX AlienVault

Search `onedrive-en[.]com` on OTX:

**Findings:**
- Present in 2 community pulses
- Both pulses tagged: `APT38`, `Lazarus Group`, `DPRK`, `Financial`
- Related IOCs in the same pulse: 12 additional domains and 4 IPs
- MITRE tags: T1566.001, T1071.001, T1048

**Intelligence gain:** Starting from 1 domain, we now have a potential infrastructure cluster of 15+ IOCs

### Step 5 — WHOIS Pivot

Check domain registration for `onedrive-en[.]com` and the 3 IPs found in Shodan:

**Pattern identified:**
- All domains registered within the same 2-week window
- All used privacy protection services (registrant details hidden)
- All registered through the same registrar
- Registrar pattern consistent with other documented APT38 infrastructure

### Step 6 — Confidence Assessment & Documentation

```
IOC: onedrive-en[.]com
Attribution: APT38 / Lazarus Group
Confidence: High
Basis:
  - US-CERT attribution in AA19-168A
  - HOPLIGHT malware sample communication confirmed
  - Infrastructure cluster shares SSL cert with 3 additional C2 nodes
  - OTX community consensus across 2 independent pulses
  - Registration pattern consistent with documented APT38 infrastructure

Related IOCs (pivoted):
  - [3 additional IPs from Shodan SSL pivot]
  - [12 additional IOCs from OTX pulse]

Recommended action:
  - Block all identified IPs and domains at firewall/proxy
  - Add to SIEM watchlist for retrospective hunting
  - Share with FS-ISAC if in financial sector environment
```

---

## IOC Confidence Scoring Framework

| Score | Label | Criteria |
|---|---|---|
| High | Confirmed | Government attribution, multiple independent sources, forensic evidence |
| Medium-High | Probable | 2+ independent sources, consistent infrastructure patterns |
| Medium | Possible | Single source, community consensus, no direct forensic link |
| Low | Unverified | Single report, no corroboration, could be false positive |

---

## Common Pivot Techniques Summary

| Starting IOC | Pivot Method | What You Find |
|---|---|---|
| File hash | VT Relations tab | Other samples by same actor, C2 domains |
| C2 domain | Passive DNS | Historical IPs the domain resolved to |
| IP address | Shodan SSL cert | Other domains/IPs sharing same certificate |
| IP address | Shodan port scan | Fingerprint of C2 software |
| Domain | WHOIS registrant | Other domains registered by same entity |
| Domain | OTX pulse | Actor's full IOC cluster |
| URL | urlscan.io | Page content, redirects, related domains |
