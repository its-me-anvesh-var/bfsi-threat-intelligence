# Threat Actor Profile: SideCopy

**Classification:** Nation-State APT
**Nexus:** Pakistan (assessed with moderate-high confidence)
**Motivation:** Espionage — Indian government, defence, and financial sector
**Active Since:** ~2019
**Also Known As:** SideCopy, Transparent Tribe subgroup (assessed)
**MITRE ATT&CK Group ID:** G1008

---

## Executive Summary

SideCopy is a Pakistan-linked APT group that derives its name from its tactic of **mimicking the infection chain of SideWinder** (an Indian APT), likely as a deliberate false-flag technique to complicate attribution.

The group primarily targets **Indian government employees, defence personnel, and increasingly BFSI sector employees** — particularly those working in financial regulatory bodies and public sector banks. Unlike APT38, SideCopy's primary motivation is **intelligence collection** rather than direct financial theft, though access to BFSI systems creates significant secondary risks (market manipulation, regulatory intelligence, customer data exfiltration).

---

## Why SideCopy Matters for Indian BFSI

- Targets **government employees who are also bank customers** — credential harvesting
- Has specifically targeted **Ministry of Finance and RBI-adjacent personnel**
- Trojanized **government document lures** are indistinguishable from legitimate communications
- Increasing overlap between government and BFSI targeting suggests **supply chain pivot potential**

---

## Infection Chain

```
Spearphishing Email
(lure: government circular, defence notification, 
 job offer, COVID-era health advisory)
        │
        ▼
Malicious attachment or link
(ZIP > LNK file > HTA/CPL dropper)
        │
        ▼
ActionRAT / MargulasRAT / ReverseRAT deployed
(custom RAT family — .NET based)
        │
        ▼
C2 communication established
(HTTP/HTTPS to compromised Indian websites used as proxies)
        │
        ▼
Credential harvesting, document exfiltration,
keylogging, screenshot capture
```

---

## TTP Mapping (MITRE ATT&CK)

| Tactic | Technique | ID | Detail |
|---|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 | ZIP archives with LNK files |
| Initial Access | Spearphishing Link | T1566.002 | Links to malicious HTA pages |
| Execution | User Execution | T1204.002 | User must open attachment |
| Execution | Mshta | T1218.005 | HTA files for dropper execution |
| Persistence | Registry Run Keys | T1547.001 | Startup persistence |
| Defense Evasion | Masquerading | T1036 | Files named as PDF/DOCX |
| Defense Evasion | Obfuscated Files | T1027 | .NET payload obfuscation |
| C2 | Web Protocols | T1071.001 | HTTP/HTTPS C2 |
| C2 | Proxy — Compromised Sites | T1090.002 | Indian websites as C2 proxies |
| Collection | Keylogging | T1056.001 | Custom keylogger module |
| Collection | Screen Capture | T1113 | Periodic screenshot exfil |
| Exfiltration | Exfil over C2 | T1041 | Documents, credentials via C2 |

---

## Malware Family Overview

### ActionRAT
- .NET-based remote access trojan
- Capabilities: file upload/download, command execution, screenshot, keylog
- C2: HTTP POST to hardcoded domains (often compromised Indian sites)
- Evasion: uses legitimate-looking user agents, delays execution

### ReverseRAT
- Similar capability set to ActionRAT
- Uses **reverse connection** — victim connects out to C2 rather than C2 connecting in
- Makes detection harder (outbound traffic looks like legitimate browsing)

---

## Lure Document Examples (Publicly Documented)

- Fake **RBI circulars** on digital payment guidelines
- Fake **SEBI advisories** on compliance requirements
- Fake **UIDAI/Aadhaar** account verification notifications
- Fake **income tax refund** notification emails
- Defence sector: fake **DRDO job offers**, army posting orders

**Pattern:** Documents are crafted in fluent Hindi and English, with legitimate-looking government formatting. Header logos are copied from actual government websites.

---

## Infrastructure Characteristics

- **C2 hosting:** Frequently uses compromised Indian hosting providers and legitimate Indian websites as unwitting proxies — makes blocklisting difficult
- **Domain patterns:** Typosquatted government domains (e.g., `india-gov[.]in`, `nic-india[.]com`)
- **IP ranges:** Dynamic — infrastructure changes frequently
- **Certificate use:** Let's Encrypt certificates on malicious domains (appears legitimate to users)

---

## Detection Opportunities

| Indicator | Detection Method |
|---|---|
| LNK files inside ZIP attachments from external email | Email gateway policy |
| MSHTA.exe spawning child processes | Sysmon EventID 1 — parent/child chain |
| .NET assemblies loaded from temp directory | EDR behavioral detection |
| Outbound HTTP POST to uncommon Indian domains | DNS monitoring + proxy logs |
| Keylogger activity (high volume keystroke data) | EDR anomaly detection |
| Screenshot files created in temp directory | File system monitoring |

---

## Defensive Recommendations

1. **Disable MSHTA** via AppLocker/WDAC if not required in environment
2. **Email gateway policy** — block ZIP attachments containing LNK files
3. **User awareness training** — specifically covering fake government document lures (relevant for Indian employees)
4. **DNS filtering** — block newly registered domains (< 30 days old)
5. **Macro policies** — disable Office macros from internet-sourced documents
6. **Monitor outbound** — alert on HTTP POST to domains with no prior history in environment

---

## References

- Cisco Talos — SideCopy APT Report (2021)
- Seqrite Labs — SideCopy Campaign Analysis (2022)
- CERT-In Advisories (various)
- MITRE ATT&CK Group G1008
- Malwarebytes Threat Intelligence — SideCopy targeting India
