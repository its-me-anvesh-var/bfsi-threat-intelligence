# 🏦 BFSI Threat Intelligence Research

> Independent threat intelligence research focused on Advanced Persistent Threat (APT) actors targeting Banking, Financial Services, and Insurance (BFSI) sector organizations — with a specific focus on Indian financial institutions. Covers IOC enrichment automation, threat actor profiling, MITRE ATT&CK mapped attack patterns, and periodic threat landscape reports.

---

## 📌 Research Overview

This repository documents structured threat intelligence research conducted using open-source intelligence (OSINT) methodologies. All research is based on publicly available threat reports, MITRE ATT&CK data, and open-source tooling.

**Research scope:**
- APT actor profiling targeting BFSI sector
- IOC enrichment automation (OTX AlienVault, VirusTotal, Shodan)
- TTP mapping to MITRE ATT&CK framework
- Strategic, operational, and tactical intelligence report writing
- Indian BFSI-specific threat landscape analysis

---

## 📂 Repository Structure

```
bfsi-threat-intelligence/
│
├── README.md
│
├── apt-profiles/
│   ├── APT38-Lazarus.md                    ← North Korean SWIFT fraud group
│   ├── Carbanak-FIN7.md                    ← Eastern European banking malware group
│   └── SideCopy.md                         ← Pakistan-nexus, India-focused APT
│
├── ioc-enrichment/
│   ├── enrichment-script.py               ← Python IOC enrichment automation
│   ├── ioc-enrichment-workflow.md         ← Step-by-step OSINT pivot methodology
│   └── sample-pivot-APT38.md              ← Real pivot walkthrough using public IOCs
│
├── threat-reports/
│   ├── strategic/
│   │   └── BFSI-ThreatLandscape-India-2026.md
│   ├── operational/
│   │   └── APT38-Campaign-Analysis.md
│   └── phishing-campaign-analysis.md      ← Phishing campaign deep-dive
│
├── mitre-mappings/
│   └── bfsi-attack-patterns.md            ← Consolidated ATT&CK matrix for BFSI APTs
│
├── dashboards/
│   └── splunk-ti-dashboard.json           ← Splunk TI dashboard config
│
└── references/
    └── sources.md                          ← All public sources used
```

---

## 🎯 Threat Actors Profiled

| Actor | Nexus | Primary Target | Motivation |
|---|---|---|---|
| **APT38 (Lazarus Group)** | North Korea | SWIFT / Central Banks | Financial gain |
| **Carbanak / FIN7** | Eastern Europe | Banking / Retail | Financial gain |
| **SideCopy** | Pakistan | Indian Govt / BFSI | Espionage |
| **DarkSide Affiliates** | Various | Insurance / Enterprises | Ransomware |
| **Local Cybercrime Groups** | India | Retail banking customers | UPI fraud / phishing |

---

## ⚡ IOC Enrichment Automation

Automates lookups across OTX AlienVault, VirusTotal, and Shodan for a given IOC (IP, domain, hash, URL).

```bash
# Install dependencies
pip install OTXv2 requests

# Run enrichment
python ioc-enrichment/enrichment-script.py --ioc "185.220.101.47" --type ip
python ioc-enrichment/enrichment-script.py --ioc "malicious-domain.com" --type domain
python ioc-enrichment/enrichment-script.py --ioc "abc123..." --type hash
```

### IOC Enrichment Pipeline

```
Raw IOC (hash / IP / domain)
        │
        ▼
VirusTotal ──────────────────────► Vendor detections, related samples
        │
        ▼
Shodan ──────────────────────────► Infrastructure fingerprint, open ports
        │
        ▼
OTX AlienVault ──────────────────► Community pulses, related IOCs
        │
        ▼
WHOIS / PassiveDNS ──────────────► Domain registration, IP history
        │
        ▼
Pivot to new IOCs ───────────────► Expand actor infrastructure map
```

---

## 📊 BFSI Threat Landscape — Key Findings

> Full report: [`threat-reports/strategic/BFSI-ThreatLandscape-India-2026.md`](./threat-reports/strategic/BFSI-ThreatLandscape-India-2026.md)

**Top threats to Indian BFSI in 2026:**
1. SWIFT fraud via insider compromise and malware (APT38 / Lazarus)
2. Spearphishing campaigns targeting treasury and finance teams (SideCopy)
3. Supply chain attacks via third-party fintech integrations
4. Ransomware targeting backup and disaster recovery systems
5. API abuse targeting UPI and mobile banking platforms

---

## 🗺️ ATT&CK Coverage Across Profiled Actors

| Tactic | APT38 | Carbanak | SideCopy |
|---|---|---|---|
| Initial Access | T1566.001 (Spearphish) | T1566.001 | T1566.001 |
| Execution | T1059.001 (PowerShell) | T1059.003 (CMD) | T1059.001 |
| Persistence | T1547.001 (Registry) | T1053.005 (Sched. Task) | T1547.001 |
| Defense Evasion | T1036 (Masquerading) | T1027 (Obfuscation) | T1036 |
| Credential Access | T1555 (Credentials from Store) | T1003 (OS Cred Dump) | T1555 |
| Lateral Movement | T1021.002 (SMB) | T1021.001 (RDP) | T1021.002 |
| Exfiltration | T1048 (Alt Protocol) | T1041 (C2 Channel) | T1048 |
| Impact | T1531 (Account Access Removal) | T1657 (Financial Theft) | T1565 (Data Manipulation) |

**Top MITRE techniques observed across BFSI sector:**

| Technique | ID | Description |
|---|---|---|
| Phishing | T1566 | Most common initial access vector |
| Exploit Public-Facing Application | T1190 | Targeting banking portals and APIs |
| Valid Accounts | T1078 | Credential theft and account takeover |
| Data Encrypted for Impact | T1486 | Ransomware against financial infrastructure |
| Exfiltration Over Alt Protocol | T1048 | Covert data exfiltration |

Full matrix → [`mitre-mappings/bfsi-attack-patterns.md`](./mitre-mappings/bfsi-attack-patterns.md)

---

## 🔬 Methodology

### Intelligence Collection
- MITRE ATT&CK Group pages
- Mandiant / FireEye threat reports (public)
- CrowdStrike Adversary Intelligence (public blogs)
- Unit 42 (Palo Alto) threat research
- CERT-In advisories
- RBI cybersecurity circulars

### Intelligence Production

Reports follow a structured 3-tier format:

| Type | Audience | Format |
|---|---|---|
| **Strategic** | Executive / Board | Business risk focus, no raw IOCs |
| **Operational** | SOC / IR Teams | Campaign-level TTPs, actor profile, mitigations |
| **Tactical** | SIEM Engineers | Raw IOCs formatted for ingestion (CSV/STIX) |

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| VirusTotal | File hash / domain / IP reputation and relationships |
| Shodan | Internet-facing infrastructure fingerprinting |
| OTX AlienVault | Community threat intelligence, pulse correlation |
| MITRE ATT&CK Navigator | TTP visualization and coverage mapping |
| ThreatConnect | Threat intel platform |
| WHOIS / DomainTools (free) | Domain registration history |
| urlscan.io | URL and domain scanning |
| abuse.ch | MalwareBazaar, URLhaus, ThreatFox IOC feeds |
| Python (requests, json) | IOC enrichment automation |
| Splunk | Dashboards and correlation |

---

## 📰 Threat Reports

- [BFSI Threat Landscape 2026](./threat-reports/strategic/BFSI-ThreatLandscape-India-2026.md)
- [APT38 Campaign Analysis](./threat-reports/operational/APT38-Campaign-Analysis.md)
- [Phishing Campaign Analysis](./threat-reports/phishing-campaign-analysis.md)

---

## 👤 Author

**Anvesh Raju Vishwaraju**
M.S. Cybersecurity — UNC Charlotte | M.Tech AI — University of Hyderabad
Ex-Security Researcher, IDRBT (RBI's Institute)
CompTIA Security+ | eJPTv2 | CASA-APIsec

🔗 [LinkedIn](https://linkedin.com/in/arv007) · [GitHub](https://github.com/its-me-anvesh-var)

> *"Good threat intelligence doesn't just tell you what happened — it tells you what's coming next."*

---

*All threat intelligence in this repository is based on publicly available sources (OTX, VirusTotal, CERT-In advisories, public threat reports). No proprietary or client data is shared.*
