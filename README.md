# bfsi-threat-intelligence
# 🏦 BFSI Threat Intelligence

A threat intelligence repository focused on the Banking, Financial Services, and Insurance (BFSI) sector — covering IOC enrichment automation, threat actor profiling, MITRE ATT&CK mapped attack patterns, and periodic threat landscape reports for the Indian financial sector.

---

## 📂 Repository Structure

```
bfsi-threat-intelligence/
├── README.md
├── ioc-enrichment/
│   ├── enrichment-script.py       # Python IOC enrichment automation
│   └── sample-output.json         # Sample enriched IOC output
├── threat-reports/
│   ├── bfsi-threat-landscape-2026.md   # Full threat landscape report
│   └── phishing-campaign-analysis.md   # Phishing campaign deep-dive
├── mitre-mappings/
│   └── bfsi-attack-patterns.md         # ATT&CK mapped BFSI threats
└── dashboards/
    └── splunk-ti-dashboard.json         # Splunk TI dashboard config
```

---

## 🛠️ Tools & APIs Used

| Tool | Purpose |
|---|---|
| OTX AlienVault | IOC lookups, threat pulses |
| VirusTotal | File/URL/IP reputation |
| Shodan | Infrastructure analysis |
| ThreatConnect | Threat intel platform |
| Python (requests, json) | Enrichment automation |
| Splunk | Dashboards and correlation |

---

## ⚡ IOC Enrichment Script

Automates lookups across OTX AlienVault, VirusTotal, and Shodan for a given IOC (IP, domain, hash, URL).

```bash
# Install dependencies
pip install OTXv2 requests

# Run enrichment
python ioc-enrichment/enrichment-script.py --ioc "185.220.101.47" --type ip
python ioc-enrichment/enrichment-script.py --ioc "malicious-domain.com" --type domain
python ioc-enrichment/enrichment-script.py --ioc "abc123..." --type hash
```

---

## 📊 Key Threat Actors Targeting Indian BFSI

| Threat Actor | Origin | Primary TTPs | Target |
|---|---|---|---|
| SideCopy | Pakistan | Spear phishing, RATs | Govt + BFSI |
| Lazarus Group | North Korea | Supply chain, SWIFT fraud | Banks |
| FIN7 | Eastern Europe | POS malware, phishing | Retail banking |
| DarkSide affiliates | Various | Ransomware | Insurance |
| Local cybercrime groups | India | UPI fraud, phishing | Retail customers |

---

## 📈 MITRE ATT&CK Coverage

See [bfsi-attack-patterns.md](mitre-mappings/bfsi-attack-patterns.md) for full mapping.

Top techniques observed in BFSI sector:
- **T1566** — Phishing (most common initial access)
- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts (credential theft)
- **T1486** — Data Encrypted for Impact (ransomware)
- **T1048** — Exfiltration Over Alternative Protocol

---

## 📰 Threat Reports

- [BFSI Threat Landscape 2026](threat-reports/bfsi-threat-landscape-2026.md)
- [Phishing Campaign Analysis](threat-reports/phishing-campaign-analysis.md)

---

## 🏅 Author

**Anvesh Raju Vishwaraju**  
Ex-Security Researcher, IDRBT (RBI's Institute)  
CompTIA Security+ | eJPTv2 | CASA-APIsec  
M.S. Cybersecurity — UNC Charlotte, USA

🔗 [LinkedIn](https://linkedin.com/in/arv007) | [GitHub](https://github.com/its-me-anvesh-var)

---

> All threat intelligence in this repository is based on publicly available sources (OTX, VirusTotal, CERT-In advisories). No proprietary or client data is shared.
