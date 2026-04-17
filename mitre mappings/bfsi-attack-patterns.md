# 🎯 BFSI Sector — MITRE ATT&CK Attack Patterns

**Author:** Anvesh Raju Vishwaraju  
**Framework:** MITRE ATT&CK v14  
**Sector:** Banking, Financial Services & Insurance (India)

---

## Most Observed Techniques — BFSI India 2026

### Initial Access

| ID | Technique | Prevalence | Actor Examples |
|---|---|---|---|
| T1566.001 | Spearphishing Attachment | 🔴 Very High | SideCopy, FIN7 |
| T1566.002 | Spearphishing Link (SMS/Email) | 🔴 Very High | Local groups |
| T1190 | Exploit Public-Facing App | 🟠 High | Lazarus, FIN7 |
| T1078 | Valid Accounts (Stolen Creds) | 🔴 Very High | All actors |
| T1195 | Supply Chain Compromise | 🟡 Medium | Lazarus |

### Execution

| ID | Technique | Prevalence | Notes |
|---|---|---|---|
| T1059.001 | PowerShell | 🔴 Very High | Most common post-access |
| T1059.003 | Windows Command Shell | 🟠 High | Batch scripts |
| T1204.002 | Malicious File (User exec) | 🔴 Very High | Office macros, LNK |
| T1106 | Native API | 🟡 Medium | Advanced actors |

### Persistence

| ID | Technique | Prevalence | Notes |
|---|---|---|---|
| T1078 | Valid Accounts | 🔴 Very High | Most persistent method |
| T1136.001 | Create Local Account | 🟠 High | Post-compromise |
| T1547.001 | Registry Run Keys | 🟠 High | Malware persistence |
| T1053.005 | Scheduled Tasks | 🟠 High | Common backdoor |
| T1543.003 | Windows Service | 🟡 Medium | Advanced actors |

### Credential Access

| ID | Technique | Prevalence | Notes |
|---|---|---|---|
| T1110.001 | Brute Force | 🔴 Very High | RDP, SSH, NetBanking |
| T1110.004 | Credential Stuffing | 🔴 Very High | Leaked DB usage |
| T1539 | Steal Web Session Cookie | 🟠 High | Banking session theft |
| T1003.001 | LSASS Memory Dump | 🟠 High | Mimikatz post-access |
| T1056.003 | Web Portal Capture | 🔴 Very High | Phishing kits |

### Lateral Movement

| ID | Technique | Prevalence | Notes |
|---|---|---|---|
| T1021.001 | RDP | 🟠 High | Internal spread |
| T1021.002 | SMB/Admin Shares | 🟠 High | WannaCry style |
| T1550.002 | Pass the Hash | 🟡 Medium | Advanced actors |
| T1563.002 | RDP Hijacking | 🟡 Medium | Insider threat |

### Exfiltration

| ID | Technique | Prevalence | Notes |
|---|---|---|---|
| T1041 | Exfil Over C2 Channel | 🟠 High | HTTP/S beaconing |
| T1567.002 | Exfil to Cloud Storage | 🟠 High | Google Drive, Dropbox |
| T1048.003 | Exfil Over DNS | 🟡 Medium | Advanced actors |
| T1657 | Financial Theft (SWIFT) | 🟡 Medium | Lazarus Group |

### Impact

| ID | Technique | Prevalence | Notes |
|---|---|---|---|
| T1486 | Ransomware Encryption | 🔴 Very High | LockBit, BlackCat |
| T1657 | Financial Theft | 🟠 High | UPI fraud, SWIFT |
| T1490 | Inhibit System Recovery | 🟠 High | Shadow copy delete |
| T1489 | Service Stop | 🟡 Medium | Pre-ransomware |

---

## Detection Priority Matrix

Based on impact and detectability:

| Priority | Technique | Why | Detection Rule |
|---|---|---|---|
| P1 | T1566 Phishing | #1 initial access | Email gateway |
| P1 | T1110 Brute Force | High volume, detectable | brute-force.spl |
| P1 | T1486 Ransomware | Catastrophic impact | custom-rules.xml |
| P2 | T1059 PowerShell | Very common post-access | powershell-abuse.spl |
| P2 | T1078 Valid Accounts | Hard to detect | after-hours-login.spl |
| P2 | T1041 Exfiltration | Data loss | data-exfiltration.spl |
| P3 | T1003 Credential Dump | Advanced actors | custom-rules.xml |
| P3 | T1021 Lateral Movement | Post-compromise | brute-force.spl |

---

## Recommended Detection Stack for BFSI

```
Layer 1 — Email Gateway (Phishing prevention)
  → DMARC + SPF + DKIM enforcement
  → URL rewriting + sandboxing
  → Attachment detonation

Layer 2 — Network (Traffic analysis)
  → Suricata with ET Open rules
  → DNS monitoring for C2/DGA
  → NetFlow analysis for exfiltration

Layer 3 — Endpoint (HIDS)
  → Wazuh agents on all endpoints
  → FIM on critical directories
  → Process creation logging

Layer 4 — SIEM (Correlation)
  → Splunk with ATT&CK mapped rules
  → Wazuh custom rules
  → Alert triage workflow

Layer 5 — Threat Intelligence (Context)
  → OTX AlienVault IOC feeds
  → CERT-In advisories
  → BFSI-ISAC sharing
```
